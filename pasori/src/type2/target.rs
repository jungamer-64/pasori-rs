use crate::ndef::{Message, MessageError};
use alloc::vec::Vec;
use core::fmt;
use iso14443::nfca::{PassiveTarget, PassiveTargetReader, TargetCommand};

const MEMORY_BYTES: usize = 64;
const DATA_START: usize = 16;
const HALT: [u8; 2] = [0x50, 0];

/// Largest message in the emulated Type 2 tag's read-only data area.
pub const MAX_TYPE2_EMULATED_NDEF_BYTES: usize = MEMORY_BYTES - DATA_START - 2;

/// Error starting or operating the read-only Type 2 target.
#[derive(Debug)]
pub enum Type2EmulationError<E> {
    /// The proposed NDEF does not fit in the emulated memory.
    MessageLength(usize),
    /// The proposed bytes do not encode one complete NDEF message.
    Message(MessageError),
    /// Setup, activation, reception or response failed at the reader boundary.
    /// The reader's error defines whether the operation can continue.
    Reader(E),
    /// The initiator halted the tag.
    Halted,
}

impl<E: fmt::Debug> fmt::Display for Type2EmulationError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageLength(length) => write!(
                f,
                "NDEF message of {length} bytes exceeds {MAX_TYPE2_EMULATED_NDEF_BYTES}"
            ),
            Self::Message(_) => f.write_str("invalid NDEF message"),
            Self::Reader(_) => f.write_str("Type 2 emulation reader command failed"),
            Self::Halted => f.write_str("Type 2 emulation was halted"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for Type2EmulationError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Message(error) => Some(error),
            Self::Reader(error) => Some(error),
            _ => None,
        }
    }
}

/// The disposition of one command received from a Type A reader.
#[derive(Debug, PartialEq, Eq)]
pub enum Type2Event {
    /// Replied with four pages beginning at the given page.
    Read(u8),
    /// No response was sent to this unsupported or malformed command.
    Ignored(Vec<u8>),
    /// The initiator halted the tag. Call [Type2Target::finish].
    Halted,
}

/// Exclusive passive target serving an immutable Type 2 memory image.
#[derive(Debug)]
pub struct Type2Target<L: PassiveTarget> {
    target: L,
    memory: [u8; MEMORY_BYTES],
    halted: bool,
}

impl<L: PassiveTarget> Type2Target<L> {
    /// Expose an NDEF message as a read-only Type 2 target at 106 kbps.
    /// The UID is 08 followed by the supplied suffix. The message is checked
    /// before entering target mode.
    pub fn listen<'a, R>(
        reader: &'a mut R,
        uid_suffix: [u8; 3],
        message: &[u8],
        timeout: L::Wait,
    ) -> Result<Self, Type2EmulationError<L::Error>>
    where
        R: PassiveTargetReader<Target<'a> = L, Error = L::Error, Wait = L::Wait> + 'a,
    {
        let length = message_length(message)?;
        let target = reader
            .listen_type_a(uid_suffix, timeout)
            .map_err(Type2EmulationError::Reader)?;
        let memory = memory_image(target.uid(), length, message);
        Ok(Self {
            target,
            memory,
            halted: false,
        })
    }

    /// Receive one command and reply to a READ within the emulated memory.
    /// READ wraps at the end of the static memory.
    pub fn serve_next(
        &mut self,
        timeout: L::Wait,
    ) -> Result<Type2Event, Type2EmulationError<L::Error>> {
        if self.halted {
            return Err(Type2EmulationError::Halted);
        }
        let command = self
            .target
            .receive(timeout)
            .map_err(Type2EmulationError::Reader)?;
        Ok(match command.data() {
            data if data == HALT => {
                self.halted = true;
                Type2Event::Halted
            }
            &[0x30, page @ 0..=15] => {
                let start = usize::from(page) * 4;
                let response: [u8; 16] =
                    core::array::from_fn(|index| self.memory[(start + index) % MEMORY_BYTES]);
                command
                    .respond(&response)
                    .map_err(Type2EmulationError::Reader)?;
                Type2Event::Read(page)
            }
            data => Type2Event::Ignored(data.to_vec()),
        })
    }

    /// Stop emulation and return the reader to RF-off readiness.
    pub fn finish(self) -> Result<(), L::Error> {
        self.target.finish()
    }
}

/// The one-byte TLV length of a message that fits the emulated data area.
fn message_length<E>(message: &[u8]) -> Result<u8, Type2EmulationError<E>> {
    let length = u8::try_from(message.len())
        .ok()
        .filter(|_| message.len() <= MAX_TYPE2_EMULATED_NDEF_BYTES)
        .ok_or(Type2EmulationError::MessageLength(message.len()))?;
    if !message.is_empty() {
        Message::parse(message).map_err(Type2EmulationError::Message)?;
    }
    Ok(length)
}

/// Static memory: UID with its BCC, lock bytes, a read-only capability
/// container, and the NDEF TLV followed by a Terminator if it fits.
fn memory_image(uid: [u8; 4], length: u8, message: &[u8]) -> [u8; MEMORY_BYTES] {
    let [a, b, c, d] = uid;
    let mut memory = [0; MEMORY_BYTES];
    memory[..5].copy_from_slice(&[a, b, c, d, a ^ b ^ c ^ d]);
    memory[10..16].copy_from_slice(&[0xff, 0xff, 0xe1, 0x10, 6, 0x0f]);
    memory[16..18].copy_from_slice(&[3, length]);
    memory[18..18 + message.len()].copy_from_slice(message);
    if let Some(terminator) = memory.get_mut(18 + message.len()) {
        *terminator = 0xfe;
    }
    memory
}
