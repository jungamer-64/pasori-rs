//! A read-only NDEF file system carried by an NFC-A ISO-DEP target.

use super::{CAPABILITY_CONTAINER_ID, NDEF_APP_ID, SHORT_FILE_END};
use crate::{
    isodep::target::{Action, Progress, Session},
    ndef::{Message, MessageError},
};
use alloc::vec::Vec;
use core::fmt;
use iso14443::nfca::Rats;
use port100::{
    reader::{self, IsoDepATarget, TargetWait},
    transport::Transport,
};

const NDEF_FILE_ID: u16 = 0xe104;
const READ_LIMIT: u8 = 255;
const NLEN_BYTES: usize = 2;
// The observed Port-100 ATS advertises FSC 256 and FWI 8 at 106 kbps.
const ATS: [u8; 4] = [4, 0x68, 0x80, 0];
const FSC: u16 = 256;
// This is the 64-byte framing range exercised by the RC-S370/P initiator.
const OUTBOUND_FRAME_BYTES: u16 = 64;

/// Maximum read-only NDEF message in the short-offset Type 4 file.
pub const MAX_TYPE4_EMULATED_NDEF_BYTES: usize = SHORT_FILE_END - NLEN_BYTES;

/// Failure preparing or operating a Type 4A target.
#[derive(Debug)]
pub enum Type4EmulationError<E> {
    /// The message exceeds the short-offset file's capacity.
    MessageLength(usize),
    /// Nonempty input must be one complete NDEF message.
    Message(MessageError),
    /// The reader failed. During service, this revokes the target.
    Reader(reader::Error<E>),
    /// The initiator's field went away during a response. Delivery may be
    /// unknown. The next receive can wait for a new activation.
    ResponseFieldOff,
    /// An unfinished command exhausted the short APDU budget. Finish the
    /// target before listening again.
    CommandLimit,
    /// The target session ended. Call [Type4Target::finish].
    Inactive,
}

impl<E: fmt::Debug> fmt::Display for Type4EmulationError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageLength(length) => write!(
                f,
                "NDEF message of {length} bytes exceeds {MAX_TYPE4_EMULATED_NDEF_BYTES}"
            ),
            Self::Message(error) => write!(f, "invalid NDEF message: {error}"),
            Self::Reader(error) => write!(f, "Type 4A target: {error}"),
            Self::ResponseFieldOff => f.write_str("field lost during Type 4A response"),
            Self::CommandLimit => f.write_str("chained command exceeds the short APDU limit"),
            Self::Inactive => f.write_str("Type 4A target session has ended"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for Type4EmulationError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Message(error) => Some(error),
            Self::Reader(error) => Some(error),
            _ => None,
        }
    }
}

/// Progress of one Type 4A service step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type4Event {
    /// Sent ATS and established the ISO-DEP session.
    Activated,
    /// Sent a chaining fragment, acknowledgement or retransmission.
    Block,
    /// Sent the final or only block of an APDU response.
    Exchange,
    /// Left an unrelated or invalid frame unanswered.
    Ignored,
    /// No frame arrived within the receive wait.
    TimedOut,
    /// Lost the initiator's field. The next call can await fresh activation.
    FieldOff,
    /// Acknowledged S(DESELECT) and closed the session. Call
    /// [Type4Target::finish] to restore reader readiness.
    Deselected,
}

/// Exclusive Port-100 NFC-A target exposing an immutable Type 4 NDEF message.
/// Each ISO-DEP activation starts with no application or file selected.
#[derive(Debug)]
pub struct Type4Target<'r, 'm, T: Transport> {
    target: IsoDepATarget<'r, T>,
    state: State,
    files: Files<'m>,
}

#[derive(Debug)]
enum State {
    WaitingForRats,
    Active {
        session: Session,
        selected: Selection,
    },
    Inactive,
}

impl<'r, 'm, T: Transport> Type4Target<'r, 'm, T> {
    /// Configure the reader with UID `08` followed by the supplied suffix.
    /// Input is validated before reader I/O. An empty message sets NLEN to zero.
    pub fn listen(
        reader: &'r mut reader::Reader<T>,
        suffix: [u8; 3],
        message: &'m [u8],
    ) -> Result<Self, Type4EmulationError<T::Error>> {
        let files = Files::new(message)?;
        let target = reader
            .listen_iso_dep_a(suffix)
            .map_err(Type4EmulationError::Reader)?;
        Ok(Self {
            target,
            state: State::WaitingForRats,
            files,
        })
    }

    /// Handle one frame. The response and next receive can share one USB
    /// command, so a following frame may already be buffered when this returns.
    /// Call again promptly while the initiator holds the field.
    pub fn serve_next(
        &mut self,
        wait: TargetWait,
    ) -> Result<Type4Event, Type4EmulationError<T::Error>> {
        if matches!(self.state, State::Inactive) {
            return Err(Type4EmulationError::Inactive);
        }
        let command = match self.target.receive(wait) {
            Ok(command) => command,
            Err(reader::Error::TargetTimeout) => return Ok(Type4Event::TimedOut),
            Err(reader::Error::TargetFieldOff) => {
                self.state = State::WaitingForRats;
                return Ok(Type4Event::FieldOff);
            }
            Err(error) => {
                self.state = State::Inactive;
                return Err(Type4EmulationError::Reader(error));
            }
        };
        let (result, event) = match &mut self.state {
            State::WaitingForRats => {
                let Some(rats) = Rats::parse(command.data()) else {
                    return Ok(Type4Event::Ignored);
                };
                self.state = State::Active {
                    session: Session::new(rats.frame_size(), FSC, OUTBOUND_FRAME_BYTES),
                    selected: Selection::None,
                };
                (command.respond_and_wait(&ATS, wait), Type4Event::Activated)
            }
            State::Active { session, selected } => {
                match session.receive(command.data(), |apdu| self.files.execute(selected, apdu)) {
                    Action::Ignore => return Ok(Type4Event::Ignored),
                    Action::Reply(reply, progress) => (
                        command.respond_and_wait(&reply, wait),
                        match progress {
                            Progress::Block => Type4Event::Block,
                            Progress::Exchange => Type4Event::Exchange,
                        },
                    ),
                    Action::Deselect => {
                        self.state = State::Inactive;
                        (command.respond(&[0xc2]), Type4Event::Deselected)
                    }
                    Action::CommandLimit => {
                        self.state = State::Inactive;
                        return Err(Type4EmulationError::CommandLimit);
                    }
                }
            }
            State::Inactive => return Err(Type4EmulationError::Inactive),
        };
        match result {
            Ok(()) => Ok(event),
            Err(reader::Error::TargetFieldOff) => {
                self.state = State::WaitingForRats;
                Err(Type4EmulationError::ResponseFieldOff)
            }
            Err(error) => {
                self.state = State::Inactive;
                Err(Type4EmulationError::Reader(error))
            }
        }
    }

    /// Stop the target and restore reader readiness.
    pub fn finish(self) -> Result<(), reader::Error<T::Error>> {
        self.target.finish()
    }
}

#[derive(Debug, Clone, Copy)]
enum Selection {
    None,
    Application,
    File(File),
}

#[derive(Debug, Clone, Copy)]
enum File {
    CapabilityContainer,
    Ndef,
}

#[derive(Debug)]
struct Files<'m> {
    message: &'m [u8],
    nlen: u16,
    cc: [u8; 15],
}

fn ndef_file_size(nlen: u16) -> u16 {
    (nlen + 2).max(5)
}

impl<'m> Files<'m> {
    fn new<E>(message: &'m [u8]) -> Result<Self, Type4EmulationError<E>> {
        let length = message.len();
        let nlen = u16::try_from(length)
            .ok()
            .filter(|_| length <= MAX_TYPE4_EMULATED_NDEF_BYTES)
            .ok_or(Type4EmulationError::MessageLength(length))?;
        if !message.is_empty() {
            Message::parse(message).map_err(Type4EmulationError::Message)?;
        }
        let [id_high, id_low] = NDEF_FILE_ID.to_be_bytes();
        let [size_high, size_low] = ndef_file_size(nlen).to_be_bytes();
        Ok(Self {
            message,
            nlen,
            cc: [
                0, 15, 0x20, 0, READ_LIMIT, 0, 255, 4, 6, id_high, id_low, size_high, size_low, 0,
                0xff,
            ],
        })
    }

    fn execute(&self, selected: &mut Selection, apdu: &[u8]) -> Vec<u8> {
        let [class, instruction, p1, p2, body @ ..] = apdu else {
            return if apdu.is_empty() {
                Vec::new()
            } else {
                status(0x6700)
            };
        };
        if *class != 0 {
            return status(0x6e00);
        }
        match *instruction {
            0xa4 => Self::select(selected, [*p1, *p2], body),
            0xb0 => self.read(*selected, [*p1, *p2], body),
            0xd6 if matches!(selected, Selection::File(_)) => status(0x6982),
            0xd6 => status(0x6986),
            _ => status(0x6d00),
        }
    }

    fn select(selected: &mut Selection, parameters: [u8; 2], body: &[u8]) -> Vec<u8> {
        match parameters {
            [4, 0] => {
                let [7, data @ ..] = body else {
                    return status(0x6700);
                };
                let Some((aid, [] | [0])) = data.split_first_chunk::<7>() else {
                    return status(0x6700);
                };
                if aid != &NDEF_APP_ID {
                    return status(0x6a82);
                }
                *selected = Selection::Application;
            }
            [0, 0x0c] => {
                let &[2, high, low] = body else {
                    return status(0x6700);
                };
                if matches!(selected, Selection::None) {
                    return status(0x6a82);
                }
                let file = match u16::from_be_bytes([high, low]) {
                    CAPABILITY_CONTAINER_ID => File::CapabilityContainer,
                    NDEF_FILE_ID => File::Ndef,
                    _ => return status(0x6a82),
                };
                *selected = Selection::File(file);
            }
            _ => return status(0x6a86),
        }
        status(0x9000)
    }

    fn read(&self, selected: Selection, address: [u8; 2], body: &[u8]) -> Vec<u8> {
        let &[length @ 1..=READ_LIMIT] = body else {
            return status(0x6700);
        };
        let Selection::File(file) = selected else {
            return status(0x6986);
        };
        let offset = usize::from(u16::from_be_bytes(address));
        let size = match file {
            File::CapabilityContainer => self.cc.len(),
            File::Ndef => usize::from(ndef_file_size(self.nlen)),
        };
        if offset >= size {
            return status(0x6b00);
        }
        let requested_end = offset + usize::from(length);
        let end = requested_end.min(size);
        let mut response = Vec::with_capacity(end - offset + 2);
        match file {
            File::CapabilityContainer => response.extend_from_slice(&self.cc[offset..end]),
            File::Ndef => {
                if offset < NLEN_BYTES {
                    response
                        .extend_from_slice(&self.nlen.to_be_bytes()[offset..end.min(NLEN_BYTES)]);
                }
                let start = offset.saturating_sub(NLEN_BYTES);
                let end_of_message = end.saturating_sub(NLEN_BYTES).min(self.message.len());
                if start < end_of_message {
                    response.extend_from_slice(&self.message[start..end_of_message]);
                }
                response.resize(end - offset, 0);
            }
        }
        let word: u16 = if end == requested_end { 0x9000 } else { 0x6282 };
        response.extend(word.to_be_bytes());
        response
    }
}

fn status(word: u16) -> Vec<u8> {
    word.to_be_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;

    #[test]
    fn ndef_file_capacity_includes_the_length_field() -> Result<(), Type4EmulationError<Infallible>>
    {
        let selected = Selection::File(File::Ndef);
        let empty = Files::new(&[])?;
        assert_eq!(&empty.cc[11..], &[0, 5, 0, 0xff]);
        assert_eq!(empty.read(selected, [0, 0], &[5]), [0, 0, 0, 0, 0, 0x90, 0]);

        let mut message = alloc::vec![0xc5, 0, 0, 0, 0x7f, 0xf8];
        message.resize(MAX_TYPE4_EMULATED_NDEF_BYTES, 0xa5);
        let full = Files::new(&message)?;
        assert_eq!(&full.cc[11..], &[0x80, 0, 0, 0xff]);
        assert_eq!(full.read(selected, [0, 1], &[3]), [0xfe, 0xc5, 0, 0x90, 0]);
        assert_eq!(full.read(selected, [0x7f, 0xff], &[2]), [0xa5, 0x62, 0x82]);
        assert_eq!(full.read(selected, [0x80, 0], &[1]), [0x6b, 0]);

        message.push(0);
        assert!(matches!(
            Files::new::<Infallible>(&message),
            Err(Type4EmulationError::MessageLength(_))
        ));
        assert!(matches!(
            Files::new::<Infallible>(&[0xd0]),
            Err(Type4EmulationError::Message(_))
        ));
        Ok(())
    }
}
