use super::{
    super::{Attribute, BLOCK_BYTES, decode_length},
    Access, WriteFlag, attribute,
};
use crate::ndef::{Message, MessageError};
use alloc::{boxed::Box, vec, vec::Vec};
use core::{fmt, num::NonZeroU16};

/// Failure constructing a writable Type 3 NDEF memory.
#[derive(Debug)]
pub enum Type3NdefMemoryError {
    /// The initial NDEF exceeds the configured data blocks.
    MessageLength {
        /// Length of the initial NDEF in bytes.
        length: usize,
        /// Bytes in the configured data blocks.
        capacity: usize,
    },
    /// The nonempty initial value is not one complete NDEF message.
    Message(MessageError),
}

impl fmt::Display for Type3NdefMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageLength { length, capacity } => write!(
                f,
                "initial NDEF length {length} exceeds data capacity {capacity}"
            ),
            Self::Message(error) => write!(f, "invalid initial NDEF message: {error}"),
        }
    }
}

impl core::error::Error for Type3NdefMemoryError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Message(error) => Some(error),
            Self::MessageLength { .. } => None,
        }
    }
}

/// Effect of an accepted write on the published NDEF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type3NdefChange {
    /// The write flag was set. No message is published until an attribute
    /// write clears it.
    UpdateStarted,
    /// The write flag was cleared and a validated NDEF message, or an empty
    /// mapping, was published.
    Published {
        /// Length of the published message in bytes.
        length: usize,
    },
}

/// Writable Type 3 NDEF data blocks and their attribute state. The
/// contents, including an unfinished update, survive RF activations and
/// target shutdown while the caller keeps the memory.
///
/// Data blocks accept writes only while the write flag is set. An attribute
/// write may change only the write flag and the message length, and
/// clearing the flag publishes the message only if it is one complete NDEF
/// message. A refused write leaves the memory as it was.
pub struct Type3NdefMemory {
    // The backing allocation is fixed at construction and equals capacity.
    bytes: Box<[u8]>,
    blocks: NonZeroU16,
    flag: WriteFlag,
    length: [u8; 3],
}

impl fmt::Debug for Type3NdefMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Type3NdefMemory")
            .field("data_blocks", &self.blocks)
            .field("flag", &self.flag)
            .field("length", &decode_length(self.length))
            .finish()
    }
}

/// One block of an accepted Write Without Encryption request, with its
/// one-based block list position. Block 0 is the attribute.
#[derive(Debug, Clone, Copy)]
pub(super) struct WrittenBlock<'p> {
    pub(super) position: u8,
    pub(super) block: u16,
    pub(super) data: &'p [u8; BLOCK_BYTES],
}

/// The block list position of the write that the memory refused.
#[derive(Debug, Clone, Copy)]
pub(super) struct Refused(pub(super) u8);

impl Type3NdefMemory {
    /// Create a memory with a fixed number of 16-byte data blocks, holding
    /// `initial_message` as the published NDEF. An empty initial slice
    /// publishes an empty mapping.
    pub fn new(
        data_blocks: NonZeroU16,
        initial_message: &[u8],
    ) -> Result<Self, Type3NdefMemoryError> {
        let capacity = usize::from(data_blocks.get()) * BLOCK_BYTES;
        let length = Attribute::encode_length(initial_message.len())
            .filter(|_| initial_message.len() <= capacity)
            .ok_or(Type3NdefMemoryError::MessageLength {
                length: initial_message.len(),
                capacity,
            })?;
        if !initial_message.is_empty() {
            Message::parse(initial_message).map_err(Type3NdefMemoryError::Message)?;
        }
        let mut bytes = vec![0; capacity].into_boxed_slice();
        bytes[..initial_message.len()].copy_from_slice(initial_message);
        Ok(Self {
            bytes,
            blocks: data_blocks,
            flag: WriteFlag::Published,
            length,
        })
    }

    /// Borrow the published NDEF bytes. An empty slice is an empty mapping.
    /// `None` means an update has set the write flag and not yet published.
    pub fn message(&self) -> Option<&[u8]> {
        (self.flag == WriteFlag::Published).then(|| &self.bytes[..decode_length(self.length)])
    }

    pub(super) fn data_blocks(&self) -> u16 {
        self.blocks.get()
    }

    /// Block 0 is the attribute. Data blocks are numbered from 1 through
    /// [Self::data_blocks].
    pub(super) fn block(&self, number: u16) -> [u8; BLOCK_BYTES] {
        let Some(data) = number.checked_sub(1) else {
            return self.attribute(self.flag, self.length);
        };
        let start = usize::from(data) * BLOCK_BYTES;
        let mut block = [0; BLOCK_BYTES];
        if let Some(bytes) = self.bytes.get(start..start + BLOCK_BYTES) {
            block.copy_from_slice(bytes);
        }
        block
    }

    /// Apply the writes in list order as one change, or refuse all of them.
    /// Block numbers are within the memory.
    pub(super) fn write(
        &mut self,
        writes: &[WrittenBlock<'_>],
    ) -> Result<Option<Type3NdefChange>, Refused> {
        let mut flag = self.flag;
        let mut length = self.length;
        let mut publication = None;
        for write in writes {
            if write.block == 0 {
                (flag, length) = self
                    .written_attribute(write.data)
                    .ok_or(Refused(write.position))?;
                publication = (flag == WriteFlag::Published).then_some(write.position);
            } else if flag != WriteFlag::Updating {
                return Err(Refused(write.position));
            }
        }

        let mut replaced = Vec::new();
        for write in writes {
            let Some(data) = write.block.checked_sub(1) else {
                continue;
            };
            let start = usize::from(data) * BLOCK_BYTES;
            let Some(block) = self.bytes.get_mut(start..start + BLOCK_BYTES) else {
                continue;
            };
            if publication.is_some() {
                let mut previous = [0; BLOCK_BYTES];
                previous.copy_from_slice(block);
                replaced.push((start, previous));
            }
            block.copy_from_slice(write.data);
        }
        if let Some(position) = publication {
            let message = &self.bytes[..decode_length(length)];
            if !message.is_empty() && Message::parse(message).is_err() {
                for (start, previous) in replaced.iter().rev() {
                    self.bytes[*start..*start + BLOCK_BYTES].copy_from_slice(previous);
                }
                return Err(Refused(position));
            }
        }

        let change = match (publication, self.flag, flag) {
            (Some(_), _, _) => Some(Type3NdefChange::Published {
                length: decode_length(length),
            }),
            (None, WriteFlag::Published, WriteFlag::Updating) => {
                Some(Type3NdefChange::UpdateStarted)
            }
            (None, _, _) => None,
        };
        self.flag = flag;
        self.length = length;
        Ok(change)
    }

    fn attribute(&self, flag: WriteFlag, length: [u8; 3]) -> [u8; BLOCK_BYTES] {
        attribute(Access::ReadWrite, self.blocks.get(), flag, length)
    }

    /// The write flag and length of an attribute that leaves every other
    /// field as this memory publishes it.
    fn written_attribute(&self, data: &[u8; BLOCK_BYTES]) -> Option<(WriteFlag, [u8; 3])> {
        let flag = WriteFlag::from_byte(data[9])?;
        let length = [data[11], data[12], data[13]];
        (decode_length(length) <= self.bytes.len() && *data == self.attribute(flag, length))
            .then_some((flag, length))
    }
}
