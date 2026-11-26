//! Block transfer of an ISO-DEP session whose block protocol the host runs.
//!
//! The reader carries each block and owns its CRC; the host block engine
//! owns sequencing, CID and NAD fields, chaining and WTX.
use crate::{FrameSize, WaitIndex};
use alloc::vec::Vec;
use core::{fmt, time::Duration};

/// A card identifier that every block of a session carries, in `1..=14`.
/// A session that assigned CID 0 omits the field instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cid(u8);

impl Cid {
    /// Accept the identifiers `1..=14`.
    pub const fn new(value: u8) -> Option<Self> {
        if value >= 1 && value <= 14 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// The 4-bit field value.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Block protocol parameters that a card's activation granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameters {
    card_frame_size: FrameSize,
    reader_frame_size: FrameSize,
    fwi: WaitIndex,
    cid: Option<Cid>,
    nad_supported: bool,
    maximum_command_bytes: Option<usize>,
}

impl Parameters {
    pub(crate) fn new(
        card_frame_size: FrameSize,
        reader_frame_size: FrameSize,
        fwi: WaitIndex,
        cid: Option<Cid>,
        nad_supported: bool,
        maximum_command_bytes: Option<usize>,
    ) -> Self {
        Self {
            card_frame_size,
            reader_frame_size,
            fwi,
            cid,
            nad_supported,
            maximum_command_bytes,
        }
    }
    /// Card frame size (FSC): the largest block the card accepts.
    pub fn card_frame_size(&self) -> FrameSize {
        self.card_frame_size
    }
    /// Reader frame size (FSD) that activation announced: the largest block
    /// the card may send.
    pub fn reader_frame_size(&self) -> FrameSize {
        self.reader_frame_size
    }
    /// Frame waiting integer.
    pub fn fwi(&self) -> WaitIndex {
        self.fwi
    }
    /// CID that every block carries, or `None` when blocks carry no CID field.
    pub fn cid(&self) -> Option<Cid> {
        self.cid
    }
    /// Whether the card advertises optional node-address fields.
    pub fn nad_supported(&self) -> bool {
        self.nad_supported
    }
    /// Command buffer limit the card advertises, when it advertises one.
    pub fn maximum_command_bytes(&self) -> Option<usize> {
        self.maximum_command_bytes
    }
}

/// Card reply to one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// The reply block without CRC, after the reader checked the CRC.
    Block(Vec<u8>),
    /// No reply arrived within the transfer's wait.
    Silence,
}

/// A card selected with ISO-DEP parameters whose blocks the reader carries.
///
/// The reader layer owns RF configuration and each transfer's failure
/// states; the host block engine owns block contents. The reader carries
/// blocks of up to [`Parameters::reader_frame_size`] in each direction.
///
/// RATS and ATTRIB move the card into a protocol state that later selection
/// requests do not reach. The reader that granted the selection therefore
/// cycles the RF field before its next selection.
pub trait Selection {
    /// Reader failure of setup or of one transfer. Whether a block was sent is
    /// part of the reader's error contract.
    type Error: fmt::Debug;
    /// Transfer authority after the reader setup that every block runs under.
    type Blocks<'s>: Blocks<Error = Self::Error>
    where
        Self: 's;

    /// Parameters that activation granted.
    fn parameters(&self) -> Parameters;

    /// Apply the reader setup of block transfers. Failure sends no block.
    ///
    /// # Errors
    ///
    /// Returns the reader's setup failure.
    fn blocks(&mut self) -> Result<Self::Blocks<'_>, Self::Error>;
}

/// Block transfers of one prepared ISO-DEP selection.
pub trait Blocks {
    /// Reader failure of one transfer.
    type Error;

    /// Send one block without CRC and return the card's reply, waiting at
    /// most `wait` for its start. The reader never replays a block
    /// automatically, and a reply missing within `wait` leaves the selection
    /// usable for the block protocol's recovery.
    ///
    /// # Errors
    ///
    /// Returns the reader's failure of this transfer, including blocks above
    /// the reader frame size before sending and an invalid reply frame.
    fn transfer(&mut self, block: &[u8], wait: Duration) -> Result<Reply, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carried_card_identifiers_exclude_zero_and_the_reserved_value() {
        assert_eq!(Cid::new(0), None);
        assert_eq!(Cid::new(1).map(Cid::get), Some(1));
        assert_eq!(Cid::new(14).map(Cid::get), Some(14));
        assert_eq!(Cid::new(15), None);
    }
}
