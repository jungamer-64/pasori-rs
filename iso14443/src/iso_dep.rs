//! Block transfer of an ISO-DEP session whose block protocol the host runs.
//!
//! The reader carries each block and owns its CRC; the host block engine
//! owns sequencing, CID and NAD fields, chaining and WTX.
use crate::WaitIndex;
use alloc::vec::Vec;
use core::{fmt, time::Duration};

/// Smallest frame of the block protocol, including CRC: the frame size that
/// FSCI and FSDI 0 grant.
pub const MIN_FRAME_BYTES: u16 = 16;

/// Block protocol parameters that a card's activation granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameters {
    frame_size: u16,
    fwi: WaitIndex,
    cid: Option<u8>,
    nad_supported: bool,
    maximum_command_bytes: Option<usize>,
}

impl Parameters {
    pub(crate) fn new(
        frame_size: u16,
        fwi: WaitIndex,
        cid: Option<u8>,
        nad_supported: bool,
        maximum_command_bytes: Option<usize>,
    ) -> Self {
        Self {
            frame_size,
            fwi,
            cid,
            nad_supported,
            maximum_command_bytes,
        }
    }
    /// Card frame size (FSC), including protocol overhead and CRC.
    pub fn frame_size(&self) -> u16 {
        self.frame_size
    }
    /// Frame waiting integer.
    pub fn fwi(&self) -> WaitIndex {
        self.fwi
    }
    /// CID that every block carries, or `None` when blocks carry no CID field.
    pub fn cid(&self) -> Option<u8> {
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

/// A card selected with ISO-DEP parameters whose blocks the reader carries.
///
/// The reader layer owns RF configuration and each transfer's failure
/// states; the host block engine owns block contents. A block exchange that
/// leaves card state which the next selection does not clear must be
/// declared with [`Self::require_field_cycle`].
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

    /// Largest block, including its two CRC bytes, that the reader carries in
    /// each direction. A reader that carries the block protocol carries
    /// blocks of at least [`MIN_FRAME_BYTES`].
    fn maximum_block_bytes(&self) -> usize;

    /// Apply the reader setup of block transfers. Failure sends no block.
    ///
    /// # Errors
    ///
    /// Returns the reader's setup failure.
    fn blocks(&mut self) -> Result<Self::Blocks<'_>, Self::Error>;

    /// Whether `error` reports a transfer that received no answer within its
    /// wait. Other failures report an invalid frame or a reader failure.
    fn is_rf_timeout(error: &Self::Error) -> bool;

    /// Make the next selection on this reader cycle the RF field before its
    /// request.
    fn require_field_cycle(&mut self);
}

/// Block transfers of one prepared ISO-DEP selection.
pub trait Blocks {
    /// Reader failure of one transfer.
    type Error;

    /// Send one block without CRC and return the card's reply block without
    /// CRC, waiting at most `wait` for its start. The reader never replays a
    /// block automatically.
    ///
    /// # Errors
    ///
    /// Returns the reader's failure of this transfer, including blocks above
    /// the reader's limit before sending.
    fn transfer(&mut self, block: &[u8], wait: Duration) -> Result<Vec<u8>, Self::Error>;
}
