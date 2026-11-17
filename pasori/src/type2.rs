//! NFC Forum Type 2 tag access and emulation over NFC-A.

mod target;

pub use target::{MAX_TYPE2_EMULATED_NDEF_BYTES, Type2EmulationError, Type2Event, Type2Target};

use rcs956::{reader::TypeACard, transport::Transport};

/// A selected Type 2 tag and the memory sector its commands address.
/// NDEF access is [`Self::read_ndef`] and [`Self::write_ndef`].
#[derive(Debug)]
pub struct Type2Tag<'a, T: Transport> {
    pub(crate) card: TypeACard<'a, T>,
    /// Sector the tag currently addresses; `None` after a SECTOR SELECT whose
    /// outcome is unknown, so that the next access selects again.
    pub(crate) sector: Option<u8>,
}

impl<'a, T: Transport> Type2Tag<'a, T> {
    /// Take Type 2 command access to a fresh NFC-A selection, which addresses
    /// sector 0. Leaving sector 0 makes the next selection cycle the RF field,
    /// because a new selection request does not reset the sector.
    pub fn new(card: TypeACard<'a, T>) -> Self {
        Self {
            card,
            sector: Some(0),
        }
    }

    /// The reader selection, including its activation data.
    pub fn selection(&self) -> &TypeACard<'a, T> {
        &self.card
    }
}
