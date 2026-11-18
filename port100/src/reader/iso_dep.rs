//! ISO-DEP selections whose blocks the reader carries.

use super::{Error, Field, Reader, ResponseWait, settings::Settings};
use crate::transport::Transport;
use alloc::vec::Vec;
use core::time::Duration;
use iso14443::{iso_dep, nfca, nfcb};

/// Largest block, including its two CRC bytes, in each direction: the frame
/// size that RATS and ATTRIB announce to the card.
pub const MAX_BLOCK_BYTES: usize = 256;

/// Activation data of an ISO-DEP selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Activation {
    /// NFC-A card activated with RATS; its ATS is present.
    TypeA(nfca::Observation),
    /// NFC-B card activated with ATTRIB.
    TypeB(nfcb::Observation),
}

/// NFC-A or NFC-B selection whose activation granted ISO-DEP. The host runs
/// the block protocol; the reader transfers each block and owns its CRC.
///
/// [`iso_dep::Selection::blocks`] requires the RF settings of the
/// activation to be in effect and sends nothing. Each block waits for the
/// wait the block engine gives it, which must not exceed
/// [`ResponseWait::MAX`]; a missing reply is [`Error::NoResponse`].
#[derive(Debug)]
pub struct IsoDepCard<'a, T: Transport> {
    pub(super) reader: &'a mut Reader<T>,
    pub(super) activation: Activation,
    pub(super) parameters: iso_dep::Parameters,
    pub(super) settings: Settings,
}

impl<T: Transport> IsoDepCard<'_, T> {
    /// Validated activation data.
    pub fn activation(&self) -> &Activation {
        &self.activation
    }
}

impl<T: Transport> iso_dep::Selection for IsoDepCard<'_, T> {
    type Error = Error<T::Error>;
    type Blocks<'s>
        = IsoDepBlocks<'s, T>
    where
        Self: 's;

    fn parameters(&self) -> iso_dep::Parameters {
        self.parameters
    }

    fn maximum_block_bytes(&self) -> usize {
        MAX_BLOCK_BYTES
    }

    fn blocks(&mut self) -> Result<IsoDepBlocks<'_, T>, Error<T::Error>> {
        match self.reader.ready()?.1 {
            Field::On { settings, .. } if settings == self.settings => Ok(IsoDepBlocks {
                reader: self.reader,
                settings: self.settings,
            }),
            _ => Err(Error::FieldReset),
        }
    }

    fn is_rf_timeout(error: &Error<T::Error>) -> bool {
        matches!(error, Error::NoResponse)
    }

    fn require_field_cycle(&mut self) {
        self.reader.require_field_cycle();
    }
}

/// Block transfer authority of an ISO-DEP selection whose settings are in effect.
#[derive(Debug)]
pub struct IsoDepBlocks<'s, T: Transport> {
    reader: &'s mut Reader<T>,
    settings: Settings,
}

impl<T: Transport> iso_dep::Blocks for IsoDepBlocks<'_, T> {
    type Error = Error<T::Error>;

    fn transfer(&mut self, block: &[u8], wait: Duration) -> Result<Vec<u8>, Error<T::Error>> {
        let maximum = MAX_BLOCK_BYTES - 2;
        if block.len() > maximum {
            return Err(Error::InputLength {
                maximum,
                actual: block.len(),
            });
        }
        let wait = ResponseWait::new(wait).ok_or(Error::WaitRange(wait))?;
        self.reader
            .transceive(self.settings, block, wait)?
            .map(|received| received.data)
            .ok_or(Error::NoResponse)
    }
}
