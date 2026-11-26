//! ISO-DEP selections whose blocks the reader carries.

use super::{Error, Field, Reader, ResponseWait, settings::Settings};
use crate::transport::Transport;
use core::time::Duration;
use iso14443::{FrameSize, iso_dep, nfca, nfcb};

/// Reader frame size (FSD) that RATS and ATTRIB announce to the card: the
/// largest block, including its two CRC bytes, carried in each direction.
pub const READER_FRAME_SIZE: FrameSize = FrameSize::from_index(8);

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
/// [`ResponseWait::MAX`]; a missing reply is [`iso_dep::Reply::Silence`].
/// Every selection starts by cycling the RF field, which releases a card
/// that an earlier selection left in the protocol state.
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

    fn blocks(&mut self) -> Result<IsoDepBlocks<'_, T>, Error<T::Error>> {
        match self.reader.ready()?.1 {
            Field::On { settings, .. } if settings == self.settings => Ok(IsoDepBlocks {
                reader: self.reader,
                settings: self.settings,
            }),
            _ => Err(Error::FieldReset),
        }
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

    fn transfer(
        &mut self,
        block: &[u8],
        wait: Duration,
    ) -> Result<iso_dep::Reply, Error<T::Error>> {
        let maximum = usize::from(READER_FRAME_SIZE.bytes()) - 2;
        if block.len() > maximum {
            return Err(Error::InputLength {
                maximum,
                actual: block.len(),
            });
        }
        let wait = ResponseWait::new(wait).ok_or(Error::WaitRange(wait))?;
        let Some(received) = self.reader.transceive(self.settings, block, wait)? else {
            return Ok(iso_dep::Reply::Silence);
        };
        if matches!(self.settings, Settings::TypeA(_)) {
            received
                .whole_bytes()
                .map(iso_dep::Reply::Block)
                .inspect_err(|_| {
                    self.reader.require_field_cycle();
                })
        } else {
            Ok(iso_dep::Reply::Block(received.data))
        }
    }
}
