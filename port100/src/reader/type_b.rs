//! NFC-B activation.

use super::{
    Error, Reader, ResponseWait,
    iso_dep::{Activation, IsoDepCard, READER_FRAME_SIZE},
    settings::Settings,
};
use crate::transport::Transport;
use iso14443::{iso_dep, nfcb};

/// REQB command byte; parameter 00 requests a single slot.
const REQB: u8 = 0x05;

impl<T: Transport> Reader<T> {
    /// Activate one NFC-B card at 106 kbps with REQB for `afi` (zero
    /// requests all families) and ATTRIB announcing [`READER_FRAME_SIZE`]
    /// with CID 0. Both wait `wait` for their reply.
    ///
    /// The field is switched off before activation, so that every card in it
    /// starts from its idle state. Returns `None` when no card answers REQB.
    /// Only cards whose ATQB advertises ISO-DEP are activated.
    ///
    /// # Errors
    ///
    /// Requires initialization. A card without ISO-DEP is
    /// [`nfcb::Error::NotIsoDep`]. Any failure after REQB was answered
    /// requires a field cycle before the next selection.
    pub fn poll_type_b(
        &mut self,
        afi: u8,
        wait: ResponseWait,
    ) -> Result<Option<IsoDepCard<'_, T>>, Error<T::Error>> {
        let settings = Settings::TypeB;
        self.begin_activation(settings)?;
        match self.activate_type_b(afi, wait) {
            Ok(Some((observation, parameters))) => Ok(Some(IsoDepCard {
                reader: self,
                activation: Activation::TypeB(observation),
                parameters,
                settings,
            })),
            Ok(None) => Ok(None),
            Err(error) => {
                self.require_field_cycle();
                Err(error)
            }
        }
    }

    fn activate_type_b(
        &mut self,
        afi: u8,
        wait: ResponseWait,
    ) -> Result<Option<(nfcb::Observation, iso_dep::Parameters)>, Error<T::Error>> {
        let Some(atqb) = self.in_comm_rf(&[REQB, afi, 0x00], wait)? else {
            return Ok(None);
        };
        let atqb = <[u8; 12]>::try_from(atqb.data.as_slice())
            .map_err(|_| Error::CardReply("ATQB length"))?;
        let atqb = nfcb::Atqb::new(atqb).map_err(Error::TypeB)?;
        let attrib = nfcb::Attrib::new(atqb, READER_FRAME_SIZE, None).map_err(Error::TypeB)?;
        let response = self.card_reply(&attrib.command(), wait)?;
        attrib
            .complete(&response.data)
            .map(Some)
            .map_err(Error::TypeB)
    }
}
