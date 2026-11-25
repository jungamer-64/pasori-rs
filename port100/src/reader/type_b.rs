//! NFC-B activation.

use super::{
    Error, Reader, ResponseWait,
    iso_dep::{Activation, IsoDepCard},
    settings::Settings,
};
use crate::transport::Transport;
use iso14443::{iso_dep, nfcb};

/// REQB command byte; parameter 00 requests a single slot.
const REQB: u8 = 0x05;
/// ATTRIB command byte.
const ATTRIB: u8 = 0x1d;
/// ATTRIB parameters 1 to 4: default TR0, TR1 and SOF/EOF; FSDI 8 (256-byte
/// frames) at 106 kbps in both directions; ISO/IEC 14443-4 compliance; CID 0.
const ATTRIB_PARAMETERS: [u8; 4] = [0x00, 0x08, 0x01, 0x00];

impl<T: Transport> Reader<T> {
    /// Activate one NFC-B card at 106 kbps with REQB for `afi` (zero
    /// requests all families) and ATTRIB with CID 0. Both wait `wait` for
    /// their reply.
    ///
    /// The field is switched off before activation, so that every card in it
    /// starts from its idle state. Returns `None` when no card answers REQB.
    /// Only cards whose ATQB advertises ISO-DEP are activated.
    ///
    /// # Errors
    ///
    /// Requires initialization. A card without ISO-DEP is
    /// [`Error::NotIsoDep`]. Any failure after REQB was answered requires a
    /// field cycle before the next selection.
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
        if !atqb.supports_iso_dep() {
            return Err(Error::NotIsoDep);
        }
        let [p0, p1, p2, p3] = atqb.pupi();
        let mut attrib = [ATTRIB, p0, p1, p2, p3, 0, 0, 0, 0];
        attrib[5..].copy_from_slice(&ATTRIB_PARAMETERS);
        let response = self.card_reply(&attrib, wait)?;
        let observation = nfcb::Observation::new(atqb, &response.data).map_err(Error::TypeB)?;
        if observation.cid() != 0 {
            return Err(Error::CardReply("ATTRIB CID differs from the assigned 0"));
        }
        let parameters = observation.iso_dep().ok_or(Error::NotIsoDep)?;
        Ok(Some((observation, parameters)))
    }
}
