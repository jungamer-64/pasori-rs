//! NFC-A and NFC-B activation and whole-byte ISO-DEP block exchange.

use super::{Error, IccResponsePolicy, Profile, Reader, ResponseWait, apdu};
use crate::transport::Transport;
use alloc::vec::Vec;
use core::time::Duration;
use iso14443::{iso_dep, nfca, nfcb};

const MAX_BLOCK: usize = 256;
const MAX_BLOCK_WITHOUT_CRC: usize = MAX_BLOCK - 2;

/// Validated card activation data for the host ISO-DEP block protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Activation {
    /// The reader selected a Type A card and the host sent RATS.
    TypeA {
        /// Final select acknowledgment reported by the reader.
        sak: u8,
        /// The actual RF answer to RATS without its CRC.
        ats: nfca::Ats,
    },
    /// The host obtained ATQB and completed ATTRIB.
    TypeB(nfcb::Observation),
}

impl<T: Transport> Reader<T> {
    /// Activate a 106 kbps NFC-A ISO-DEP card, returning `None` when the
    /// reader's Layer 3 selection receives no RF answer. A fresh field
    /// precedes selection. RATS requests 256-byte frames with CID zero.
    ///
    /// # Errors
    ///
    /// Requires initialization. A Layer 3 selection without ISO-DEP yields
    /// [`Error::NotIsoDep`]. A failed RATS or invalid ATS ends the selection.
    pub fn poll_type_a(
        &mut self,
        wait: ResponseWait,
    ) -> Result<Option<IsoDepCard<'_, T>>, Error<T::Error>> {
        self.rf_off()?;
        self.energize()?;
        let sak = match self.objects(
            &Profile::TypeA.switch_command(),
            IccResponsePolicy::Unique,
            |objects| objects.sak(),
        ) {
            Err(Error::DeviceApdu(error)) if error.icc_timeout() => return Ok(None),
            result => result?,
        };
        if sak & 0x04 != 0 {
            return Err(Error::TypeASak(sak));
        }
        if sak & 0x20 == 0 {
            return Err(Error::NotIsoDep);
        }
        self.acknowledge(&Profile::TypeA.framing_command())?;
        self.enable_profile(Profile::TypeA);
        let result = self
            .exchange_rf(&[0xe0, 0x80], wait, IccResponsePolicy::Unique)
            .and_then(|ats| nfca::Ats::parse(&ats).map_err(Error::TypeA));
        let ats = match result {
            Ok(ats) => ats,
            Err(error) => {
                self.invalidate_field();
                return Err(error);
            }
        };
        self.link.wait(ats.startup_guard());
        let parameters = ats.iso_dep();
        Ok(Some(IsoDepCard {
            reader: self,
            activation: Activation::TypeA { sak, ats },
            parameters,
        }))
    }

    /// Activate a 106 kbps NFC-B ISO-DEP card using one REQB slot and
    /// ATTRIB with CID zero. AFI zero matches all application families.
    /// Returns `None` when no card answers REQB.
    ///
    /// # Errors
    ///
    /// Requires initialization. A card without ISO-DEP, a malformed ATQB
    /// or ATTRIB response, or failure after REQB answered is an error.
    pub fn poll_type_b(
        &mut self,
        afi: u8,
        wait: ResponseWait,
    ) -> Result<Option<IsoDepCard<'_, T>>, Error<T::Error>> {
        self.rf_off()?;
        self.invalidate_field();
        self.acknowledge(&Profile::TypeB.switch_command())?;
        self.acknowledge(&Profile::TypeB.framing_command())?;
        self.energize()?;
        self.acknowledge(&apdu::speed(0x80))?;
        self.enable_profile(Profile::TypeB);
        match self.activate_type_b(afi, wait) {
            Ok(Some((observation, parameters))) => Ok(Some(IsoDepCard {
                reader: self,
                activation: Activation::TypeB(observation),
                parameters,
            })),
            Ok(None) => Ok(None),
            Err(error) => {
                self.invalidate_field();
                Err(error)
            }
        }
    }

    fn activate_type_b(
        &mut self,
        afi: u8,
        wait: ResponseWait,
    ) -> Result<Option<(nfcb::Observation, iso_dep::Parameters)>, Error<T::Error>> {
        let atqb = match self.exchange_rf(&[0x05, afi, 0x00], wait, IccResponsePolicy::Unique) {
            Err(Error::NoResponse) => return Ok(None),
            result => result?,
        };
        let atqb =
            <[u8; 12]>::try_from(atqb.as_slice()).map_err(|_| Error::ReplyLength(atqb.len()))?;
        let atqb = nfcb::Atqb::new(atqb).map_err(Error::TypeB)?;
        if !atqb.supports_iso_dep() {
            return Err(Error::NotIsoDep);
        }
        // Default guard and framing, FSDI 8, 106 kbps, ISO-DEP, CID zero.
        let [a, b, c, d] = atqb.pupi();
        let attrib = self.exchange_rf(
            &[0x1d, a, b, c, d, 0x00, 0x08, 0x01, 0x00],
            wait,
            IccResponsePolicy::Unique,
        )?;
        let observation = nfcb::Observation::new(atqb, &attrib).map_err(Error::TypeB)?;
        if observation.cid() != 0 {
            return Err(Error::AttribCid(observation.cid()));
        }
        let parameters = observation.iso_dep().ok_or(Error::NotIsoDep)?;
        Ok(Some((observation, parameters)))
    }
}

/// An activated NFC-A or NFC-B card that grants exclusive block exchange.
#[derive(Debug)]
pub struct IsoDepCard<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    activation: Activation,
    parameters: iso_dep::Parameters,
}

impl<T: Transport> IsoDepCard<'_, T> {
    /// Validated activation data for this selection.
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
        MAX_BLOCK
    }

    fn blocks(&mut self) -> Result<Self::Blocks<'_>, Self::Error> {
        self.reader.require_configured_field()?;
        Ok(IsoDepBlocks {
            reader: self.reader,
        })
    }

    fn is_rf_timeout(error: &Self::Error) -> bool {
        matches!(error, Error::NoResponse)
    }

    fn require_field_cycle(&mut self) {
        self.reader.require_cycle();
    }
}

/// Block transfer authority borrowed from an ISO-DEP selection. The reader
/// handles the RF CRC and carries the ISO-DEP prologue supplied by the host.
#[derive(Debug)]
pub struct IsoDepBlocks<'s, T: Transport> {
    reader: &'s mut Reader<T>,
}

impl<T: Transport> iso_dep::Blocks for IsoDepBlocks<'_, T> {
    type Error = Error<T::Error>;

    fn transfer(&mut self, block: &[u8], wait: Duration) -> Result<Vec<u8>, Self::Error> {
        if block.is_empty() || block.len() > MAX_BLOCK_WITHOUT_CRC {
            return Err(Error::InputLength(block.len()));
        }
        let wait = ResponseWait::new(wait).ok_or(Error::WaitRange(wait))?;
        let response = self
            .reader
            .exchange_rf(block, wait, IccResponsePolicy::Unique)?;
        if response.is_empty() || response.len() > MAX_BLOCK_WITHOUT_CRC {
            self.reader.invalidate_field();
            return Err(Error::ReplyLength(response.len()));
        }
        Ok(response)
    }
}
