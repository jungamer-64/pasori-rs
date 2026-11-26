//! NFC-A and NFC-B activation and whole-byte ISO-DEP block exchange.

use super::{Error, IccResponsePolicy, Profile, Reader, ResponseWait, apdu};
use crate::transport::Transport;
use core::time::Duration;
use iso14443::{FrameSize, iso_dep, nfca, nfcb};

/// Reader frame size (FSD) that RATS and ATTRIB announce to the card: the
/// largest block, including its two CRC bytes, carried in each direction.
pub const READER_FRAME_SIZE: FrameSize = FrameSize::from_index(8);
const MAX_BLOCK_WITHOUT_CRC: usize = READER_FRAME_SIZE.bytes() as usize - 2;
/// RATS announcing the reader frame size and assigning CID 0.
const RATS: nfca::Rats = nfca::Rats::new(READER_FRAME_SIZE, None);

/// Validated card activation data for the host ISO-DEP block protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Activation {
    /// The reader selected a Type A card and the host sent RATS.
    TypeA {
        /// Final select acknowledgment reported by the reader.
        sak: nfca::SelRes,
        /// The actual RF answer to RATS without its CRC.
        ats: nfca::Ats,
    },
    /// The host obtained ATQB and completed ATTRIB.
    TypeB(nfcb::Observation),
}

impl<T: Transport> Reader<T> {
    /// Activate a 106 kbps NFC-A ISO-DEP card, returning `None` when the
    /// reader's Layer 3 selection receives no RF answer. A fresh field
    /// precedes selection, which releases a card that an earlier selection
    /// left in the protocol state. RATS announces [`READER_FRAME_SIZE`] with
    /// CID zero.
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
            result => nfca::SelRes::new(result?),
        };
        if sak.continues_cascade() {
            return Err(Error::TypeASak(sak.byte()));
        }
        if !sak.supports_iso_dep() {
            return Err(Error::NotIsoDep);
        }
        self.acknowledge(&Profile::TypeA.framing_command())?;
        self.enable_profile(Profile::TypeA);
        let result = self
            .exchange_rf(&RATS.bytes(), wait, IccResponsePolicy::Unique)
            .and_then(|ats| nfca::Ats::parse(&ats).map_err(Error::TypeA));
        let ats = match result {
            Ok(ats) => ats,
            Err(error) => {
                self.invalidate_field();
                return Err(error);
            }
        };
        self.link.wait(ats.startup_guard());
        let parameters = ats.iso_dep(RATS);
        Ok(Some(IsoDepCard {
            reader: self,
            activation: Activation::TypeA { sak, ats },
            parameters,
        }))
    }

    /// Activate a 106 kbps NFC-B ISO-DEP card using one REQB slot and
    /// ATTRIB announcing [`READER_FRAME_SIZE`] with CID zero. AFI zero
    /// matches all application families. Returns `None` when no card answers
    /// REQB. A fresh field precedes REQB.
    ///
    /// # Errors
    ///
    /// Requires initialization. A card without ISO-DEP
    /// ([`nfcb::Error::NotIsoDep`]), a malformed ATQB or ATTRIB response, or
    /// failure after REQB answered is an error.
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
        let attrib = nfcb::Attrib::new(atqb, READER_FRAME_SIZE, None).map_err(Error::TypeB)?;
        let response = self.exchange_rf(&attrib.command(), wait, IccResponsePolicy::Unique)?;
        attrib.complete(&response).map(Some).map_err(Error::TypeB)
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

    fn blocks(&mut self) -> Result<Self::Blocks<'_>, Self::Error> {
        self.reader.require_configured_field()?;
        Ok(IsoDepBlocks {
            reader: self.reader,
        })
    }
}

/// Block transfer authority borrowed from an ISO-DEP selection. The reader
/// handles the RF CRC and carries the ISO-DEP prologue supplied by the host.
/// A missing reply is [`iso_dep::Reply::Silence`] and keeps the field.
#[derive(Debug)]
pub struct IsoDepBlocks<'s, T: Transport> {
    reader: &'s mut Reader<T>,
}

impl<T: Transport> iso_dep::Blocks for IsoDepBlocks<'_, T> {
    type Error = Error<T::Error>;

    fn transfer(&mut self, block: &[u8], wait: Duration) -> Result<iso_dep::Reply, Self::Error> {
        if block.is_empty() || block.len() > MAX_BLOCK_WITHOUT_CRC {
            return Err(Error::InputLength(block.len()));
        }
        let wait = ResponseWait::new(wait).ok_or(Error::WaitRange(wait))?;
        let response = match self
            .reader
            .exchange_rf(block, wait, IccResponsePolicy::Unique)
        {
            Err(Error::NoResponse) => return Ok(iso_dep::Reply::Silence),
            result => result?,
        };
        if response.is_empty() || response.len() > MAX_BLOCK_WITHOUT_CRC {
            self.reader.invalidate_field();
            return Err(Error::ReplyLength(response.len()));
        }
        Ok(iso_dep::Reply::Block(response))
    }
}
