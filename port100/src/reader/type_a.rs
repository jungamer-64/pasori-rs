//! NFC-A activation and command exchange.

use super::{
    Error, Field, Reader, Received, ResponseWait,
    iso_dep::{Activation, IsoDepCard},
    settings::{CrcCheck, Settings},
};
use crate::transport::Transport;
use alloc::{vec, vec::Vec};
use iso14443::nfca;

/// SENS_REQ, sent as a 7-bit short frame.
const SENS_REQ: u8 = 0x26;
/// SEL codes of the three cascade levels.
const SELECT: [u8; 3] = [0x93, 0x95, 0x97];
/// First UID byte of a level whose UID continues at the next level.
const CASCADE_TAG: u8 = 0x88;
/// RATS with FSDI 8 (256-byte frames) and CID 0.
const RATS: [u8; 2] = [0xe0, 0x80];
/// InSetProtocol pairs that leave CRC to the host and send 7-bit frames.
const SHORT_FRAME: [u8; 6] = [0x01, 0x00, 0x02, 0x00, 0x07, 0x07];
/// InSetProtocol pair that sends complete bytes.
const COMPLETE_BYTES: [u8; 2] = [0x07, 0x08];
/// InSetProtocol pairs that leave CRC to the host.
const WITHOUT_CRC: [u8; 4] = [0x01, 0x00, 0x02, 0x00];
/// InSetProtocol pairs that append and check CRC in the reader.
const WITH_CRC: [u8; 4] = [0x01, 0x01, 0x02, 0x01];

/// An NFC-A selection granting the operations of its advertised protocol.
#[derive(Debug)]
pub enum TypeASelection<'a, T: Transport> {
    /// SEL_RES advertised ISO-DEP and RATS returned an ATS. The host runs the
    /// block protocol.
    IsoDep(IsoDepCard<'a, T>),
    /// SEL_RES advertised no ISO-DEP. The caller supplies command frames.
    Command(TypeACard<'a, T>),
}

impl<T: Transport> Reader<T> {
    /// Activate one NFC-A card at 106 kbps: SENS_REQ, the anticollision and
    /// select loop over up to three cascade levels, and RATS when SEL_RES
    /// advertises ISO-DEP, followed by the card's startup frame guard time.
    /// Every step waits `wait` for its reply, and the returned card's
    /// commands wait as long.
    ///
    /// The field is switched off before activation, so that every card in it
    /// starts from its idle state. Returns `None` when no card answers
    /// SENS_REQ. Several cards answering at once are not resolved: the
    /// reader's collision status is returned as an RF failure.
    ///
    /// # Errors
    ///
    /// Requires initialization. Any failure after SENS_REQ was answered
    /// requires a field cycle before the next selection.
    pub fn poll_type_a(
        &mut self,
        wait: ResponseWait,
    ) -> Result<Option<TypeASelection<'_, T>>, Error<T::Error>> {
        let settings = Settings::TypeA(CrcCheck::Reader);
        self.begin_activation(settings)?;
        let observation = match self.activate_type_a(wait) {
            Ok(Some(observation)) => observation,
            Ok(None) => return Ok(None),
            Err(error) => {
                self.require_field_cycle();
                return Err(error);
            }
        };
        Ok(Some(match observation.ats().map(nfca::Ats::iso_dep) {
            Some(parameters) => TypeASelection::IsoDep(IsoDepCard {
                reader: self,
                activation: Activation::TypeA(observation),
                parameters,
                settings,
            }),
            None => TypeASelection::Command(TypeACard {
                reader: self,
                observation,
                wait,
            }),
        }))
    }

    fn activate_type_a(
        &mut self,
        wait: ResponseWait,
    ) -> Result<Option<nfca::Observation>, Error<T::Error>> {
        self.set_protocol(&SHORT_FRAME)?;
        let Some(sens_res) = self.in_comm_rf(&[SENS_REQ], wait)? else {
            return Ok(None);
        };
        let sens_res = <[u8; 2]>::try_from(sens_res.data.as_slice())
            .map_err(|_| Error::CardReply("SENS_RES length"))?;
        self.set_protocol(&COMPLETE_BYTES)?;
        let mut uid = Vec::with_capacity(10);
        let mut sel_res = None;
        for select in SELECT {
            let [a, b, c, d, bcc] = <[u8; 5]>::try_from(self.card_reply(&[select, 0x20], wait)?)
                .map_err(|_| Error::CardReply("SDD_RES length"))?;
            if a ^ b ^ c ^ d != bcc {
                return Err(Error::CardReply("SDD_RES BCC"));
            }
            self.set_protocol(&WITH_CRC)?;
            let sak = match self
                .card_reply(&[select, 0x70, a, b, c, d, bcc], wait)?
                .as_slice()
            {
                [sak] => *sak,
                _ => return Err(Error::CardReply("SEL_RES length")),
            };
            if sak & 0x04 == 0 {
                uid.extend_from_slice(&[a, b, c, d]);
                sel_res = Some(sak);
                break;
            }
            if a != CASCADE_TAG {
                return Err(Error::CardReply("cascade tag"));
            }
            uid.extend_from_slice(&[b, c, d]);
            self.set_protocol(&WITHOUT_CRC)?;
        }
        let sel_res = sel_res.ok_or(Error::CardReply("UID beyond three cascade levels"))?;
        // The pairs sent since the configuration restore its settings.
        self.set_field(Field::On {
            settings: Settings::TypeA(CrcCheck::Reader),
            cycle: false,
        });
        let ats = if sel_res & 0x24 == 0x20 {
            let ats = nfca::Ats::parse(&self.card_reply(&RATS, wait)?).map_err(Error::TypeA)?;
            self.link.wait(ats.startup_guard());
            Some(ats)
        } else {
            None
        };
        nfca::Observation::new(sens_res, sel_res, &uid, ats)
            .map(Some)
            .map_err(Error::TypeA)
    }
}

/// NFC-A selection without ISO-DEP, tied to one exclusive reader borrow.
///
/// [`nfca::Selection::exchange`] appends CRC to the command and checks the
/// reply's CRC on the host, so that 4-bit ACK and NAK replies reach the
/// caller. A one-byte reply whose InCommRF response byte 5 is 4 is taken as
/// a 4-bit reply, reading that byte as the number of valid bits in the last
/// byte; this reading is inferred, not established. It waits as long as the
/// activation steps.
#[derive(Debug)]
pub struct TypeACard<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    observation: nfca::Observation,
    wait: ResponseWait,
}

impl<T: Transport> nfca::Selection for TypeACard<'_, T> {
    type Error = Error<T::Error>;

    fn observation(&self) -> &nfca::Observation {
        &self.observation
    }

    fn exchange(&mut self, command: &[u8]) -> Result<nfca::Reply, Error<T::Error>> {
        match self
            .reader
            .transceive(Settings::TypeA(CrcCheck::Host), command, self.wait)?
        {
            None => Ok(nfca::Reply::Silence),
            Some(received) => host_checked(received).map(nfca::Reply::Data),
        }
    }

    fn require_field_cycle(&mut self) {
        self.reader.require_field_cycle();
    }
}

/// Interpret a reply whose CRC the reader did not check.
fn host_checked<E>(received: Received) -> Result<Vec<u8>, Error<E>> {
    match (received.data.as_slice(), received.last_bits) {
        ([nibble], 4) => Ok(vec![nibble & 0x0f]),
        (frame, 8) => match frame.split_last_chunk::<2>() {
            Some((body, crc)) if !body.is_empty() => {
                if crc_a(body) == *crc {
                    Ok(body.to_vec())
                } else {
                    Err(Error::CardCrc)
                }
            }
            _ => Err(Error::CardReply("NFC-A frame shorter than its CRC")),
        },
        _ => Err(Error::CardReply("NFC-A reply bit count")),
    }
}

/// ISO/IEC 14443-3 CRC_A, least significant byte first.
fn crc_a(data: &[u8]) -> [u8; 2] {
    data.iter()
        .fold(0x6363_u16, |crc, byte| {
            let [low, _] = crc.to_le_bytes();
            let mut value = byte ^ low;
            value ^= value << 4;
            let value = u16::from(value);
            (crc >> 8) ^ (value << 8) ^ (value << 3) ^ (value >> 4)
        })
        .to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_a_known_answers() {
        assert_eq!(crc_a(&[0x30, 0x00]), [0x02, 0xa8]);
        assert_eq!(crc_a(&[0x50, 0x00]), [0x57, 0xcd]);
        assert_eq!(crc_a(&[0x00, 0x00]), [0xa0, 0x1e]);
    }

    #[test]
    fn host_checked_replies_separate_nibbles_frames_and_damage() {
        let reply = |data: &[u8], last_bits| Received {
            data: data.to_vec(),
            last_bits,
        };
        assert_eq!(host_checked::<()>(reply(&[0x0a], 4)).ok(), Some(vec![0x0a]));
        assert_eq!(
            host_checked::<()>(reply(&[0x30, 0x00, 0x02, 0xa8], 8)).ok(),
            Some(vec![0x30, 0x00])
        );
        assert!(matches!(
            host_checked::<()>(reply(&[0x30, 0x00, 0x02, 0xa9], 8)),
            Err(Error::CardCrc)
        ));
        assert!(matches!(
            host_checked::<()>(reply(&[0x02, 0xa8], 8)),
            Err(Error::CardReply(_))
        ));
        assert!(matches!(
            host_checked::<()>(reply(&[0x0a, 0x00], 4)),
            Err(Error::CardReply(_))
        ));
    }
}
