//! NFC-B activation data: ATQB, ATTRIB and its response.
use crate::{FrameSize, WaitIndex, iso_dep};
use alloc::vec::Vec;
use core::fmt;

/// Invalid NFC-B activation data or unsupported standard-frame parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// ATQB does not start with its required response byte 50h.
    AtqbResponseCode(u8),
    /// A selected card did not return the mandatory MBLI/CID response byte.
    MissingAttrib,
    /// FWI contains the reserved value 15.
    FrameWaitIndex(u8),
    /// ATTRIB assigns reserved CID 15.
    ReservedCid,
    /// A nonzero CID was assigned although ATQB does not advertise CID support.
    UnsupportedCid(u8),
    /// ISO-DEP activation was requested for a card whose ATQB does not
    /// advertise ISO-DEP.
    NotIsoDep,
    /// The ATTRIB response reports a CID other than the one ATTRIB assigned.
    CidMismatch {
        /// CID that ATTRIB assigned.
        assigned: u8,
        /// CID that the response reports.
        returned: u8,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtqbResponseCode(code) => write!(f, "ATQB response code {code:02X}, expected 50"),
            Self::MissingAttrib => f.write_str("card returned no ATTRIB response"),
            Self::FrameWaitIndex(index) => write!(f, "reserved FWI {index}"),
            Self::ReservedCid => f.write_str("ATTRIB assigned reserved CID 15"),
            Self::UnsupportedCid(cid) => {
                write!(f, "ATTRIB assigned CID {cid} to a card without CID support")
            }
            Self::NotIsoDep => f.write_str("ATQB does not advertise ISO-DEP"),
            Self::CidMismatch { assigned, returned } => {
                write!(
                    f,
                    "ATTRIB assigned CID {assigned}, response reports {returned}"
                )
            }
        }
    }
}

impl core::error::Error for Error {}

/// Validated 12-byte ATQB without CRC, received before ATTRIB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Atqb {
    bytes: [u8; 12],
    fwi: WaitIndex,
}

impl Atqb {
    /// Validate the response byte and FWI.
    ///
    /// # Errors
    ///
    /// Rejects a first byte other than `50` and the reserved FWI 15.
    pub fn new(bytes: [u8; 12]) -> Result<Self, Error> {
        if bytes[0] != 0x50 {
            return Err(Error::AtqbResponseCode(bytes[0]));
        }
        let fwi = WaitIndex::new(bytes[11] >> 4).ok_or(Error::FrameWaitIndex(bytes[11] >> 4))?;
        Ok(Self { bytes, fwi })
    }
    /// Original 12 bytes.
    pub fn bytes(&self) -> &[u8; 12] {
        &self.bytes
    }
    /// Session PUPI in wire order; this value is not an authenticated identity.
    pub fn pupi(&self) -> [u8; 4] {
        [self.bytes[1], self.bytes[2], self.bytes[3], self.bytes[4]]
    }
    /// Four application bytes, whose interpretation depends on application coding.
    pub fn application_data(&self) -> [u8; 4] {
        [self.bytes[5], self.bytes[6], self.bytes[7], self.bytes[8]]
    }
    /// Bit-rate, frame-size/protocol-type, and timing/options bytes.
    pub fn protocol_info(&self) -> [u8; 3] {
        [self.bytes[9], self.bytes[10], self.bytes[11]]
    }
    /// Protocol_Type bit b1 advertises the ISO-DEP block protocol. Bits b3-b2
    /// carry the card's minimum TR2 and do not affect the protocol; a set b4
    /// is outside this profile and is not treated as ISO-DEP.
    pub fn supports_iso_dep(&self) -> bool {
        self.bytes[10] & 0x09 == 0x01
    }
    /// Maximum frame size (FSC) the card advertises.
    pub fn frame_size(&self) -> FrameSize {
        FrameSize::from_index(self.bytes[10] >> 4)
    }
    /// Frame waiting integer.
    pub fn fwi(&self) -> WaitIndex {
        self.fwi
    }
    /// Whether ATQB advertises optional card-identifier fields.
    pub fn cid_supported(&self) -> bool {
        self.bytes[11] & 1 != 0
    }
    /// Whether ATQB advertises optional node-address fields.
    pub fn nad_supported(&self) -> bool {
        self.bytes[11] & 2 != 0
    }
}

/// The ATTRIB that the host sends to activate an ISO-DEP card: default TR0,
/// TR1 and SOF/EOF, 106 kbps in both directions, ISO-DEP compliance, the
/// reader frame size (FSD) and the assigned CID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attrib {
    atqb: Atqb,
    reader_frame_size: FrameSize,
    cid: Option<iso_dep::Cid>,
}

impl Attrib {
    /// Prepare ATTRIB for the card that sent `atqb`, assigning `cid`, or
    /// CID 0 when `cid` is `None`.
    ///
    /// # Errors
    ///
    /// Rejects a card whose ATQB does not advertise ISO-DEP and a nonzero
    /// CID for a card without CID support.
    pub fn new(
        atqb: Atqb,
        reader_frame_size: FrameSize,
        cid: Option<iso_dep::Cid>,
    ) -> Result<Self, Error> {
        if !atqb.supports_iso_dep() {
            return Err(Error::NotIsoDep);
        }
        if let Some(cid) = cid
            && !atqb.cid_supported()
        {
            return Err(Error::UnsupportedCid(cid.get()));
        }
        Ok(Self {
            atqb,
            reader_frame_size,
            cid,
        })
    }

    /// ATTRIB command bytes without CRC.
    pub fn command(&self) -> [u8; 9] {
        let [a, b, c, d] = self.atqb.pupi();
        [
            0x1d,
            a,
            b,
            c,
            d,
            0x00,
            self.reader_frame_size.index(),
            0x01,
            self.assigned_cid(),
        ]
    }

    fn assigned_cid(&self) -> u8 {
        self.cid.map_or(0, iso_dep::Cid::get)
    }

    /// Combine this ATTRIB with the card's complete response, without CRC,
    /// into the observation and the block parameters it grants.
    ///
    /// # Errors
    ///
    /// The response needs its MBLI/CID byte, and its CID must be the
    /// assigned one.
    pub fn complete(self, response: &[u8]) -> Result<(Observation, iso_dep::Parameters), Error> {
        let returned = response_cid(&self.atqb, response)?;
        let assigned = self.assigned_cid();
        if returned != assigned {
            return Err(Error::CidMismatch { assigned, returned });
        }
        let observation = Observation {
            atqb: self.atqb,
            reader_frame_size: self.reader_frame_size,
            attrib: response.to_vec(),
        };
        let parameters = observation.parameters();
        Ok((observation, parameters))
    }
}

/// The CID of a complete ATTRIB response.
fn response_cid(atqb: &Atqb, response: &[u8]) -> Result<u8, Error> {
    let cid = response.first().ok_or(Error::MissingAttrib)? & 0x0f;
    if cid == 15 {
        return Err(Error::ReservedCid);
    }
    if cid != 0 && !atqb.cid_supported() {
        return Err(Error::UnsupportedCid(cid));
    }
    Ok(cid)
}

/// Complete ATQB and ATTRIB data for one selected NFC-B card.
///
/// The immutable ATQB is the authority for advertised capabilities. An observed
/// proprietary protocol type remains detectable and is not promoted to ISO-DEP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    atqb: Atqb,
    reader_frame_size: FrameSize,
    attrib: Vec<u8>,
}

impl Observation {
    /// Combine ATQB with the complete response, without CRC, to an ATTRIB
    /// that reader firmware sent announcing `reader_frame_size`. The host
    /// does not see that ATTRIB, so the response's CID is the record of the
    /// assignment.
    ///
    /// # Errors
    ///
    /// The response needs its MBLI/CID byte; CID 15 is reserved, and a
    /// nonzero CID requires advertised CID support.
    pub fn from_reader_attrib(
        atqb: Atqb,
        reader_frame_size: FrameSize,
        response: &[u8],
    ) -> Result<Self, Error> {
        response_cid(&atqb, response)?;
        Ok(Self {
            atqb,
            reader_frame_size,
            attrib: response.to_vec(),
        })
    }
    /// The validated ATQB.
    pub fn atqb(&self) -> &Atqb {
        &self.atqb
    }
    /// Reader frame size (FSD) that ATTRIB announced.
    pub fn reader_frame_size(&self) -> FrameSize {
        self.reader_frame_size
    }
    /// ATTRIB response: the MBLI/CID byte followed by the card's optional
    /// higher-layer response, which is preserved without interpretation.
    pub fn attrib_response(&self) -> &[u8] {
        &self.attrib
    }
    /// CID assigned during ATTRIB. Zero permits communication without CID fields.
    pub fn cid(&self) -> u8 {
        self.attrib[0] & 0x0f
    }
    /// Raw maximum-buffer-length index from the ATTRIB response.
    pub fn mbli(&self) -> u8 {
        self.attrib[0] >> 4
    }
    /// Advertised command buffer limit, or unknown when MBLI is zero.
    /// A nonzero MBLI encodes `FSC * 2^(MBLI - 1)`.
    pub fn maximum_command_bytes(&self) -> Option<usize> {
        match self.mbli() {
            0 => None,
            mbli => Some(usize::from(self.atqb.frame_size().bytes()) << (mbli - 1)),
        }
    }
    /// Block parameters that ATQB and ATTRIB grant, or `None` when ATQB does
    /// not advertise ISO-DEP.
    pub fn iso_dep(&self) -> Option<iso_dep::Parameters> {
        self.atqb.supports_iso_dep().then(|| self.parameters())
    }

    fn parameters(&self) -> iso_dep::Parameters {
        iso_dep::Parameters::new(
            self.atqb.frame_size(),
            self.reader_frame_size,
            self.atqb.fwi(),
            iso_dep::Cid::new(self.cid()),
            self.atqb.nad_supported(),
            self.maximum_command_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATQB: [u8; 12] = [0x50, 1, 2, 3, 4, 0x11, 0x22, 0x33, 0x44, 0, 0x51, 0x41];
    const FSD_64: FrameSize = FrameSize::from_index(5);
    const FSD_256: FrameSize = FrameSize::from_index(8);

    #[test]
    fn host_attrib_encodes_fsd_and_cid_and_requires_the_echo() -> Result<(), Error> {
        let attrib = Attrib::new(Atqb::new(ATQB)?, FSD_256, iso_dep::Cid::new(3))?;
        assert_eq!(attrib.command(), [0x1d, 1, 2, 3, 4, 0, 0x08, 0x01, 3]);
        assert_eq!(
            attrib.complete(&[0x02]),
            Err(Error::CidMismatch {
                assigned: 3,
                returned: 2
            })
        );
        let (observation, parameters) = attrib.complete(&[0x13])?;
        assert_eq!(observation.iso_dep(), Some(parameters));
        assert_eq!(parameters.cid().map(iso_dep::Cid::get), Some(3));
        assert_eq!(parameters.reader_frame_size(), FSD_256);
        let zero = Attrib::new(Atqb::new(ATQB)?, FSD_256, None)?;
        assert_eq!(
            zero.complete(&[0]).map(|(_, parameters)| parameters.cid()),
            Ok(None)
        );
        Ok(())
    }

    #[test]
    fn host_attrib_rejects_assignments_the_card_cannot_take() -> Result<(), Error> {
        let mut without_cid = ATQB;
        without_cid[11] = 0x40;
        assert_eq!(
            Attrib::new(Atqb::new(without_cid)?, FSD_256, iso_dep::Cid::new(1)),
            Err(Error::UnsupportedCid(1))
        );
        let mut proprietary = ATQB;
        proprietary[10] = 0x50;
        assert_eq!(
            Attrib::new(Atqb::new(proprietary)?, FSD_256, None),
            Err(Error::NotIsoDep)
        );
        Ok(())
    }

    #[test]
    fn reader_attrib_preserves_identity_capabilities_and_response() -> Result<(), Error> {
        let observation = Observation::from_reader_attrib(Atqb::new(ATQB)?, FSD_64, &[1])?;
        let atqb = observation.atqb();
        assert_eq!(atqb.pupi(), [1, 2, 3, 4]);
        assert_eq!(atqb.application_data(), [0x11, 0x22, 0x33, 0x44]);
        assert_eq!(atqb.protocol_info(), [0, 0x51, 0x41]);
        assert_eq!(atqb.frame_size().bytes(), 64);
        assert_eq!(atqb.fwi().get(), 4);
        assert!(atqb.supports_iso_dep());
        assert!(atqb.cid_supported());
        assert_eq!(observation.cid(), 1);
        assert_eq!(observation.attrib_response(), [1]);
        let parameters = observation.iso_dep().ok_or(Error::MissingAttrib)?;
        assert_eq!(parameters.cid().map(iso_dep::Cid::get), Some(1));
        assert_eq!(parameters.card_frame_size().bytes(), 64);
        assert_eq!(parameters.reader_frame_size(), FSD_64);
        Ok(())
    }

    #[test]
    fn proprietary_card_and_zero_cid_are_observable() -> Result<(), Error> {
        let mut atqb = ATQB;
        atqb[10] = 0;
        atqb[11] = 0x40;
        let observation = Observation::from_reader_attrib(Atqb::new(atqb)?, FSD_64, &[0])?;
        assert!(!observation.atqb().supports_iso_dep());
        assert!(!observation.atqb().cid_supported());
        assert_eq!(observation.cid(), 0);
        assert_eq!(observation.iso_dep(), None);
        Ok(())
    }

    #[test]
    fn large_and_rfu_frame_size_indices_scale_the_card_buffer() -> Result<(), Error> {
        let mut atqb = ATQB;
        for (fsci, frame_size) in [(9, 512), (0x0c, 4096), (0x0f, 4096)] {
            atqb[10] = fsci << 4 | 1;
            let (observation, _) =
                Attrib::new(Atqb::new(atqb)?, FSD_256, None)?.complete(&[0x20])?;
            assert_eq!(observation.atqb().frame_size().bytes(), frame_size);
            assert_eq!(
                observation.maximum_command_bytes(),
                Some(usize::from(frame_size) * 2)
            );
        }
        Ok(())
    }

    #[test]
    fn higher_layer_response_is_preserved_and_mbli_bounds_commands() -> Result<(), Error> {
        let observation =
            Observation::from_reader_attrib(Atqb::new(ATQB)?, FSD_64, &[0x21, 0x9f, 0x0f])?;
        assert_eq!(observation.attrib_response(), [0x21, 0x9f, 0x0f]);
        assert_eq!(observation.maximum_command_bytes(), Some(128));
        Ok(())
    }

    #[test]
    fn minimum_tr2_bits_keep_iso_dep_and_b4_withholds_it() -> Result<(), Error> {
        let mut atqb = ATQB;
        for (protocol_type, iso_dep) in [(1, true), (3, true), (5, true), (7, true), (9, false)] {
            atqb[10] = 0x50 | protocol_type;
            assert_eq!(Atqb::new(atqb)?.supports_iso_dep(), iso_dep);
        }
        Ok(())
    }

    #[test]
    fn response_and_protocol_boundaries_are_checked() -> Result<(), Error> {
        let mut bad = ATQB;
        bad[0] = 0x51;
        assert_eq!(Atqb::new(bad), Err(Error::AtqbResponseCode(0x51)));
        bad = ATQB;
        bad[11] = 0xf1;
        assert_eq!(Atqb::new(bad), Err(Error::FrameWaitIndex(15)));
        let atqb = Atqb::new(ATQB)?;
        assert_eq!(
            Observation::from_reader_attrib(atqb, FSD_64, &[]),
            Err(Error::MissingAttrib)
        );
        assert_eq!(
            Observation::from_reader_attrib(atqb, FSD_64, &[0x1f]),
            Err(Error::ReservedCid)
        );
        assert_eq!(
            Attrib::new(atqb, FSD_256, None)?.complete(&[]),
            Err(Error::MissingAttrib)
        );
        let mut without_cid = ATQB;
        without_cid[11] = 0x40;
        assert_eq!(
            Observation::from_reader_attrib(Atqb::new(without_cid)?, FSD_64, &[1]),
            Err(Error::UnsupportedCid(1))
        );
        Ok(())
    }
}
