//! NFC-B activation data: ATQB and the ATTRIB response.
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
    /// Maximum card frame size including protocol overhead and CRC.
    pub fn frame_size(&self) -> u16 {
        FrameSize::from_index(self.fsci()).bytes()
    }
    /// Standard maximum-card-frame-size code.
    pub fn fsci(&self) -> u8 {
        self.bytes[10] >> 4
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

/// Complete ATQB and ATTRIB data for one selected NFC-B card.
///
/// The immutable ATQB is the authority for advertised capabilities. An observed
/// proprietary protocol type remains detectable and is not promoted to ISO-DEP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    atqb: Atqb,
    attrib: Vec<u8>,
}

impl Observation {
    /// Combine ATQB with the card's complete ATTRIB response, without CRC.
    ///
    /// # Errors
    ///
    /// A completed ATTRIB needs its MBLI/CID byte; CID 15 is reserved, and a
    /// nonzero CID requires advertised CID support.
    pub fn new(atqb: Atqb, attrib: &[u8]) -> Result<Self, Error> {
        let first = *attrib.first().ok_or(Error::MissingAttrib)?;
        let cid = first & 0x0f;
        if cid == 15 {
            return Err(Error::ReservedCid);
        }
        if cid != 0 && !atqb.cid_supported() {
            return Err(Error::UnsupportedCid(cid));
        }
        Ok(Self {
            atqb,
            attrib: attrib.to_vec(),
        })
    }
    /// The validated ATQB.
    pub fn atqb(&self) -> &Atqb {
        &self.atqb
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
            mbli => Some(usize::from(self.atqb.frame_size()) << (mbli - 1)),
        }
    }
    /// Block parameters that ATQB and ATTRIB grant, or `None` when ATQB does
    /// not advertise ISO-DEP.
    pub fn iso_dep(&self) -> Option<iso_dep::Parameters> {
        self.atqb.supports_iso_dep().then(|| {
            iso_dep::Parameters::new(
                self.atqb.frame_size(),
                self.atqb.fwi(),
                match self.cid() {
                    0 => None,
                    cid => Some(cid),
                },
                self.atqb.nad_supported(),
                self.maximum_command_bytes(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATQB: [u8; 12] = [0x50, 1, 2, 3, 4, 0x11, 0x22, 0x33, 0x44, 0, 0x51, 0x41];

    #[test]
    fn selected_card_preserves_identity_capabilities_and_attrib() -> Result<(), Error> {
        let observation = Observation::new(Atqb::new(ATQB)?, &[1])?;
        let atqb = observation.atqb();
        assert_eq!(atqb.pupi(), [1, 2, 3, 4]);
        assert_eq!(atqb.application_data(), [0x11, 0x22, 0x33, 0x44]);
        assert_eq!(atqb.protocol_info(), [0, 0x51, 0x41]);
        assert_eq!(atqb.frame_size(), 64);
        assert_eq!(atqb.fwi().get(), 4);
        assert!(atqb.supports_iso_dep());
        assert!(atqb.cid_supported());
        assert_eq!(observation.cid(), 1);
        assert_eq!(observation.attrib_response(), [1]);
        let parameters = observation.iso_dep().ok_or(Error::MissingAttrib)?;
        assert_eq!(parameters.cid(), Some(1));
        assert_eq!(parameters.frame_size(), 64);
        Ok(())
    }

    #[test]
    fn proprietary_card_and_zero_cid_are_observable() -> Result<(), Error> {
        let mut atqb = ATQB;
        atqb[10] = 0;
        atqb[11] = 0x40;
        let observation = Observation::new(Atqb::new(atqb)?, &[0])?;
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
            let observation = Observation::new(Atqb::new(atqb)?, &[0x21])?;
            assert_eq!(observation.atqb().frame_size(), frame_size);
            assert_eq!(
                observation.maximum_command_bytes(),
                Some(usize::from(frame_size) * 2)
            );
        }
        Ok(())
    }

    #[test]
    fn higher_layer_response_is_preserved_and_mbli_bounds_commands() -> Result<(), Error> {
        let observation = Observation::new(Atqb::new(ATQB)?, &[0x21, 0x9f, 0x0f])?;
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
    fn attrib_and_protocol_boundaries_are_checked() -> Result<(), Error> {
        let mut bad = ATQB;
        bad[0] = 0x51;
        assert_eq!(Atqb::new(bad), Err(Error::AtqbResponseCode(0x51)));
        bad = ATQB;
        bad[11] = 0xf1;
        assert_eq!(Atqb::new(bad), Err(Error::FrameWaitIndex(15)));
        let atqb = Atqb::new(ATQB)?;
        assert_eq!(Observation::new(atqb, &[]), Err(Error::MissingAttrib));
        assert_eq!(Observation::new(atqb, &[0x1f]), Err(Error::ReservedCid));
        let mut without_cid = ATQB;
        without_cid[11] = 0x40;
        assert_eq!(
            Observation::new(Atqb::new(without_cid)?, &[1]),
            Err(Error::UnsupportedCid(1))
        );
        Ok(())
    }
}
