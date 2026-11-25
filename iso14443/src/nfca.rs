//! NFC-A activation data and the frame exchange of a selected card.
//!
//! UID bytes remain in wire order, and ATS retains its own inclusive length
//! byte without RF CRC bytes.
use crate::{FrameSize, iso_dep};
use alloc::vec::Vec;
use core::{fmt, time::Duration};

/// Invalid NFC-A selection data or unsupported ISO-DEP timing parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The data cannot contain the required field.
    Truncated {
        /// Field whose bytes are missing.
        field: &'static str,
        /// Minimum bytes needed for that field.
        minimum: usize,
        /// Bytes available in the containing data.
        actual: usize,
    },
    /// UID length is not one of the single, double, or triple cascade lengths.
    UidLength(usize),
    /// ATS has a zero or mismatched inclusive length.
    AtsLength {
        /// Inclusive length declared by TL.
        declared: usize,
        /// Actual ATS bytes, including TL.
        actual: usize,
    },
    /// The format byte contains an unsupported format bit.
    AtsFormat(u8),
    /// FWI contains the reserved value 15.
    FrameWaitIndex(u8),
    /// SFGI contains the reserved value 15.
    GuardTimeIndex(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                field,
                minimum,
                actual,
            } => write!(f, "NFC-A {field} needs {minimum} bytes, got {actual}"),
            Self::UidLength(length) => write!(f, "unsupported NFC-A UID length {length}"),
            Self::AtsLength { declared, actual } => {
                write!(f, "ATS declares {declared} bytes, got {actual}")
            }
            Self::AtsFormat(format) => write!(f, "unsupported ATS format byte {format:02X}"),
            Self::FrameWaitIndex(index) => write!(f, "reserved FWI {index}"),
            Self::GuardTimeIndex(index) => write!(f, "reserved SFGI {index}"),
        }
    }
}

impl core::error::Error for Error {}

/// A Request for Answer to Select, without RF CRC bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rats {
    frame_size: FrameSize,
    cid: u8,
}

impl Rats {
    /// Decode the initiator's frame-size limit and card identifier.
    /// Returns `None` for a different command, wrong length or reserved CID.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let &[0xe0, parameter] = bytes else {
            return None;
        };
        let cid = parameter & 0x0f;
        (cid != 0x0f).then_some(Self {
            frame_size: FrameSize::from_index(parameter >> 4),
            cid,
        })
    }

    /// Maximum frame size the initiator accepts, including overhead and CRC.
    pub fn frame_size(self) -> u16 {
        self.frame_size.bytes()
    }

    /// The proposed card identifier. Its use depends on the ATS capabilities.
    pub fn cid(self) -> u8 {
        self.cid
    }
}

/// A complete ATS with checked interface-byte boundaries and timing fields.
///
/// The raw bytes are immutable after construction; cached offsets and decoded
/// parameters are established together with those bytes by [`Self::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ats {
    bytes: Vec<u8>,
    fwi: u8,
    sfgi: u8,
    tc: Option<u8>,
    historical_start: usize,
}

impl Ats {
    /// Validate TL, optional TA/TB/TC bytes, and timing indices. RF CRC bytes
    /// are absent. FWI/SFGI value 15 is rejected rather than reinterpreted.
    ///
    /// # Errors
    ///
    /// Rejects a TL that differs from the length, a set format bit 8, missing
    /// interface bytes, and reserved timing indices.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let declared = bytes.first().copied().map_or(0, usize::from);
        if bytes.is_empty() || declared != bytes.len() {
            return Err(Error::AtsLength {
                declared,
                actual: bytes.len(),
            });
        }
        let format = bytes.get(1).copied().unwrap_or(2);
        if format & 0x80 != 0 {
            return Err(Error::AtsFormat(format));
        }
        let mut cursor = bytes.len().min(2);
        let mut interfaces = [None; 3];
        for (index, mask) in [0x10, 0x20, 0x40].into_iter().enumerate() {
            if format & mask != 0 {
                let value = bytes.get(cursor).copied().ok_or(Error::Truncated {
                    field: "ATS interface byte",
                    minimum: cursor + 1,
                    actual: bytes.len(),
                })?;
                interfaces[index] = Some(value);
                cursor += 1;
            }
        }
        let timing = interfaces[1].unwrap_or(0x40);
        let fwi = timing >> 4;
        let sfgi = timing & 0x0f;
        if fwi == 15 {
            return Err(Error::FrameWaitIndex(fwi));
        }
        if sfgi == 15 {
            return Err(Error::GuardTimeIndex(sfgi));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            fwi,
            sfgi,
            tc: interfaces[2],
            historical_start: cursor,
        })
    }

    /// ATS including TL, without CRC.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Maximum frame size the card advertises, including protocol overhead.
    pub fn frame_size(&self) -> u16 {
        FrameSize::from_index(self.fsci()).bytes()
    }
    /// Standard frame-size code; 2 is the default when T0 is absent.
    pub fn fsci(&self) -> u8 {
        self.bytes.get(1).copied().unwrap_or(2) & 0x0f
    }
    /// Frame waiting integer; 4 is the default when TB is absent.
    pub fn fwi(&self) -> u8 {
        self.fwi
    }
    /// Card frame waiting time, rounded upward to whole nanoseconds.
    pub fn frame_wait(&self) -> Duration {
        crate::frame_wait(self.fwi)
    }
    /// Startup frame guard integer; 0 means no additional startup guard time.
    pub fn sfgi(&self) -> u8 {
        self.sfgi
    }
    /// Time the card needs after sending ATS before it can receive a frame,
    /// or zero when SFGI is 0.
    pub fn startup_guard(&self) -> Duration {
        if self.sfgi == 0 {
            Duration::ZERO
        } else {
            crate::frame_wait(self.sfgi)
        }
    }
    /// Whether TC advertises optional card-identifier fields.
    pub fn cid_supported(&self) -> bool {
        self.tc.is_some_and(|byte| byte & 2 != 0)
    }
    /// Whether TC advertises optional node-address fields.
    pub fn nad_supported(&self) -> bool {
        self.tc.is_some_and(|byte| byte & 1 != 0)
    }
    /// Historical bytes after all present interface bytes.
    pub fn historical_bytes(&self) -> &[u8] {
        &self.bytes[self.historical_start..]
    }
    /// Block parameters of a card that RATS activated with CID 0, so that its
    /// blocks carry no CID field.
    pub fn iso_dep(&self) -> iso_dep::Parameters {
        iso_dep::Parameters::new(
            self.frame_size(),
            self.fwi,
            None,
            self.nad_supported(),
            None,
        )
    }
}

/// Activation data of one selected NFC-A card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    sens_res: [u8; 2],
    sel_res: u8,
    uid: Vec<u8>,
    ats: Option<Ats>,
}

impl Observation {
    /// Combine SENS_RES, SEL_RES, a complete 4/7/10-byte UID and the ATS that
    /// RATS returned, if RATS was sent.
    ///
    /// ISO-DEP support in SEL_RES is an advertised capability. An absent ATS
    /// does not establish ISO-DEP activation and remains explicit as `None`.
    ///
    /// # Errors
    ///
    /// Rejects UID lengths other than 4, 7 and 10.
    pub fn new(
        sens_res: [u8; 2],
        sel_res: u8,
        uid: &[u8],
        ats: Option<Ats>,
    ) -> Result<Self, Error> {
        if !matches!(uid.len(), 4 | 7 | 10) {
            return Err(Error::UidLength(uid.len()));
        }
        Ok(Self {
            sens_res,
            sel_res,
            uid: uid.to_vec(),
            ats,
        })
    }
    /// SENS_RES in MSB-first byte order.
    pub fn sens_res(&self) -> [u8; 2] {
        self.sens_res
    }
    /// Raw select acknowledgment byte.
    pub fn sel_res(&self) -> u8 {
        self.sel_res
    }
    /// Complete UID with cascade tags removed by activation, in wire byte order.
    pub fn uid(&self) -> &[u8] {
        &self.uid
    }
    /// ATS when activation returned one; its length byte is retained.
    pub fn ats(&self) -> Option<&Ats> {
        self.ats.as_ref()
    }
    /// SEL_RES advertises ISO-DEP without an unfinished UID cascade.
    pub fn supports_iso_dep(&self) -> bool {
        self.sel_res & 0x24 == 0x20
    }
}

/// Card reply to one NFC-A command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// Reply bytes. A standard frame is returned without its CRC once the
    /// CRC has been checked; a 4-bit ACK or NAK is returned as one byte
    /// holding that nibble. Empty when the reader reports completion without
    /// passing on any card bytes.
    Data(Vec<u8>),
    /// No reply arrived within the reader's wait.
    Silence,
}

/// An NFC-A card selected by a reader, whose command frames the reader
/// carries with CRC appended and checked.
///
/// The reader layer owns the RF transfer, its wait and its failure states;
/// card command protocols own frame contents. A command that leaves card
/// state which the next selection does not clear must be declared with
/// [`Self::require_field_cycle`] before it is sent.
pub trait Selection {
    /// Reader failure of one exchange. Whether the command was sent is part
    /// of the reader's error contract.
    type Error: fmt::Debug;

    /// The card's activation data.
    fn observation(&self) -> &Observation;

    /// Send one command and return the card's reply. The reader never
    /// replays a command automatically; after a failure that follows
    /// sending, the command may have taken effect.
    ///
    /// # Errors
    ///
    /// Returns the reader's failure of this exchange.
    fn exchange(&mut self, command: &[u8]) -> Result<Reply, Self::Error>;

    /// Make the next selection on this reader cycle the RF field before its
    /// request, because the card now holds state that selection does not clear.
    fn require_field_cycle(&mut self);
}

/// A passive NFC-A target with a single-size UID and no ISO-DEP.
pub trait PassiveTarget {
    /// Reader failure at the target boundary.
    type Error: fmt::Debug;
    /// Reader-specific wait for an initiator.
    type Wait;
    /// One received command and the exclusive right to answer it.
    type Command<'a>: TargetCommand<Error = Self::Error>
    where
        Self: 'a;

    /// The UID advertised during anticollision.
    fn uid(&self) -> [u8; 4];
    /// Receive the next initiator command, without CRC.
    fn receive(&mut self, wait: Self::Wait) -> Result<Self::Command<'_>, Self::Error>;
    /// Stop target operation and restore the reader to RF-off readiness.
    fn finish(self) -> Result<(), Self::Error>;
}

/// A command received by a passive target. Dropping it leaves it unanswered.
pub trait TargetCommand {
    /// Reader failure while transmitting a response.
    type Error: fmt::Debug;

    /// Received command bytes, without CRC.
    fn data(&self) -> &[u8];
    /// Answer this command once. On failure, delivery can be uncertain.
    fn respond(self, data: &[u8]) -> Result<(), Self::Error>;
}

/// Reader able to advertise a passive NFC-A target without ISO-DEP.
pub trait PassiveTargetReader {
    /// Reader failure while entering target mode.
    type Error: fmt::Debug;
    /// Reader-specific wait for an initiator.
    type Wait;
    /// Passive target holding the exclusive reader borrow.
    type Target<'a>: PassiveTarget<Error = Self::Error, Wait = Self::Wait>
    where
        Self: 'a;

    /// Prepare the target with UID `08` followed by `suffix`. A reader may
    /// wait for the first command during setup or on the first receive.
    fn listen_type_a(
        &mut self,
        suffix: [u8; 3],
        wait: Self::Wait,
    ) -> Result<Self::Target<'_>, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rats_distinguishes_frame_size_and_card_identifier() {
        let rats = Rats::parse(&[0xe0, 0x5e]);
        assert_eq!(rats.map(Rats::frame_size), Some(64));
        assert_eq!(rats.map(Rats::cid), Some(14));
        assert_eq!(Rats::parse(&[0xe0, 0xf0]).map(Rats::frame_size), Some(4096));
        assert_eq!(Rats::parse(&[0xe0, 0x5f]), None);
        assert_eq!(Rats::parse(&[0xe0, 0x50, 0]), None);
        assert_eq!(Rats::parse(&[0xc2]), None);
    }

    #[test]
    fn ats_parameters_and_omitted_interface_defaults() -> Result<(), Error> {
        let ats = Ats::parse(&[6, 0x75, 0x80, 0x61, 2, 0x42])?;
        assert_eq!(ats.frame_size(), 64);
        assert_eq!(ats.fwi(), 6);
        assert_eq!(ats.sfgi(), 1);
        assert_eq!(ats.startup_guard(), crate::frame_wait(1));
        assert!(ats.cid_supported());
        assert!(!ats.nad_supported());
        assert_eq!(ats.historical_bytes(), [0x42]);
        let parameters = ats.iso_dep();
        assert_eq!(parameters.frame_size(), 64);
        assert_eq!(parameters.cid(), None);

        let ats = Ats::parse(&[1])?;
        assert_eq!(ats.fsci(), 2);
        assert_eq!(ats.frame_size(), 32);
        assert_eq!(ats.fwi(), 4);
        assert_eq!(ats.startup_guard(), Duration::ZERO);
        assert!(!ats.cid_supported());
        assert_eq!(Ats::parse(&[3, 0x25, 0x80])?.fwi(), 8);
        // FSCI above 8 advertises a larger card buffer; D-F read as C.
        assert_eq!(Ats::parse(&[2, 0x09])?.frame_size(), 512);
        assert_eq!(Ats::parse(&[2, 0x0f])?.frame_size(), 4096);
        Ok(())
    }

    #[test]
    fn selection_and_interface_boundaries_are_checked() {
        assert!(matches!(
            Observation::new([0, 4], 0, &[1, 2, 3, 4, 5], None),
            Err(Error::UidLength(5))
        ));
        assert!(matches!(
            Ats::parse(&[2, 0x25]),
            Err(Error::Truncated { .. })
        ));
        assert!(matches!(
            Ats::parse(&[3, 0x05]),
            Err(Error::AtsLength { .. })
        ));
        assert!(matches!(
            Ats::parse(&[2, 0x80]),
            Err(Error::AtsFormat(0x80))
        ));
        assert!(matches!(
            Ats::parse(&[3, 0x25, 0xf0]),
            Err(Error::FrameWaitIndex(15))
        ));
        assert!(matches!(
            Ats::parse(&[3, 0x25, 0x4f]),
            Err(Error::GuardTimeIndex(15))
        ));
    }

    #[test]
    fn iso_dep_support_requires_a_complete_cascade() -> Result<(), Error> {
        let uid = [1, 2, 3, 4, 5, 6, 7];
        assert!(Observation::new([0, 0x44], 0x20, &uid, None)?.supports_iso_dep());
        assert!(!Observation::new([0, 0x44], 0x24, &uid, None)?.supports_iso_dep());
        assert!(!Observation::new([0, 0x44], 0x00, &uid, None)?.supports_iso_dep());
        Ok(())
    }
}
