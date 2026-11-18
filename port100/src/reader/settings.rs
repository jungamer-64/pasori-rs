//! RF and protocol settings that InSetRF and InSetProtocol apply.
//!
//! The values are those that Sony's NFC Port 5.6.9.0 driver package sends
//! to Port-100 readers with its default registry, including the items it
//! withholds from older firmware and the older bit-rate codes it uses there.

use super::BitRate;
use alloc::vec::Vec;

/// Firmware observations that select the settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Firmware {
    pub(super) version: u16,
    pub(super) option_60: u16,
}

impl Firmware {
    /// Whether the firmware belongs to the older range that ends at `last`.
    /// Only option-60 values up to 5 have older ranges, and for them
    /// versions `0101`..`0199` compare as if shifted left by four bits, which
    /// places them above every range.
    pub(super) fn at_most(self, last: u16) -> bool {
        if self.option_60 > 5 {
            return false;
        }
        let version = u32::from(self.version);
        let version = if (0x101..0x19a).contains(&version) {
            version << 4
        } else {
            version
        };
        (1..=u32::from(last)).contains(&version)
    }
}

/// Which side checks the CRC of NFC-A replies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CrcCheck {
    /// The reader checks and removes the CRC of every reply.
    Reader,
    /// The reader passes replies on unchecked, so that 4-bit ACK and NAK
    /// replies reach the host, which checks frame CRCs itself.
    Host,
}

/// Settings a card exchange runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Settings {
    /// FeliCa at the given rate.
    Felica(BitRate),
    /// NFC-A at 106 kbps with CRC appended to every frame.
    TypeA(CrcCheck),
    /// NFC-B at 106 kbps with CRC appended and checked.
    TypeB,
}

/// InSetRF technology code of FeliCa.
const FELICA: u8 = 0x01;
/// InSetRF technology code of NFC-A at 106 kbps.
const TYPE_A: u8 = 0x02;
/// InSetRF technology code of NFC-B.
const TYPE_B: u8 = 0x03;
/// InSetRF receive technology code meaning "same as the send technology".
const SAME_AS_SEND: u8 = 0x0f;
/// InSetRF bit-rate code of NFC-A at 106 kbps, shared by every firmware.
const TYPE_A_106: u8 = 0x03;

impl Settings {
    /// The InSetRF arguments of these settings. Firmware up to 0299 uses an
    /// older bit-rate code for NFC-B.
    pub(super) fn rf(self, firmware: Firmware) -> [u8; 4] {
        let (technology, code) = match self {
            Self::Felica(BitRate::Kbps212) => (FELICA, 0x01),
            Self::Felica(BitRate::Kbps424) => (FELICA, 0x02),
            Self::TypeA(_) => (TYPE_A, TYPE_A_106),
            Self::TypeB if firmware.at_most(0x299) => (TYPE_B, 0x06),
            Self::TypeB => (TYPE_B, 0x07),
        };
        [technology, code, SAME_AS_SEND, code]
    }

    /// InSetProtocol pairs of these settings. CRC is appended and, unless
    /// the host checks it, checked; frames carry 8 bits in their last byte;
    /// guard time is 6. Each technology has its own initial guard time,
    /// parity and SOF/EOF framing. Firmware up to 0599 receives tag 0D
    /// instead of tag 12, firmware up to 0619 does not receive tag 13, and
    /// tags 0E to 10 carry the general receive settings except for FeliCa on
    /// firmware above 0609.
    pub(super) fn protocol(self, firmware: Firmware) -> Vec<u8> {
        let (initial_guard, parity, framing) = match self {
            Self::Felica(_) => (0x18, 0x00, 0x00),
            Self::TypeA(_) => (0x06, 0x01, 0x00),
            Self::TypeB => (0x14, 0x00, 0x01),
        };
        let check_crc = match self {
            Self::TypeA(CrcCheck::Host) => 0x00,
            _ => 0x01,
        };
        let mut pairs = Vec::with_capacity(38);
        pairs.extend_from_slice(&[
            0x00,
            initial_guard,
            0x01,
            0x01,
            0x02,
            check_crc,
            0x03,
            0x00,
            0x04,
            parity,
            0x05,
            parity,
            0x06,
            0x00,
            0x07,
            0x08,
            0x08,
            0x00,
            0x09,
            framing,
            0x0a,
            framing,
            0x0b,
            framing,
            0x0c,
            framing,
        ]);
        let older_tags = firmware.at_most(0x599);
        if older_tags {
            pairs.extend_from_slice(&[0x0d, 0x00]);
        }
        if matches!(self, Self::Felica(_)) && !firmware.at_most(0x609) {
            pairs.extend_from_slice(&[0x0e, 0x00, 0x0f, 0x05, 0x10, 0xff]);
        } else {
            pairs.extend_from_slice(&[0x0e, 0x04, 0x0f, 0x00, 0x10, 0x00]);
        }
        pairs.extend_from_slice(&[0x11, 0x00]);
        if !older_tags {
            pairs.extend_from_slice(&[0x12, 0x00]);
        }
        if !firmware.at_most(0x619) {
            pairs.extend_from_slice(&[0x13, 0x06]);
        }
        pairs
    }
}

/// InSetProtocol pairs that switch NFC-A between the two CRC checks.
pub(super) fn crc_check(check: CrcCheck) -> [u8; 2] {
    [
        0x02,
        match check {
            CrcCheck::Reader => 0x01,
            CrcCheck::Host => 0x00,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn older_firmware_ranges_follow_option_60_and_the_shifted_versions() {
        let firmware = |option_60, version| Firmware { version, option_60 };
        assert!(firmware(0, 0x0599).at_most(0x599));
        assert!(!firmware(0, 0x0600).at_most(0x599));
        assert!(!firmware(6, 0x0100).at_most(0x599));
        assert!(!firmware(0, 0x0000).at_most(0x599));
        assert!(firmware(5, 0x0100).at_most(0x199));
        assert!(!firmware(5, 0x0101).at_most(0x711));
        assert!(!firmware(5, 0x0199).at_most(0x711));
        assert!(!firmware(5, 0x019a).at_most(0x199));
        assert!(firmware(5, 0x019a).at_most(0x299));
    }

    #[test]
    fn type_b_uses_the_older_bit_rate_code_on_older_firmware() {
        let older = Firmware {
            version: 0x0200,
            option_60: 0,
        };
        let newer = Firmware {
            version: 0x0111,
            option_60: 0,
        };
        assert_eq!(Settings::TypeB.rf(older), [0x03, 0x06, 0x0f, 0x06]);
        assert_eq!(Settings::TypeB.rf(newer), [0x03, 0x07, 0x0f, 0x07]);
        assert_eq!(
            Settings::TypeA(CrcCheck::Reader).rf(older),
            [0x02, 0x03, 0x0f, 0x03]
        );
    }
}
