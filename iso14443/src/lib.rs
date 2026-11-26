//! NFC-A and NFC-B activation data and the selected-card exchanges.
//!
//! Reader layers activate cards and report what activation established:
//! [`nfca::Observation`] and [`nfcb::Observation`]. Card protocols run over
//! the exchange that the selection grants: [`nfca::Selection`] carries NFC-A
//! frames, and [`iso_dep::Selection`] carries the blocks of an ISO-DEP
//! session whose block protocol the host runs. Byte sequences are in wire
//! order and exclude RF CRC bytes.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod iso_dep;
pub mod nfca;
pub mod nfcb;

use core::time::Duration;

/// Card frame capacity, including CRC, decoded from a 4-bit FSCI field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameSize(u16);

impl FrameSize {
    /// FSCI D–F are RFU; ISO/IEC 14443-4 directs a PCD to read them as C.
    fn from_index(index: u8) -> Self {
        Self(match index {
            0 => iso_dep::MIN_FRAME_BYTES,
            1 => 24,
            2 => 32,
            3 => 40,
            4 => 48,
            5 => 64,
            6 => 96,
            7 => 128,
            8 => 256,
            9 => 512,
            0x0a => 1024,
            0x0b => 2048,
            _ => 4096,
        })
    }

    fn bytes(self) -> u16 {
        self.0
    }
}

/// A frame waiting integer (FWI) or startup frame guard integer (SFGI).
/// Both fields scale 4096 carrier periods by `2^index`; their value 15 is
/// reserved and names no time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WaitIndex(u8);

impl WaitIndex {
    /// The largest defined index.
    pub const MAX: Self = Self(14);

    /// Accept the defined indices `0..=14`.
    pub const fn new(index: u8) -> Option<Self> {
        if index <= Self::MAX.0 {
            Some(Self(index))
        } else {
            None
        }
    }

    /// The 4-bit field value.
    pub const fn get(self) -> u8 {
        self.0
    }

    /// 4096 carrier periods at 13.56 MHz times `2^index`, rounded upward to
    /// whole nanoseconds: the frame waiting time of this FWI and the startup
    /// frame guard time of this SFGI.
    pub const fn duration(self) -> Duration {
        Duration::from_nanos((4_096_000_000_000u64 << self.0).div_ceil(13_560_000))
    }

    /// `unit` times `2^index`, saturating at [`Duration::MAX`]. A wait policy
    /// with its own per-index unit derives its waits through this scale.
    pub const fn scaled(self, unit: Duration) -> Duration {
        unit.saturating_mul(1 << self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_and_rfu_frame_size_indices_decode_to_4096() {
        assert_eq!(
            [8, 9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0f].map(|index| FrameSize::from_index(index).bytes()),
            [256, 512, 1024, 2048, 4096, 4096, 4096]
        );
    }

    #[test]
    fn wait_indices_exclude_the_reserved_value_and_round_up_the_carrier_periods() {
        assert_eq!(WaitIndex::new(15), None);
        assert_eq!(WaitIndex::new(14), Some(WaitIndex::MAX));
        assert_eq!(
            WaitIndex::new(0).map(WaitIndex::duration),
            Some(Duration::from_nanos(302_065))
        );
        assert_eq!(
            WaitIndex::new(4).map(WaitIndex::duration),
            Some(Duration::from_nanos(4_833_039))
        );
        assert_eq!(
            WaitIndex::MAX.duration(),
            Duration::from_nanos(4_949_031_269)
        );
        assert_eq!(
            WaitIndex::new(3).map(|index| index.scaled(Duration::from_micros(330))),
            Some(Duration::from_micros(2640))
        );
    }
}
