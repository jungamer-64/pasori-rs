//! ISO/IEC 14443-4 activation parameters reported by NFC-A and NFC-B activation.

use core::time::Duration;

/// Card frame capacity, including CRC, decoded from a 4-bit FSCI field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FrameSize(u16);

impl FrameSize {
    /// FSCI D–F are RFU; ISO/IEC 14443-4 directs a PCD to read them as C.
    pub(crate) fn from_index(index: u8) -> Self {
        Self(match index {
            0 => 16,
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

    pub(crate) fn bytes(self) -> u16 {
        self.0
    }
}

/// ISO-DEP FWT = 4096 carrier periods at 13.56 MHz times 2^FWI, rounded upward to ns.
pub(crate) fn frame_wait(index: u8) -> Duration {
    Duration::from_nanos((4_096_000_000_000u64 * (1u64 << index)).div_ceil(13_560_000))
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
}
