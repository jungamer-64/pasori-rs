//! Bounded host and reader frames, independent of USB transfer boundaries.
//!
//! The host sends extended frames
//! `00 00 FF FF FF LENlo LENhi LCS D6 CMD ARGS DCS 00`; the reader answers
//! with extended frames or with normal frames `00 00 FF LEN LCS D7 CMD DATA
//! DCS 00`. `LEN` counts the direction byte, the command and its bytes, `LCS`
//! makes the length bytes sum to zero and `DCS = -sum(payload)`. A response
//! command is its request command plus one. A successful decode establishes
//! frame integrity, not command completion.

use alloc::vec::Vec;
use core::fmt;

/// Largest `LEN`, counting the direction byte, the command and its bytes,
/// that the reader exchanges in one frame.
pub const MAX_LENGTH: usize = 0x316;
/// Largest frame, including its extended envelope.
pub const MAX_FRAME: usize = MAX_LENGTH + 10;
/// Acknowledgement. The reader sends it after accepting a host frame, which
/// does not mean that a card operation succeeded; the host sends it to
/// cancel the command in progress.
pub const ACK: [u8; 6] = [0, 0, 0xff, 0, 0xff, 0];
/// Reader negative acknowledgement.
pub const NAK: [u8; 6] = [0, 0, 0xff, 0xff, 0, 0];
const HOST: u8 = 0xd6;
const READER: u8 = 0xd7;
const READER_ERROR: u8 = 0x7f;

/// Verified reader frame with its checksum envelope removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Frame<'a> {
    /// Reader accepted a host frame.
    Ack,
    /// Reader returned a negative acknowledgement.
    Nak,
    /// Reader returned the `7F` error frame.
    ReaderError,
    /// Response payload after the `D7` direction byte.
    Data {
        /// Response command byte.
        command: u8,
        /// Command-specific bytes; these do not universally start with status.
        data: &'a [u8],
    },
}

/// Frame integrity or size failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameError {
    /// Input does not start with `00 00 FF`.
    Preamble,
    /// More bytes are needed to establish or complete the frame.
    Truncated,
    /// A complete single-frame decode received the wrong total length.
    Length {
        /// Number of bytes required by the header.
        expected: usize,
        /// Number of supplied bytes.
        actual: usize,
    },
    /// `LEN` exceeds [`MAX_LENGTH`].
    PayloadTooLarge {
        /// Rejected `LEN`.
        length: usize,
    },
    /// The payload lacks a direction byte and a command.
    PayloadTooShort,
    /// Length checksum is invalid.
    LengthChecksum,
    /// Payload checksum is invalid.
    DataChecksum,
    /// Postamble is not zero.
    Postamble,
    /// The payload does not start with the reader direction byte `D7`.
    Direction(u8),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preamble => f.write_str("invalid frame preamble"),
            Self::Truncated => f.write_str("incomplete frame"),
            Self::Length { expected, actual } => {
                write!(f, "frame length {actual}, expected {expected}")
            }
            Self::PayloadTooLarge { length } => {
                write!(f, "payload length {length} exceeds {MAX_LENGTH}")
            }
            Self::PayloadTooShort => f.write_str("frame has no command"),
            Self::LengthChecksum => f.write_str("invalid length checksum"),
            Self::DataChecksum => f.write_str("invalid data checksum"),
            Self::Postamble => f.write_str("invalid postamble"),
            Self::Direction(direction) => write!(f, "direction byte {direction:02X}"),
        }
    }
}

impl core::error::Error for FrameError {}

/// Encode a host command as an extended frame.
///
/// # Errors
///
/// Returns [`FrameError::PayloadTooLarge`] when the direction byte, command
/// and arguments exceed [`MAX_LENGTH`]. No transport action occurs here.
pub fn encode(command: u8, args: &[u8]) -> Result<Vec<u8>, FrameError> {
    let length = args
        .len()
        .checked_add(2)
        .ok_or(FrameError::PayloadTooLarge { length: args.len() })?;
    let wire_length = u16::try_from(length)
        .ok()
        .filter(|_| length <= MAX_LENGTH)
        .ok_or(FrameError::PayloadTooLarge { length })?;
    let [low, high] = wire_length.to_le_bytes();
    let mut bytes = Vec::with_capacity(length + 10);
    bytes.extend_from_slice(&[
        0,
        0,
        0xff,
        0xff,
        0xff,
        low,
        high,
        low.wrapping_add(high).wrapping_neg(),
        HOST,
        command,
    ]);
    bytes.extend_from_slice(args);
    let sum = args.iter().fold(HOST.wrapping_add(command), |sum, byte| {
        sum.wrapping_add(*byte)
    });
    bytes.extend_from_slice(&[sum.wrapping_neg(), 0]);
    Ok(bytes)
}

/// Header of the first frame: total length and the payload's start offset.
struct Header {
    total: usize,
    payload: usize,
}

fn header(input: &[u8]) -> Result<Option<Header>, FrameError> {
    if input.iter().zip([0, 0, 0xff]).take(3).any(|(a, b)| *a != b) {
        return Err(FrameError::Preamble);
    }
    let Some(&[first, second]) = input.get(3..5) else {
        return Ok(None);
    };
    match [first, second] {
        [0, 0xff] | [0xff, 0] => Ok(Some(Header {
            total: 6,
            payload: 5,
        })),
        [0xff, 0xff] => {
            let Some(&[low, high, checksum]) = input.get(5..8) else {
                return Ok(None);
            };
            if low.wrapping_add(high).wrapping_add(checksum) != 0 {
                return Err(FrameError::LengthChecksum);
            }
            let length = usize::from(u16::from_le_bytes([low, high]));
            if length > MAX_LENGTH {
                return Err(FrameError::PayloadTooLarge { length });
            }
            if length == 0 {
                return Err(FrameError::PayloadTooShort);
            }
            Ok(Some(Header {
                total: length + 10,
                payload: 8,
            }))
        }
        [length, checksum] => {
            if length.wrapping_add(checksum) != 0 {
                return Err(FrameError::LengthChecksum);
            }
            if length == 0 {
                return Err(FrameError::PayloadTooShort);
            }
            Ok(Some(Header {
                total: usize::from(length) + 7,
                payload: 5,
            }))
        }
    }
}

/// Establish the first reader frame's total length from a possibly partial
/// stream.
///
/// `None` means that more header bytes are needed. `Some(n)` can be returned
/// before all `n` bytes arrive; it does not establish payload integrity. Bytes
/// after that first frame belong to the stream owner.
///
/// # Errors
///
/// Rejects an invalid preamble, an invalid length checksum, a zero length
/// that is not ACK, or a length above [`MAX_LENGTH`].
pub fn frame_length(input: &[u8]) -> Result<Option<usize>, FrameError> {
    Ok(header(input)?.map(|header| header.total))
}

/// Decode exactly one complete reader frame, verifying its checksums and its
/// direction byte.
///
/// # Errors
///
/// Returns the specific integrity error. Extra trailing bytes are a length
/// failure; split or coalesced USB reads must first be framed by the stream owner.
pub fn parse(input: &[u8]) -> Result<Frame<'_>, FrameError> {
    let header = header(input)?.ok_or(FrameError::Truncated)?;
    if input.len() != header.total {
        return Err(FrameError::Length {
            expected: header.total,
            actual: input.len(),
        });
    }
    if input.last() != Some(&0) {
        return Err(FrameError::Postamble);
    }
    if input == ACK {
        return Ok(Frame::Ack);
    }
    if input == NAK {
        return Ok(Frame::Nak);
    }
    let (checksum, payload) = input[header.payload..input.len() - 1]
        .split_last()
        .ok_or(FrameError::PayloadTooShort)?;
    if payload
        .iter()
        .fold(*checksum, |sum, byte| sum.wrapping_add(*byte))
        != 0
    {
        return Err(FrameError::DataChecksum);
    }
    match payload {
        [READER_ERROR] => Ok(Frame::ReaderError),
        [READER, command, data @ ..] => Ok(Frame::Data {
            command: *command,
            data,
        }),
        [direction, _, ..] => Err(FrameError::Direction(*direction)),
        _ => Err(FrameError::PayloadTooShort),
    }
}
