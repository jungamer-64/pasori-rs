//! Bounded host and reader frames, independent of USB transfer boundaries.
//!
//! A frame is `00 00 FF LEN LCS DATA DCS 00` with `LCS = -LEN` and
//! `DCS = -sum(DATA)`. `DATA` starts with the command byte and has no
//! direction byte; a response command is its request command plus one. A
//! successful decode establishes frame integrity, not command completion.

use alloc::vec::Vec;
use core::fmt;

/// Largest payload, including the command byte, that one length byte counts.
pub const MAX_PAYLOAD: usize = 255;
/// Largest frame, including its envelope.
pub const MAX_FRAME: usize = MAX_PAYLOAD + 7;
/// Reader acknowledgement of a host frame; this does not mean that a card
/// operation succeeded.
pub const ACK: [u8; 6] = [0, 0, 0xff, 0, 0xff, 0];
/// Reader negative acknowledgement.
pub const NAK: [u8; 6] = [0, 0, 0xff, 0xff, 0, 0];
const READER_ERROR: [u8; 8] = [0, 0, 0xff, 1, 0xff, 0x7f, 0x81, 0];

/// Verified frame with its checksum envelope removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Frame<'a> {
    /// Reader accepted a host frame.
    Ack,
    /// Reader returned a negative acknowledgement.
    Nak,
    /// Reader returned the special `7F` error frame.
    ReaderError,
    /// Command or response payload.
    Data {
        /// Request or response command byte.
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
    /// Payload exceeds one length byte.
    PayloadTooLarge {
        /// Rejected payload size, including the command byte.
        length: usize,
    },
    /// Data lacks a command byte.
    PayloadTooShort,
    /// Length checksum is invalid.
    LengthChecksum,
    /// Payload checksum is invalid.
    DataChecksum,
    /// Postamble is not zero.
    Postamble,
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
                write!(f, "payload length {length} exceeds {MAX_PAYLOAD}")
            }
            Self::PayloadTooShort => f.write_str("data frame has no command"),
            Self::LengthChecksum => f.write_str("invalid length checksum"),
            Self::DataChecksum => f.write_str("invalid data checksum"),
            Self::Postamble => f.write_str("invalid postamble"),
        }
    }
}

impl core::error::Error for FrameError {}

/// Encode a host command.
///
/// # Errors
///
/// Returns [`FrameError::PayloadTooLarge`] when the command and arguments
/// exceed 255 bytes. No transport action occurs here.
pub fn encode(command: u8, args: &[u8]) -> Result<Vec<u8>, FrameError> {
    let length = args
        .len()
        .checked_add(1)
        .ok_or(FrameError::PayloadTooLarge { length: args.len() })?;
    let short = u8::try_from(length).map_err(|_| FrameError::PayloadTooLarge { length })?;
    let mut bytes = Vec::with_capacity(length + 7);
    bytes.extend_from_slice(&[0, 0, 0xff, short, short.wrapping_neg(), command]);
    bytes.extend_from_slice(args);
    let sum = args
        .iter()
        .fold(command, |sum, byte| sum.wrapping_add(*byte));
    bytes.extend_from_slice(&[sum.wrapping_neg(), 0]);
    Ok(bytes)
}

/// Establish the first frame's total length from a possibly partial stream.
///
/// `None` means that more header bytes are needed. `Some(n)` can be returned
/// before all `n` bytes arrive; it does not establish payload integrity. Bytes
/// after that first frame belong to the stream owner.
///
/// # Errors
///
/// Rejects an invalid preamble, an invalid length checksum, or a zero length
/// that is not ACK.
pub fn frame_length(input: &[u8]) -> Result<Option<usize>, FrameError> {
    if input.iter().zip([0, 0, 0xff]).take(3).any(|(a, b)| *a != b) {
        return Err(FrameError::Preamble);
    }
    let Some(header) = input.get(..5) else {
        return Ok(None);
    };
    if header == &ACK[..5] || header == &NAK[..5] {
        return Ok(Some(6));
    }
    if header[3].wrapping_add(header[4]) != 0 {
        return Err(FrameError::LengthChecksum);
    }
    if header[3] == 0 {
        return Err(FrameError::PayloadTooShort);
    }
    Ok(Some(usize::from(header[3]) + 7))
}

/// Decode exactly one complete frame, verifying its checksums.
///
/// # Errors
///
/// Returns the specific integrity error. Extra trailing bytes are a length
/// failure; split or coalesced USB reads must first be framed by the stream owner.
pub fn parse(input: &[u8]) -> Result<Frame<'_>, FrameError> {
    let expected = frame_length(input)?.ok_or(FrameError::Truncated)?;
    if input.len() != expected {
        return Err(FrameError::Length {
            expected,
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
    if input == READER_ERROR {
        return Ok(Frame::ReaderError);
    }
    let (checksum, payload) = input[5..input.len() - 1]
        .split_last()
        .ok_or(FrameError::PayloadTooShort)?;
    if payload
        .iter()
        .fold(*checksum, |sum, byte| sum.wrapping_add(*byte))
        != 0
    {
        return Err(FrameError::DataChecksum);
    }
    let (command, data) = payload.split_first().ok_or(FrameError::PayloadTooShort)?;
    Ok(Frame::Data {
        command: *command,
        data,
    })
}
