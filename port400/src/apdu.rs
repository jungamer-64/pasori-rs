//! Device APDUs and the bounded Transparent Session response format.

use core::{error, fmt};

const GENERIC_STATUS: u16 = 0xc0;
const RX_BITS: u16 = 0x92;
const RX_STATUS: u16 = 0x96;
const ICC_RESPONSE: u16 = 0x97;
const SWITCH_RESPONSE: u16 = 0x8f;

pub(crate) const READ_FIRMWARE: [u8; 5] = [0xff, 0x56, 0, 0, 0];

pub(crate) const fn session_command(object: u8) -> [u8; 8] {
    [0xff, 0x50, 0, 0, 2, object, 0, 0]
}

pub(crate) const fn switch_protocol(standard: u8, layer: u8) -> [u8; 10] {
    [0xff, 0x50, 0, 2, 4, 0x8f, 2, standard, layer, 0]
}

pub(crate) const fn framing(flags: u16) -> [u8; 10] {
    let [high, low] = flags.to_be_bytes();
    [0xff, 0x50, 0, 1, 4, 0x90, 2, high, low, 0]
}

pub(crate) const fn speed(parameter: u8) -> [u8; 12] {
    [0xff, 0x50, 0, 0, 6, 0xff, 0x6e, 3, 5, 1, parameter, 0]
}

// The Sony USB exchange uses a fixed-width BER length for transceive data
// and a three-byte suffix, even when the APDU would fit in the short form.
const EXCHANGE_OVERHEAD: usize = 21;
pub(crate) const EXCHANGE_CAPACITY: usize = EXCHANGE_OVERHEAD + u8::MAX as usize;

pub(crate) fn exchange<'a>(
    packet: &[u8],
    wait_us: u32,
    buffer: &'a mut [u8; EXCHANGE_CAPACITY],
) -> Option<&'a [u8]> {
    let length = u16::from(u8::try_from(packet.len()).ok()?);
    let [lc_hi, lc_lo] = (length + 11).to_be_bytes();
    let [wait_a, wait_b, wait_c, wait_d] = wait_us.to_le_bytes();
    let [rf_hi, rf_lo] = length.to_be_bytes();
    let prefix = [
        0xff, 0x50, 0, 1, 0, lc_hi, lc_lo, 0x5f, 0x46, 4, wait_a, wait_b, wait_c, wait_d, 0x95,
        0x82, rf_hi, rf_lo,
    ];
    buffer[..prefix.len()].copy_from_slice(&prefix);
    let packet_end = prefix.len() + packet.len();
    buffer[prefix.len()..packet_end].copy_from_slice(packet);
    buffer[packet_end..packet_end + 3].fill(0);
    Some(&buffer[..packet_end + 3])
}

/// A Port-400 device APDU response could not establish success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApduError {
    /// No complete outer status word was received.
    MissingStatus,
    /// The outer APDU status word indicated failure.
    Status([u8; 2]),
    /// A data object failed inside the APDU.
    ObjectStatus {
        /// Data object index reported by the reader.
        index: u8,
        /// Inner status word.
        status: [u8; 2],
    },
    /// A TLV tag or length cannot be decoded in the Port-400 response format.
    InvalidTlv,
    /// A mandatory data object was absent.
    MissingTag(u16),
    /// An object repeated in a response to a single operation.
    DuplicateTag(u16),
    /// A data object has an unexpected length.
    TagLength {
        /// Tag of the data object.
        tag: u16,
        /// Actual length of its value.
        length: usize,
    },
    /// The success status named a failing object index.
    SuccessIndex(u8),
    /// A whole-byte exchange returned an incomplete last byte.
    PartialByte(u8),
    /// The reader reported a card timeout alongside received RF data.
    UnexpectedIccResponse,
    /// The reader reported an RF reception error.
    RfStatus {
        /// CRC, collision, parity and framing status flags.
        flags: u8,
        /// Detail reported by the reader.
        detail: u8,
    },
}

impl fmt::Display for ApduError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::MissingStatus => f.write_str("APDU reply lacks a status word"),
            Self::Status([high, low]) => write!(f, "device APDU status {high:02X}{low:02X}"),
            Self::ObjectStatus {
                index,
                status: [high, low],
            } => {
                write!(f, "device APDU object {index} returned {high:02X}{low:02X}")
            }
            Self::InvalidTlv => f.write_str("malformed device APDU data object"),
            Self::MissingTag(tag) => write!(f, "missing data object {tag:02X}"),
            Self::DuplicateTag(tag) => write!(f, "repeated data object {tag:02X}"),
            Self::TagLength { tag, length } => {
                write!(f, "data object {tag:02X} has length {length}")
            }
            Self::SuccessIndex(index) => {
                write!(f, "successful status contains object index {index}")
            }
            Self::PartialByte(bits) => {
                write!(f, "RF reply reported {bits} valid bits in its last byte")
            }
            Self::UnexpectedIccResponse => f.write_str("RF data accompanied a card timeout"),
            Self::RfStatus { flags, detail } => {
                write!(f, "RF status {flags:02X}, detail {detail:02X}")
            }
        }
    }
}

impl error::Error for ApduError {}

impl ApduError {
    pub(crate) fn icc_timeout(self) -> bool {
        matches!(
            self,
            Self::Status([0x64, 0x01])
                | Self::ObjectStatus {
                    status: [0x64, 0x01],
                    ..
                }
        )
    }

    pub(crate) fn session_sequence_invalid(self) -> bool {
        matches!(
            self,
            Self::ObjectStatus {
                status: [0x63, 0x01],
                ..
            }
        )
    }
}

pub(crate) fn response_body(response: &[u8]) -> Result<&[u8], ApduError> {
    let Some((body, &[high, low])) = response.split_last_chunk::<2>() else {
        return Err(ApduError::MissingStatus);
    };
    match [high, low] {
        [0x90, 0] => Ok(body),
        status => Err(ApduError::Status(status)),
    }
}

pub(crate) struct Objects<'a> {
    status: &'a [u8; 3],
    rx_bits: Option<&'a [u8; 1]>,
    rx_status: Option<&'a [u8; 2]>,
    icc_response: Option<&'a [u8]>,
    switch: Option<&'a [u8]>,
}

impl<'a> Objects<'a> {
    pub(crate) fn parse(response: &'a [u8]) -> Result<Self, ApduError> {
        let mut input = response_body(response)?;
        let mut status = None;
        let mut rx_bits = None;
        let mut rx_status = None;
        let mut icc_response = None;
        let mut switch = None;
        while !input.is_empty() {
            let (tag, value, rest) = object(input)?;
            match tag {
                GENERIC_STATUS => set(&mut status, tag, sized(tag, value)?)?,
                RX_BITS => set(&mut rx_bits, tag, sized(tag, value)?)?,
                RX_STATUS => set(&mut rx_status, tag, sized(tag, value)?)?,
                ICC_RESPONSE => set(&mut icc_response, tag, value)?,
                SWITCH_RESPONSE => set(&mut switch, tag, value)?,
                _ => {}
            }
            input = rest;
        }
        Ok(Self {
            status: status.ok_or(ApduError::MissingTag(GENERIC_STATUS))?,
            rx_bits,
            rx_status,
            icc_response,
            switch,
        })
    }

    pub(crate) fn require_success(&self) -> Result<(), ApduError> {
        match *self.status {
            [0, 0x90, 0] => Ok(()),
            [index, 0x90, 0] => Err(ApduError::SuccessIndex(index)),
            [index, high, low] => Err(ApduError::ObjectStatus {
                index,
                status: [high, low],
            }),
        }
    }

    pub(crate) fn sak(&self) -> Result<u8, ApduError> {
        self.require_success()?;
        let [sak] = sized(
            SWITCH_RESPONSE,
            self.switch.ok_or(ApduError::MissingTag(SWITCH_RESPONSE))?,
        )?;
        Ok(*sak)
    }

    pub(crate) fn received(&self) -> Result<&'a [u8], ApduError> {
        if let Some(&[flags, detail]) = self.rx_status
            && flags != 0
        {
            return Err(ApduError::RfStatus { flags, detail });
        }
        if let Some(&[bits]) = self.rx_bits
            && bits != 0
        {
            return Err(ApduError::PartialByte(bits));
        }
        let status = self.require_success();
        if self
            .icc_response
            .is_some_and(|response| !response.is_empty())
            && status.as_ref().is_err_and(|error| error.icc_timeout())
        {
            return Err(ApduError::UnexpectedIccResponse);
        }
        status?;
        self.icc_response.ok_or(ApduError::MissingTag(ICC_RESPONSE))
    }
}

fn sized<const N: usize>(tag: u16, value: &[u8]) -> Result<&[u8; N], ApduError> {
    value.try_into().map_err(|_| ApduError::TagLength {
        tag,
        length: value.len(),
    })
}

fn set<T>(field: &mut Option<T>, tag: u16, value: T) -> Result<(), ApduError> {
    if field.is_some() {
        return Err(ApduError::DuplicateTag(tag));
    }
    *field = Some(value);
    Ok(())
}

fn object(input: &[u8]) -> Result<(u16, &[u8], &[u8]), ApduError> {
    let (tag, rest) = match input {
        [high, low, rest @ ..] if high & 0x1f == 0x1f && low & 0x80 == 0 && *low != 0 => {
            (u16::from_be_bytes([*high, *low]), rest)
        }
        [tag, rest @ ..] if tag & 0x1f != 0x1f => (u16::from(*tag), rest),
        _ => return Err(ApduError::InvalidTlv),
    };
    let (length, rest) = match rest {
        [length @ 0..=0x7f, rest @ ..] | [0x81, length, rest @ ..] => (u16::from(*length), rest),
        [0x82, high, low, rest @ ..] => (u16::from_be_bytes([*high, *low]), rest),
        _ => return Err(ApduError::InvalidTlv),
    };
    let (value, tail) = rest
        .split_at_checked(usize::from(length))
        .ok_or(ApduError::InvalidTlv)?;
    Ok((tag, value, tail))
}
