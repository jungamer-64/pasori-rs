//! FeliCa card packets and the selected-card packet exchange.
//!
//! Reader layers select cards with [`PollRequest`] and carry packets for a
//! [`Selection`]; card command protocols run over that exchange. Packets here
//! include their FeliCa length byte and exclude CRC and reader envelopes.
//!
//! Identity is session data, not a universally unique or authenticated
//! credential. Polling system codes are encoded big-endian.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// Eight-byte card identity returned by the selected system's polling response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Idm([u8; 8]);

impl Idm {
    /// Preserve the identity's wire byte order.
    pub const fn new(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// Borrow the identity bytes in their wire order.
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Display for Idm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

/// Polling parameters outside the values the Polling command defines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PollRequestError {
    /// Polling request code is outside `00/01/02`.
    RequestCode(u8),
    /// Polling slot selector is outside `00/01/03/07/0F`.
    TimeSlots(u8),
}

impl fmt::Display for PollRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestCode(value) => write!(f, "unsupported polling request {value:02X}"),
            Self::TimeSlots(value) => write!(f, "invalid polling slot selector {value:02X}"),
        }
    }
}

impl core::error::Error for PollRequestError {}

/// A FeliCa packet whose length byte or response command is malformed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketError {
    /// Actual bytes do not match the packet's declared or required length.
    Length {
        /// Required packet length.
        expected: usize,
        /// Actual packet length.
        actual: usize,
    },
    /// Unexpected card response command.
    ResponseCode {
        /// Required response command.
        expected: u8,
        /// Actual response command.
        actual: u8,
    },
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { expected, actual } => {
                write!(f, "card packet length {actual}, expected {expected}")
            }
            Self::ResponseCode { expected, actual } => {
                write!(f, "card response {actual:02X}, expected {expected:02X}")
            }
        }
    }
}

impl core::error::Error for PacketError {}

/// Validated six-byte polling command, including its FeliCa length byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollRequest {
    system: u16,
    request: u8,
    slots: u8,
}

impl PollRequest {
    /// Construct polling parameters. `FF` is a wildcard in each system-code byte.
    ///
    /// # Errors
    ///
    /// Rejects request codes outside `0..=2` and invalid slot selectors.
    pub const fn new(system: u16, request: u8, slots: u8) -> Result<Self, PollRequestError> {
        if request > 2 {
            return Err(PollRequestError::RequestCode(request));
        }
        if !matches!(slots, 0 | 1 | 3 | 7 | 15) {
            return Err(PollRequestError::TimeSlots(slots));
        }
        Ok(Self {
            system,
            request,
            slots,
        })
    }

    /// The requested system code, possibly holding `FF` wildcard bytes.
    pub const fn system(self) -> u16 {
        self.system
    }

    /// The request code that determines the meaning of optional response data.
    pub const fn request_code(self) -> u8 {
        self.request
    }

    /// Encode the six-byte card command, without CRC or reader timeout fields.
    pub fn encode(self) -> [u8; 6] {
        let [high, low] = self.system.to_be_bytes();
        [6, 0, high, low, self.request, self.slots]
    }
}

/// Validated polling response; optional bytes depend on the polling request code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollResponse {
    /// Selected system's manufacturing identity, in wire order.
    pub idm: Idm,
    /// Manufacturing parameters, preserved without inferring a product model.
    pub pmm: [u8; 8],
    /// Optional two-byte request data, kept in wire order.
    pub request_data: Option<[u8; 2]>,
}

impl PollResponse {
    /// Decode an 18- or 20-byte polling response, including its card length byte.
    ///
    /// # Errors
    ///
    /// Rejects malformed length, a response command other than `01`, or a packet
    /// shape that cannot contain complete identity and manufacturing parameters.
    pub fn parse(input: &[u8]) -> Result<Self, PacketError> {
        validate_length(input, 18)?;
        if input[1] != 0x01 {
            return Err(PacketError::ResponseCode {
                expected: 0x01,
                actual: input[1],
            });
        }
        if input.len() != 18 && input.len() != 20 {
            return Err(PacketError::Length {
                expected: 18,
                actual: input.len(),
            });
        }
        let mut idm = [0; 8];
        let mut pmm = [0; 8];
        idm.copy_from_slice(&input[2..10]);
        pmm.copy_from_slice(&input[10..18]);
        let request_data = input.get(18..20).map(|bytes| [bytes[0], bytes[1]]);
        Ok(Self {
            idm: Idm::new(idm),
            pmm,
            request_data,
        })
    }
}

/// Check that a packet holds at least `minimum` bytes and that its length
/// byte counts the whole packet.
///
/// # Errors
///
/// Returns [`PacketError::Length`] for a shorter packet or a length byte that
/// differs from the packet length.
pub fn validate_length(input: &[u8], minimum: usize) -> Result<(), PacketError> {
    if input.len() < minimum {
        return Err(PacketError::Length {
            expected: minimum,
            actual: input.len(),
        });
    }
    let declared = usize::from(input[0]);
    if declared != input.len() {
        return Err(PacketError::Length {
            expected: declared,
            actual: input.len(),
        });
    }
    Ok(())
}

/// A FeliCa card selected by polling, whose packet exchange authority is
/// held by the implementing reader handle.
///
/// The reader layer owns the RF transfer, its wait and its failure states;
/// card command protocols own packet contents. A packet that leaves card
/// state which a new Polling does not clear, such as authentication, must be
/// declared with [`Self::require_field_cycle`] before it is sent.
pub trait Selection {
    /// Reader failure of one packet exchange. Whether the packet was sent is
    /// part of the reader's error contract.
    type Error: fmt::Debug;

    /// The Polling command that selected this card.
    fn poll_request(&self) -> PollRequest;

    /// The card's validated polling response.
    fn poll_response(&self) -> &PollResponse;

    /// Maximum packet length in either direction, including the length byte.
    fn max_packet_len(&self) -> usize;

    /// Send one packet and return the card's reply, whose length byte has
    /// been checked. The reader never replays a packet automatically; after a
    /// failure that follows sending, the packet may have taken effect.
    ///
    /// # Errors
    ///
    /// Returns the reader's failure of this exchange.
    fn exchange_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Make the next selection on this reader cycle the RF field before its
    /// request, because the card now holds state that a new Polling does not
    /// clear.
    fn require_field_cycle(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polling_known_answer() -> Result<(), alloc::boxed::Box<dyn core::error::Error>> {
        assert_eq!(
            PollRequest::new(0xffff, 0, 0)?.encode(),
            [6, 0, 0xff, 0xff, 0, 0]
        );
        assert_eq!(
            PollRequest::new(0x1234, 1, 15)?.encode(),
            [6, 0, 0x12, 0x34, 1, 15]
        );
        let response = [
            20, 1, 1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x12,
            0x34,
        ];
        let card = PollResponse::parse(&response)?;
        assert_eq!(card.idm, Idm::new([1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(card.request_data, Some([0x12, 0x34]));
        assert!(matches!(
            PollRequest::new(0xffff, 0, 2),
            Err(PollRequestError::TimeSlots(2))
        ));
        Ok(())
    }
}
