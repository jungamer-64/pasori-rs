//! FeliCa card commands over a card selected by RC-S956 polling.
//!
//! Service and block numbers are encoded little-endian.

use alloc::vec::Vec;
use core::fmt;
use rcs956::{
    felica::Idm,
    reader::{self, FelicaCard},
    transport::Transport,
};

#[cfg(feature = "felica-lite-s")]
pub mod lite_s;
#[cfg(feature = "felica-standard-aes")]
pub mod standard_aes;

/// Maximum blocks in one supported Read Without Encryption command.
pub const MAX_READ_BLOCKS: usize = 12;

/// Maximum write blocks that fit a single-service packet with short addresses.
pub const MAX_WRITE_BLOCKS: usize = 13;

/// Card packet validation or card-reported status failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CardError {
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
    /// Read block count is outside the supported baseline range `1..=12`.
    BlockCount(usize),
    /// Write block count is outside `1..=13`.
    WriteBlockCount(usize),
    /// A response belongs to a different selected identity.
    IdentityMismatch {
        /// Identity selected by the caller.
        expected: Idm,
        /// Identity received from the card.
        actual: Idm,
    },
    /// Card-reported operation failure; both status flags are preserved.
    Status {
        /// First status flag.
        flag1: u8,
        /// Second status flag.
        flag2: u8,
    },
    /// A successful response contains a different number of blocks.
    ResponseBlockCount {
        /// Number of requested blocks.
        expected: usize,
        /// Number returned in the response.
        actual: usize,
    },
}

impl fmt::Display for CardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { expected, actual } => {
                write!(f, "card packet length {actual}, expected {expected}")
            }
            Self::ResponseCode { expected, actual } => {
                write!(f, "card response {actual:02X}, expected {expected:02X}")
            }
            Self::BlockCount(count) => {
                write!(f, "block count {count} is outside 1..={MAX_READ_BLOCKS}")
            }
            Self::WriteBlockCount(count) => {
                write!(
                    f,
                    "write block count {count} is outside 1..={MAX_WRITE_BLOCKS}"
                )
            }
            Self::IdentityMismatch { expected, actual } => {
                write!(f, "card identity {actual}, expected {expected}")
            }
            Self::Status { flag1, flag2 } => write!(f, "card status {flag1:02X} {flag2:02X}"),
            Self::ResponseBlockCount { expected, actual } => {
                write!(f, "response has {actual} blocks, expected {expected}")
            }
        }
    }
}

impl core::error::Error for CardError {}

/// Build a one-service Read Without Encryption packet for at most 12 blocks.
///
/// The service code is little-endian. Block numbers through 255 use the two-byte
/// list element; larger numbers use the three-byte form. No CRC is appended.
///
/// # Errors
///
/// Rejects an empty block list or more than 12 blocks. Individual card products
/// can have additional restrictions beyond this baseline packet format.
pub fn read_without_encryption(
    idm: Idm,
    service_code: u16,
    blocks: &[u16],
) -> Result<Vec<u8>, CardError> {
    let count =
        block_count(blocks.len(), MAX_READ_BLOCKS).ok_or(CardError::BlockCount(blocks.len()))?;
    let mut packet = block_list(0x06, idm, service_code, count, blocks.iter().copied());
    set_length(&mut packet)?;
    Ok(packet)
}

/// A block address and the 16 bytes to replace at that address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockWrite {
    /// Block number within the selected service.
    pub block: u16,
    /// Replacement bytes in wire order.
    pub data: [u8; 16],
}

pub(crate) fn write_without_encryption(
    idm: Idm,
    service: u16,
    blocks: &[BlockWrite],
) -> Result<Vec<u8>, CardError> {
    let count = block_count(blocks.len(), MAX_WRITE_BLOCKS)
        .ok_or(CardError::WriteBlockCount(blocks.len()))?;
    let mut packet = block_list(
        0x08,
        idm,
        service,
        count,
        blocks.iter().map(|entry| entry.block),
    );
    for entry in blocks {
        packet.extend_from_slice(&entry.data);
    }
    set_length(&mut packet)?;
    Ok(packet)
}

/// The packet's block-count byte for 1 to `maximum` blocks.
fn block_count(blocks: usize, maximum: usize) -> Option<u8> {
    u8::try_from(blocks)
        .ok()
        .filter(|count| (1..=maximum).contains(&usize::from(*count)))
}

fn block_list(
    command: u8,
    idm: Idm,
    service: u16,
    count: u8,
    blocks: impl Iterator<Item = u16>,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(14 + usize::from(count) * 3);
    packet.extend_from_slice(&[0, command]);
    packet.extend_from_slice(idm.as_bytes());
    packet.push(1);
    packet.extend_from_slice(&service.to_le_bytes());
    packet.push(count);
    for block in blocks {
        let [low, high] = block.to_le_bytes();
        if high == 0 {
            packet.extend_from_slice(&[0x80, low]);
        } else {
            packet.extend_from_slice(&[0, low, high]);
        }
    }
    packet
}

fn set_length(packet: &mut [u8]) -> Result<(), CardError> {
    packet[0] = u8::try_from(packet.len()).map_err(|_| CardError::Length {
        expected: 255,
        actual: packet.len(),
    })?;
    Ok(())
}

/// A service or area registered at the requested search index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceEntry {
    /// A service code.
    Service(u16),
    /// An area and the inclusive upper end of its code range.
    Area {
        /// Area code.
        code: u16,
        /// Last code in the area.
        end: u16,
    },
}

pub(crate) fn addressed_command(idm: Idm, command: u8, data: &[u8]) -> Result<Vec<u8>, CardError> {
    if data.len() > 245 {
        return Err(CardError::Length {
            expected: 255,
            actual: data.len().saturating_add(10),
        });
    }
    let mut packet = Vec::with_capacity(10 + data.len());
    packet.extend_from_slice(&[0, command]);
    packet.extend_from_slice(idm.as_bytes());
    packet.extend_from_slice(data);
    set_length(&mut packet)?;
    Ok(packet)
}

pub(crate) fn addressed_response(input: &[u8], idm: Idm, code: u8) -> Result<&[u8], CardError> {
    validate_packet(input, code, 10)?;
    let mut actual = [0; 8];
    actual.copy_from_slice(&input[2..10]);
    let actual = Idm::new(actual);
    if actual != idm {
        return Err(CardError::IdentityMismatch {
            expected: idm,
            actual,
        });
    }
    Ok(&input[10..])
}

pub(crate) fn write_response(input: &[u8], idm: Idm) -> Result<(), CardError> {
    let status = addressed_response(input, idm, 0x09)?;
    match status {
        [0, 0] => Ok(()),
        [flag1, flag2] => Err(CardError::Status {
            flag1: *flag1,
            flag2: *flag2,
        }),
        _ => Err(CardError::Length {
            expected: 12,
            actual: input.len(),
        }),
    }
}

pub(crate) fn system_codes(input: &[u8], idm: Idm) -> Result<Vec<u16>, CardError> {
    let body = addressed_response(input, idm, 0x0d)?;
    let count = body.first().copied().unwrap_or(0);
    let expected = 11 + usize::from(count) * 2;
    if input.len() != expected {
        return Err(CardError::Length {
            expected,
            actual: input.len(),
        });
    }
    Ok(body[1..]
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_be_bytes)
        .collect())
}

pub(crate) fn service_entry(input: &[u8], idm: Idm) -> Result<Option<ServiceEntry>, CardError> {
    let body = addressed_response(input, idm, 0x0b)?;
    Ok(match body {
        [0xff, 0xff] => None,
        [a, b] => Some(ServiceEntry::Service(u16::from_le_bytes([*a, *b]))),
        [a, b, c, d] => Some(ServiceEntry::Area {
            code: u16::from_le_bytes([*a, *b]),
            end: u16::from_le_bytes([*c, *d]),
        }),
        _ => {
            return Err(CardError::Length {
                expected: 12,
                actual: input.len(),
            });
        }
    })
}

/// Successful read response whose identities, status and block count are checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadResponse {
    blocks: Vec<[u8; 16]>,
}

impl ReadResponse {
    /// Decode the card response for a particular identity and requested count.
    ///
    /// # Errors
    ///
    /// Returns card status with both flags intact. Rejects another identity,
    /// malformed byte lengths and a block count different from the request.
    pub fn parse(input: &[u8], idm: Idm, expected_blocks: usize) -> Result<Self, CardError> {
        if !(1..=MAX_READ_BLOCKS).contains(&expected_blocks) {
            return Err(CardError::BlockCount(expected_blocks));
        }
        let body = addressed_response(input, idm, 0x07)?;
        match body {
            [0, 0, ..] => {}
            [flag1, flag2, ..] => {
                return Err(CardError::Status {
                    flag1: *flag1,
                    flag2: *flag2,
                });
            }
            _ => {
                return Err(CardError::Length {
                    expected: 12,
                    actual: input.len(),
                });
            }
        }
        let actual_blocks = input.get(12).copied().ok_or(CardError::Length {
            expected: 13,
            actual: input.len(),
        })?;
        let actual_blocks = usize::from(actual_blocks);
        if actual_blocks != expected_blocks {
            return Err(CardError::ResponseBlockCount {
                expected: expected_blocks,
                actual: actual_blocks,
            });
        }
        let length = 13 + actual_blocks * 16;
        if input.len() != length {
            return Err(CardError::Length {
                expected: length,
                actual: input.len(),
            });
        }
        let blocks = input[13..]
            .as_chunks::<16>()
            .0
            .iter()
            .map(|bytes| {
                let mut block = [0; 16];
                block.copy_from_slice(bytes);
                block
            })
            .collect();
        Ok(Self { blocks })
    }

    /// Read blocks in the same order as the request's block list.
    pub fn blocks(&self) -> &[[u8; 16]] {
        &self.blocks
    }
}

fn validate_length(input: &[u8], minimum: usize) -> Result<(), CardError> {
    if input.len() < minimum {
        return Err(CardError::Length {
            expected: minimum,
            actual: input.len(),
        });
    }
    let declared = usize::from(input[0]);
    if declared != input.len() {
        return Err(CardError::Length {
            expected: declared,
            actual: input.len(),
        });
    }
    Ok(())
}

fn validate_packet(input: &[u8], command: u8, minimum: usize) -> Result<(), CardError> {
    validate_length(input, minimum)?;
    if input[1] != command {
        return Err(CardError::ResponseCode {
            expected: command,
            actual: input[1],
        });
    }
    Ok(())
}

/// A FeliCa command failure, split at the transfer of the command packet.
#[derive(Debug)]
pub enum Error<E> {
    /// Request validation failed before the command was sent.
    Request(CardError),
    /// The reader command carrying the packet failed; its transaction
    /// progress tells whether the packet was sent.
    Reader(reader::Error<E>),
    /// The command was sent but the card reply reported an error or failed
    /// validation. The command may have taken effect.
    Response(CardError),
}

impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Request(_) => "FeliCa request rejected before sending",
            Self::Reader(_) => "FeliCa reader command failed",
            Self::Response(_) => "FeliCa response failed; the command may have taken effect",
        })
    }
}

impl<E: core::error::Error + 'static> core::error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Request(error) | Self::Response(error) => Some(error),
            Self::Reader(error) => Some(error),
        }
    }
}

impl<E> From<reader::Error<E>> for Error<E> {
    fn from(error: reader::Error<E>) -> Self {
        Self::Reader(error)
    }
}

/// Typed command access to a FeliCa card selected by polling. Every command
/// addresses the polled IDm and leaves no state that a new Polling does not
/// clear.
#[derive(Debug)]
pub struct Card<'a, T: Transport> {
    selection: FelicaCard<'a, T>,
}

impl<'a, T: Transport> Card<'a, T> {
    /// Take typed command authority over a polled card.
    pub fn new(selection: FelicaCard<'a, T>) -> Self {
        Self { selection }
    }

    /// The reader selection, including its polling response and rate.
    pub fn selection(&self) -> &FelicaCard<'a, T> {
        &self.selection
    }

    fn idm(&self) -> Idm {
        self.selection.observation().idm
    }

    /// Read up to twelve blocks from one unencrypted service. The caller chooses
    /// a service known to exist on this card; no card data is written.
    pub fn read_without_encryption(
        &mut self,
        service: u16,
        blocks: &[u16],
    ) -> Result<ReadResponse, Error<T::Error>> {
        let idm = self.idm();
        let request = read_without_encryption(idm, service, blocks).map_err(Error::Request)?;
        let response = self.selection.exchange_packet(&request)?;
        ReadResponse::parse(&response, idm, blocks.len()).map_err(Error::Response)
    }

    /// Write blocks to one service with Write Without Encryption. Card-specific
    /// limits still apply. [`Error::Request`] means validation stopped the
    /// command before sending. [`Error::Response`] means it was sent and the
    /// write outcome may be uncertain. Reader failures carry their own
    /// transaction progress.
    pub fn write_without_encryption(
        &mut self,
        service: u16,
        blocks: &[BlockWrite],
    ) -> Result<(), Error<T::Error>> {
        let idm = self.idm();
        let request = write_without_encryption(idm, service, blocks).map_err(Error::Request)?;
        let response = self.selection.exchange_packet(&request)?;
        write_response(&response, idm).map_err(Error::Response)
    }

    /// Confirm that the selected card still answers at its IDm, using Request
    /// Response. Returns the card's current mode byte; the command changes no
    /// card state. An absent card surfaces as a reader RF timeout, a different
    /// card as [`Error::Response`].
    pub fn request_response(&mut self) -> Result<u8, Error<T::Error>> {
        match self.exchange_command(0x04, &[], 0x05)?.as_slice() {
            [mode] => Ok(*mode),
            payload => Err(Error::Response(CardError::Length {
                expected: 11,
                actual: payload.len() + 10,
            })),
        }
    }

    /// Request the system codes exposed by this card. Card products can omit this command.
    pub fn request_system_codes(&mut self) -> Result<Vec<u16>, Error<T::Error>> {
        let idm = self.idm();
        let response = self.exchange_addressed(0x0c, &[])?;
        system_codes(&response, idm).map_err(Error::Response)
    }

    /// Look up one service or area index within the selected system.
    /// The end-of-list marker returns `None`; an RF failure remains an error.
    pub fn search_service_code(
        &mut self,
        index: u16,
    ) -> Result<Option<ServiceEntry>, Error<T::Error>> {
        let idm = self.idm();
        let response = self.exchange_addressed(0x0a, &index.to_le_bytes())?;
        service_entry(&response, idm).map_err(Error::Response)
    }

    /// Send a crate-owned FeliCa command with the selected IDm. `parameters`
    /// starts after IDm. Returns the payload after checking the length, response
    /// code and IDm. A command that changes card state outside the typed
    /// operations must first require a field cycle, as authentication does.
    pub(crate) fn exchange_command(
        &mut self,
        command: u8,
        parameters: &[u8],
        response_code: u8,
    ) -> Result<Vec<u8>, Error<T::Error>> {
        let idm = self.idm();
        let response = self.exchange_addressed(command, parameters)?;
        addressed_response(&response, idm, response_code)
            .map(<[u8]>::to_vec)
            .map_err(Error::Response)
    }

    fn exchange_addressed(&mut self, command: u8, data: &[u8]) -> Result<Vec<u8>, Error<T::Error>> {
        let request = addressed_command(self.idm(), command, data).map_err(Error::Request)?;
        Ok(self.selection.exchange_packet(&request)?)
    }

    /// Authentication changes card state that a new Polling does not clear.
    #[cfg(any(feature = "felica-lite-s", feature = "felica-standard-aes"))]
    pub(crate) fn begin_authentication(&mut self) {
        self.selection.require_field_cycle();
    }

    /// Consume typed command authority to send opaque packets at the card's
    /// polling rate. Packets can affect addressing or card state, so the
    /// polled identity is no longer an authority, and the next selection
    /// cycles the RF field first.
    pub fn into_raw(mut self) -> FelicaCard<'a, T> {
        self.selection.require_field_cycle();
        self.selection
    }

    /// Consume typed command authority for a host-run packet stream.
    pub(crate) fn into_selection(self) -> FelicaCard<'a, T> {
        self.selection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn service_and_large_block_byte_order() -> Result<(), CardError> {
        let idm = Idm::new([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            read_without_encryption(idm, 0x000b, &[0, 255, 256])?,
            [
                21, 6, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0x0b, 0, 3, 0x80, 0, 0x80, 0xff, 0, 0, 1
            ]
        );
        assert!(matches!(
            read_without_encryption(idm, 0x000b, &[]),
            Err(CardError::BlockCount(0))
        ));
        assert!(matches!(
            read_without_encryption(idm, 0x000b, &[0; 13]),
            Err(CardError::BlockCount(13))
        ));
        Ok(())
    }

    #[test]
    fn read_response_validates_identity_status_count_and_bytes() -> Result<(), CardError> {
        let idm = Idm::new([1, 2, 3, 4, 5, 6, 7, 8]);
        let mut response = vec![29, 7, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 1];
        response.extend_from_slice(&[0xab; 16]);
        assert_eq!(
            ReadResponse::parse(&response, idm, 1)?.blocks(),
            &[[0xab; 16]]
        );
        assert!(matches!(
            ReadResponse::parse(&response, idm, 2),
            Err(CardError::ResponseBlockCount {
                expected: 2,
                actual: 1
            })
        ));
        response[2] = 0;
        assert!(matches!(
            ReadResponse::parse(&response, idm, 1),
            Err(CardError::IdentityMismatch { .. })
        ));
        let failure = [12, 7, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0xa2];
        assert_eq!(
            ReadResponse::parse(&failure, idm, 1),
            Err(CardError::Status {
                flag1: 1,
                flag2: 0xa2
            })
        );
        response[2] = 1;
        response.pop();
        response[0] = 28;
        assert!(matches!(
            ReadResponse::parse(&response, idm, 1),
            Err(CardError::Length {
                expected: 29,
                actual: 28
            })
        ));
        Ok(())
    }
}
