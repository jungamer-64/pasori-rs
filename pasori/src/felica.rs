//! FeliCa card commands over a card selected by a reader's polling.
//!
//! Service and block numbers are encoded little-endian.

use alloc::vec::Vec;
use core::fmt;
use felica_packet::{Idm, Selection};

mod discovery;
pub use discovery::{KeyVersion, SpecificationVersion, V2KeyVersions, ValueLimitedPurseProperty};

#[cfg(feature = "felica-lite-s")]
pub mod lite_s;
#[cfg(feature = "felica-standard-aes")]
pub mod standard_aes;
#[cfg(feature = "felica-standard-des")]
pub mod standard_des;
#[cfg(any(feature = "felica-standard-aes", feature = "felica-standard-des"))]
mod standard_session;
#[cfg(any(feature = "felica-standard-aes", feature = "felica-standard-des"))]
pub use standard_session::{IssueInformation, StandardError, StandardSession};

/// Maximum blocks in one supported Read Without Encryption command.
pub const MAX_READ_BLOCKS: usize = 12;

/// Maximum write blocks that fit a single-service packet with short addresses.
pub const MAX_WRITE_BLOCKS: usize = 13;

/// Card packet validation or a card-reported nonzero status.
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
    /// The read block count is outside the command's supported range.
    BlockCount(usize),
    /// Write block count is outside `1..=13`.
    WriteBlockCount(usize),
    /// A service or node list is outside the command's supported count range.
    CodeCount {
        /// Maximum number of codes in the list.
        maximum: usize,
        /// Number of supplied codes.
        actual: usize,
    },
    /// A block's service index cannot address an entry in the command's list.
    ServiceIndex(u8),
    /// A request or its successful reply exceeds the selected reader's limit.
    PacketBudget {
        /// Maximum bytes the exchange can carry in either direction.
        maximum: usize,
        /// Required bytes, including the FeliCa length byte.
        required: usize,
    },
    /// A successful reply's item count differs from the request.
    ResponseCount {
        /// Requested item count.
        expected: usize,
        /// Item count declared in the reply.
        actual: usize,
    },
    /// Request Service v2 returned an unrecognized cryptographic identifier.
    CryptoIdentifier(u8),
    /// Request Specification Version returned an unsupported reply format.
    SpecificationFormat(u8),
    /// An enabled/disabled MAC communication flag had a different value.
    MacProperty(u8),
    /// The value-limited purse enable flag was neither `0x00` nor `0x01`.
    PursePropertyFlag(u8),
    /// A disabled value-limited purse did not return all `0xff` in its remaining fields.
    PursePropertyDisabledFields,
    /// A response belongs to a different selected identity.
    IdentityMismatch {
        /// Identity selected by the caller.
        expected: Idm,
        /// Identity received from the card.
        actual: Idm,
    },
    /// A nonzero card status; both flags are preserved. A write status with
    /// flag 2 set to `0x71` reports a write performed with a memory wear warning.
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
                write!(f, "unsupported read block count {count}")
            }
            Self::WriteBlockCount(count) => {
                write!(
                    f,
                    "write block count {count} is outside 1..={MAX_WRITE_BLOCKS}"
                )
            }
            Self::CodeCount { maximum, actual } => {
                write!(f, "code count {actual} is outside 1..={maximum}")
            }
            Self::ServiceIndex(index) => write!(f, "invalid service index {index}"),
            Self::PacketBudget { maximum, required } => {
                write!(
                    f,
                    "packet needs {required} bytes but the limit is {maximum}"
                )
            }
            Self::ResponseCount { expected, actual } => {
                write!(f, "response declares {actual} entries, expected {expected}")
            }
            Self::CryptoIdentifier(value) => write!(f, "unknown crypto identifier {value:02X}"),
            Self::SpecificationFormat(value) => {
                write!(f, "unsupported specification response format {value:02X}")
            }
            Self::MacProperty(value) => write!(f, "invalid MAC property {value:02X}"),
            Self::PursePropertyFlag(value) => write!(f, "invalid purse property flag {value:02X}"),
            Self::PursePropertyDisabledFields => {
                f.write_str("disabled purse property fields are not all FF")
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

/// A block in the command or session's ordered service list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockAddress {
    service_index: u8,
    number: u16,
}

impl BlockAddress {
    /// Specify a block by its service's zero-based index and its block number.
    ///
    /// # Errors
    ///
    /// Returns [`CardError::ServiceIndex`] for an index above 15. An exchange
    /// also checks that the index exists in its service list.
    pub const fn new(service_index: u8, number: u16) -> Result<Self, CardError> {
        if service_index > 15 {
            return Err(CardError::ServiceIndex(service_index));
        }
        Ok(Self {
            service_index,
            number,
        })
    }

    /// Address a block in the first service.
    pub const fn first(number: u16) -> Self {
        Self {
            service_index: 0,
            number,
        }
    }
}

/// One operation in a FeliCa block write.
///
/// For purse adjustments, the caller selects the corresponding service and
/// supplies the execution ID. The card can acknowledge an adjustment without
/// updating the block when its stored execution ID equals the supplied one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockWrite {
    /// Send a block of data in card byte order with the ordinary access mode.
    Data {
        /// Block to update.
        address: BlockAddress,
        /// Block data in card byte order.
        data: [u8; 16],
    },
    /// Debit a service whose attributes permit purse decrement.
    PurseDecrement {
        /// Block to update.
        address: BlockAddress,
        /// Amount to debit.
        amount: u32,
        /// Execution ID in card byte order.
        execution_id: [u8; 2],
    },
    /// Credit a service whose attributes permit purse cashback, up to the
    /// cashback amount stored on the card.
    PurseCashback {
        /// Block to update.
        address: BlockAddress,
        /// Amount to credit.
        amount: u32,
        /// Execution ID in card byte order.
        execution_id: [u8; 2],
    },
}

impl BlockWrite {
    fn list_element(self) -> (BlockAddress, AccessMode) {
        match self {
            Self::Data { address, .. } | Self::PurseDecrement { address, .. } => {
                (address, AccessMode::Ordinary)
            }
            Self::PurseCashback { address, .. } => (address, AccessMode::Cashback),
        }
    }

    fn payload(self) -> [u8; 16] {
        match self {
            Self::Data { data, .. } => data,
            Self::PurseDecrement {
                amount,
                execution_id,
                ..
            }
            | Self::PurseCashback {
                amount,
                execution_id,
                ..
            } => {
                // Both operations put the amount at D0–D3 and execution ID at D14–D15.
                let mut data = [0; 16];
                data[..4].copy_from_slice(&amount.to_le_bytes());
                data[14..].copy_from_slice(&execution_id);
                data
            }
        }
    }
}

#[derive(Clone, Copy)]
enum AccessMode {
    Ordinary = 0x00,
    Cashback = 0x10,
}

fn code_count(actual: usize, maximum: u8) -> Result<u8, CardError> {
    u8::try_from(actual)
        .ok()
        .filter(|count| (1..=maximum).contains(count))
        .ok_or(CardError::CodeCount {
            maximum: usize::from(maximum),
            actual,
        })
}

fn append_codes(data: &mut Vec<u8>, codes: &[u16], maximum: u8) -> Result<(), CardError> {
    data.push(code_count(codes.len(), maximum)?);
    data.extend(codes.iter().flat_map(|code| code.to_le_bytes()));
    Ok(())
}

fn append_block_list(
    data: &mut Vec<u8>,
    service_count: usize,
    blocks: impl ExactSizeIterator<Item = (BlockAddress, AccessMode)>,
) -> Result<(), CardError> {
    data.push(u8::try_from(blocks.len()).map_err(|_| CardError::BlockCount(blocks.len()))?);
    for (block, mode) in blocks {
        if usize::from(block.service_index) >= service_count {
            return Err(CardError::ServiceIndex(block.service_index));
        }
        let flags = mode as u8 | block.service_index;
        let [low, high] = block.number.to_le_bytes();
        if high == 0 {
            data.extend([0x80 | flags, low]);
        } else {
            data.extend([flags, low, high]);
        }
    }
    Ok(())
}

fn append_read_blocks(
    data: &mut Vec<u8>,
    service_count: usize,
    blocks: &[BlockAddress],
) -> Result<(), CardError> {
    append_block_list(
        data,
        service_count,
        blocks
            .iter()
            .map(|&address| (address, AccessMode::Ordinary)),
    )
}

fn append_write_blocks(
    data: &mut Vec<u8>,
    service_count: usize,
    blocks: &[BlockWrite],
) -> Result<(), CardError> {
    if !(1..=MAX_WRITE_BLOCKS).contains(&blocks.len()) {
        return Err(CardError::WriteBlockCount(blocks.len()));
    }
    append_block_list(
        data,
        service_count,
        blocks.iter().copied().map(BlockWrite::list_element),
    )?;
    for block in blocks {
        data.extend(block.payload());
    }
    Ok(())
}

fn admit_packet(selection: &impl Selection, required: usize) -> Result<(), CardError> {
    let maximum = selection.max_packet_len().min(usize::from(u8::MAX));
    if required > maximum {
        return Err(CardError::PacketBudget { maximum, required });
    }
    Ok(())
}

fn unencrypted_read_parameters(
    services: &[u16],
    blocks: &[BlockAddress],
) -> Result<Vec<u8>, CardError> {
    if !(1..=MAX_READ_BLOCKS).contains(&blocks.len()) {
        return Err(CardError::BlockCount(blocks.len()));
    }
    let mut data = Vec::new();
    append_codes(&mut data, services, 16)?;
    append_read_blocks(&mut data, services.len(), blocks)?;
    Ok(data)
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
    /// The reader exchange carrying the packet failed; the reader's error
    /// tells whether the packet was sent.
    Reader(E),
    /// The command was sent but the card reply reported an error or failed
    /// validation. The command may have taken effect.
    Response(CardError),
}

impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Request(_) => "FeliCa request rejected before sending",
            Self::Reader(_) => "FeliCa reader exchange failed",
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

/// Typed command access to a FeliCa card selected by polling. Every command
/// addresses the polled IDm and leaves no state that a new Polling does not
/// clear.
#[derive(Debug)]
pub struct Card<S: Selection> {
    selection: S,
}

impl<S: Selection> Card<S> {
    /// Take typed command authority over a polled card.
    pub fn new(selection: S) -> Self {
        Self { selection }
    }

    /// The reader selection, including its polling response.
    pub fn selection(&self) -> &S {
        &self.selection
    }

    fn idm(&self) -> Idm {
        self.selection.poll_response().idm
    }

    /// Read up to twelve blocks from up to sixteen unencrypted services.
    /// Blocks are returned in request order. Card-specific limits also apply.
    pub fn read_without_encryption(
        &mut self,
        services: &[u16],
        blocks: &[BlockAddress],
    ) -> Result<ReadResponse, Error<S::Error>> {
        let data = unencrypted_read_parameters(services, blocks).map_err(Error::Request)?;
        admit_packet(&self.selection, 13 + blocks.len() * 16).map_err(Error::Request)?;
        let response = self.exchange_addressed(0x06, &data)?;
        ReadResponse::parse(&response, self.idm(), blocks.len()).map_err(Error::Response)
    }

    /// Write blocks in one command to up to sixteen unencrypted services.
    /// Card-specific limits also apply. After sending, a lost or invalid response
    /// can leave the write applied. The reader error carries transfer progress.
    /// Reconcile with the card before attempting a new purse adjustment.
    pub fn write_without_encryption(
        &mut self,
        services: &[u16],
        blocks: &[BlockWrite],
    ) -> Result<(), Error<S::Error>> {
        let mut data = Vec::new();
        append_codes(&mut data, services, 16).map_err(Error::Request)?;
        append_write_blocks(&mut data, services.len(), blocks).map_err(Error::Request)?;
        let reply = self.exchange_addressed(0x08, &data)?;
        write_response(&reply, self.idm()).map_err(Error::Response)
    }

    /// Confirm that the selected card still answers at its IDm, using Request
    /// Response. Returns the card's current mode byte; the command changes no
    /// card state. An absent card surfaces as the reader's failure to receive
    /// a reply, a different card as [`Error::Response`].
    pub fn request_response(&mut self) -> Result<u8, Error<S::Error>> {
        match self.exchange_command(0x04, &[], 0x05)?.as_slice() {
            [mode] => Ok(*mode),
            payload => Err(Error::Response(CardError::Length {
                expected: 11,
                actual: payload.len() + 10,
            })),
        }
    }

    /// Request the system codes exposed by this card. Card products can omit this command.
    pub fn request_system_codes(&mut self) -> Result<Vec<u16>, Error<S::Error>> {
        let idm = self.idm();
        let response = self.exchange_addressed(0x0c, &[])?;
        system_codes(&response, idm).map_err(Error::Response)
    }

    /// Look up one service or area index within the selected system.
    /// The end-of-list marker returns `None`; an RF failure remains an error.
    pub fn search_service_code(
        &mut self,
        index: u16,
    ) -> Result<Option<ServiceEntry>, Error<S::Error>> {
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
    ) -> Result<Vec<u8>, Error<S::Error>> {
        let idm = self.idm();
        let response = self.exchange_addressed(command, parameters)?;
        addressed_response(&response, idm, response_code)
            .map(<[u8]>::to_vec)
            .map_err(Error::Response)
    }

    fn exchange_addressed(&mut self, command: u8, data: &[u8]) -> Result<Vec<u8>, Error<S::Error>> {
        admit_packet(&self.selection, 10 + data.len()).map_err(Error::Request)?;
        let request = addressed_command(self.idm(), command, data).map_err(Error::Request)?;
        self.exchange_packet(&request)
    }

    fn exchange_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error<S::Error>> {
        self.selection
            .exchange_packet(packet)
            .map_err(Error::Reader)
    }

    /// Authentication changes card state that a new Polling does not clear.
    #[cfg(any(
        feature = "felica-lite-s",
        feature = "felica-standard-aes",
        feature = "felica-standard-des"
    ))]
    pub(crate) fn begin_authentication(&mut self) {
        self.selection.require_field_cycle();
    }

    /// Consume typed command authority to send opaque packets. Packets can
    /// affect addressing or card state, so the polled identity is no longer
    /// an authority, and the next selection cycles the RF field first.
    pub fn into_raw(mut self) -> S {
        self.selection.require_field_cycle();
        self.selection
    }

    /// Consume typed command authority for a host-run packet stream.
    pub(crate) fn into_selection(self) -> S {
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
        let services = [0x000b, 0x1234];
        let blocks = [
            BlockAddress::first(0),
            BlockAddress::new(1, 255)?,
            BlockAddress::new(1, 256)?,
        ];
        assert_eq!(
            addressed_command(idm, 0x06, &unencrypted_read_parameters(&services, &blocks)?)?,
            [
                23, 6, 1, 2, 3, 4, 5, 6, 7, 8, 2, 0x0b, 0, 0x34, 0x12, 3, 0x80, 0, 0x81, 0xff, 1,
                0, 1
            ]
        );
        assert!(matches!(
            unencrypted_read_parameters(&services, &[]),
            Err(CardError::BlockCount(0))
        ));
        assert!(matches!(
            unencrypted_read_parameters(&services, &[BlockAddress::first(0); 13]),
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
