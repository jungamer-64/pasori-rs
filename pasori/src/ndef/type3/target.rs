//! An NDEF mapping carried by a Port-100 FeliCa target.

mod memory;

pub use memory::{Type3NdefChange, Type3NdefMemory, Type3NdefMemoryError};

use super::{Attribute, BLOCK_BYTES, READ_SERVICE, SYSTEM, WRITE_SERVICE, checksum};
use crate::ndef::{Message, MessageError};
use alloc::vec::Vec;
use core::fmt;
use felica_packet::Idm;
use iso14443::nfca::TargetEvent;
use memory::{Refused, WrittenBlock};
use port100::{
    reader::{self, FelicaTarget, PollingResponder, TargetWait},
    transport::Transport,
};

const READ_LIMIT: u8 = 12;
// Twelve blocks with three-byte block list elements still fit the FeliCa
// length field.
const WRITE_LIMIT: u8 = 12;
const MAX_SERVICES: u8 = 16;

const READ: u8 = 0x06;
const WRITE: u8 = 0x08;

// Status Flag 2 values for a request the emulated tag does not perform.
const SERVICE_COUNT: u8 = 0xa1;
const BLOCK_COUNT: u8 = 0xa2;
const SERVICE_ORDER: u8 = 0xa3;
const REFUSED: u8 = 0xa5;
const NO_SERVICE: u8 = 0xa6;
const ACCESS_MODE: u8 = 0xa7;
const BLOCK_NUMBER: u8 = 0xa8;

/// Maximum message length of an emulated Type 3 mapping.
pub const MAX_TYPE3_EMULATED_NDEF_BYTES: usize = u16::MAX as usize * BLOCK_BYTES;

/// Failure preparing or operating a Type 3 target.
#[derive(Debug)]
pub enum Type3EmulationError<E> {
    /// The proposed bytes exceed the mapping's capacity.
    MessageLength(usize),
    /// The bytes do not encode a complete NDEF message.
    Message(MessageError),
    /// Target setup, reception or response failed at the reader.
    Reader(reader::Error<E>),
    /// The change was applied to the emulated memory before the response
    /// was sent. The initiator may not have received the response. The
    /// reader's error defines whether the target can continue.
    NdefResponse {
        /// The change already applied to the published NDEF.
        change: Type3NdefChange,
        /// The reader's response failure.
        cause: reader::Error<E>,
    },
}

impl<E: fmt::Debug> fmt::Display for Type3EmulationError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageLength(length) => write!(
                f,
                "NDEF message of {length} bytes exceeds {MAX_TYPE3_EMULATED_NDEF_BYTES}"
            ),
            Self::Message(error) => write!(f, "invalid NDEF message: {error}"),
            Self::Reader(error) => write!(f, "Type 3 target: {error}"),
            Self::NdefResponse { change, cause } => write!(
                f,
                "Type 3 response failed after NDEF change {change:?}: {cause}"
            ),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for Type3EmulationError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::MessageLength(_) => None,
            Self::Message(error) => Some(error),
            Self::Reader(error) | Self::NdefResponse { cause: error, .. } => Some(error),
        }
    }
}

/// The disposition of one packet received by a Type 3 target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type3Event {
    /// Sent the requested blocks, in the requested order.
    Read,
    /// Stored the written blocks without changing the published NDEF.
    Written,
    /// Stored the written blocks, changed the published NDEF and sent the
    /// response.
    NdefChanged(Type3NdefChange),
    /// Answered with a nonzero card status and left the memory unchanged.
    /// Status Flag 1 is `FF` for a failure that no list entry causes, or
    /// the one-based position of the failing service code list or block
    /// list entry.
    Rejected {
        /// Status Flag 1.
        flag1: u8,
        /// Status Flag 2.
        flag2: u8,
    },
    /// A packet for another IDm, another command or a malformed packet was
    /// left unanswered.
    Ignored,
    /// No packet arrived within the wait.
    Silence,
    /// The initiator's field went off. The next call awaits a new activation.
    FieldOff,
}

/// Passive Type 3 target on Port-100. The reader answers the activation
/// Polling as configured. The host serves Read Without Encryption through
/// service `000B` and, for a writable memory, Read and Write Without
/// Encryption through service `0009`.
#[derive(Debug)]
pub struct Type3Target<'r, 'm, T: Transport> {
    target: FelicaTarget<'r, T>,
    idm: Idm,
    memory: Memory<'m>,
}

impl<'r, 'm, T: Transport> Type3Target<'r, 'm, T> {
    /// Configure a read-only Type 3 target with the supplied identity and PMm,
    /// activated as `activation` selects. The message is validated before
    /// configuring the reader. An empty message exposes an empty mapping.
    pub fn listen(
        reader: &'r mut reader::Reader<T>,
        activation: PollingResponder,
        idm: Idm,
        pmm: [u8; 8],
        message: &'m [u8],
    ) -> Result<Self, Type3EmulationError<T::Error>> {
        let blocks = u16::try_from(message.len().div_ceil(BLOCK_BYTES).max(1))
            .map_err(|_| Type3EmulationError::MessageLength(message.len()))?;
        let length = Attribute::encode_length(message.len())
            .ok_or(Type3EmulationError::MessageLength(message.len()))?;
        if !message.is_empty() {
            Message::parse(message).map_err(Type3EmulationError::Message)?;
        }
        let memory = Memory::ReadOnly {
            attribute: attribute(Access::ReadOnly, blocks, WriteFlag::Published, length),
            blocks,
            message,
        };
        Self::start(reader, activation, idm, pmm, memory)
    }

    /// Configure a writable Type 3 target with the supplied identity and PMm,
    /// activated as `activation` selects. Any initiator that addresses this
    /// IDm can update the memory. The caller retains the memory, including
    /// an unfinished update, after the target releases its borrow.
    pub fn listen_writable(
        reader: &'r mut reader::Reader<T>,
        activation: PollingResponder,
        idm: Idm,
        pmm: [u8; 8],
        memory: &'m mut Type3NdefMemory,
    ) -> Result<Self, Type3EmulationError<T::Error>> {
        Self::start(reader, activation, idm, pmm, Memory::Writable(memory))
    }

    fn start(
        reader: &'r mut reader::Reader<T>,
        activation: PollingResponder,
        idm: Idm,
        pmm: [u8; 8],
        memory: Memory<'m>,
    ) -> Result<Self, Type3EmulationError<T::Error>> {
        let target = reader
            .listen_felica(activation, idm, pmm, SYSTEM)
            .map_err(Type3EmulationError::Reader)?;
        Ok(Self {
            target,
            idm,
            memory,
        })
    }

    /// Borrow the published NDEF bytes, including after a response failure.
    /// An empty slice is an empty mapping. `None` means an update is in
    /// progress.
    pub fn message(&self) -> Option<&[u8]> {
        self.memory.message()
    }

    /// Receive one packet and serve a Read or Write Without Encryption
    /// request addressed to this tag's IDm.
    pub fn serve_next(
        &mut self,
        wait: TargetWait,
    ) -> Result<Type3Event, Type3EmulationError<T::Error>> {
        let command = match self
            .target
            .receive(wait)
            .map_err(Type3EmulationError::Reader)?
        {
            TargetEvent::Command(command) => command,
            TargetEvent::Silence => return Ok(Type3Event::Silence),
            TargetEvent::FieldOff => return Ok(Type3Event::FieldOff),
        };
        let Some((reply, event)) = serve(self.idm, &mut self.memory, command.data()) else {
            return Ok(Type3Event::Ignored);
        };
        command.respond(&reply).map_err(|cause| match event {
            Type3Event::NdefChanged(change) => Type3EmulationError::NdefResponse { change, cause },
            _ => Type3EmulationError::Reader(cause),
        })?;
        Ok(event)
    }

    /// Stop target operation and reinitialize the reader.
    pub fn finish(self) -> Result<(), reader::Error<T::Error>> {
        self.target.finish()
    }
}

#[derive(Debug)]
enum Memory<'m> {
    ReadOnly {
        attribute: [u8; BLOCK_BYTES],
        blocks: u16,
        message: &'m [u8],
    },
    Writable(&'m mut Type3NdefMemory),
}

impl Memory<'_> {
    fn message(&self) -> Option<&[u8]> {
        match self {
            Self::ReadOnly { message, .. } => Some(message),
            Self::Writable(memory) => memory.message(),
        }
    }

    fn data_blocks(&self) -> u16 {
        match self {
            Self::ReadOnly { blocks, .. } => *blocks,
            Self::Writable(memory) => memory.data_blocks(),
        }
    }

    fn admits(&self, command: u8, service: u16) -> bool {
        match (command, service) {
            (READ, READ_SERVICE) => true,
            (READ | WRITE, WRITE_SERVICE) => matches!(self, Self::Writable(_)),
            _ => false,
        }
    }

    /// Block 0 is the attribute. Data blocks are numbered from 1.
    fn block(&self, number: u16) -> [u8; BLOCK_BYTES] {
        match self {
            Self::ReadOnly {
                attribute, message, ..
            } => {
                let Some(data) = number.checked_sub(1) else {
                    return *attribute;
                };
                let mut block = [0; BLOCK_BYTES];
                let start = usize::from(data) * BLOCK_BYTES;
                if let Some(bytes) = message.get(start..) {
                    let length = bytes.len().min(BLOCK_BYTES);
                    block[..length].copy_from_slice(&bytes[..length]);
                }
                block
            }
            Self::Writable(memory) => memory.block(number),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Access {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteFlag {
    Published,
    Updating,
}

impl WriteFlag {
    const fn byte(self) -> u8 {
        match self {
            Self::Published => 0,
            Self::Updating => 0x0f,
        }
    }

    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Published),
            0x0f => Some(Self::Updating),
            _ => None,
        }
    }
}

/// The Attribute Information Block of an emulated mapping with `blocks`
/// data blocks and the 24-bit big-endian message length `length`.
fn attribute(access: Access, blocks: u16, flag: WriteFlag, length: [u8; 3]) -> [u8; BLOCK_BYTES] {
    let (write_limit, access) = match access {
        Access::ReadOnly => (0, 0),
        Access::ReadWrite => (WRITE_LIMIT, 1),
    };
    let [blocks_high, blocks_low] = blocks.to_be_bytes();
    let [length_high, length_middle, length_low] = length;
    let mut block = [
        0x10,
        READ_LIMIT,
        write_limit,
        blocks_high,
        blocks_low,
        0,
        0,
        0,
        0,
        flag.byte(),
        access,
        length_high,
        length_middle,
        length_low,
        0,
        0,
    ];
    let checksum = checksum(&block);
    block[14..].copy_from_slice(&checksum.to_be_bytes());
    block
}

/// Card status sent in place of the requested access.
#[derive(Debug, Clone, Copy)]
struct Status {
    flag1: u8,
    flag2: u8,
}

impl Status {
    const fn general(flag2: u8) -> Self {
        Self { flag1: 0xff, flag2 }
    }

    /// Failure at a one-based list position, which fits a byte because
    /// both lists are limited to 16 entries.
    const fn at(position: u8, flag2: u8) -> Self {
        Self {
            flag1: position,
            flag2,
        }
    }
}

/// A block list element addressing an NDEF block.
#[derive(Debug, Clone, Copy)]
struct Element {
    position: u8,
    block: u16,
}

/// The reply and its disposition, or `None` to leave the packet unanswered.
fn serve(idm: Idm, memory: &mut Memory<'_>, packet: &[u8]) -> Option<(Vec<u8>, Type3Event)> {
    let (&[length, command], body) = packet.split_first_chunk::<2>()?;
    let (identity, body) = body.split_first_chunk::<8>()?;
    if usize::from(length) != packet.len()
        || !matches!(command, READ | WRITE)
        || identity != idm.as_bytes()
    {
        return None;
    }
    let status = match request(memory, command, body)? {
        Ok(Request::Read(elements)) => {
            let mut reply = Vec::with_capacity(13 + elements.len() * BLOCK_BYTES);
            reply.extend([0, command + 1]);
            reply.extend_from_slice(idm.as_bytes());
            reply.extend([0, 0, u8::try_from(elements.len()).ok()?]);
            for element in &elements {
                reply.extend(memory.block(element.block));
            }
            reply[0] = u8::try_from(reply.len()).ok()?;
            return Some((reply, Type3Event::Read));
        }
        Ok(Request::Write(writes)) => {
            let Memory::Writable(memory) = memory else {
                return None;
            };
            match memory.write(&writes) {
                Ok(change) => {
                    let event = change.map_or(Type3Event::Written, Type3Event::NdefChanged);
                    return Some((status_reply(idm, command, 0, 0), event));
                }
                Err(Refused(position)) => Status::at(position, REFUSED),
            }
        }
        Err(status) => status,
    };
    Some((
        status_reply(idm, command, status.flag1, status.flag2),
        Type3Event::Rejected {
            flag1: status.flag1,
            flag2: status.flag2,
        },
    ))
}

fn status_reply(idm: Idm, command: u8, flag1: u8, flag2: u8) -> Vec<u8> {
    let mut reply = Vec::with_capacity(12);
    reply.extend([12, command + 1]);
    reply.extend_from_slice(idm.as_bytes());
    reply.extend([flag1, flag2]);
    reply
}

/// A request accepted for every service and block it names.
enum Request<'p> {
    Read(Vec<Element>),
    Write(Vec<WrittenBlock<'p>>),
}

/// Parse and check the service and block lists that follow the IDm.
/// `None` leaves a malformed packet unanswered.
fn request<'p>(
    memory: &Memory<'_>,
    command: u8,
    body: &'p [u8],
) -> Option<Result<Request<'p>, Status>> {
    let (&services, body) = body.split_first()?;
    if !(1..=MAX_SERVICES).contains(&services) {
        return Some(Err(Status::general(SERVICE_COUNT)));
    }
    let (codes, body) = body.split_at_checked(usize::from(services) * 2)?;
    let (&blocks, mut body) = body.split_first()?;
    let limit = if command == WRITE {
        WRITE_LIMIT
    } else {
        READ_LIMIT
    };
    if !(1..=limit).contains(&blocks) {
        return Some(Err(Status::general(BLOCK_COUNT)));
    }
    let mut list = Vec::with_capacity(usize::from(blocks));
    for position in 1..=blocks {
        let (&head, tail) = body.split_first()?;
        let (number, tail) = if head & 0x80 == 0 {
            let (&number, tail) = tail.split_first_chunk::<2>()?;
            (u16::from_le_bytes(number), tail)
        } else {
            let (&number, tail) = tail.split_first()?;
            (u16::from(number), tail)
        };
        list.push((position, head, number));
        body = tail;
    }
    let (data, []) = body.as_chunks::<BLOCK_BYTES>() else {
        return None;
    };
    let expected_data = if command == WRITE { list.len() } else { 0 };
    if data.len() != expected_data {
        return None;
    }

    let (codes, _) = codes.as_chunks::<2>();
    for (position, &code) in (1..).zip(codes) {
        if !memory.admits(command, u16::from_le_bytes(code)) {
            return Some(Err(Status::at(position, NO_SERVICE)));
        }
    }
    let mut elements = Vec::with_capacity(list.len());
    for (position, head, block) in list {
        let failure = if head & 0x0f >= services {
            SERVICE_ORDER
        } else if head & 0x70 != 0 {
            ACCESS_MODE
        } else if block > memory.data_blocks() {
            BLOCK_NUMBER
        } else {
            elements.push(Element { position, block });
            continue;
        };
        return Some(Err(Status::at(position, failure)));
    }
    Some(Ok(if command == WRITE {
        Request::Write(
            elements
                .into_iter()
                .zip(data)
                .map(|(element, data)| WrittenBlock {
                    position: element.position,
                    block: element.block,
                    data,
                })
                .collect(),
        )
    } else {
        Request::Read(elements)
    }))
}
