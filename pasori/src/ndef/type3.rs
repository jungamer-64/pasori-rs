use super::{Error, Message, MessageError, UpdateStage, WriteError};
use crate::felica::{self, BlockAddress, BlockWrite, Card, MAX_READ_BLOCKS, MAX_WRITE_BLOCKS};
use alloc::vec::Vec;
use core::fmt;
use felica_packet::{Idm, PollRequest, Selection};
use port100::{
    reader::{self, BitRate, FelicaTarget, TargetWait},
    transport::Transport,
};

/// NFC Forum Type 3 system code.
const SYSTEM: u16 = 0x12fc;

/// Polling for the NFC Forum Type 3 system 12FC without request data, which
/// selects the IDm that [`Type3Tag::new`] accepts.
pub const TYPE3_POLLING: PollRequest = match PollRequest::new(SYSTEM, 0, 0) {
    Ok(request) => request,
    Err(_) => panic!("the NDEF polling request is valid"),
};
const READ_SERVICE: u16 = 0x000b;
const WRITE_SERVICE: u16 = 0x0009;
const BLOCK_BYTES: usize = 16;
const READ_LIMIT: u8 = 12;

/// Maximum message length of the read-only Type 3 mapping.
pub const MAX_TYPE3_EMULATED_NDEF_BYTES: usize = u16::MAX as usize * BLOCK_BYTES;

/// Failure preparing or operating a read-only Type 3 target.
#[derive(Debug)]
pub enum Type3EmulationError<E> {
    /// The proposed bytes exceed the mapping's capacity.
    MessageLength(usize),
    /// The bytes do not encode a complete NDEF message.
    Message(MessageError),
    /// Target setup, reception or response failed at the reader.
    Reader(reader::Error<E>),
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
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for Type3EmulationError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::MessageLength(_) => None,
            Self::Message(error) => Some(error),
            Self::Reader(error) => Some(error),
        }
    }
}

/// The disposition of one frame received by a read-only Type 3 target.
#[derive(Debug, PartialEq, Eq)]
pub enum Type3Event {
    /// Sent the requested NDEF blocks, in the requested order.
    Read,
    /// An unsupported command, address or packet was left unanswered.
    Ignored,
}

/// Passive Type 3 target serving a fixed NDEF message on Port-100.
/// The reader answers the activation Polling. The host serves the read-only
/// NDEF service.
#[derive(Debug)]
pub struct Type3Target<'r, 'm, T: Transport> {
    target: FelicaTarget<'r, T>,
    idm: Idm,
    attribute: [u8; BLOCK_BYTES],
    message: &'m [u8],
}

impl<'r, 'm, T: Transport> Type3Target<'r, 'm, T> {
    /// Configure a read-only Type 3 target with the supplied identity and PMm.
    /// The message is validated before configuring the reader. An empty
    /// message exposes an empty mapping.
    pub fn listen(
        reader: &'r mut reader::Reader<T>,
        rate: BitRate,
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
        let mut attribute = [0; BLOCK_BYTES];
        attribute[0] = 0x10;
        attribute[1] = READ_LIMIT;
        attribute[3..5].copy_from_slice(&blocks.to_be_bytes());
        let target = reader
            .listen_felica(rate, idm, pmm, SYSTEM)
            .map_err(Type3EmulationError::Reader)?;
        Ok(Self {
            target,
            idm,
            attribute: Attribute(attribute).published(length),
            message,
        })
    }

    /// Receive one command and serve a valid Read Without Encryption request
    /// addressed to this tag's read-only NDEF service.
    pub fn serve_next(
        &mut self,
        wait: TargetWait,
    ) -> Result<Type3Event, Type3EmulationError<T::Error>> {
        let command = self
            .target
            .receive(wait)
            .map_err(Type3EmulationError::Reader)?;
        let Some(reply) = type3_read_reply(self.idm, &self.attribute, self.message, command.data())
        else {
            return Ok(Type3Event::Ignored);
        };
        command
            .respond(&reply)
            .map_err(Type3EmulationError::Reader)?;
        Ok(Type3Event::Read)
    }

    /// Stop target operation and reinitialize the reader.
    pub fn finish(self) -> Result<(), reader::Error<T::Error>> {
        self.target.finish()
    }
}

fn type3_read_reply(
    idm: Idm,
    attribute: &[u8; BLOCK_BYTES],
    message: &[u8],
    packet: &[u8],
) -> Option<Vec<u8>> {
    let (
        &[
            _,
            0x06,
            a,
            b,
            c,
            d,
            e,
            f,
            g,
            h,
            1,
            service_low,
            service_high,
            count @ 1..=READ_LIMIT,
        ],
        mut blocks,
    ) = packet.split_first_chunk::<14>()?
    else {
        return None;
    };
    if &[a, b, c, d, e, f, g, h] != idm.as_bytes()
        || u16::from_le_bytes([service_low, service_high]) != READ_SERVICE
    {
        return None;
    }
    let length = 13 + usize::from(count) * BLOCK_BYTES;
    let mut reply = Vec::with_capacity(length);
    reply.extend([u8::try_from(length).ok()?, 0x07]);
    reply.extend_from_slice(idm.as_bytes());
    reply.extend([0, 0, count]);
    for _ in 0..count {
        let (block, tail) = match blocks {
            [0x80, low, tail @ ..] => (u16::from(*low), tail),
            [0x00, low, high, tail @ ..] => (u16::from_le_bytes([*low, *high]), tail),
            _ => return None,
        };
        blocks = tail;
        if block == 0 {
            reply.extend_from_slice(attribute);
        } else {
            let start = usize::from(block - 1) * BLOCK_BYTES;
            let available_blocks = u16::from_be_bytes([attribute[3], attribute[4]]);
            if block > available_blocks {
                return None;
            }
            let end = (start + BLOCK_BYTES).min(message.len());
            let bytes = &message[start..end];
            reply.extend_from_slice(bytes);
            reply.resize(reply.len() + BLOCK_BYTES - bytes.len(), 0);
        }
    }
    blocks.is_empty().then_some(reply)
}

/// A selected NFC Forum Type 3 system. Its IDm comes from polling system 12FC.
#[derive(Debug)]
pub struct Type3Tag<S: Selection>(Card<S>);

impl<S: Selection> Type3Tag<S> {
    /// Take a card whose Polling named system 12FC; any other card is
    /// returned unchanged. The NDEF mapping is checked when a message is
    /// accessed.
    pub fn new(card: Card<S>) -> Result<Self, Card<S>> {
        if card.selection().poll_request().system() == SYSTEM {
            Ok(Self(card))
        } else {
            Err(card)
        }
    }

    /// Read the message from an initialized Type 3 mapping. An empty mapping
    /// returns an empty vector. An interrupted update is reported separately.
    pub fn read_ndef(&mut self) -> Result<Vec<u8>, Error<felica::Error<S::Error>>> {
        let attribute = self.attribute()?;
        let length = attribute.length();
        let mut data = Vec::with_capacity(length);
        let mut blocks = BlockRange::for_bytes(length)?;
        let limit = usize::from(attribute.0[1]).min(MAX_READ_BLOCKS);
        while !blocks.is_empty() {
            let batch: Vec<_> = blocks.take(limit).map(BlockAddress::first).collect();
            let response = self
                .0
                .read_without_encryption(&[READ_SERVICE], &batch)
                .map_err(Error::Exchange)?;
            for block in response.blocks() {
                data.extend_from_slice(&block[..(length - data.len()).min(BLOCK_BYTES)]);
            }
        }
        Ok(data)
    }

    /// Replace the message in a writable Type 3 mapping. An empty slice
    /// clears it. The tag's write flag stays set until publication succeeds.
    pub fn write_ndef(
        &mut self,
        message: &[u8],
    ) -> Result<(), WriteError<felica::Error<S::Error>>> {
        let attribute = self.attribute().map_err(WriteError::Preparation)?;
        let capacity = attribute.capacity();
        let limit = usize::from(attribute.0[2]).min(MAX_WRITE_BLOCKS);
        if attribute.0[10] != 1 || limit == 0 {
            return Err(WriteError::Preparation(Error::WriteAccess));
        }
        let capacity_error = || {
            WriteError::Preparation(Error::Capacity {
                requested: message.len(),
                available: capacity,
            })
        };
        if message.len() > capacity {
            return Err(capacity_error());
        }
        let encoded_length = Attribute::encode_length(message.len()).ok_or_else(capacity_error)?;
        let mut blocks = BlockRange::for_bytes(message.len()).map_err(WriteError::Preparation)?;
        self.write_attribute(attribute.update_started())
            .map_err(|cause| WriteError::update(UpdateStage::Begin, 0, cause))?;
        let mut written = 0;
        while !blocks.is_empty() {
            // A long block address uses one extra packet byte. Thirteen
            // long-addressed blocks would exceed the FeliCa length field.
            let count = if blocks
                .next()
                .is_some_and(|next| usize::from(next) + limit <= 256)
            {
                limit
            } else {
                limit.min(12)
            };
            let mut end = written;
            let batch: Vec<_> = blocks
                .take(count)
                .map(|block| {
                    let mut data = [0; BLOCK_BYTES];
                    let len = (message.len() - end).min(BLOCK_BYTES);
                    data[..len].copy_from_slice(&message[end..end + len]);
                    end += len;
                    BlockWrite::Data {
                        address: BlockAddress::first(block),
                        data,
                    }
                })
                .collect();
            self.0
                .write_without_encryption(&[WRITE_SERVICE], &batch)
                .map_err(|error| {
                    WriteError::update(UpdateStage::Data, written, Error::Exchange(error))
                })?;
            written = end;
        }
        self.write_attribute(attribute.published(encoded_length))
            .map_err(|cause| WriteError::update(UpdateStage::Publish, written, cause))
    }

    fn attribute(&mut self) -> Result<Attribute, Error<felica::Error<S::Error>>> {
        let response = self
            .0
            .read_without_encryption(&[READ_SERVICE], &[BlockAddress::first(0)])
            .map_err(Error::Exchange)?;
        let [block] = response.blocks() else {
            return Err(Error::Layout("Type 3 attribute block count"));
        };
        Attribute::parse(*block)
    }

    fn write_attribute(&mut self, data: [u8; 16]) -> Result<(), Error<felica::Error<S::Error>>> {
        self.0
            .write_without_encryption(
                &[WRITE_SERVICE],
                &[BlockWrite::Data {
                    address: BlockAddress::first(0),
                    data,
                }],
            )
            .map_err(Error::Exchange)
    }
}

struct Attribute([u8; 16]);

impl Attribute {
    fn parse<E>(block: [u8; 16]) -> Result<Self, Error<E>> {
        if checksum(&block).to_be_bytes() != block[14..] {
            return Err(Error::Layout("Type 3 attribute checksum"));
        }
        if block[0] >> 4 != 1 {
            return Err(Error::UnsupportedMapping);
        }
        if block[9] == 0x0f {
            return Err(Error::WriteInProgress);
        }
        let attribute = Self(block);
        if block[1] == 0
            || block[5..9] != [0; 4]
            || block[9] != 0
            || block[10] > 1
            || attribute.length() > attribute.capacity()
        {
            return Err(Error::Layout("Type 3 attribute fields"));
        }
        Ok(attribute)
    }

    fn length(&self) -> usize {
        (usize::from(self.0[11]) << 16) | usize::from(u16::from_be_bytes([self.0[12], self.0[13]]))
    }

    fn capacity(&self) -> usize {
        usize::from(u16::from_be_bytes([self.0[3], self.0[4]])) * BLOCK_BYTES
    }

    fn update_started(&self) -> [u8; 16] {
        let mut block = self.0;
        block[9] = 0x0f;
        let checksum = checksum(&block);
        block[14..].copy_from_slice(&checksum.to_be_bytes());
        block
    }

    /// The attribute's 24-bit big-endian length field.
    fn encode_length(length: usize) -> Option<[u8; 3]> {
        match u32::try_from(length).map(u32::to_be_bytes) {
            Ok([0, a, b, c]) => Some([a, b, c]),
            _ => None,
        }
    }

    fn published(self, length: [u8; 3]) -> [u8; 16] {
        let mut block = self.0;
        block[11..14].copy_from_slice(&length);
        let checksum = checksum(&block);
        block[14..].copy_from_slice(&checksum.to_be_bytes());
        block
    }
}

fn checksum(block: &[u8; 16]) -> u16 {
    block[..14].iter().copied().map(u16::from).sum()
}

/// Data blocks 1 through the last block holding the message.
struct BlockRange(core::ops::RangeInclusive<u16>);

impl BlockRange {
    fn for_bytes<E>(length: usize) -> Result<Self, Error<E>> {
        let last = u16::try_from(length.div_ceil(BLOCK_BYTES))
            .map_err(|_| Error::Layout("Type 3 block number"))?;
        Ok(Self(1..=last))
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn next(&self) -> Option<u16> {
        self.0.clone().next()
    }

    fn take(&mut self, limit: usize) -> impl Iterator<Item = u16> {
        self.0.by_ref().take(limit)
    }
}
