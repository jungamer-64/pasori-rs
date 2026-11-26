use super::{Error, UpdateStage, WriteError, control_range};
use crate::type2::Type2Tag;
use alloc::{collections::BTreeMap, vec::Vec};
use core::ops::Range;
use iso14443::nfca::{self, Nibble, Reply};

/// The 4-bit ACK of a Type 2 command.
const ACK: u8 = 0x0a;

impl<C: nfca::Selection> Type2Tag<C> {
    /// Read the NDEF message across the tag's Type 2 memory sectors.
    /// Reserved bytes and dynamic lock bytes are skipped. An empty mapped
    /// message is returned as an empty vector. No write is performed.
    pub fn read_ndef(&mut self) -> Result<Option<Vec<u8>>, Error<C::Error>> {
        let mut tag = Type2Data::open(self)?;
        if !tag.find_message()? {
            return Ok(None);
        }
        let length = tag.tlv_length()?;
        (0..length)
            .map(|_| tag.byte())
            .collect::<Result<_, _>>()
            .map(Some)
    }

    /// Replace the first NDEF TLV in an initialized, publicly writable Type 2
    /// mapping. The Terminator
    /// after the new message supersedes any TLVs that followed the old message.
    /// An empty slice clears the message.
    pub fn write_ndef(&mut self, message: &[u8]) -> Result<(), WriteError<C::Error>> {
        let mut tag = Type2Data::open(self).map_err(WriteError::Preparation)?;
        let write = tag
            .prepare_write(message)
            .map_err(WriteError::Preparation)?;
        tag.write_page(write.length_page, write.unpublished)
            .map_err(|cause| WriteError::update(UpdateStage::Begin, 0, cause))?;
        let mut written = 0;
        for (page, patch) in write.data {
            tag.write_page(page, patch.bytes)
                .map_err(|cause| WriteError::update(UpdateStage::Data, written, cause))?;
            written += patch.message_bytes;
        }
        tag.write_page(write.length_page, write.published)
            .map_err(|cause| WriteError::update(UpdateStage::Publish, written, cause))
    }
}

struct Type2Data<'card, C: nfca::Selection> {
    card: &'card mut Type2Tag<C>,
    cached_start: usize,
    cache: [u8; 16],
    /// Next address to map; excluded ranges are skipped when it is consumed.
    address: usize,
    /// End of the CC-declared data area. Lock and reserved bytes inside it
    /// occupy addresses without holding TLV data.
    end: usize,
    excluded: Vec<Range<usize>>,
    writable: bool,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct Type2Page(u16);

impl Type2Page {
    fn containing<E>(address: usize) -> Result<Self, Error<E>> {
        u16::try_from(address / 4)
            .map(Self)
            .map_err(|_| Error::Address(address))
    }

    fn offset(self) -> usize {
        usize::from(self.0) * 4
    }

    fn wire_address(self) -> (u8, u8) {
        let [sector, page] = self.0.to_be_bytes();
        (sector, page)
    }
}

struct PagePatch {
    bytes: [u8; 4],
    message_bytes: usize,
}

struct Type2Write {
    length_page: Type2Page,
    unpublished: [u8; 4],
    data: BTreeMap<Type2Page, PagePatch>,
    published: [u8; 4],
}

impl<'card, C: nfca::Selection> Type2Data<'card, C> {
    fn open(card: &'card mut Type2Tag<C>) -> Result<Self, Error<C::Error>> {
        if card.card.observation().sel_res().byte() != 0 {
            return Err(Error::UnsupportedMapping);
        }
        let header = type2_read_window(card, Type2Page(0))?;
        let [magic, version, size, access] = [header[12], header[13], header[14], header[15]];
        if magic != 0xe1 || version >> 4 != 1 {
            return Err(Error::UnsupportedMapping);
        }
        if access >> 4 != 0 {
            return Err(Error::ReadAccess);
        }
        Ok(Self {
            card,
            cached_start: 0,
            cache: header,
            address: 16,
            end: 16 + usize::from(size) * 8,
            excluded: Vec::new(),
            writable: access & 0x0f == 0,
        })
    }

    fn find_message(&mut self) -> Result<bool, Error<C::Error>> {
        while self.remaining() != 0 {
            let tag = self.byte()?;
            match tag {
                0 => continue,
                0xfe => return Ok(false),
                3 => return Ok(true),
                _ => {}
            }
            let length = self.tlv_length()?;
            if matches!(tag, 1 | 2) {
                if length != 3 {
                    return Err(Error::Layout("Type 2 control TLV length"));
                }
                self.exclude(tag)?;
            } else {
                for _ in 0..length {
                    self.next_address()?;
                }
            }
        }
        Ok(false)
    }

    fn exclude(&mut self, tag: u8) -> Result<(), Error<C::Error>> {
        let reserved = control_range(tag, [self.byte()?, self.byte()?, self.byte()?])?;
        if reserved.start < self.address
            || self
                .excluded
                .iter()
                .any(|range| range.start < reserved.end && reserved.start < range.end)
        {
            return Err(Error::Layout("Type 2 control TLV overlaps mapped bytes"));
        }
        self.excluded.push(reserved);
        Ok(())
    }

    fn tlv_length(&mut self) -> Result<usize, Error<C::Error>> {
        let length = match self.byte()? {
            0xff => {
                let length = usize::from(u16::from_be_bytes([self.byte()?, self.byte()?]));
                if !(255..=65534).contains(&length) {
                    return Err(Error::Layout("Type 2 extended TLV length"));
                }
                length
            }
            length => usize::from(length),
        };
        if length > self.remaining() {
            return Err(Error::Layout("Type 2 TLV exceeds data area"));
        }
        Ok(length)
    }

    fn next_address(&mut self) -> Result<usize, Error<C::Error>> {
        while let Some(range) = self
            .excluded
            .iter()
            .find(|range| range.contains(&self.address))
        {
            self.address = range.end;
        }
        if self.address >= self.end {
            return Err(Error::Layout("Type 2 data area exhausted"));
        }
        let address = self.address;
        Type2Page::containing(address)?;
        self.address += 1;
        Ok(address)
    }

    /// TLV bytes left before the data area ends, excluding lock and reserved
    /// bytes. Accepted control ranges do not overlap one another.
    fn remaining(&self) -> usize {
        let start = self.address.min(self.end);
        let excluded: usize = self
            .excluded
            .iter()
            .map(|range| {
                range
                    .end
                    .min(self.end)
                    .saturating_sub(range.start.max(start))
            })
            .sum();
        self.end - start - excluded
    }

    fn window(&mut self, address: usize) -> Result<&[u8; 16], Error<C::Error>> {
        let start = address / 16 * 16;
        if self.cached_start != start {
            self.cache = type2_read_window(self.card, Type2Page::containing(start)?)?;
            self.cached_start = start;
        }
        Ok(&self.cache)
    }

    fn byte(&mut self) -> Result<u8, Error<C::Error>> {
        let address = self.next_address()?;
        Ok(self.window(address)?[address % 16])
    }

    fn prepare_write(&mut self, message: &[u8]) -> Result<Type2Write, Error<C::Error>> {
        if !self.writable {
            return Err(Error::WriteAccess);
        }
        if !self.find_message()? {
            return Err(Error::MissingMessageTlv);
        }
        let position = self.address;
        self.tlv_length()?;
        self.address = position;

        let address = self.next_address()?;
        let length_page = Type2Page::containing(address)?;
        let length_index = address % 4;
        let mut unpublished = self.page(length_page)?;
        unpublished[length_index] = 0;

        let remaining = self.remaining();
        let available = remaining.saturating_sub(2).max(remaining.min(254));
        if message.len() > available {
            return Err(Error::Capacity {
                requested: message.len(),
                available,
            });
        }
        let (length, extended) = match u8::try_from(message.len()) {
            Ok(length @ 0..=254) => (length, None),
            _ => (
                0xff,
                Some(u16::try_from(message.len()).map_err(|_| Error::Capacity {
                    requested: message.len(),
                    available,
                })?),
            ),
        };
        let mut data = BTreeMap::new();
        if let Some(extended) = extended {
            for byte in extended.to_be_bytes() {
                self.patch_byte(&mut data, byte, 0)?;
            }
        }
        for &byte in message {
            self.patch_byte(&mut data, byte, 1)?;
        }
        if self.remaining() != 0 {
            self.patch_byte(&mut data, 0xfe, 0)?;
        }
        // The length page can also hold payload or the rest of the extended
        // length. Keep the leading length byte zero throughout staging.
        let mut published = unpublished;
        if let Some(page) = data.get_mut(&length_page) {
            page.bytes[length_index] = 0;
            published = page.bytes;
        }
        published[length_index] = length;
        Ok(Type2Write {
            length_page,
            unpublished,
            data,
            published,
        })
    }

    fn patch_byte(
        &mut self,
        pages: &mut BTreeMap<Type2Page, PagePatch>,
        value: u8,
        message_bytes: usize,
    ) -> Result<(), Error<C::Error>> {
        let address = self.next_address()?;
        let page = Type2Page::containing(address)?;
        use alloc::collections::btree_map::Entry;
        let patch = match pages.entry(page) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(PagePatch {
                bytes: self.page(page)?,
                message_bytes: 0,
            }),
        };
        patch.bytes[address % 4] = value;
        patch.message_bytes += message_bytes;
        Ok(())
    }

    fn page(&mut self, page: Type2Page) -> Result<[u8; 4], Error<C::Error>> {
        let offset = page.offset();
        let start = offset % 16;
        let window = self.window(offset)?;
        Ok(core::array::from_fn(|index| window[start + index]))
    }

    fn write_page(&mut self, page: Type2Page, data: [u8; 4]) -> Result<(), Error<C::Error>> {
        let [a, b, c, d] = data;
        let (sector, address) = page.wire_address();
        select_sector(self.card, sector)?;
        let answer = type2_exchange(self.card, &[0xa2, address, a, b, c, d])?;
        match answer.four_bit() {
            Some(ACK) => return Ok(()),
            Some(nibble) => return Err(nak(nibble)),
            None => {}
        }
        match answer {
            Answer::Unreported => {
                // A reader that consumes the 4-bit reply leaves no ACK to
                // inspect, so the page itself confirms the write.
                let window = type2_read_window(self.card, page)?;
                if window[..4] != data {
                    return Err(Error::Layout("Type 2 WRITE readback"));
                }
                Ok(())
            }
            _ => Err(Error::Layout("Type 2 WRITE response")),
        }
    }
}

fn type2_read_window<C: nfca::Selection>(
    card: &mut Type2Tag<C>,
    page: Type2Page,
) -> Result<[u8; 16], Error<C::Error>> {
    let (sector, address) = page.wire_address();
    select_sector(card, sector)?;
    let answer = type2_exchange(card, &[0x30, address])?;
    match (answer.four_bit(), answer) {
        (_, Answer::Frame(data)) => data
            .try_into()
            .map_err(|_| Error::Layout("Type 2 READ length")),
        (Some(nibble), _) if nibble != ACK => Err(nak(nibble)),
        _ => Err(Error::Layout("Type 2 READ response")),
    }
}

fn select_sector<C: nfca::Selection>(
    card: &mut Type2Tag<C>,
    sector: u8,
) -> Result<(), Error<C::Error>> {
    if card.sector == Some(sector) {
        return Ok(());
    }
    // Until both packets complete, the addressed sector is unknown. Any
    // sector but 0 survives a new selection request.
    card.sector = None;
    if sector != 0 {
        card.card.require_field_cycle();
    }
    let selected = (|| {
        match type2_exchange(card, &[0xc2, 0xff])?.four_bit() {
            Some(ACK) => {}
            Some(nibble) => return Err(nak(nibble)),
            None => return Err(Error::Layout("Type 2 SECTOR SELECT first response")),
        }
        // The second packet succeeds with a passive ACK. Only the reader's
        // report of silence demonstrates it; a failed exchange leaves it unknown.
        match card.card.exchange(&[sector, 0, 0, 0]) {
            Ok(Reply::Silence) => Ok(()),
            Ok(reply) => match Answer::from_reply(reply).and_then(|answer| answer.four_bit()) {
                Some(nibble) if nibble != ACK => Err(nak(nibble)),
                _ => Err(Error::Layout("Type 2 SECTOR SELECT second response")),
            },
            Err(error) => Err(Error::Exchange(error)),
        }
    })();
    if selected.is_ok() {
        card.sector = Some(sector);
    }
    selected
}

/// A reply to a Type 2 command that the tag must answer.
enum Answer {
    Frame(Vec<u8>),
    Nibble(Nibble),
    Byte(u8),
    Unreported,
}

impl Answer {
    fn from_reply(reply: Reply) -> Option<Self> {
        match reply {
            Reply::Frame(data) => Some(Self::Frame(data)),
            Reply::Nibble(nibble) => Some(Self::Nibble(nibble)),
            Reply::Byte(byte) => Some(Self::Byte(byte)),
            Reply::Unreported => Some(Self::Unreported),
            Reply::Silence => None,
        }
    }

    /// The 4-bit value of an ACK or NAK. A Type 2 tag sends no one-byte
    /// standard frame, so a byte without a reported bit count that fits in
    /// four bits is that reply.
    fn four_bit(&self) -> Option<u8> {
        match self {
            Self::Nibble(nibble) => Some(nibble.get()),
            Self::Byte(byte @ 0..=0x0f) => Some(*byte),
            _ => None,
        }
    }
}

/// Send a command that the tag must answer; silence is [`Error::NoResponse`].
fn type2_exchange<C: nfca::Selection>(
    card: &mut Type2Tag<C>,
    command: &[u8],
) -> Result<Answer, Error<C::Error>> {
    Answer::from_reply(card.card.exchange(command).map_err(Error::Exchange)?)
        .ok_or(Error::NoResponse)
}

/// A 4-bit reply other than ACK: one of the NAK values, or an undefined one.
fn nak<E>(nibble: u8) -> Error<E> {
    match nibble {
        nak @ (0 | 1 | 4 | 5) => Error::Type2Nak(nak),
        _ => Error::Layout("Type 2 4-bit reply"),
    }
}
