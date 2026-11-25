use super::{
    super::{CAPABILITY_CONTAINER_ID, NDEF_APP_ID, SHORT_FILE_END},
    Type4EmulationError,
};
use crate::ndef::{Message, MessageError};
use alloc::{boxed::Box, vec, vec::Vec};
use core::fmt;

const NDEF_FILE_ID: u16 = 0xe104;
const READ_LIMIT: u8 = 255;
const WRITE_LIMIT: u8 = 255;
const NLEN_BYTES: u16 = 2;
const NLEN_WIDTH: usize = NLEN_BYTES as usize;
const MIN_MESSAGE_CAPACITY: u16 = 3;

/// Maximum NDEF message length in the short-offset Type 4 file.
pub const MAX_TYPE4_EMULATED_NDEF_BYTES: usize = SHORT_FILE_END - NLEN_WIDTH;

/// Failure constructing a writable Type 4 NDEF file.
#[derive(Debug)]
pub enum Type4NdefFileError {
    /// The requested message capacity is outside the supported range.
    Capacity(usize),
    /// The initial NDEF exceeds the configured message capacity.
    MessageLength {
        /// Length of the initial NDEF in bytes.
        length: usize,
        /// Configured message capacity in bytes.
        capacity: usize,
    },
    /// The nonempty initial value is not one complete NDEF message.
    Message(MessageError),
}

impl fmt::Display for Type4NdefFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity(capacity) => write!(
                f,
                "Type 4 NDEF capacity {capacity} is outside {MIN_MESSAGE_CAPACITY}..={MAX_TYPE4_EMULATED_NDEF_BYTES}"
            ),
            Self::MessageLength { length, capacity } => write!(
                f,
                "initial NDEF length {length} exceeds message capacity {capacity}"
            ),
            Self::Message(error) => write!(f, "invalid initial NDEF message: {error}"),
        }
    }
}

impl core::error::Error for Type4NdefFileError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Message(error) => Some(error),
            _ => None,
        }
    }
}

/// A writable NDEF file whose published contents survive RF activations and
/// target shutdown while the caller keeps the file in memory.
pub struct Type4NdefFile {
    // The backing allocation is fixed at construction and equals capacity.
    bytes: Box<[u8]>,
    capacity: u16,
    published_length: u16,
}

impl fmt::Debug for Type4NdefFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Type4NdefFile")
            .field("message_capacity", &self.capacity)
            .field("published_length", &self.published_length)
            .finish()
    }
}

impl Type4NdefFile {
    /// Create a file with a fixed capacity of 3 through
    /// [MAX_TYPE4_EMULATED_NDEF_BYTES] message bytes, excluding NLEN.
    /// An empty initial slice creates a file with NLEN zero.
    pub fn new(
        message_capacity: usize,
        initial_message: &[u8],
    ) -> Result<Self, Type4NdefFileError> {
        let capacity = short_message_length(message_capacity)
            .filter(|&capacity| capacity >= MIN_MESSAGE_CAPACITY)
            .ok_or(Type4NdefFileError::Capacity(message_capacity))?;
        let published_length = short_message_length(initial_message.len())
            .filter(|&length| length <= capacity)
            .ok_or(Type4NdefFileError::MessageLength {
                length: initial_message.len(),
                capacity: message_capacity,
            })?;
        validate_message(initial_message).map_err(Type4NdefFileError::Message)?;
        let mut bytes = vec![0; usize::from(capacity)].into_boxed_slice();
        bytes[..initial_message.len()].copy_from_slice(initial_message);
        Ok(Self {
            bytes,
            capacity,
            published_length,
        })
    }

    /// Borrow the currently published NDEF bytes. An empty slice means NLEN
    /// is zero, including after an interrupted update that cleared NLEN.
    pub fn message(&self) -> &[u8] {
        &self.bytes[..usize::from(self.published_length)]
    }

    fn update(
        &mut self,
        pending: &mut Option<PendingWrite>,
        address: [u8; 2],
        body: &[u8],
    ) -> Result<Option<Type4NdefChange>, u16> {
        let &[length @ 1..=WRITE_LIMIT, ref data @ ..] = body else {
            return Err(0x6700);
        };
        if data.len() != usize::from(length) {
            return Err(0x6700);
        }
        let offset = usize::from(u16::from_be_bytes(address));
        let file_size = usize::from(ndef_file_size(self.capacity));
        if offset >= file_size || offset == 1 {
            return Err(0x6b00);
        }
        if data.len() > file_size - offset {
            return Err(0x6a84);
        }
        if offset >= NLEN_WIDTH {
            let update = pending.as_mut().ok_or(0x6985u16)?;
            update.write(&mut self.bytes, offset - NLEN_WIDTH, data);
            return Ok(None);
        }

        // NLEN is indivisible. A command may also carry the start of the
        // unpublished body or a complete message to publish atomically.
        let Some((&nlen, data)) = data.split_first_chunk::<NLEN_WIDTH>() else {
            return Err(0x6700);
        };
        let nlen = u16::from_be_bytes(nlen);
        if nlen == 0 {
            let mut update = PendingWrite::new(self.bytes.len());
            self.published_length = 0;
            update.write(&mut self.bytes, 0, data);
            *pending = Some(update);
            return Ok(Some(Type4NdefChange::Cleared));
        }
        if nlen > self.capacity {
            return Err(0x6a84);
        }
        let length = usize::from(nlen);
        if data.is_empty() {
            let update = pending.as_ref().ok_or(0x6985u16)?;
            if !(0..length).all(|index| update.covers(index)) {
                return Err(0x6985);
            }
            validate_message(&self.bytes[..length]).map_err(|_| 0x6a80u16)?;
        } else {
            if data.len() != length {
                return Err(0x6a80);
            }
            validate_message(data).map_err(|_| 0x6a80u16)?;
            self.bytes[..length].copy_from_slice(data);
        }
        self.published_length = nlen;
        *pending = None;
        Ok(Some(Type4NdefChange::Published { length }))
    }
}

/// Effect of an accepted APDU on the published NDEF file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type4NdefChange {
    /// NLEN was set to zero. A new message can be staged in this activation.
    Cleared,
    /// A validated NDEF message was published.
    Published {
        /// Length of the published message in bytes, excluding NLEN.
        length: usize,
    },
}

/// The written ranges belong to one activation. Bytes in the backing file
/// without coverage cannot be published as part of a staged update.
#[derive(Debug)]
struct PendingWrite {
    coverage: Vec<u8>,
}

impl PendingWrite {
    fn new(capacity: usize) -> Self {
        Self {
            coverage: vec![0; capacity.div_ceil(8)],
        }
    }

    fn write(&mut self, bytes: &mut [u8], start: usize, data: &[u8]) {
        let range = start..start + data.len();
        bytes[range.clone()].copy_from_slice(data);
        for index in range {
            self.coverage[index / 8] |= 1 << (index % 8);
        }
    }

    fn covers(&self, index: usize) -> bool {
        self.coverage[index / 8] & (1 << (index % 8)) != 0
    }
}

#[derive(Debug, Default)]
pub(super) struct Application {
    selected: Selection,
    pending: Option<PendingWrite>,
}

#[derive(Debug, Default, Clone, Copy)]
enum Selection {
    #[default]
    None,
    Application,
    File(File),
}

#[derive(Debug, Clone, Copy)]
enum File {
    CapabilityContainer,
    Ndef,
}

#[derive(Debug)]
pub(super) enum Files<'m> {
    ReadOnly { message: &'m [u8], nlen: u16 },
    Writable(&'m mut Type4NdefFile),
}

impl<'m> Files<'m> {
    pub(super) fn read_only<E>(message: &'m [u8]) -> Result<Self, Type4EmulationError<E>> {
        let nlen = short_message_length(message.len())
            .ok_or(Type4EmulationError::MessageLength(message.len()))?;
        validate_message(message).map_err(Type4EmulationError::Message)?;
        Ok(Self::ReadOnly { message, nlen })
    }

    pub(super) fn message(&self) -> &[u8] {
        match self {
            Self::ReadOnly { message, .. } => message,
            Self::Writable(file) => file.message(),
        }
    }

    fn nlen(&self) -> u16 {
        match self {
            Self::ReadOnly { nlen, .. } => *nlen,
            Self::Writable(file) => file.published_length,
        }
    }

    fn ndef_file_size(&self) -> u16 {
        let capacity = match self {
            Self::ReadOnly { nlen, .. } => (*nlen).max(MIN_MESSAGE_CAPACITY),
            Self::Writable(file) => file.capacity,
        };
        ndef_file_size(capacity)
    }

    fn capability_container(&self) -> [u8; 15] {
        let [id_high, id_low] = NDEF_FILE_ID.to_be_bytes();
        let [size_high, size_low] = self.ndef_file_size().to_be_bytes();
        let write_access = match self {
            Self::ReadOnly { .. } => 0xff,
            Self::Writable(_) => 0,
        };
        [
            0,
            15,
            0x20,
            0,
            READ_LIMIT,
            0,
            WRITE_LIMIT,
            4,
            6,
            id_high,
            id_low,
            size_high,
            size_low,
            0,
            write_access,
        ]
    }

    pub(super) fn execute(
        &mut self,
        application: &mut Application,
        apdu: &[u8],
    ) -> (Vec<u8>, Option<Type4NdefChange>) {
        let [class, instruction, p1, p2, body @ ..] = apdu else {
            let reply = if apdu.is_empty() {
                Vec::new()
            } else {
                status(0x6700)
            };
            return (reply, None);
        };
        if *class != 0 {
            return (status(0x6e00), None);
        }
        let parameters = [*p1, *p2];
        let reply = match *instruction {
            0xa4 => status(select(&mut application.selected, parameters, body)),
            0xb0 => self.read(application, parameters, body),
            0xd6 => {
                return match self.update(application, parameters, body) {
                    Ok(change) => (status(0x9000), change),
                    Err(word) => (status(word), None),
                };
            }
            _ => status(0x6d00),
        };
        (reply, None)
    }

    fn update(
        &mut self,
        application: &mut Application,
        address: [u8; 2],
        body: &[u8],
    ) -> Result<Option<Type4NdefChange>, u16> {
        match (application.selected, self) {
            (Selection::File(File::Ndef), Self::Writable(file)) => {
                file.update(&mut application.pending, address, body)
            }
            (Selection::File(_), _) => Err(0x6982),
            _ => Err(0x6986),
        }
    }

    fn read(&self, application: &Application, address: [u8; 2], body: &[u8]) -> Vec<u8> {
        let &[length @ 1..=READ_LIMIT] = body else {
            return status(0x6700);
        };
        let Selection::File(file) = application.selected else {
            return status(0x6986);
        };
        let offset = usize::from(u16::from_be_bytes(address));
        let size = match file {
            File::CapabilityContainer => self.capability_container().len(),
            File::Ndef => usize::from(self.ndef_file_size()),
        };
        if offset >= size {
            return status(0x6b00);
        }
        let requested_end = offset + usize::from(length);
        let end = requested_end.min(size);
        let mut response = Vec::with_capacity(end - offset + 2);
        match file {
            File::CapabilityContainer => {
                response.extend_from_slice(&self.capability_container()[offset..end]);
            }
            File::Ndef => {
                let nlen = self.nlen().to_be_bytes();
                if offset < NLEN_WIDTH {
                    response.extend_from_slice(&nlen[offset..end.min(NLEN_WIDTH)]);
                }
                let start = offset.saturating_sub(NLEN_WIDTH);
                let end_of_body = end.saturating_sub(NLEN_WIDTH);
                if let (Self::Writable(file), Some(pending)) = (self, &application.pending) {
                    response.extend((start..end_of_body).map(|index| {
                        if pending.covers(index) {
                            file.bytes[index]
                        } else {
                            0
                        }
                    }));
                } else {
                    let message = self.message();
                    let end_of_message = end_of_body.min(message.len());
                    if start < end_of_message {
                        response.extend_from_slice(&message[start..end_of_message]);
                    }
                    response.resize(end - offset, 0);
                }
            }
        }
        let word: u16 = if end == requested_end { 0x9000 } else { 0x6282 };
        response.extend(word.to_be_bytes());
        response
    }
}

fn short_message_length(length: usize) -> Option<u16> {
    u16::try_from(length)
        .ok()
        .filter(|_| length <= MAX_TYPE4_EMULATED_NDEF_BYTES)
}

fn ndef_file_size(message_capacity: u16) -> u16 {
    // Both modes bound message capacity to SHORT_FILE_END minus NLEN.
    message_capacity + NLEN_BYTES
}

fn validate_message(message: &[u8]) -> Result<(), MessageError> {
    if !message.is_empty() {
        Message::parse(message)?;
    }
    Ok(())
}

fn select(selected: &mut Selection, parameters: [u8; 2], body: &[u8]) -> u16 {
    *selected = match parameters {
        [4, 0] => {
            let [7, data @ ..] = body else {
                return 0x6700;
            };
            let Some((aid, [] | [0])) = data.split_first_chunk::<7>() else {
                return 0x6700;
            };
            if aid != &NDEF_APP_ID {
                return 0x6a82;
            }
            Selection::Application
        }
        [0, 0x0c] => {
            let &[2, high, low] = body else {
                return 0x6700;
            };
            if matches!(selected, Selection::None) {
                return 0x6a82;
            }
            Selection::File(match u16::from_be_bytes([high, low]) {
                CAPABILITY_CONTAINER_ID => File::CapabilityContainer,
                NDEF_FILE_ID => File::Ndef,
                _ => return 0x6a82,
            })
        }
        _ => return 0x6a86,
    };
    0x9000
}

fn status(word: u16) -> Vec<u8> {
    word.to_be_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;

    fn selected_ndef() -> Application {
        Application {
            selected: Selection::File(File::Ndef),
            pending: None,
        }
    }

    #[test]
    fn ndef_file_capacity_includes_the_length_field()
    -> Result<(), alloc::boxed::Box<dyn core::error::Error>> {
        let application = selected_ndef();
        let empty = Files::read_only::<Infallible>(&[])?;
        assert_eq!(&empty.capability_container()[11..], &[0, 5, 0, 0xff]);
        assert_eq!(
            empty.read(&application, [0, 0], &[5]),
            [0, 0, 0, 0, 0, 0x90, 0]
        );

        let mut message = vec![0xc5, 0, 0, 0, 0x7f, 0xf8];
        message.resize(MAX_TYPE4_EMULATED_NDEF_BYTES, 0xa5);
        let full = Files::read_only::<Infallible>(&message)?;
        assert_eq!(&full.capability_container()[11..], &[0x80, 0, 0, 0xff]);
        assert_eq!(
            full.read(&application, [0, 1], &[3]),
            [0xfe, 0xc5, 0, 0x90, 0]
        );
        assert_eq!(
            full.read(&application, [0x7f, 0xff], &[2]),
            [0xa5, 0x62, 0x82]
        );
        assert_eq!(full.read(&application, [0x80, 0], &[1]), [0x6b, 0]);

        let mut writable = Type4NdefFile::new(MAX_TYPE4_EMULATED_NDEF_BYTES, &message)?;
        let writable = Files::Writable(&mut writable);
        assert_eq!(&writable.capability_container()[11..], &[0x80, 0, 0, 0]);
        assert_eq!(
            writable.read(&application, [0x7f, 0xff], &[2]),
            [0xa5, 0x62, 0x82]
        );
        Ok(())
    }

    #[test]
    fn validates_writable_ndef_file_configuration() {
        assert!(matches!(
            Type4NdefFile::new(2, &[]),
            Err(Type4NdefFileError::Capacity(2))
        ));
        assert!(matches!(
            Type4NdefFile::new(MAX_TYPE4_EMULATED_NDEF_BYTES + 1, &[]),
            Err(Type4NdefFileError::Capacity(_))
        ));
        assert!(matches!(
            Type4NdefFile::new(3, &[0; 4]),
            Err(Type4NdefFileError::MessageLength {
                length: 4,
                capacity: 3
            })
        ));
        assert!(matches!(
            Type4NdefFile::new(3, &[0xd0]),
            Err(Type4NdefFileError::Message(_))
        ));
    }

    #[test]
    fn accepts_a_full_short_update_apdu_at_the_file_boundary() -> Result<(), Type4NdefFileError> {
        let mut file = Type4NdefFile::new(255, &[])?;
        let mut pending = None;
        let mut command = [0xa5; 256];
        command[..4].copy_from_slice(&[0xff, 0xd5, 0, 252]);

        assert_eq!(
            file.update(&mut pending, [0, 0], &[2, 0, 0]),
            Ok(Some(Type4NdefChange::Cleared))
        );
        assert_eq!(file.update(&mut pending, [0, 2], &command), Ok(None));
        assert_eq!(
            file.update(&mut pending, [0, 0], &[2, 0, 0xff]),
            Ok(Some(Type4NdefChange::Published { length: 255 }))
        );
        assert_eq!(file.message(), &command[1..]);
        Ok(())
    }

    #[test]
    fn rejected_updates_do_not_modify_published_or_staged_bytes() -> Result<(), Type4NdefFileError>
    {
        let mut file = Type4NdefFile::new(3, &[0xd0, 0, 0])?;
        let mut pending = None;
        for (address, data, status) in [
            ([0, 0], &[0][..], 0x6700),
            ([0, 0], &[2, 0, 0, 0], 0x6700),
            ([0, 0], &[1, 0], 0x6700),
            ([0, 1], &[1, 0], 0x6b00),
            ([0, 5], &[1, 0], 0x6b00),
            ([0, 4], &[2, 0, 0], 0x6a84),
            ([0, 0], &[2, 0, 4], 0x6a84),
            ([0, 0], &[3, 0, 3, 0xd0], 0x6a80),
            ([0, 0], &[5, 0, 3, 0, 0, 0], 0x6a80),
            ([0, 2], &[1, 0], 0x6985),
        ] {
            assert_eq!(file.update(&mut pending, address, data), Err(status));
            assert_eq!(file.message(), [0xd0, 0, 0]);
        }

        assert_eq!(
            file.update(&mut pending, [0, 0], &[2, 0, 0]),
            Ok(Some(Type4NdefChange::Cleared))
        );
        assert_eq!(file.update(&mut pending, [0, 4], &[1, 0]), Ok(None));
        assert_eq!(file.update(&mut pending, [0, 0], &[2, 0, 3]), Err(0x6985));
        assert_eq!(file.update(&mut pending, [0, 2], &[2, 0, 0]), Ok(None));
        assert_eq!(file.update(&mut pending, [0, 0], &[2, 0, 3]), Err(0x6a80));
        assert!(file.message().is_empty());
        assert_eq!(file.update(&mut pending, [0, 2], &[1, 0xd0]), Ok(None));
        assert_eq!(
            file.update(&mut pending, [0, 0], &[2, 0, 3]),
            Ok(Some(Type4NdefChange::Published { length: 3 }))
        );
        assert_eq!(file.message(), [0xd0, 0, 0]);
        Ok(())
    }
}
