use super::{
    BlockAddress, BlockWrite, Card, CardError, Error, admit_packet, append_read_blocks,
    append_write_blocks,
};
#[cfg(feature = "felica-standard-aes")]
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use felica_packet::Selection;
use zeroize::Zeroizing;

/// Issue information verified by the card's second authentication response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssueInformation {
    /// Issue ID in card byte order.
    pub id: [u8; 8],
    /// Issue parameters in card byte order.
    pub parameters: [u8; 8],
}

impl IssueInformation {
    pub(super) fn parse<E>(payload: &[u8]) -> Result<Self, StandardError<E>> {
        let bytes = <&[u8; 16]>::try_from(payload).map_err(|_| StandardError::Layout)?;
        let [id, parameters] = bytes.as_chunks::<8>().0 else {
            return Err(StandardError::Layout);
        };
        Ok(Self {
            id: *id,
            parameters: *parameters,
        })
    }
}

/// A FeliCa Standard authentication or encrypted command failure.
#[derive(Debug)]
pub enum StandardError<E> {
    /// Invalid input or insufficient packet capacity. No packet was sent.
    Request(CardError),
    /// A card command could not be completed.
    Exchange {
        /// Card command code identifying the step.
        command: u8,
        /// Underlying failure, including any reader transaction progress.
        cause: Error<E>,
    },
    /// The card did not prove possession of the authentication key.
    CardProof,
    /// DES block access needs at least one service contributing a DES key.
    NoAuthenticatedService,
    /// Unexpected secure reply layout. A submitted write may have taken effect.
    Layout,
    /// A verified read reply declares a different block count.
    ReadBlockCount {
        /// Requested number of blocks.
        expected: usize,
        /// Number of blocks declared by the card.
        actual: usize,
    },
    /// The secure response's message authentication code did not verify.
    Mac,
    /// The authenticated DES reply belongs to another transaction.
    TransactionId,
    /// The authenticated response did not advance past the sent counter.
    TransactionNumber {
        /// Counter in the command.
        sent: u16,
        /// Counter authenticated in the response.
        received: u16,
    },
    /// The session has insufficient counter space for another exchange.
    CounterExhausted,
    /// Both status flags from an authenticated operation response. A write
    /// status with flag 2 set to `0x71` reports a write performed with a
    /// memory wear warning.
    Status {
        /// First status flag.
        first: u8,
        /// Second status flag.
        second: u8,
    },
    /// A preceding exchange failed, revoking the session.
    SessionUnavailable,
}

impl<E: fmt::Debug> fmt::Display for StandardError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => error.fmt(f),
            Self::Exchange { command, .. } => {
                write!(f, "FeliCa Standard command {command:02X} exchange failed")
            }
            Self::CardProof => f.write_str("card did not prove possession of the key"),
            Self::NoAuthenticatedService => f.write_str("no service contributed a DES key"),
            Self::Layout => f.write_str("malformed secure response"),
            Self::ReadBlockCount { expected, actual } => {
                write!(
                    f,
                    "secure reply declares {actual} blocks, expected {expected}"
                )
            }
            Self::Mac => f.write_str("secure response MAC mismatch"),
            Self::TransactionId => f.write_str("secure response transaction ID mismatch"),
            Self::TransactionNumber { sent, received } => write!(
                f,
                "response transaction number {received} does not follow {sent}"
            ),
            Self::CounterExhausted => f.write_str("transaction counter exhausted"),
            Self::Status { first, second } => {
                write!(f, "card status flags {first:02X} {second:02X}")
            }
            Self::SessionUnavailable => f.write_str("FeliCa Standard session was revoked"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for StandardError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            Self::Exchange { cause, .. } => Some(cause),
            _ => None,
        }
    }
}

pub(super) enum Cipher {
    #[cfg(feature = "felica-standard-aes")]
    Aes(Box<super::standard_aes::AesCipher>),
    #[cfg(feature = "felica-standard-des")]
    Des(super::standard_des::DesCipher),
}

#[derive(Clone, Copy)]
enum Operation {
    Read,
    Write,
}

impl Cipher {
    fn command(&self, operation: Operation) -> u8 {
        match (self, operation) {
            #[cfg(feature = "felica-standard-aes")]
            (Self::Aes(_), Operation::Read) => 0x44,
            #[cfg(feature = "felica-standard-aes")]
            (Self::Aes(_), Operation::Write) => 0x46,
            #[cfg(feature = "felica-standard-des")]
            (Self::Des(_), Operation::Read) => 0x14,
            #[cfg(feature = "felica-standard-des")]
            (Self::Des(_), Operation::Write) => 0x16,
        }
    }

    fn packet_len(&self, payload_len: usize) -> usize {
        match self {
            #[cfg(feature = "felica-standard-aes")]
            Self::Aes(_) => super::standard_aes::packet_len(payload_len),
            #[cfg(feature = "felica-standard-des")]
            Self::Des(_) => super::standard_des::packet_len(payload_len),
        }
    }

    fn seal(&self, code: u8, counter: u16, payload: &mut [u8]) -> Option<Vec<u8>> {
        match self {
            #[cfg(feature = "felica-standard-aes")]
            Self::Aes(cipher) => cipher.seal(code, counter, payload),
            #[cfg(feature = "felica-standard-des")]
            Self::Des(cipher) => cipher.seal(code, counter, payload),
        }
    }

    fn open<E>(
        &self,
        code: u8,
        packet: Vec<u8>,
        success_len: usize,
    ) -> Result<(u16, Zeroizing<Vec<u8>>), StandardError<E>> {
        let (counter, payload) = match self {
            #[cfg(feature = "felica-standard-aes")]
            Self::Aes(cipher) => cipher.open(code, packet)?,
            #[cfg(feature = "felica-standard-des")]
            Self::Des(cipher) => cipher.open_operation(code, packet, success_len)?,
        };
        let expected = if payload.starts_with(&[0, 0]) {
            success_len
        } else {
            2
        };
        if payload.len() != expected {
            return Err(StandardError::Layout);
        }
        Ok((counter, payload))
    }
}

struct Active {
    cipher: Cipher,
    counter: u16,
}

/// Exclusive Mode2 authority for one polled FeliCa Standard system.
///
/// Request errors leave the session available. Once a secure exchange starts,
/// only a verified, successful response retains that authority. The next
/// polling after release cycles the RF field before selecting a card.
pub struct StandardSession<S: Selection> {
    card: Card<S>,
    active: Option<Active>,
    issue: IssueInformation,
    services: usize,
}

impl<S: Selection> fmt::Debug for StandardSession<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StandardSession")
            .field("active", &self.active.is_some())
            .field("services", &self.services)
            .finish_non_exhaustive()
    }
}

impl<S: Selection> StandardSession<S> {
    pub(super) fn new(
        card: Card<S>,
        cipher: Cipher,
        counter: u16,
        issue: IssueInformation,
        services: usize,
    ) -> Self {
        Self {
            card,
            active: Some(Active { cipher, counter }),
            issue,
            services,
        }
    }

    /// Issue data obtained during successful authentication.
    pub fn issue(&self) -> IssueInformation {
        self.issue
    }

    /// Read blocks in request order and verify the response before returning data.
    pub fn read_blocks(
        &mut self,
        blocks: &[BlockAddress],
    ) -> Result<Vec<[u8; 16]>, StandardError<S::Error>> {
        if !(1..=15).contains(&blocks.len()) {
            return Err(StandardError::Request(CardError::BlockCount(blocks.len())));
        }
        let mut payload = Zeroizing::new(Vec::new());
        append_read_blocks(&mut payload, self.services, blocks).map_err(StandardError::Request)?;
        self.transact(Operation::Read, payload, 3 + 16 * blocks.len(), |reply| {
            let [0, 0, count, data @ ..] = reply else {
                return Err(StandardError::Layout);
            };
            let actual = usize::from(*count);
            if actual != blocks.len() {
                return Err(StandardError::ReadBlockCount {
                    expected: blocks.len(),
                    actual,
                });
            }
            Ok(data.as_chunks::<16>().0.to_vec())
        })
    }

    /// Write blocks in one command. If the exchange fails after sending, the
    /// write may have taken effect. Reauthenticate and read back to reconcile.
    pub fn write_blocks(&mut self, blocks: &[BlockWrite]) -> Result<(), StandardError<S::Error>> {
        let mut payload = Zeroizing::new(Vec::new());
        append_write_blocks(&mut payload, self.services, blocks).map_err(StandardError::Request)?;
        self.transact(Operation::Write, payload, 2, |_| Ok(()))
    }

    /// Consume this session and return ordinary access only after a successful
    /// Reset Mode response. Drop the session and reselect if the card omits it.
    pub fn reset_mode(mut self) -> Result<Card<S>, StandardError<S::Error>> {
        self.active
            .take()
            .ok_or(StandardError::SessionUnavailable)?;
        self.card
            .reset_mode()
            .map_err(|cause| StandardError::Exchange {
                command: 0x3e,
                cause,
            })?;
        Ok(self.card)
    }

    fn transact<U>(
        &mut self,
        operation: Operation,
        mut payload: Zeroizing<Vec<u8>>,
        success_len: usize,
        decode: impl FnOnce(&[u8]) -> Result<U, StandardError<S::Error>>,
    ) -> Result<U, StandardError<S::Error>> {
        let active = self
            .active
            .as_ref()
            .ok_or(StandardError::SessionUnavailable)?;
        let sent = active
            .counter
            .checked_add(1)
            .filter(|counter| *counter < u16::MAX)
            .ok_or(StandardError::CounterExhausted)?;
        let required = active
            .cipher
            .packet_len(payload.len())
            .max(active.cipher.packet_len(success_len));
        admit_packet(self.card.selection(), required).map_err(StandardError::Request)?;
        let command = active.cipher.command(operation);
        let request =
            active
                .cipher
                .seal(command, sent, &mut payload)
                .ok_or(StandardError::Request(CardError::PacketBudget {
                    maximum: usize::from(u8::MAX),
                    required,
                }))?;
        let mut active = self
            .active
            .take()
            .ok_or(StandardError::SessionUnavailable)?;
        let reply = self
            .card
            .exchange_packet(&request)
            .map_err(|cause| StandardError::Exchange { command, cause })?;
        let (received, plaintext) = active.cipher.open(command + 1, reply, success_len)?;
        if received <= sent {
            return Err(StandardError::TransactionNumber { sent, received });
        }
        if let [first, second, ..] = plaintext.as_slice()
            && (*first != 0 || *second != 0)
        {
            return Err(StandardError::Status {
                first: *first,
                second: *second,
            });
        }
        let result = decode(&plaintext)?;
        active.counter = received;
        self.active = Some(active);
        Ok(result)
    }
}
