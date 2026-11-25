//! Synchronous USB bulk I/O and CCID transaction failures.

use core::{error, fmt, time::Duration};

/// Bulk I/O on one exclusively owned Port-400 device. The caller selects
/// the endpoints from the USB descriptors and prevents concurrent PC/SC or
/// vendor traffic, including traffic through the other USB interface.
pub trait Transport: fmt::Debug {
    /// Backend failure preserved by the reader.
    type Error: error::Error;

    /// Monotonic elapsed time, including time spent in I/O and waits.
    fn monotonic_time(&self) -> Duration;

    /// Wait at least the given RF settling time.
    fn wait(&mut self, duration: Duration);

    /// Send one complete bulk message and report the number of bytes written.
    /// An error may follow a partial or complete write. The backend must
    /// complete or cancel and reap the transfer before returning.
    fn write(&mut self, message: &[u8], timeout: Duration) -> Result<usize, Self::Error>;

    /// Read one bulk transfer, including its short-packet termination. Return
    /// initialized bytes only, and complete or cancel and reap the transfer
    /// before returning. A short transfer ending within a CCID message
    /// indicates a truncated message.
    fn read(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<usize, Self::Error>;
}

/// Last confirmed phase of a failed CCID transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// No request write was attempted.
    NotSent,
    /// A request write was attempted, and its effects may be unknown.
    Writing,
    /// The complete request was written.
    Sent,
    /// A matching time-extension message was received.
    AwaitingCompletion,
    /// A matching final response was received.
    Completed,
}

/// Reason that a USB CCID Escape transaction did not succeed.
#[derive(Debug)]
pub enum Failure<E> {
    /// The underlying USB transfer failed.
    Io(E),
    /// The total host deadline expired.
    Deadline,
    /// The connection needs to be resynchronized before reuse.
    RecoveryRequired,
    /// The command payload exceeded the supported message size.
    PayloadLength(usize),
    /// The backend reported a byte count different from the requested write.
    WriteLength {
        /// Bytes submitted.
        requested: usize,
        /// Bytes reported by the backend.
        actual: usize,
    },
    /// The reply was too short, too long, or disagreed with its length field.
    ResponseLength {
        /// Bytes reported by the backend, including the header.
        actual: usize,
        /// Declared payload length, when the complete header is available.
        declared: Option<u32>,
    },
    /// The reply was for an unexpected message type, slot, or sequence.
    UnexpectedResponse {
        /// Response message type.
        message_type: u8,
        /// Slot from the response.
        slot: u8,
        /// Sequence of the outstanding request.
        expected_sequence: u8,
        /// Sequence from the response.
        sequence: u8,
    },
    /// A reserved response header value or invalid extension was received.
    InvalidStatus {
        /// CCID status byte.
        status: u8,
        /// CCID error byte.
        error: u8,
        /// Reserved byte at the end of the CCID header.
        reserved: u8,
    },
    /// The reader returned a final CCID command failure.
    CommandFailed {
        /// CCID status byte, including ICC state.
        status: u8,
        /// CCID error byte, including `E0` for a busy slot.
        error: u8,
    },
}

/// A CCID failure with enough progress information to identify a request
/// that may already have reached the reader.
#[derive(Debug)]
pub struct TransactionError<E> {
    /// Last confirmed phase.
    pub progress: Progress,
    /// Why the transaction failed.
    pub failure: Failure<E>,
}

impl<E: fmt::Display> fmt::Display for TransactionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CCID {:?}: ", self.progress)?;
        match &self.failure {
            Failure::Io(error) => write!(f, "{error}"),
            Failure::Deadline => f.write_str("host deadline expired"),
            Failure::RecoveryRequired => f.write_str("connection requires resynchronization"),
            Failure::PayloadLength(actual) => {
                write!(f, "payload of {actual} bytes exceeds {MAX_PAYLOAD}")
            }
            Failure::WriteLength { requested, actual } => {
                write!(f, "wrote {actual} of {requested} bytes")
            }
            Failure::ResponseLength { actual, declared } => {
                write!(
                    f,
                    "response has {actual} bytes with declared payload {declared:?}"
                )
            }
            Failure::UnexpectedResponse {
                message_type,
                slot,
                expected_sequence,
                sequence,
            } => {
                write!(
                    f,
                    "unexpected response {message_type:02X}, slot {slot}, sequence {sequence} (expected {expected_sequence})"
                )
            }
            Failure::InvalidStatus {
                status,
                error,
                reserved,
            } => {
                write!(
                    f,
                    "invalid response header {status:02X} {error:02X} {reserved:02X}"
                )
            }
            Failure::CommandFailed { status, error } => {
                write!(
                    f,
                    "reader command failed with status {status:02X}, error {error:02X}"
                )
            }
        }
    }
}

impl<E: error::Error + 'static> error::Error for TransactionError<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.failure {
            Failure::Io(error) => Some(error),
            _ => None,
        }
    }
}

const HEADER_BYTES: usize = 10;
const MAX_PAYLOAD: usize = 512;
const MAX_MESSAGE: usize = HEADER_BYTES + MAX_PAYLOAD;
const BULK_PACKET_BYTES: usize = 64;
pub(crate) const READ_CAPACITY: usize = MAX_MESSAGE.next_multiple_of(BULK_PACKET_BYTES);
const HOST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub(crate) struct Link<T> {
    transport: T,
    state: LinkState,
}

#[derive(Debug, Clone, Copy)]
enum LinkState {
    Ready(u8),
    Desynchronized,
}

impl<T: Transport> Link<T> {
    pub(crate) fn new(transport: T) -> Self {
        Self {
            transport,
            state: LinkState::Ready(0),
        }
    }

    pub(crate) fn into_transport(self) -> T {
        self.transport
    }

    pub(crate) fn wait(&mut self, duration: Duration) {
        self.transport.wait(duration);
    }

    pub(crate) fn escape<'r>(
        &mut self,
        payload: &[u8],
        response: &'r mut [u8; READ_CAPACITY],
    ) -> Result<&'r [u8], TransactionError<T::Error>> {
        let LinkState::Ready(sequence) = self.state else {
            return Err(transaction_error(
                Progress::NotSent,
                Failure::RecoveryRequired,
            ));
        };
        let mut message = [0; MAX_MESSAGE];
        let Some(message) = message.get_mut(..HEADER_BYTES.saturating_add(payload.len())) else {
            return Err(transaction_error(
                Progress::NotSent,
                Failure::PayloadLength(payload.len()),
            ));
        };
        let length = u32::try_from(payload.len()).map_err(|_| {
            transaction_error(Progress::NotSent, Failure::PayloadLength(payload.len()))
        })?;
        message[0] = 0x6b;
        message[1..5].copy_from_slice(&length.to_le_bytes());
        message[6] = sequence;
        message[HEADER_BYTES..].copy_from_slice(payload);

        let deadline = self
            .transport
            .monotonic_time()
            .checked_add(HOST_TIMEOUT)
            .ok_or_else(|| transaction_error(Progress::NotSent, Failure::Deadline))?;
        let remaining = self.remaining(deadline, Progress::NotSent)?;
        self.state = LinkState::Desynchronized;
        let actual = self
            .transport
            .write(message, remaining)
            .map_err(|error| transaction_error(Progress::Writing, Failure::Io(error)))?;
        if actual != message.len() {
            return Err(transaction_error(
                Progress::Writing,
                Failure::WriteLength {
                    requested: message.len(),
                    actual,
                },
            ));
        }

        let mut progress = Progress::Sent;
        loop {
            let remaining = self.remaining(deadline, progress)?;
            let actual = self
                .transport
                .read(response, remaining)
                .map_err(|error| transaction_error(progress, Failure::Io(error)))?;
            self.remaining(deadline, progress)?;
            match escape_response(response, actual, sequence)
                .map_err(|failure| transaction_error(progress, failure))?
            {
                EscapeResponse::Success => {
                    self.state = LinkState::Ready(sequence.wrapping_add(1));
                    return Ok(&response[HEADER_BYTES..actual]);
                }
                EscapeResponse::Failed { status, error } => {
                    self.state = LinkState::Ready(sequence.wrapping_add(1));
                    return Err(transaction_error(
                        Progress::Completed,
                        Failure::CommandFailed { status, error },
                    ));
                }
                EscapeResponse::Extension => progress = Progress::AwaitingCompletion,
            }
        }
    }

    fn remaining(
        &self,
        deadline: Duration,
        progress: Progress,
    ) -> Result<Duration, TransactionError<T::Error>> {
        deadline
            .checked_sub(self.transport.monotonic_time())
            .filter(|wait| !wait.is_zero())
            .ok_or_else(|| transaction_error(progress, Failure::Deadline))
    }
}

fn transaction_error<E>(progress: Progress, failure: Failure<E>) -> TransactionError<E> {
    TransactionError { progress, failure }
}

enum EscapeResponse {
    Success,
    Failed { status: u8, error: u8 },
    Extension,
}

fn escape_response<E>(
    response: &[u8],
    actual: usize,
    expected_sequence: u8,
) -> Result<EscapeResponse, Failure<E>> {
    let Some((
        &[
            message_type,
            a,
            b,
            c,
            d,
            slot,
            sequence,
            status,
            error,
            reserved,
        ],
        payload,
    )) = response
        .get(..actual)
        .and_then(<[u8]>::split_first_chunk::<HEADER_BYTES>)
    else {
        return Err(Failure::ResponseLength {
            actual,
            declared: None,
        });
    };
    let declared = u32::from_le_bytes([a, b, c, d]);
    if actual > MAX_MESSAGE || usize::try_from(declared) != Ok(payload.len()) {
        return Err(Failure::ResponseLength {
            actual,
            declared: Some(declared),
        });
    }
    if message_type != 0x83 || slot != 0 || sequence != expected_sequence {
        return Err(Failure::UnexpectedResponse {
            message_type,
            slot,
            expected_sequence,
            sequence,
        });
    }
    if reserved == 0 && status & 0x3c == 0 && status & 0x03 != 3 {
        match status >> 6 {
            0 => return Ok(EscapeResponse::Success),
            1 => return Ok(EscapeResponse::Failed { status, error }),
            2 if payload.is_empty() => return Ok(EscapeResponse::Extension),
            _ => {}
        }
    }
    Err(Failure::InvalidStatus {
        status,
        error,
        reserved,
    })
}
