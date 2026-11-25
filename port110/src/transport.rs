//! Exclusive command transactions over the reader's GATT service.
//!
//! The host writes each command frame to [`COMMAND`] in values of at most
//! [`MAX_WRITE`] bytes. The reader indicates an ACK on [`RESPONSE`] as a value
//! of its own and then the response frame, which may span several values.

use crate::wire::{self, Frame, FrameError};
use alloc::vec::Vec;
use core::{error, fmt, time::Duration};

/// UUID of the reader's GATT service.
pub const SERVICE: u128 = 0x233e8100_3a1b_1c59_9bee_180373dd03a1;
/// UUID of the characteristic whose indications carry the reader's ACK and
/// response frames.
pub const RESPONSE: u128 = 0x233e8101_3a1b_1c59_9bee_180373dd03a1;
/// UUID of the characteristic on which Sony's driver enables notifications.
/// Their values are not part of the command stream.
pub const NOTIFICATION: u128 = 0x233e8102_3a1b_1c59_9bee_180373dd03a1;
/// UUID of the characteristic that receives the host's command frames.
pub const COMMAND: u128 = 0x233e8103_3a1b_1c59_9bee_180373dd03a1;
/// Largest value of one command write.
pub const MAX_WRITE: usize = 20;
/// Largest attribute value that one indication can carry.
pub const MAX_VALUE: usize = 512;

/// GATT backend contract.
///
/// The backend owns the connection: it discovers [`SERVICE`], enables
/// indications on [`RESPONSE`] and notifications on [`NOTIFICATION`] as Sony's
/// driver does, with encryption and authentication, and re-establishes them
/// after a reconnection. Each operation must finish or cancel its I/O before
/// returning. A write error may have delivered the value, so callers must not
/// assume that an error means zero device effects.
pub trait Transport: fmt::Debug {
    /// Backend failure, preserved in transaction errors.
    type Error: error::Error;

    /// Elapsed time since a fixed epoch for this transport. Values must be
    /// nondecreasing and account for transfers and waits.
    fn monotonic_time(&self) -> Duration;
    /// Block for at least the requested duration, including reader settle times.
    fn wait(&mut self, duration: Duration);
    /// Write `value`, at most [`MAX_WRITE`] bytes, to [`COMMAND`] with a write
    /// request, returning once the write response arrives.
    fn write(&mut self, value: &[u8], timeout: Duration) -> Result<(), Self::Error>;
    /// Copy the oldest unread indication value of [`RESPONSE`] into `buffer`
    /// and return its length, or `None` when no value arrives within
    /// `timeout`. Values that arrive while no receive is pending, including
    /// during writes, must be queued in arrival order, not dropped.
    fn receive(
        &mut self,
        buffer: &mut [u8; MAX_VALUE],
        timeout: Duration,
    ) -> Result<Option<usize>, Self::Error>;
}

/// Last externally visible phase reached by a failed transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// No write was attempted.
    NotSent,
    /// A write was attempted; the reader may hold part of the frame.
    Sending,
    /// Complete host frame written; ACK has not been observed.
    Sent,
    /// ACK received; a matching response is still needed.
    Acknowledged,
}

/// Machine-readable failure independent of display text.
#[derive(Debug)]
pub enum Failure<E> {
    /// Host validation or reader frame validation failed.
    Frame(FrameError),
    /// OS/device transport failure.
    Io(E),
    /// A prior failed transaction requires explicit recovery.
    RecoveryRequired,
    /// Finite host deadline expired.
    Deadline,
    /// The backend reported more bytes than an indication value can hold.
    ReceiveLength {
        /// Available buffer bytes.
        capacity: usize,
        /// Reported bytes.
        reported: usize,
    },
    /// Reader returned NAK instead of a response.
    Nak,
    /// Reader returned the `7F` error frame.
    ReaderError,
    /// Frame was valid but occurred in the wrong transaction phase.
    UnexpectedFrame,
    /// `FF` has no response command, so [`Link::command`] cannot transact it.
    UnsupportedCommand(u8),
    /// The response was for a different command.
    ResponseCommand {
        /// Expected response command.
        expected: u8,
        /// Received response command.
        actual: u8,
    },
    /// A valid response was followed by unconsumed bytes.
    TrailingData,
}

/// Transaction failure plus progress. Any value other than `NotSent` may carry
/// device effects, even if ACK was not seen.
#[derive(Debug)]
pub struct TransactionError<E> {
    /// Phase reached before failure.
    pub progress: Progress,
    /// Specific reason for failure.
    pub failure: Failure<E>,
}

impl<E: fmt::Debug> fmt::Display for TransactionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.failure {
            Failure::Frame(_) => f.write_str("invalid frame")?,
            Failure::Io(_) => f.write_str("transport I/O failed")?,
            Failure::RecoveryRequired => f.write_str("stream requires recovery")?,
            Failure::Deadline => f.write_str("host deadline expired")?,
            Failure::ReceiveLength { capacity, reported } => {
                write!(
                    f,
                    "backend reported {reported} bytes for a {capacity}-byte buffer"
                )?;
            }
            Failure::Nak => f.write_str("reader returned NAK")?,
            Failure::ReaderError => f.write_str("reader returned an error frame")?,
            Failure::UnexpectedFrame => {
                f.write_str("unexpected frame for the transaction phase")?
            }
            Failure::UnsupportedCommand(command) => {
                write!(
                    f,
                    "command {command:02X} cannot be sent as an ordinary command"
                )?;
            }
            Failure::ResponseCommand { expected, actual } => {
                write!(f, "response command {actual:02X}, expected {expected:02X}")?;
            }
            Failure::TrailingData => f.write_str("unconsumed bytes followed the response")?,
        }
        f.write_str(match self.progress {
            Progress::NotSent => " before sending",
            Progress::Sending => " while sending",
            Progress::Sent => " before ACK",
            Progress::Acknowledged => " after ACK",
        })
    }
}

impl<E: error::Error + 'static> error::Error for TransactionError<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.failure {
            Failure::Frame(error) => Some(error),
            Failure::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// Owned command response, with the direction and response command removed.
#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    /// Matched response command (request + 1).
    pub command: u8,
    /// Command-specific bytes. These do not always begin with a status byte.
    pub data: Vec<u8>,
}

/// Owner of a single, serialized command stream.
///
/// Every failure after the first write attempt leaves the reader's frame
/// parser and the command's state unknown and requires [`Link::recover`].
#[derive(Debug)]
pub struct Link<T: Transport> {
    transport: T,
    state: StreamState,
}

#[derive(Debug, PartialEq, Eq)]
enum StreamState {
    Ready,
    RecoveryRequired,
}

/// Host deadline for writing the zero fill of a resynchronization.
const FILL_WRITE: Duration = Duration::from_secs(40);
/// Host deadline for the ACK write that ends the fill.
const ACK_WRITE: Duration = Duration::from_secs(1);
/// Silence that ends the discarding of indications after the fill.
const QUIET: Duration = Duration::from_millis(2800);
/// Host bound on discarding indications that keep arriving after the fill.
const DISCARD_LIMIT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Deadline(Duration);

impl Deadline {
    fn after(now: Duration, timeout: Duration) -> Option<Self> {
        now.checked_add(timeout).map(Self)
    }

    fn remaining(self, now: Duration) -> Option<Duration> {
        self.0.checked_sub(now).filter(|wait| !wait.is_zero())
    }
}

impl<T: Transport> Link<T> {
    /// Take ownership of a connected transport without sending data.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            state: StreamState::Ready,
        }
    }

    /// Send one command and return its matching response. The writes, the
    /// ACK and the response must all complete within `timeout`. Indications
    /// that arrive before the ACK, other than the ACK itself, are discarded,
    /// as Sony's driver does. No automatic replay.
    ///
    /// # Errors
    ///
    /// Rejects `FF` with [`Failure::UnsupportedCommand`] before sending.
    /// Every failure after the first write attempt requires [`Link::recover`].
    pub fn command(
        &mut self,
        command: u8,
        args: &[u8],
        timeout: Duration,
    ) -> Result<Response, TransactionError<T::Error>> {
        if self.state != StreamState::Ready {
            return Err(not_sent(Failure::RecoveryRequired));
        }
        let expected = command
            .checked_add(1)
            .ok_or(not_sent(Failure::UnsupportedCommand(command)))?;
        if timeout.is_zero() {
            return Err(not_sent(Failure::Deadline));
        }
        let frame = wire::encode(command, args).map_err(|e| not_sent(Failure::Frame(e)))?;
        let deadline = Deadline::after(self.transport.monotonic_time(), timeout)
            .ok_or(not_sent(Failure::Deadline))?;
        let data = self.transact(&frame, expected, deadline)?;
        self.state = StreamState::Ready;
        Ok(Response {
            command: expected,
            data,
        })
    }

    /// Run one admitted transaction. The stream stays in `RecoveryRequired`
    /// from the first write until the caller publishes the next state.
    fn transact(
        &mut self,
        frame: &[u8],
        expected: u8,
        deadline: Deadline,
    ) -> Result<Vec<u8>, TransactionError<T::Error>> {
        self.send(frame, deadline)?;
        let mut value = [0; MAX_VALUE];
        loop {
            let received =
                self.next_value(&mut value, deadline)
                    .map_err(|failure| TransactionError {
                        progress: Progress::Sent,
                        failure,
                    })?;
            if received == wire::ACK {
                break;
            }
        }
        let acknowledged = |failure| TransactionError {
            progress: Progress::Acknowledged,
            failure,
        };
        let mut pending = Vec::new();
        loop {
            if let Some(length) =
                wire::frame_length(&pending).map_err(|e| acknowledged(Failure::Frame(e)))?
                && pending.len() >= length
            {
                let (frame, rest) = pending.split_at(length);
                let failure = match wire::parse(frame) {
                    Err(error) => Failure::Frame(error),
                    Ok(Frame::Nak) => Failure::Nak,
                    Ok(Frame::ReaderError) => Failure::ReaderError,
                    Ok(Frame::Ack) => Failure::UnexpectedFrame,
                    Ok(Frame::Data { command, .. }) if command != expected => {
                        Failure::ResponseCommand {
                            expected,
                            actual: command,
                        }
                    }
                    Ok(Frame::Data { .. }) if !rest.is_empty() => Failure::TrailingData,
                    Ok(Frame::Data { data, .. }) => return Ok(data.to_vec()),
                };
                return Err(acknowledged(failure));
            }
            let received = self
                .next_value(&mut value, deadline)
                .map_err(acknowledged)?;
            pending.extend_from_slice(received);
        }
    }

    /// Write `bytes` in values of at most [`MAX_WRITE`] bytes before
    /// `deadline`. The stream requires recovery from the first write attempt
    /// until the caller publishes the next state.
    fn send(&mut self, bytes: &[u8], deadline: Deadline) -> Result<(), TransactionError<T::Error>> {
        let sending = |failure| TransactionError {
            progress: Progress::Sending,
            failure,
        };
        for (index, value) in bytes.chunks(MAX_WRITE).enumerate() {
            let remaining =
                deadline
                    .remaining(self.transport.monotonic_time())
                    .ok_or(TransactionError {
                        progress: if index == 0 {
                            Progress::NotSent
                        } else {
                            Progress::Sending
                        },
                        failure: Failure::Deadline,
                    })?;
            self.state = StreamState::RecoveryRequired;
            self.transport
                .write(value, remaining)
                .map_err(|e| sending(Failure::Io(e)))?;
        }
        Ok(())
    }

    /// Receive the next indication value that arrives before `deadline`.
    fn next_value<'b>(
        &mut self,
        buffer: &'b mut [u8; MAX_VALUE],
        deadline: Deadline,
    ) -> Result<&'b [u8], Failure<T::Error>> {
        let remaining = deadline
            .remaining(self.transport.monotonic_time())
            .ok_or(Failure::Deadline)?;
        let length = self
            .transport
            .receive(buffer, remaining)
            .map_err(Failure::Io)?
            .ok_or(Failure::Deadline)?;
        // Admit only a value that arrived before the deadline.
        if deadline
            .remaining(self.transport.monotonic_time())
            .is_none()
        {
            return Err(Failure::Deadline);
        }
        buffer.get(..length).ok_or(Failure::ReceiveLength {
            capacity: MAX_VALUE,
            reported: length,
        })
    }

    /// Resynchronize the reader's frame parser: write one maximum frame of
    /// zero bytes and an ACK, then discard indications until none arrives
    /// for 2.8 s, as Sony's driver does, and admit commands. This never
    /// determines whether a preceding card operation executed.
    ///
    /// # Errors
    ///
    /// A failure leaves the link requiring recovery. Discarding fails with
    /// [`Failure::Deadline`] when indications keep arriving for 30 s.
    pub fn recover(&mut self) -> Result<(), TransactionError<T::Error>> {
        self.state = StreamState::RecoveryRequired;
        let now = self.transport.monotonic_time();
        let fill = Deadline::after(now, FILL_WRITE).ok_or(not_sent(Failure::Deadline))?;
        self.send(&[0; wire::MAX_FRAME], fill)?;
        let now = self.transport.monotonic_time();
        let ack = Deadline::after(now, ACK_WRITE).ok_or(not_sent(Failure::Deadline))?;
        self.send(&wire::ACK, ack)?;
        let discarding = |failure| TransactionError {
            progress: Progress::Sent,
            failure,
        };
        let limit = Deadline::after(self.transport.monotonic_time(), DISCARD_LIMIT)
            .ok_or(discarding(Failure::Deadline))?;
        let mut value = [0; MAX_VALUE];
        loop {
            if limit.remaining(self.transport.monotonic_time()).is_none() {
                return Err(discarding(Failure::Deadline));
            }
            let received = self
                .transport
                .receive(&mut value, QUIET)
                .map_err(|e| discarding(Failure::Io(e)))?;
            if received.is_none() {
                break;
            }
        }
        self.state = StreamState::Ready;
        Ok(())
    }

    pub(crate) fn wait(&mut self, duration: Duration) {
        self.transport.wait(duration);
    }
}

fn not_sent<E>(failure: Failure<E>) -> TransactionError<E> {
    TransactionError {
        progress: Progress::NotSent,
        failure,
    }
}
