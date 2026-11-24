//! Exclusive command transactions over a bounded byte transport.

use crate::wire::{self, Frame, FrameError};
use alloc::vec::Vec;
use core::{cmp::Ordering, error, fmt, time::Duration};

/// Backend transfer contract. Reads return initialized bytes only; each operation
/// must finish or cancel and reap its I/O before returning. A write error may have
/// sent bytes, so callers must not assume that an error means zero device effects.
pub trait Transport: fmt::Debug {
    /// Backend failure, preserved in transaction errors.
    type Error: error::Error;

    /// Elapsed time since a fixed epoch for this transport. Values must be
    /// nondecreasing and account for transfers and waits.
    fn monotonic_time(&self) -> Duration;
    /// Block for at least the requested duration, including reader settle times.
    fn wait(&mut self, duration: Duration);
    /// Send one frame on the bulk OUT endpoint, ending it with a zero-length
    /// packet when its length is a multiple of the endpoint's packet size.
    fn write(&mut self, frame: &[u8], timeout: Duration) -> Result<usize, Self::Error>;
    /// Receive at most `buffer.len()` bytes from the bulk IN endpoint within
    /// the backend's timeout policy. Returning zero bytes ends the
    /// transaction with [`Failure::Deadline`].
    fn read(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<usize, Self::Error>;
    /// Discard cached input bytes. Do not reset or clear the halt of an
    /// endpoint that has not stalled: the RC-S380 keeps its data toggle
    /// across CLEAR_FEATURE(ENDPOINT_HALT), so such a reset can lose the
    /// next ACK. This does not cancel a reader command or establish whether
    /// a prior card operation executed.
    fn recover(&mut self) -> Result<(), Self::Error>;
}

/// Last externally visible phase reached by a failed transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// No send was attempted.
    NotSent,
    /// A send was attempted; the device outcome may be unknown.
    Sending,
    /// Complete host frame sent; ACK has not been observed.
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
    /// A short host transfer cannot establish command completion.
    ShortWrite {
        /// Requested bytes.
        requested: usize,
        /// Confirmed bytes.
        transferred: usize,
    },
    /// The backend reported more bytes than the frame it was given.
    TransmitLength {
        /// Frame bytes supplied to the backend.
        requested: usize,
        /// Reported bytes.
        reported: usize,
    },
    /// The backend reported more bytes than the supplied buffer could hold.
    ReceiveLength {
        /// Available buffer bytes.
        capacity: usize,
        /// Reported bytes.
        reported: usize,
    },
    /// Reader returned NAK instead of ACK.
    Nak,
    /// Reader returned the `7F` error frame.
    ReaderError,
    /// Frame was valid but occurred in the wrong transaction phase.
    UnexpectedFrame,
    /// [`Link::command`] cannot transact this request command: ResetDevice
    /// (`12`) is answered by a host ACK instead of a read response, and `FF`
    /// has no response command.
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
            Failure::ShortWrite {
                requested,
                transferred,
            } => write!(f, "short write of {transferred} of {requested} bytes")?,
            Failure::TransmitLength {
                requested,
                reported,
            } => write!(
                f,
                "backend reported {reported} bytes written for a {requested}-byte frame"
            )?,
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
/// The reader answers a command with ACK and then its response. Every
/// failure after the first write attempt leaves the command's state on the
/// reader unknown and requires [`Link::recover`], which cancels it.
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

const RESET_DEVICE: u8 = 0x12;
/// Host wait for the cancelling ACK write.
const CANCEL_WRITE: Duration = Duration::from_secs(1);
/// Time the reader is given to drop a cancelled command before cached input
/// is discarded again.
const CANCEL_SETTLE: Duration = Duration::from_millis(10);

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
    /// Take ownership of a newly opened transport without sending data.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            state: StreamState::Ready,
        }
    }

    /// Send one command and return its matching response. ACK and response
    /// must both arrive within `timeout`. No automatic replay.
    ///
    /// # Errors
    ///
    /// Rejects ResetDevice (`12`) and `FF` with
    /// [`Failure::UnsupportedCommand`] before sending. Every failure after
    /// the first write attempt requires [`Link::recover`].
    pub fn command(
        &mut self,
        command: u8,
        args: &[u8],
        timeout: Duration,
    ) -> Result<Response, TransactionError<T::Error>> {
        if self.state != StreamState::Ready {
            return Err(not_sent(Failure::RecoveryRequired));
        }
        if command == RESET_DEVICE {
            return Err(not_sent(Failure::UnsupportedCommand(command)));
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
        let remaining = deadline
            .remaining(self.transport.monotonic_time())
            .ok_or(not_sent(Failure::Deadline))?;
        self.send_frame(frame, remaining)?;
        let mut pending = Vec::with_capacity(PENDING_CAPACITY);
        let mut progress = Progress::Sent;
        loop {
            let packet = next_frame(&mut self.transport, &mut pending, deadline)
                .map_err(|failure| TransactionError { progress, failure })?;
            let failure = match wire::parse(&packet) {
                Err(error) => Failure::Frame(error),
                Ok(Frame::Ack) if progress == Progress::Sent => {
                    progress = Progress::Acknowledged;
                    continue;
                }
                Ok(Frame::Nak) => Failure::Nak,
                Ok(Frame::ReaderError) => Failure::ReaderError,
                Ok(Frame::Data {
                    command: actual,
                    data,
                }) if progress == Progress::Acknowledged => {
                    if actual != expected {
                        Failure::ResponseCommand { expected, actual }
                    } else if !pending.is_empty() {
                        Failure::TrailingData
                    } else {
                        return Ok(data.to_vec());
                    }
                }
                Ok(Frame::Ack | Frame::Data { .. }) => Failure::UnexpectedFrame,
            };
            return Err(TransactionError { progress, failure });
        }
    }

    /// Write one complete host frame. The stream requires recovery from the
    /// write attempt until the caller publishes the next state.
    fn send_frame(
        &mut self,
        frame: &[u8],
        timeout: Duration,
    ) -> Result<(), TransactionError<T::Error>> {
        self.state = StreamState::RecoveryRequired;
        let sending = |failure| TransactionError {
            progress: Progress::Sending,
            failure,
        };
        let reported = self
            .transport
            .write(frame, timeout)
            .map_err(|e| sending(Failure::Io(e)))?;
        match reported.cmp(&frame.len()) {
            Ordering::Equal => Ok(()),
            Ordering::Less => Err(sending(Failure::ShortWrite {
                requested: frame.len(),
                transferred: reported,
            })),
            Ordering::Greater => Err(sending(Failure::TransmitLength {
                requested: frame.len(),
                reported,
            })),
        }
    }

    /// Recover the transport, cancel an unfinished reader command with a host
    /// ACK, wait 10 ms, then recover the transport again and admit commands. This
    /// never determines whether a preceding card operation executed.
    ///
    /// # Errors
    ///
    /// A failure leaves the link requiring recovery; its progress tells
    /// whether the cancelling ACK was sent.
    pub fn recover(&mut self) -> Result<(), TransactionError<T::Error>> {
        self.state = StreamState::RecoveryRequired;
        self.transport
            .recover()
            .map_err(|e| not_sent(Failure::Io(e)))?;
        self.send_frame(&wire::ACK, CANCEL_WRITE)?;
        self.transport.wait(CANCEL_SETTLE);
        self.transport.recover().map_err(|e| TransactionError {
            progress: Progress::Sent,
            failure: Failure::Io(e),
        })?;
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

/// Bytes read per backend call; one call can hold a complete frame.
const READ_CHUNK: usize = wire::MAX_FRAME;
/// `pending` holds less than one frame before each read, so it never exceeds
/// an incomplete frame plus one chunk.
const PENDING_CAPACITY: usize = wire::MAX_FRAME - 1 + READ_CHUNK;

fn next_frame<T: Transport>(
    transport: &mut T,
    pending: &mut Vec<u8>,
    deadline: Deadline,
) -> Result<Vec<u8>, Failure<T::Error>> {
    loop {
        if let Some(length) = wire::frame_length(pending).map_err(Failure::Frame)?
            && pending.len() >= length
        {
            return Ok(pending.drain(..length).collect());
        }
        let remaining = deadline
            .remaining(transport.monotonic_time())
            .ok_or(Failure::Deadline)?;
        let mut buffer = [0u8; READ_CHUNK];
        let n = transport
            .read(&mut buffer, remaining)
            .map_err(Failure::Io)?;
        // Admit only bytes from a read that completed before the deadline.
        if n == 0 || deadline.remaining(transport.monotonic_time()).is_none() {
            return Err(Failure::Deadline);
        }
        let bytes = buffer.get(..n).ok_or(Failure::ReceiveLength {
            capacity: buffer.len(),
            reported: n,
        })?;
        pending.extend_from_slice(bytes);
    }
}
