//! An NDEF file system carried by an NFC-A ISO-DEP target.

mod file;

pub use file::{MAX_TYPE4_EMULATED_NDEF_BYTES, Type4NdefChange, Type4NdefFile, Type4NdefFileError};

use crate::{
    isodep::target::{Action, Progress, Session},
    ndef::MessageError,
};
use core::fmt;
use file::{Application, Files};
use iso14443::nfca::{Rats, TargetEvent};
use port100::{
    reader::{self, IsoDepATarget, TargetWait},
    transport::Transport,
};

// The observed Port-100 ATS advertises FSC 256 and FWI 8 at 106 kbps.
const ATS: [u8; 4] = [4, 0x68, 0x80, 0];
const FSC: u16 = 256;
// This is the 64-byte framing range exercised by the RC-S370/P initiator.
const OUTBOUND_FRAME_BYTES: u16 = 64;

/// Failure preparing or operating a Type 4A target.
#[derive(Debug)]
pub enum Type4EmulationError<E> {
    /// The message exceeds the short-offset file's capacity.
    MessageLength(usize),
    /// Nonempty input must be one complete NDEF message.
    Message(MessageError),
    /// The reader failed. During service, this revokes the target.
    Reader(reader::Error<E>),
    /// The initiator's field went away during a response. Delivery may be
    /// unknown. The next receive can wait for a new activation.
    ResponseFieldOff,
    /// The change was applied to the emulated file before attempting to
    /// send the response. The initiator may not have received the response.
    /// Field loss allows a fresh activation. Other causes revoke the target.
    NdefResponse {
        /// The change already applied to the published NDEF.
        change: Type4NdefChange,
        /// The reader's response failure.
        cause: reader::Error<E>,
    },
    /// An unfinished command exhausted the short APDU budget. Finish the
    /// target before listening again.
    CommandLimit,
    /// The target session ended. Call [Type4Target::finish].
    Inactive,
}

impl<E: fmt::Debug> fmt::Display for Type4EmulationError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageLength(length) => write!(
                f,
                "NDEF message of {length} bytes exceeds {MAX_TYPE4_EMULATED_NDEF_BYTES}"
            ),
            Self::Message(error) => write!(f, "invalid NDEF message: {error}"),
            Self::Reader(error) => write!(f, "Type 4A target: {error}"),
            Self::ResponseFieldOff => f.write_str("field lost during Type 4A response"),
            Self::NdefResponse { change, cause } => {
                write!(
                    f,
                    "Type 4A response failed after NDEF change {change:?}: {cause}"
                )
            }
            Self::CommandLimit => f.write_str("chained command exceeds the short APDU limit"),
            Self::Inactive => f.write_str("Type 4A target session has ended"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for Type4EmulationError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Message(error) => Some(error),
            Self::Reader(error) | Self::NdefResponse { cause: error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Progress of one Type 4A service step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type4Event {
    /// Sent ATS and established the ISO-DEP session.
    Activated,
    /// Sent a chaining fragment, acknowledgement or retransmission.
    Block,
    /// Sent the final or only block of an APDU response.
    Exchange,
    /// Applied a change to the published NDEF and sent the APDU response.
    NdefChanged(Type4NdefChange),
    /// Left an unrelated or invalid frame unanswered.
    Ignored,
    /// No frame arrived within the receive wait.
    Silence,
    /// Lost the initiator's field. The next call can await fresh activation.
    FieldOff,
    /// Acknowledged S(DESELECT) and closed the session. Call
    /// [Type4Target::finish] to restore reader readiness.
    Deselected,
}

/// Exclusive Port-100 NFC-A target exposing a Type 4 NDEF file.
/// Each ISO-DEP activation starts with no application or file selected.
#[derive(Debug)]
pub struct Type4Target<'r, 'm, T: Transport> {
    target: IsoDepATarget<'r, T>,
    state: State,
    files: Files<'m>,
}

#[derive(Debug)]
enum State {
    WaitingForRats,
    Active {
        session: Session,
        application: Application,
    },
    Inactive,
}

impl<'r, 'm, T: Transport> Type4Target<'r, 'm, T> {
    /// Expose a read-only file with UID `08` followed by the supplied suffix.
    /// Input is validated before reader I/O. An empty message sets NLEN to zero.
    pub fn listen(
        reader: &'r mut reader::Reader<T>,
        suffix: [u8; 3],
        message: &'m [u8],
    ) -> Result<Self, Type4EmulationError<T::Error>> {
        Self::start(reader, suffix, Files::read_only(message)?)
    }

    /// Expose a writable file with UID `08` followed by the supplied suffix.
    /// Any initiator that selects the NDEF file can update its contents.
    /// The caller retains the published contents after the target releases
    /// its exclusive borrow of the file. Clearing NLEN takes effect immediately.
    /// An unfinished update loses its staged bytes when its activation ends.
    pub fn listen_writable(
        reader: &'r mut reader::Reader<T>,
        suffix: [u8; 3],
        file: &'m mut Type4NdefFile,
    ) -> Result<Self, Type4EmulationError<T::Error>> {
        Self::start(reader, suffix, Files::Writable(file))
    }

    fn start(
        reader: &'r mut reader::Reader<T>,
        suffix: [u8; 3],
        files: Files<'m>,
    ) -> Result<Self, Type4EmulationError<T::Error>> {
        let target = reader
            .listen_iso_dep_a(suffix)
            .map_err(Type4EmulationError::Reader)?;
        Ok(Self {
            target,
            state: State::WaitingForRats,
            files,
        })
    }

    /// Borrow the published NDEF bytes, including after a response failure.
    /// An empty slice corresponds to NLEN zero.
    pub fn message(&self) -> &[u8] {
        self.files.message()
    }

    /// Handle one frame. The response and next receive can share one USB
    /// command, so a following frame may already be buffered when this returns.
    /// Call again promptly while the initiator holds the field.
    pub fn serve_next(
        &mut self,
        wait: TargetWait,
    ) -> Result<Type4Event, Type4EmulationError<T::Error>> {
        if matches!(self.state, State::Inactive) {
            return Err(Type4EmulationError::Inactive);
        }
        let command = match self.target.receive(wait) {
            Ok(TargetEvent::Command(command)) => command,
            Ok(TargetEvent::Silence) => return Ok(Type4Event::Silence),
            Ok(TargetEvent::FieldOff) => {
                self.state = State::WaitingForRats;
                return Ok(Type4Event::FieldOff);
            }
            Err(error) => {
                self.state = State::Inactive;
                return Err(Type4EmulationError::Reader(error));
            }
        };
        let mut ndef_change = None;
        let (result, event) = match &mut self.state {
            State::WaitingForRats => {
                let Some(rats) = Rats::parse(command.data()) else {
                    return Ok(Type4Event::Ignored);
                };
                self.state = State::Active {
                    session: Session::new(rats.frame_size().bytes(), FSC, OUTBOUND_FRAME_BYTES),
                    application: Application::default(),
                };
                (command.respond_and_wait(&ATS, wait), Type4Event::Activated)
            }
            State::Active {
                session,
                application,
            } => {
                match session.receive(command.data(), |apdu| {
                    let (reply, change) = self.files.execute(application, apdu);
                    ndef_change = change;
                    reply
                }) {
                    Action::Ignore => return Ok(Type4Event::Ignored),
                    Action::Reply(reply, progress) => (
                        command.respond_and_wait(&reply, wait),
                        match progress {
                            Progress::Block => Type4Event::Block,
                            Progress::Exchange => Type4Event::Exchange,
                        },
                    ),
                    Action::Deselect => {
                        self.state = State::Inactive;
                        (command.respond(&[0xc2]), Type4Event::Deselected)
                    }
                    Action::CommandLimit => {
                        self.state = State::Inactive;
                        return Err(Type4EmulationError::CommandLimit);
                    }
                }
            }
            State::Inactive => return Err(Type4EmulationError::Inactive),
        };
        if let Err(cause) = result {
            let field_off = matches!(cause, reader::Error::TargetFieldOff);
            self.state = if field_off {
                State::WaitingForRats
            } else {
                State::Inactive
            };
            return Err(match ndef_change {
                Some(change) => Type4EmulationError::NdefResponse { change, cause },
                None if field_off => Type4EmulationError::ResponseFieldOff,
                None => Type4EmulationError::Reader(cause),
            });
        }
        Ok(ndef_change.map_or(event, Type4Event::NdefChanged))
    }

    /// Stop the target and restore reader readiness.
    pub fn finish(self) -> Result<(), reader::Error<T::Error>> {
        self.target.finish()
    }
}
