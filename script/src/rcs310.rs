//! Scripted RC-S310 and RC-S320 transport.

use rcs310::{
    device::Descriptor,
    reader::ResponseWait,
    transport::Transport,
    wire::{self, Frame},
};
use std::{cell::RefCell, collections::VecDeque, io, rc::Rc, time::Duration};

/// How the simulated reader answers one command.
#[derive(Debug)]
pub enum Answer {
    /// ACK followed by a response carrying these data bytes.
    Data(Vec<u8>),
    /// ACK, then no response before the host deadline.
    Unanswered,
    /// ACK, no response before the host deadline, then a response with
    /// these data bytes that the host must discard.
    UnansweredThenLate(Vec<u8>),
    /// ACK followed by the `7F` error frame.
    ReaderError,
}

/// One expected command and its answer.
#[derive(Debug)]
pub struct Step {
    /// Required command byte.
    pub command: u8,
    /// Required command arguments.
    pub args: Vec<u8>,
    /// Simulated reader answer.
    pub answer: Answer,
}

/// A command step answered with `data`.
pub fn command(command: u8, args: &[u8], data: &[u8]) -> Step {
    Step {
        command,
        args: args.to_vec(),
        answer: Answer::Data(data.to_vec()),
    }
}

/// A command step that the reader acknowledges but never answers.
pub fn unanswered(command: u8, args: &[u8]) -> Step {
    Step {
        command,
        args: args.to_vec(),
        answer: Answer::Unanswered,
    }
}

#[derive(Debug)]
enum Input {
    Bytes(Vec<u8>),
    Silence,
}

/// Observations of the host's use of a [`Script`].
#[derive(Debug)]
pub struct Journal {
    /// Commands received, in order.
    pub commands: Vec<(u8, Vec<u8>)>,
    /// Simulated time of each command.
    pub command_times: Vec<Duration>,
    /// Steps not yet consumed.
    pub remaining: usize,
    /// Calls of [`Transport::recover`].
    pub recoveries: usize,
}

/// A transport that requires `steps` in order and answers each one, with a
/// simulated clock that advances only through waits.
#[derive(Debug)]
pub struct Script {
    descriptor: Descriptor,
    steps: VecDeque<Step>,
    input: VecDeque<Input>,
    journal: Rc<RefCell<Journal>>,
    elapsed: Duration,
}

impl Script {
    /// A script for a device with `descriptor` and the journal that records its use.
    pub fn new(descriptor: Descriptor, steps: Vec<Step>) -> (Self, Rc<RefCell<Journal>>) {
        let journal = Rc::new(RefCell::new(Journal {
            commands: Vec::new(),
            command_times: Vec::new(),
            remaining: steps.len(),
            recoveries: 0,
        }));
        (
            Self {
                descriptor,
                steps: steps.into(),
                input: VecDeque::new(),
                journal: Rc::clone(&journal),
                elapsed: Duration::ZERO,
            },
            journal,
        )
    }
}

// Independent frame oracle for the simulated reader.
fn reader_frame(data: &[u8]) -> io::Result<Vec<u8>> {
    let length = u8::try_from(data.len())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut bytes = vec![0, 0, 0xff, length, length.wrapping_neg()];
    bytes.extend_from_slice(data);
    let checksum = data
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
        .wrapping_neg();
    bytes.extend_from_slice(&[checksum, 0]);
    Ok(bytes)
}

fn response(command: u8, data: &[u8]) -> io::Result<Vec<u8>> {
    let response = command
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "response command overflow"))?;
    reader_frame(&[&[response], data].concat())
}

const ACK: [u8; 6] = [0, 0, 0xff, 0, 0xff, 0];

impl Transport for Script {
    type Error = io::Error;

    fn descriptor(&self) -> Descriptor {
        self.descriptor
    }

    fn monotonic_time(&self) -> Duration {
        self.elapsed
    }

    fn wait(&mut self, duration: Duration) {
        self.elapsed += duration;
    }

    fn write(&mut self, bytes: &[u8], timeout: Duration) -> io::Result<usize> {
        assert!(!timeout.is_zero());
        assert!(
            self.input.is_empty(),
            "new command before consuming or discarding the preceding reply"
        );
        let Frame::Data { command, data } = wire::parse(bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "host sent a non-command frame",
            ));
        };
        let step = self.steps.pop_front().ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected reader command")
        })?;
        assert_eq!(
            (command, data),
            (step.command, step.args.as_slice()),
            "wire command order or arguments"
        );
        {
            let mut journal = self.journal.borrow_mut();
            journal.commands.push((command, data.to_vec()));
            journal.command_times.push(self.elapsed);
            journal.remaining = self.steps.len();
        }
        self.input.push_back(Input::Bytes(ACK.to_vec()));
        match step.answer {
            Answer::Data(data) => self
                .input
                .push_back(Input::Bytes(response(command, &data)?)),
            Answer::Unanswered => self.input.push_back(Input::Silence),
            Answer::UnansweredThenLate(data) => {
                self.input.push_back(Input::Silence);
                self.input
                    .push_back(Input::Bytes(response(command, &data)?));
            }
            Answer::ReaderError => self.input.push_back(Input::Bytes(reader_frame(&[0x7f])?)),
        }
        Ok(bytes.len())
    }

    fn read(&mut self, buffer: &mut [u8], timeout: Duration) -> io::Result<usize> {
        assert!(!timeout.is_zero());
        match self.input.pop_front() {
            Some(Input::Bytes(mut bytes)) => {
                // A read returns at most the supplied capacity; the rest stays queued.
                if bytes.len() > buffer.len() {
                    self.input
                        .push_front(Input::Bytes(bytes.split_off(buffer.len())));
                }
                buffer[..bytes.len()].copy_from_slice(&bytes);
                Ok(bytes.len())
            }
            Some(Input::Silence) => {
                self.elapsed += timeout;
                Ok(0)
            }
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read without a pending reader reply",
            )),
        }
    }

    fn recover(&mut self) -> io::Result<()> {
        self.input.clear();
        self.journal.borrow_mut().recoveries += 1;
        Ok(())
    }
}

/// An RC-S320 descriptor (`054C:01BB`, release 0128).
pub fn rcs320() -> Descriptor {
    Descriptor {
        vendor_id: 0x054c,
        product_id: 0x01bb,
        device_subclass: 0,
        release: 0x0128,
    }
}

/// Firmware bytes answered by [`rcs320_initialization`].
pub const FIRMWARE: [u8; 2] = [0x13, 0x01];

/// Steps of `Reader::initialize` on an RC-S320 whose registers `80`, `81`,
/// `82` and `87` read `CC`, `88`, `88` and `01`.
pub fn rcs320_initialization() -> Vec<Step> {
    vec![
        command(0x58, &[], &FIRMWARE),
        command(0x62, &[2, 0x80, 0x81], &[0, 0xcc, 0x88]),
        command(0x62, &[0x22, 0x80, 0xcc, 0x81, 0x88], &[0]),
        command(0x62, &[2, 0x80, 0x81], &[0, 0xcc, 0x88]),
        command(0x62, &[2, 0x82, 0x87], &[0, 0x88, 0x01]),
        command(0x62, &[0x21, 0x25, 0x58], &[0]),
        command(0x5a, &[0x80], &[0]),
        command(0x54, &[], &[0]),
    ]
}

/// IDm of the card in [`polling_reply`].
pub const IDENTITY: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

/// PMm of the card in [`polling_reply`].
pub const PARAMETERS: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

/// The `5D` data of one card's Polling response without request data.
pub fn polling_reply() -> Vec<u8> {
    let mut packet = vec![18, 1];
    packet.extend_from_slice(&IDENTITY);
    packet.extend_from_slice(&PARAMETERS);
    packet
}

/// A 100 ms card wait.
pub fn wait() -> Option<ResponseWait> {
    ResponseWait::new(Duration::from_millis(100))
}
