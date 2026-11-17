//! Scripted RC-S956 transport for wire-level tests of `rcs956` and `pasori`.
//!
//! Responses are built independently of the production frame encoder. The
//! script models command and response contracts, not physical device timing.

use felica_packet::{PollRequest, PollRequestError};
use rcs956::{
    reader::{RfTimeout, TimeoutRange},
    transport::Transport,
    wire::{self, Direction, Frame},
};
use std::{cell::RefCell, collections::VecDeque, io, rc::Rc, time::Duration};

/// One host frame the reader receives.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    /// A command code and its arguments.
    Command(u8, Vec<u8>),
    /// A host ACK.
    HostAck,
}

/// How the simulated reader answers one request.
#[derive(Debug)]
pub enum Answer {
    /// ACK followed by a response carrying these data bytes.
    Data(Vec<u8>),
    /// ACK, then the response is lost.
    LostAfterAck,
    /// Response data that completes the given time after the ACK.
    Late(Duration, Vec<u8>),
}

/// One expected request and its answer.
#[derive(Debug)]
pub struct Step {
    /// Required host frame.
    pub request: Request,
    /// Simulated reader answer.
    pub answer: Answer,
}

/// A command step answered with `data`.
pub fn command(cc: u8, args: &[u8], data: &[u8]) -> Step {
    Step {
        request: Request::Command(cc, args.to_vec()),
        answer: Answer::Data(data.to_vec()),
    }
}

#[derive(Debug)]
enum Input {
    Bytes(Vec<u8>),
    Late(Duration, Vec<u8>),
    Timeout,
}

/// Observations of the host's use of a [`Script`].
#[derive(Debug)]
pub struct Journal {
    /// Requests received, in order.
    pub requests: Vec<Request>,
    /// Simulated time of each request.
    pub request_times: Vec<Duration>,
    /// Simulated time when the last read completed.
    pub last_read_completed: Option<Duration>,
    /// Steps not yet consumed.
    pub remaining: usize,
    /// Calls of [`Transport::recover`].
    pub recoveries: usize,
}

/// A transport that requires `steps` in order and answers each one, with a
/// simulated clock that advances only through waits and late answers.
#[derive(Debug)]
pub struct Script {
    steps: VecDeque<Step>,
    input: VecDeque<Input>,
    journal: Rc<RefCell<Journal>>,
    elapsed: Duration,
}

impl Script {
    /// A script and the journal that records its use.
    pub fn new(steps: Vec<Step>) -> (Self, Rc<RefCell<Journal>>) {
        let journal = Rc::new(RefCell::new(Journal {
            requests: Vec::new(),
            request_times: Vec::new(),
            last_read_completed: None,
            remaining: steps.len(),
            recoveries: 0,
        }));
        (
            Self {
                steps: steps.into(),
                input: VecDeque::new(),
                journal: Rc::clone(&journal),
                elapsed: Duration::ZERO,
            },
            journal,
        )
    }
}

// Independent response-frame oracle for the simulated reader.
fn reader_response(cc: u8, data: &[u8]) -> io::Result<Vec<u8>> {
    let length = u16::try_from(data.len() + 2)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut bytes = vec![0, 0, 0xff];
    if let Ok(length) = u8::try_from(length) {
        bytes.extend([length, length.wrapping_neg()]);
    } else {
        let [high, low] = length.to_be_bytes();
        bytes.extend([0xff, 0xff, high, low, high.wrapping_add(low).wrapping_neg()]);
    }
    bytes.extend([0xd5, cc]);
    bytes.extend_from_slice(data);
    let checksum = data
        .iter()
        .fold(0xd5_u8.wrapping_add(cc), |sum, byte| {
            sum.wrapping_add(*byte)
        })
        .wrapping_neg();
    bytes.extend_from_slice(&[checksum, 0]);
    Ok(bytes)
}

impl Transport for Script {
    type Error = io::Error;

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
            "new command before consuming the preceding reply"
        );
        let actual = match wire::parse(bytes, Direction::Host)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        {
            Frame::Ack => Request::HostAck,
            Frame::Data { command, data } => Request::Command(command, data.to_vec()),
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected host frame {other:?}"),
                ));
            }
        };
        let step = self.steps.pop_front().ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected reader command")
        })?;
        assert_eq!(actual, step.request, "wire request order or arguments");
        self.journal.borrow_mut().requests.push(actual.clone());
        self.journal.borrow_mut().request_times.push(self.elapsed);
        self.journal.borrow_mut().remaining = self.steps.len();
        match actual {
            Request::HostAck => {}
            Request::Command(cc, _) => match step.answer {
                Answer::Data(data) => {
                    let response_cc = cc.checked_add(1).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "response command overflow")
                    })?;
                    self.input.push_back(Input::Bytes(
                        [wire::ACK.to_vec(), reader_response(response_cc, &data)?].concat(),
                    ));
                }
                Answer::LostAfterAck => {
                    self.input.push_back(Input::Bytes(wire::ACK.to_vec()));
                    self.input.push_back(Input::Timeout);
                }
                Answer::Late(delay, data) => {
                    let response_cc = cc.checked_add(1).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "response command overflow")
                    })?;
                    self.input.push_back(Input::Bytes(wire::ACK.to_vec()));
                    self.input
                        .push_back(Input::Late(delay, reader_response(response_cc, &data)?));
                }
            },
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
                self.journal.borrow_mut().last_read_completed = Some(self.elapsed);
                Ok(bytes.len())
            }
            Some(Input::Late(delay, bytes)) => {
                self.elapsed += delay;
                self.input.push_front(Input::Bytes(bytes));
                self.read(buffer, timeout)
            }
            Some(Input::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "scripted reader response loss",
            )),
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

/// A valid configuration image with model 0131 and FeliCa RF bytes 1..=8.
pub fn config_image() -> [u8; 256] {
    let mut bytes = [0; 256];
    bytes[0] = 0x55;
    bytes[1] = 0xaa;
    bytes[2] = 1;
    bytes[0x1b..=0x22].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    bytes[0x3f] = 0xdc;
    bytes[0x40] = 0x11;
    bytes[0x41] = 0x22;
    bytes[0x80] = 0x33;
    bytes[0xbf] = 0x9a;
    bytes[0xfd] = 1;
    bytes[0xfe] = 0x31;
    bytes
}

/// Register addresses of one 64-byte configuration bank read.
pub fn bank_addresses(bank: u8) -> Vec<u8> {
    (0u8..64)
        .flat_map(|index| [0xa0, bank * 64 + index])
        .collect()
}

/// Steps of `Reader::initialize` on a reader holding `config`.
pub fn initialization(config: &[u8; 256]) -> Vec<Step> {
    let mut steps = vec![
        Step {
            request: Request::HostAck,
            answer: Answer::Data(Vec::new()),
        },
        command(0x18, &[1], &[]),
        Step {
            request: Request::HostAck,
            answer: Answer::Data(Vec::new()),
        },
        command(2, &[], &[0x32, 1, 6, 7]),
        command(6, &[0xa0, 0], &[0x55]),
    ];
    for bank in 0u8..4 {
        let begin = usize::from(bank) * 64;
        steps.push(command(
            6,
            &bank_addresses(bank),
            &config[begin..begin + 64],
        ));
    }
    steps.extend([
        command(0x0c, &[], &[0x1c]),
        command(0x12, &[0x1c], &[]),
        command(0x32, &[4, 0], &[]),
        command(8, &[0x63, 0x0a, 0x40], &[0]),
        command(8, &[0x63, 0x0d, 0], &[0]),
        command(0x32, &[1, 0], &[]),
    ]);
    steps
}

/// Receiver probe before InListPassiveTarget, answered with an idle receiver.
pub fn idle_receiver() -> Step {
    command(6, &[0x63, 0x37, 0x63, 0x31], &[0, 0])
}

/// FeliCa RF configuration with a 100 ms timer after [`initialization`].
pub fn mode_configuration() -> Vec<Step> {
    vec![
        command(0x1c, &[0x80, 0x63, 0], &[]),
        command(0x32, &[5, 0, 0, 0], &[]),
        command(0x32, &[0x81, 0xb7], &[]),
        command(0x32, &[0x0b, 1, 2, 3, 4, 5, 6, 7, 8], &[]),
        command(8, &[0x63, 0x0d, 0], &[0]),
    ]
}

/// IDm of the card in [`poll_response`].
pub const IDENTITY: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

/// PMm of the card in [`poll_response`].
pub const PARAMETERS: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

/// Polling of system 1234 with system-code request data.
pub fn poll_request() -> Result<PollRequest, PollRequestError> {
    PollRequest::new(0x1234, 1, 0)
}

/// InListPassiveTarget reply carrying one FeliCa card at 212 kbps.
pub fn poll_response() -> Vec<u8> {
    let mut packet = vec![1, 7, 18, 1];
    packet.extend_from_slice(&IDENTITY);
    packet.extend_from_slice(&PARAMETERS);
    packet
}

/// A 100 ms RF wait.
pub fn timeout() -> Result<RfTimeout, TimeoutRange> {
    RfTimeout::new(Duration::from_millis(100))
}

/// [`config_image`] with distinct NFC-A and NFC-B RF bytes and a valid checksum.
pub fn ab_config_image() -> [u8; 256] {
    let mut image = config_image();
    image[0x10..=0x1a].copy_from_slice(&[10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
    image[0x23..=0x25].copy_from_slice(&[0x31, 0x32, 0x33]);
    image[0xc0..=0xc2].copy_from_slice(&[0x41, 0x42, 0x43]);
    image[0x3f] = image[0x10..0x3f]
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte))
        .wrapping_neg();
    image
}

/// NFC-A or NFC-B RF configuration of [`ab_config_image`] with a 100 ms timer.
pub fn ab_mode(type_b: bool) -> Vec<Step> {
    let mut steps = vec![
        command(0x1c, &[0x80, 0x63, 0], &[]),
        command(0x32, &[5, 0, 0, 4], &[]),
        command(0x32, &[0x81, 0x8f], &[]),
    ];
    if type_b {
        steps.push(command(
            0x32,
            &[0x0a, 0x41, 0x31, 0x42, 0x32, 0x43, 0x33, 16, 17, 18, 19, 20],
            &[],
        ));
        steps.push(command(0x32, &[0x0c, 0x31, 0x32, 0x33], &[]));
    } else {
        steps.push(command(
            0x32,
            &[0x0a, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
            &[],
        ));
    }
    steps.push(command(8, &[0x63, 0x0d, 0], &[0]));
    steps
}

/// InListPassiveTarget reply for one ISO-DEP NFC-A card with ATS.
pub fn type_a_response(target: u8) -> Vec<u8> {
    vec![1, target, 4, 0, 0x20, 4, 1, 2, 3, 4, 3, 0x20, 0x40]
}

/// InListPassiveTarget reply for one ISO-DEP NFC-B card with its ATTRIB response.
pub fn type_b_response() -> Vec<u8> {
    vec![1, 9, 0x50, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0x51, 0x40, 1, 0]
}
