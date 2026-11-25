//! Scripted Port-110 GATT transport.

use port110::{
    reader::ResponseWait,
    transport::{MAX_VALUE, Transport},
};
use std::{cell::RefCell, collections::VecDeque, io, rc::Rc, time::Duration};

/// Largest value the simulated reader indicates, and the largest command
/// write it accepts.
const VALUE: usize = 20;
/// Zero bytes of one resynchronization fill.
pub const FILL: usize = 1013;

/// How the simulated reader answers one command.
#[derive(Debug)]
pub enum Answer {
    /// ACK followed by an extended response frame carrying these data bytes.
    Data(Vec<u8>),
    /// ACK followed by a normal response frame carrying these data bytes.
    NormalData(Vec<u8>),
    /// ACK, then no response before the host deadline.
    Silence,
    /// ACK followed by the `7F` error frame.
    ReaderError,
    /// These indication values, then silence.
    Indications(Vec<Vec<u8>>),
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

/// An InCommRF step that sends `packet` with a wait of `units` × 100 µs and
/// answers with `status` and the `received` card bytes, whose last byte is
/// complete. Without card bytes the reply holds the status only.
pub fn in_comm_rf(units: u16, packet: &[u8], status: u32, received: &[u8]) -> Step {
    let mut args = units.to_le_bytes().to_vec();
    args.extend_from_slice(packet);
    let mut data = status.to_le_bytes().to_vec();
    if !received.is_empty() {
        data.push(8);
        data.extend_from_slice(received);
    }
    Step {
        command: 0x04,
        args,
        answer: Answer::Data(data),
    }
}

#[derive(Debug)]
enum Input {
    Value(Vec<u8>),
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
    /// GATT writes, of at most 20 bytes each.
    pub writes: usize,
    /// Resynchronizations: complete zero fills followed by a host ACK.
    pub resyncs: usize,
    /// Indication values received by the host.
    pub received: usize,
}

/// A transport that requires `steps` in order and answers each one, with a
/// simulated clock that advances only through waits and silences.
#[derive(Debug)]
pub struct Script {
    steps: VecDeque<Step>,
    written: Vec<u8>,
    fill: usize,
    input: VecDeque<Input>,
    journal: Rc<RefCell<Journal>>,
    elapsed: Duration,
}

impl Script {
    /// A script and the journal that records its use.
    pub fn new(steps: Vec<Step>) -> (Self, Rc<RefCell<Journal>>) {
        let journal = Rc::new(RefCell::new(Journal {
            commands: Vec::new(),
            command_times: Vec::new(),
            remaining: steps.len(),
            writes: 0,
            resyncs: 0,
            received: 0,
        }));
        (
            Self {
                steps: steps.into(),
                written: Vec::new(),
                fill: 0,
                input: VecDeque::new(),
                journal: Rc::clone(&journal),
                elapsed: Duration::ZERO,
            },
            journal,
        )
    }

    /// Consume complete host ACKs, fill bytes and command frames from the
    /// written bytes.
    fn absorb(&mut self) -> io::Result<()> {
        loop {
            if self.written.starts_with(&[0, 0, 0]) {
                self.written.remove(0);
                self.fill += 1;
                continue;
            }
            if self.written.starts_with(&ACK) {
                self.written.drain(..ACK.len());
                if self.fill < FILL {
                    return Err(invalid("host ACK without a complete fill"));
                }
                self.fill = 0;
                self.journal.borrow_mut().resyncs += 1;
                continue;
            }
            let Some(length) = host_frame_length(&self.written)? else {
                return Ok(());
            };
            if self.written.len() < length {
                return Ok(());
            }
            if self.fill != 0 {
                return Err(invalid("command after an unfinished fill"));
            }
            let frame: Vec<u8> = self.written.drain(..length).collect();
            self.answer(&frame)?;
        }
    }

    fn answer(&mut self, frame: &[u8]) -> io::Result<()> {
        assert!(
            self.input.is_empty(),
            "new command before consuming or discarding the preceding reply"
        );
        let (command, data) = host_command(frame)?;
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
        let response = match step.answer {
            Answer::Data(data) => extended_frame(&response_payload(command, &data)?)?,
            Answer::NormalData(data) => normal_frame(&response_payload(command, &data)?)?,
            Answer::ReaderError => normal_frame(&[0x7f])?,
            Answer::Silence => {
                self.input.push_back(Input::Value(ACK.to_vec()));
                self.input.push_back(Input::Silence);
                return Ok(());
            }
            Answer::Indications(values) => {
                self.input.extend(values.into_iter().map(Input::Value));
                self.input.push_back(Input::Silence);
                return Ok(());
            }
        };
        self.input.push_back(Input::Value(ACK.to_vec()));
        self.input.extend(
            response
                .chunks(VALUE)
                .map(|value| Input::Value(value.to_vec())),
        );
        Ok(())
    }
}

/// The host and reader ACK frame.
pub const ACK: [u8; 6] = [0, 0, 0xff, 0, 0xff, 0];

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
        .wrapping_neg()
}

// Independent decoder of the host's extended command frames.
fn host_frame_length(bytes: &[u8]) -> io::Result<Option<usize>> {
    let Some(&[a, b, c, d, e, low, high, lcs]) = bytes.first_chunk::<8>() else {
        return Ok(None);
    };
    if [a, b, c, d, e] != [0, 0, 0xff, 0xff, 0xff] {
        return Err(invalid("host frame is not an extended frame"));
    }
    if low.wrapping_add(high).wrapping_add(lcs) != 0 {
        return Err(invalid("host frame length checksum"));
    }
    Ok(Some(usize::from(u16::from_le_bytes([low, high])) + 10))
}

fn host_command(bytes: &[u8]) -> io::Result<(u8, &[u8])> {
    let payload = &bytes[8..bytes.len() - 2];
    let [dcs, postamble] = bytes[bytes.len() - 2..] else {
        return Err(invalid("host frame length"));
    };
    if checksum(payload) != dcs || postamble != 0 {
        return Err(invalid("host frame data checksum or postamble"));
    }
    match payload {
        [0xd6, command, args @ ..] => Ok((*command, args)),
        _ => Err(invalid("host frame direction")),
    }
}

/// Independent encoder of an extended reader frame carrying `payload`.
pub fn extended_frame(payload: &[u8]) -> io::Result<Vec<u8>> {
    let [low, high] = u16::try_from(payload.len())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .to_le_bytes();
    let mut bytes = vec![
        0,
        0,
        0xff,
        0xff,
        0xff,
        low,
        high,
        low.wrapping_add(high).wrapping_neg(),
    ];
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&[checksum(payload), 0]);
    Ok(bytes)
}

fn normal_frame(payload: &[u8]) -> io::Result<Vec<u8>> {
    let length = u8::try_from(payload.len())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut bytes = vec![0, 0, 0xff, length, length.wrapping_neg()];
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&[checksum(payload), 0]);
    Ok(bytes)
}

/// The `D7` payload of the response to `command` carrying `data`.
pub fn response_payload(command: u8, data: &[u8]) -> io::Result<Vec<u8>> {
    let response = command
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "response command overflow"))?;
    Ok([&[0xd7, response][..], data].concat())
}

impl Transport for Script {
    type Error = io::Error;

    fn monotonic_time(&self) -> Duration {
        self.elapsed
    }

    fn wait(&mut self, duration: Duration) {
        self.elapsed += duration;
    }

    fn write(&mut self, value: &[u8], timeout: Duration) -> io::Result<()> {
        assert!(!timeout.is_zero());
        assert!(
            !value.is_empty() && value.len() <= VALUE,
            "GATT write of {} bytes",
            value.len()
        );
        self.journal.borrow_mut().writes += 1;
        self.written.extend_from_slice(value);
        self.absorb()
    }

    fn receive(
        &mut self,
        buffer: &mut [u8; MAX_VALUE],
        timeout: Duration,
    ) -> io::Result<Option<usize>> {
        assert!(!timeout.is_zero());
        match self.input.pop_front() {
            Some(Input::Value(value)) => {
                buffer[..value.len()].copy_from_slice(&value);
                self.journal.borrow_mut().received += 1;
                Ok(Some(value.len()))
            }
            // Without a pending reply the reader stays silent.
            Some(Input::Silence) | None => {
                self.elapsed += timeout;
                Ok(None)
            }
        }
    }
}

/// GetFirmwareVersion value answered by [`initialization`].
pub const FIRMWARE: u16 = 0x0110;
/// GetPDDataVersion value answered by [`initialization`].
pub const PD_DATA: u16 = 0x0100;

/// GetProperty data of a reader whose RF table the driver leaves alone.
pub fn property() -> [u8; 32] {
    let mut property = [0x5a; 32];
    property[14..16].copy_from_slice(&[0x00, 0x99]);
    property
}

/// InSetRF arguments for FeliCa at 212 kbps.
pub const FELICA_212: [u8; 4] = [0x01, 0x01, 0x01, 0x01];
/// InSetRF arguments for FeliCa at 424 kbps.
pub const FELICA_424: [u8; 4] = [0x01, 0x02, 0x01, 0x02];
/// InSetProtocol arguments of every RF setting.
pub const PROTOCOL: [u8; 6] = [0x0e, 0x00, 0x0f, 0x05, 0x10, 0xff];
/// The driver's default connection parameter request.
pub const CONNECTION: [u8; 8] = [0x06, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x3c, 0x00];

/// Steps of `Reader::initialize` with the default connection parameters on
/// a reader that reports command type 3, [`FIRMWARE`], [`PD_DATA`] and
/// [`property`].
pub fn initialization() -> Vec<Step> {
    initialization_with(PD_DATA, &property(), Vec::new())
}

/// Steps of `Reader::initialize` for a PD data version and a property,
/// with `adjustment` between the InSetRF and InSetProtocol steps.
pub fn initialization_with(pd_data: u16, property: &[u8; 32], adjustment: Vec<Step>) -> Vec<Step> {
    let mut steps = vec![
        command(0x28, &[], &[0, 0, 0, 0, 0, 0, 0, 0x0f]),
        command(0x2a, &[3], &[0]),
        command(0x1c, &CONNECTION, &[0]),
        command(0x20, &[], &FIRMWARE.to_le_bytes()),
        command(0x22, &[], &pd_data.to_le_bytes()),
        command(0x24, &[], property),
        command(0x00, &FELICA_212, &[0]),
    ];
    steps.extend(adjustment);
    steps.push(command(0x02, &PROTOCOL, &[0]));
    steps.push(command(0x06, &[0], &[0]));
    steps
}

/// Steps that apply FeliCa at `rf` on a reader whose RF table is left alone.
pub fn rate_configuration(rf: [u8; 4]) -> Vec<Step> {
    vec![command(0x00, &rf, &[0]), command(0x02, &PROTOCOL, &[0])]
}

/// IDm of the card in [`polling_reply`].
pub const IDENTITY: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

/// PMm of the card in [`polling_reply`].
pub const PARAMETERS: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

/// One card's Polling response without request data.
pub fn polling_reply() -> Vec<u8> {
    let mut packet = vec![18, 1];
    packet.extend_from_slice(&IDENTITY);
    packet.extend_from_slice(&PARAMETERS);
    packet
}

/// Unit count of [`wait`].
pub const WAIT_UNITS: u16 = 1000;

/// A 100 ms card wait.
pub fn wait() -> Option<ResponseWait> {
    ResponseWait::new(Duration::from_millis(100))
}
