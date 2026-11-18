//! Scripted Port-100 transport.

use port100::{reader::ResponseWait, transport::Transport};
use std::{cell::RefCell, collections::VecDeque, io, rc::Rc, time::Duration};

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
/// complete.
pub fn in_comm_rf(units: u16, packet: &[u8], status: u32, received: &[u8]) -> Step {
    let last_bits = if received.is_empty() { 0 } else { 8 };
    in_comm_rf_bits(units, packet, status, last_bits, received)
}

/// An InCommRF step whose reply reports `last_bits` valid bits in its last byte.
pub fn in_comm_rf_bits(
    units: u16,
    packet: &[u8],
    status: u32,
    last_bits: u8,
    received: &[u8],
) -> Step {
    let mut args = units.to_le_bytes().to_vec();
    args.extend_from_slice(packet);
    let mut data = status.to_le_bytes().to_vec();
    data.push(last_bits);
    data.extend_from_slice(received);
    Step {
        command: 0x04,
        args,
        answer: Answer::Data(data),
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
    /// Host ACK frames written to cancel a command.
    pub cancels: usize,
}

/// A transport that requires `steps` in order and answers each one, with a
/// simulated clock that advances only through waits.
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
            commands: Vec::new(),
            command_times: Vec::new(),
            remaining: steps.len(),
            recoveries: 0,
            cancels: 0,
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

const ACK: [u8; 6] = [0, 0, 0xff, 0, 0xff, 0];

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
fn host_command(bytes: &[u8]) -> io::Result<(u8, &[u8])> {
    let Some((&[0, 0, 0xff, 0xff, 0xff, low, high, lcs], rest)) = bytes.split_first_chunk::<8>()
    else {
        return Err(invalid("host frame is not an extended frame"));
    };
    if low.wrapping_add(high).wrapping_add(lcs) != 0 {
        return Err(invalid("host frame length checksum"));
    }
    let length = usize::from(u16::from_le_bytes([low, high]));
    let Some((payload, [dcs, 0])) = rest.split_at_checked(length) else {
        return Err(invalid("host frame length or postamble"));
    };
    if checksum(payload) != *dcs {
        return Err(invalid("host frame data checksum"));
    }
    match payload {
        [0xd6, command, args @ ..] => Ok((*command, args)),
        _ => Err(invalid("host frame direction")),
    }
}

// Independent encoders of the simulated reader's response frames.
fn extended_frame(payload: &[u8]) -> io::Result<Vec<u8>> {
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

fn response_payload(command: u8, data: &[u8]) -> io::Result<Vec<u8>> {
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

    fn write(&mut self, bytes: &[u8], timeout: Duration) -> io::Result<usize> {
        assert!(!timeout.is_zero());
        if bytes == ACK {
            self.journal.borrow_mut().cancels += 1;
            return Ok(bytes.len());
        }
        assert!(
            self.input.is_empty(),
            "new command before consuming or discarding the preceding reply"
        );
        let (command, data) = host_command(bytes)?;
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
        let reply = match step.answer {
            Answer::Data(data) => Input::Bytes(extended_frame(&response_payload(command, &data)?)?),
            Answer::NormalData(data) => {
                Input::Bytes(normal_frame(&response_payload(command, &data)?)?)
            }
            Answer::Silence => Input::Silence,
            Answer::ReaderError => Input::Bytes(normal_frame(&[0x7f])?),
        };
        self.input.push_back(reply);
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

/// GetFirmwareVersion value answered by [`initialization`].
pub const FIRMWARE: u16 = 0x0111;
/// GetPDDataVersion value answered by [`initialization`].
pub const PD_DATA: u16 = 0x0100;

/// Steps of `Reader::initialize` on a reader that reports command types 0
/// and 1 and firmware [`FIRMWARE`], which is outside the older ranges.
pub fn initialization() -> Vec<Step> {
    initialization_with(&[0, 0, 0, 0, 0, 0, 0, 0x03], 1, [0, 0], FIRMWARE)
}

/// Steps of `Reader::initialize` for a command type bitmap, the type it
/// selects, the option-60 bytes and the firmware version.
pub fn initialization_with(
    types: &[u8; 8],
    selected: u8,
    option_60: [u8; 2],
    firmware: u16,
) -> Vec<Step> {
    vec![
        command(0x28, &[], types),
        command(0x2a, &[selected], &[0]),
        command(0x20, &[0x60], &option_60),
        command(0x20, &[], &firmware.to_le_bytes()),
        command(0x22, &[], &PD_DATA.to_le_bytes()),
        command(0x06, &[0], &[0]),
    ]
}

/// InSetRF arguments for FeliCa at 212 kbps.
pub const FELICA_212: [u8; 4] = [0x01, 0x01, 0x0f, 0x01];

/// InSetProtocol arguments for FeliCa on firmware outside the older ranges.
pub const FELICA_PROTOCOL: [u8; 38] = [
    0x00, 0x18, 0x01, 0x01, 0x02, 0x01, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x08,
    0x08, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x0e, 0x00, 0x0f, 0x05, 0x10, 0xff,
    0x11, 0x00, 0x12, 0x00, 0x13, 0x06,
];

/// Steps that configure FeliCa at 212 kbps on firmware outside the older ranges.
pub fn felica_212_configuration() -> Vec<Step> {
    vec![
        command(0x00, &FELICA_212, &[0]),
        command(0x02, &FELICA_PROTOCOL, &[0]),
    ]
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

/// InSetRF arguments for NFC-A at 106 kbps.
pub const TYPE_A_106: [u8; 4] = [0x02, 0x03, 0x0f, 0x03];

/// InSetProtocol arguments for NFC-A on firmware outside the older ranges.
pub const TYPE_A_PROTOCOL: [u8; 38] = [
    0x00, 0x06, 0x01, 0x01, 0x02, 0x01, 0x03, 0x00, 0x04, 0x01, 0x05, 0x01, 0x06, 0x00, 0x07, 0x08,
    0x08, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x0e, 0x04, 0x0f, 0x00, 0x10, 0x00,
    0x11, 0x00, 0x12, 0x00, 0x13, 0x06,
];

/// InSetRF arguments for NFC-B at 106 kbps on firmware outside the older ranges.
pub const TYPE_B_106: [u8; 4] = [0x03, 0x07, 0x0f, 0x07];

/// InSetProtocol arguments for NFC-B on firmware outside the older ranges.
pub const TYPE_B_PROTOCOL: [u8; 38] = [
    0x00, 0x14, 0x01, 0x01, 0x02, 0x01, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x08,
    0x08, 0x00, 0x09, 0x01, 0x0a, 0x01, 0x0b, 0x01, 0x0c, 0x01, 0x0e, 0x04, 0x0f, 0x00, 0x10, 0x00,
    0x11, 0x00, 0x12, 0x00, 0x13, 0x06,
];

/// Steps that switch the field off, as a selection does when it is not off.
pub fn field_off() -> Vec<Step> {
    vec![command(0x06, &[0], &[0])]
}

/// Steps that configure NFC-A at 106 kbps.
pub fn type_a_configuration() -> Vec<Step> {
    vec![
        command(0x00, &TYPE_A_106, &[0]),
        command(0x02, &TYPE_A_PROTOCOL, &[0]),
    ]
}

/// Steps that configure NFC-B at 106 kbps.
pub fn type_b_configuration() -> Vec<Step> {
    vec![
        command(0x00, &TYPE_B_106, &[0]),
        command(0x02, &TYPE_B_PROTOCOL, &[0]),
    ]
}

/// SENS_RES of the cards in [`type_a_activation`].
pub const SENS_RES: [u8; 2] = [0x44, 0x00];

/// Steps from SENS_REQ through the last SEL_REQ for a card whose UID is
/// `uid` (4, 7 or 10 bytes) and whose final SEL_RES is `sel_res`, following
/// the configuration.
pub fn type_a_activation(uid: &[u8], sel_res: u8) -> Vec<Step> {
    let mut steps = vec![
        command(0x02, &[0x01, 0x00, 0x02, 0x00, 0x07, 0x07], &[0]),
        in_comm_rf(WAIT_UNITS, &[0x26], 0, &SENS_RES),
        command(0x02, &[0x07, 0x08], &[0]),
    ];
    let mut levels: Vec<[u8; 4]> = Vec::new();
    let mut rest = uid;
    while rest.len() > 4 {
        levels.push([0x88, rest[0], rest[1], rest[2]]);
        rest = &rest[3..];
    }
    levels.push([rest[0], rest[1], rest[2], rest[3]]);
    let last = levels.len() - 1;
    for (level, part) in levels.iter().enumerate() {
        let select = [0x93, 0x95, 0x97][level];
        let bcc = part.iter().fold(0, |bcc, byte| bcc ^ byte);
        let mut sdd = part.to_vec();
        sdd.push(bcc);
        steps.push(in_comm_rf(WAIT_UNITS, &[select, 0x20], 0, &sdd));
        steps.push(command(0x02, &[0x01, 0x01, 0x02, 0x01], &[0]));
        let mut sel = vec![select, 0x70];
        sel.extend_from_slice(&sdd);
        let sak = if level == last { sel_res } else { 0x04 };
        steps.push(in_comm_rf(WAIT_UNITS, &sel, 0, &[sak]));
        if level != last {
            steps.push(command(0x02, &[0x01, 0x00, 0x02, 0x00], &[0]));
        }
    }
    steps
}

/// Independent bitwise CRC_A (reflected polynomial 8408, initial 6363) of
/// `data`, least significant byte first.
pub fn crc_a(data: &[u8]) -> [u8; 2] {
    let mut crc: u16 = 0x6363;
    for byte in data {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x8408
            } else {
                crc >> 1
            };
        }
    }
    crc.to_le_bytes()
}

/// `data` followed by its CRC_A.
pub fn with_crc_a(data: &[u8]) -> Vec<u8> {
    [data, &crc_a(data)].concat()
}
