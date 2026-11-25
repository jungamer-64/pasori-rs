//! Scripted Port-400 USB bulk transfers and fixed command fixtures.

use port400::transport::Transport;
use std::{collections::VecDeque, io, time::Duration};

/// Result of the script's next complete bulk IN transfer.
#[derive(Debug)]
pub enum Reply {
    /// A CCID message correlated with the last expected write.
    Ccid {
        /// CCID status byte.
        status: u8,
        /// CCID error byte.
        error: u8,
        /// Escape response bytes.
        payload: Vec<u8>,
        /// Simulated I/O time before the response arrives.
        delay: Duration,
    },
    /// Literal bytes for exercising malformed headers or transport reports.
    Raw(Vec<u8>),
    /// The connection disappeared before completion.
    Disconnected,
}

/// Result of the script's next bulk OUT request.
#[derive(Debug)]
pub enum Outcome {
    /// A complete write followed by these reads.
    Replies(Vec<Reply>),
    /// Only this many bytes were written.
    ShortWrite(usize),
}

/// One expected Escape command.
#[derive(Debug)]
pub struct Step {
    /// Device APDU that must appear in the CCID message.
    pub apdu: Vec<u8>,
    /// What the transport does after receiving that command.
    pub outcome: Outcome,
}

/// A normal Escape response, with card state independent of the APDU status.
pub fn command(apdu: &[u8], result: &[u8]) -> Step {
    Step {
        apdu: apdu.to_vec(),
        outcome: Outcome::Replies(vec![Reply::Ccid {
            status: 0x02,
            error: 0,
            payload: result.to_vec(),
            delay: Duration::ZERO,
        }]),
    }
}

/// Wait used in fixture selection commands.
pub const WAIT_US: u32 = 200_000;
/// Valid firmware response in the 20-byte layout.
pub const FIRMWARE: [u8; 20] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xff, 0xff, 0, 0, 0x90, 0,
];
/// Device info query.
pub const READ_FIRMWARE: [u8; 5] = [0xff, 0x56, 0, 0, 0];
/// Transparent Session start.
pub const START: [u8; 8] = [0xff, 0x50, 0, 0, 2, 0x81, 0, 0];
/// Transparent Session end.
pub const END: [u8; 8] = [0xff, 0x50, 0, 0, 2, 0x82, 0, 0];
/// RF field off.
pub const RF_OFF: [u8; 8] = [0xff, 0x50, 0, 0, 2, 0x83, 0, 0];
/// RF field on.
pub const RF_ON: [u8; 8] = [0xff, 0x50, 0, 0, 2, 0x84, 0, 0];
/// Successful control response.
pub const OK: [u8; 7] = [0xc0, 3, 0, 0x90, 0, 0x90, 0];
/// Reader-reported card timeout for the transceive data object.
pub const RF_TIMEOUT: [u8; 7] = [0xc0, 3, 2, 0x64, 1, 0x90, 0];

/// Commands required to establish a session on initially normal firmware.
pub fn initialization() -> Vec<Step> {
    vec![
        command(&READ_FIRMWARE, &FIRMWARE),
        command(&END, &OK),
        command(&START, &OK),
        command(&RF_OFF, &OK),
    ]
}

/// Confirmed RF off followed by a completed End.
pub fn finish() -> [Step; 2] {
    [command(&RF_OFF, &OK), command(&END, &OK)]
}

/// Set up the FeliCa 212 kbps profile.
pub fn felica() -> [Step; 5] {
    [
        command(&[0xff, 0x50, 0, 2, 4, 0x8f, 2, 3, 0, 0], &OK),
        command(&RF_OFF, &OK),
        command(&[0xff, 0x50, 0, 1, 4, 0x90, 2, 0, 0x1c, 0], &OK),
        command(&RF_ON, &OK),
        command(&[0xff, 0x50, 0, 0, 6, 0xff, 0x6e, 3, 5, 1, 0x89, 0], &OK),
    ]
}

/// NFC-A Layer 3 selection and framing, ready for RATS.
pub fn type_a(field_on: bool) -> Vec<Step> {
    let mut steps = Vec::new();
    if field_on {
        steps.push(command(&RF_OFF, &OK));
    }
    steps.extend([
        command(&RF_ON, &OK),
        command(
            &[0xff, 0x50, 0, 2, 4, 0x8f, 2, 0, 3, 0],
            &[0xc0, 3, 0, 0x90, 0, 0x8f, 1, 0x20, 0x90, 0],
        ),
        command(&[0xff, 0x50, 0, 1, 4, 0x90, 2, 0, 0x10, 0], &OK),
    ]);
    steps
}

/// NFC-B Layer 2 and framing, ready for REQB at 106 kbps.
pub fn type_b(field_on: bool) -> Vec<Step> {
    let mut steps = Vec::new();
    if field_on {
        steps.push(command(&RF_OFF, &OK));
    }
    steps.extend([
        command(&[0xff, 0x50, 0, 2, 4, 0x8f, 2, 1, 2, 0], &OK),
        command(&[0xff, 0x50, 0, 1, 4, 0x90, 2, 0, 0x1c, 0], &OK),
        command(&RF_ON, &OK),
        command(&[0xff, 0x50, 0, 0, 6, 0xff, 0x6e, 3, 5, 1, 0x80, 0], &OK),
    ]);
    steps
}

/// Escape APDU for a transparent RF exchange from the USB wire format.
pub fn rf_apdu(wait_us: u32, packet: &[u8]) -> Vec<u8> {
    let mut objects = vec![0x5f, 0x46, 4];
    objects.extend(wait_us.to_le_bytes());
    objects.extend([0x95, 0x82]);
    objects.extend(wire_len(packet.len()));
    objects.extend(packet);

    let mut apdu = vec![0xff, 0x50, 0, 1, 0];
    apdu.extend(wire_len(objects.len()));
    apdu.extend(objects);
    apdu.extend([0; 3]);
    apdu
}

/// An RF exchange that returned a whole-byte card response.
pub fn exchange(wait_us: u32, packet: &[u8], received: &[u8]) -> Step {
    let mut result = vec![0xc0, 3, 0, 0x90, 0, 0x92, 1, 0, 0x96, 2, 0, 0, 0x97, 0x82];
    result.extend(wire_len(received.len()));
    result.extend(received);
    result.extend([0x90, 0]);
    command(&rf_apdu(wait_us, packet), &result)
}

fn wire_len(bytes: usize) -> [u8; 2] {
    let Ok(bytes) = u16::try_from(bytes) else {
        panic!("test fixture exceeds the wire length");
    };
    bytes.to_be_bytes()
}

/// A scripted backend that checks complete outgoing USB messages and owns
/// the clock for their deadlines.
#[derive(Debug)]
pub struct Script {
    steps: VecDeque<Step>,
    replies: VecDeque<Reply>,
    sequence: u8,
    elapsed: Duration,
    waits: Vec<Duration>,
}

impl Script {
    /// Require these commands and replies in exactly this order.
    pub fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            replies: VecDeque::new(),
            sequence: 0,
            elapsed: Duration::ZERO,
            waits: Vec::new(),
        }
    }

    /// Confirm that every command and reply in the fixture was consumed.
    pub fn is_exhausted(&self) -> bool {
        self.steps.is_empty() && self.replies.is_empty()
    }

    /// RF settling waits requested by the reader.
    pub fn waits(&self) -> &[Duration] {
        &self.waits
    }
}

impl Transport for Script {
    type Error = io::Error;

    fn monotonic_time(&self) -> Duration {
        self.elapsed
    }

    fn wait(&mut self, duration: Duration) {
        self.elapsed += duration;
        self.waits.push(duration);
    }

    fn write(&mut self, message: &[u8], timeout: Duration) -> io::Result<usize> {
        assert!(!timeout.is_zero());
        assert!(
            self.replies.is_empty(),
            "write while an earlier response is pending"
        );
        let Some(step) = self.steps.pop_front() else {
            panic!("unexpected USB write: {message:02x?}");
        };
        let [high, low] = wire_len(step.apdu.len());
        let expected_header = [0x6b, low, high, 0, 0, 0, self.sequence, 0, 0, 0];
        assert_eq!(message, &[expected_header.as_slice(), &step.apdu].concat());
        self.sequence = self.sequence.wrapping_add(1);
        match step.outcome {
            Outcome::ShortWrite(count) => Ok(count),
            Outcome::Replies(replies) => {
                self.replies = replies.into();
                Ok(message.len())
            }
        }
    }

    fn read(&mut self, buffer: &mut [u8], timeout: Duration) -> io::Result<usize> {
        assert!(!timeout.is_zero());
        let message = match self.replies.pop_front() {
            Some(Reply::Ccid {
                status,
                error,
                payload,
                delay,
            }) => {
                self.elapsed += delay.min(timeout);
                if delay >= timeout {
                    return Ok(0);
                }
                let [high, low] = wire_len(payload.len());
                let header = [
                    0x83,
                    low,
                    high,
                    0,
                    0,
                    0,
                    self.sequence.wrapping_sub(1),
                    status,
                    error,
                    0,
                ];
                [header.as_slice(), &payload].concat()
            }
            Some(Reply::Raw(message)) => message,
            Some(Reply::Disconnected) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "reader disconnected",
                ));
            }
            None => panic!("unexpected USB read"),
        };
        assert!(message.len() <= buffer.len());
        buffer[..message.len()].copy_from_slice(&message);
        Ok(message.len())
    }
}
