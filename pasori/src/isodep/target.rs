//! ISO-DEP card-side block sequencing for a session without CID or NAD.

use alloc::{vec, vec::Vec};

const MAX_COMMAND_BYTES: usize = 4 + 1 + 255 + 1;
const WRONG_LENGTH: [u8; 2] = [0x67, 0];
const PCB_AND_CRC_BYTES: usize = 3;

#[derive(Debug)]
pub(crate) struct Session {
    receive_limit: usize,
    send_information_limit: usize,
    number: u8,
    transfer: Transfer,
    last: Option<Exchange>,
}

#[derive(Debug)]
enum Transfer {
    AwaitingCommand,
    Receiving(Vec<u8>),
    Responding { data: Vec<u8>, sent: usize },
}

#[derive(Debug)]
struct Exchange {
    request: Vec<u8>,
    reply: Vec<u8>,
}

pub(crate) enum Action {
    Ignore,
    Reply(Vec<u8>, Progress),
    Deselect,
    CommandLimit,
}

#[derive(Clone, Copy)]
pub(crate) enum Progress {
    Block,
    Exchange,
}

impl Session {
    pub(crate) fn new(initiator_frame_size: u16, card_frame_size: u16, send_limit: u16) -> Self {
        Self {
            receive_limit: usize::from(card_frame_size) - 2,
            send_information_limit: usize::from(initiator_frame_size.min(send_limit))
                - PCB_AND_CRC_BYTES,
            number: 1,
            transfer: Transfer::AwaitingCommand,
            last: None,
        }
    }

    pub(crate) fn receive(
        &mut self,
        frame: &[u8],
        application: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> Action {
        if frame.len() > self.receive_limit {
            return Action::Ignore;
        }
        match frame {
            [0xc2] => Action::Deselect,
            [pcb @ (0x02 | 0x03 | 0x12 | 0x13), data @ ..] => {
                self.information(frame, *pcb, data, application)
            }
            [pcb @ (0xa2 | 0xa3 | 0xb2 | 0xb3)] => self.acknowledgement(frame, *pcb),
            _ => Action::Ignore,
        }
    }

    fn information(
        &mut self,
        frame: &[u8],
        pcb: u8,
        data: &[u8],
        application: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> Action {
        let number = pcb & 1;
        if number == self.number {
            return match &self.last {
                Some(last) if last.request == frame => self.replay(),
                _ => Action::Ignore,
            };
        }
        let more = pcb & 0x10 != 0;
        if matches!(self.transfer, Transfer::Responding { .. }) || (more && data.is_empty()) {
            return Action::Ignore;
        }
        self.number = number;
        let prior = core::mem::replace(&mut self.transfer, Transfer::AwaitingCommand);
        let mut prefix = match prior {
            Transfer::Receiving(prefix) => prefix,
            _ => Vec::new(),
        };
        let length = prefix.len() + data.len();
        if more {
            if length >= MAX_COMMAND_BYTES {
                return Action::CommandLimit;
            }
            prefix.extend_from_slice(data);
            self.transfer = Transfer::Receiving(prefix);
            return self.record(frame, vec![0xa2 | number], Progress::Block);
        }
        let response = if length > MAX_COMMAND_BYTES {
            WRONG_LENGTH.to_vec()
        } else if prefix.is_empty() {
            application(data)
        } else {
            prefix.extend_from_slice(data);
            application(&prefix)
        };
        self.response(frame, response, 0)
    }

    fn acknowledgement(&mut self, frame: &[u8], pcb: u8) -> Action {
        let number = pcb & 1;
        if number == self.number {
            return self.replay();
        }
        if pcb & 0x10 != 0 {
            return Action::Reply(vec![0xa2 | self.number], Progress::Block);
        }
        match core::mem::replace(&mut self.transfer, Transfer::AwaitingCommand) {
            Transfer::Responding { data, sent } => {
                self.number = number;
                self.response(frame, data, sent)
            }
            prior => {
                self.transfer = prior;
                Action::Ignore
            }
        }
    }

    fn response(&mut self, request: &[u8], data: Vec<u8>, sent: usize) -> Action {
        let end = (sent + self.send_information_limit).min(data.len());
        let more = end < data.len();
        let mut frame = Vec::with_capacity(1 + end - sent);
        frame.push(0x02 | self.number | (u8::from(more) << 4));
        frame.extend_from_slice(&data[sent..end]);
        if more {
            self.transfer = Transfer::Responding { data, sent: end };
        }
        let progress = if more {
            Progress::Block
        } else {
            Progress::Exchange
        };
        self.record(request, frame, progress)
    }

    fn record(&mut self, request: &[u8], reply: Vec<u8>, progress: Progress) -> Action {
        self.last = Some(Exchange {
            request: request.to_vec(),
            reply: reply.clone(),
        });
        Action::Reply(reply, progress)
    }

    fn replay(&self) -> Action {
        match &self.last {
            Some(last) => Action::Reply(last.reply.clone(), Progress::Block),
            None => Action::Ignore,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_apdu_reassembly_before_calling_the_application() {
        let no_application = |_: &[u8]| panic!("an oversized APDU reached the application");
        let mut frame = [0; 254];
        frame[0] = 0x12;

        let mut session = Session::new(64, 256, 64);
        assert!(matches!(
            session.receive(&frame, no_application),
            Action::Reply(reply, Progress::Block) if reply == [0xa2]
        ));
        assert!(matches!(
            session.receive(&[0x13; 9], no_application),
            Action::CommandLimit
        ));

        let mut session = Session::new(64, 256, 64);
        assert!(matches!(
            session.receive(&frame, no_application),
            Action::Reply(_, Progress::Block)
        ));
        assert!(matches!(
            session.receive(&[0x03; 10], no_application),
            Action::Reply(reply, Progress::Exchange) if reply == [0x03, 0x67, 0]
        ));
    }
}
