use super::{Error, FelicaCard, Reader, RfTimeout, State};
use crate::{felica::BitRate, transport::Transport};
use alloc::vec::Vec;
use core::time::Duration;
use felica_packet::Idm;

/// Host wait of one-way frames.
const READER_WAIT: Duration = Duration::from_secs(1);
/// TgInitTarget fields before the FeliCa parameters: passive-only mode and
/// NFC-A parameters, which a FeliCa activation does not use.
const LISTEN_PREFIX: [u8; 7] = [0, 0, 1, 1, 2, 3, 0];
/// TgInitTarget fields after the FeliCa parameters, which a FeliCa
/// activation does not use.
const LISTEN_SUFFIX: [u8; 11] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x55];

/// Which side of the FeliCa exchange the reader takes in a [`FelicaLink`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FelicaRole {
    /// The reader polled the peer and generates the RF field.
    Initiator,
    /// The reader answered as a passive FeliCa target.
    Target,
}

/// Identity a listening FeliCa target answers Polling with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FelicaListen {
    /// Advertised IDm.
    pub idm: Idm,
    /// Advertised manufacturing parameters.
    pub pmm: [u8; 8],
    /// Advertised system code.
    pub system_code: u16,
}

/// A FeliCa target activation and the initiator packet that completed it.
#[derive(Debug)]
pub struct FelicaActivation<'a, T: Transport> {
    /// Packet stream of the activated target.
    pub link: FelicaLink<'a, T>,
    /// First initiator packet after Polling, including its length byte.
    pub packet: Vec<u8>,
}

/// Exclusive FeliCa packet stream for a host-run protocol. Sending and
/// receiving are separate reader commands, so the reader stays in a mode that
/// only [`Self::finish`] or [`Reader::initialize`] leaves.
#[derive(Debug)]
pub struct FelicaLink<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    role: FelicaRole,
    rate: BitRate,
}

impl<T: Transport> Reader<T> {
    /// Reset the reader and listen as a passive FeliCa target answering
    /// Polling with `listen`. `timeout` bounds the wait for an initiator; a
    /// timeout of the activation command fails the reader transaction.
    pub fn listen_felica(
        &mut self,
        listen: FelicaListen,
        timeout: RfTimeout,
    ) -> Result<FelicaActivation<'_, T>, Error<T::Error>> {
        self.initialize()?;
        self.state = State::NeedsInitialization;
        let mut args = Vec::with_capacity(36);
        args.extend_from_slice(&LISTEN_PREFIX);
        args.extend_from_slice(listen.idm.as_bytes());
        args.extend_from_slice(&listen.pmm);
        args.extend_from_slice(&listen.system_code.to_be_bytes());
        args.extend_from_slice(&LISTEN_SUFFIX);
        let activation = self.command(0x8c, &args, timeout.host_wait())?;
        let (rate, packet) = match activation.as_slice() {
            [0x12, packet @ ..] => (BitRate::Kbps212, packet),
            [0x22, packet @ ..] => (BitRate::Kbps424, packet),
            [mode, ..] => return Err(Error::TargetMode(*mode)),
            [] => return Err(Error::Response("target activation length")),
        };
        felica_packet::validate_length(packet, 2).map_err(Error::FelicaResponse)?;
        let packet = packet.to_vec();
        Ok(FelicaActivation {
            link: FelicaLink {
                reader: self,
                role: FelicaRole::Target,
                rate,
            },
            packet,
        })
    }
}

impl<'a, T: Transport> FelicaCard<'a, T> {
    /// Consume the selected card's typed authority for a packet stream at its
    /// polling rate. The reader requires initialization from here on, which
    /// [`FelicaLink::finish`] performs.
    pub fn into_link(self) -> FelicaLink<'a, T> {
        let Self { reader, rate, .. } = self;
        reader.state = State::NeedsInitialization;
        FelicaLink {
            reader,
            role: FelicaRole::Initiator,
            rate,
        }
    }
}

impl<T: Transport> FelicaLink<'_, T> {
    /// Side the reader takes.
    pub fn role(&self) -> FelicaRole {
        self.role
    }

    /// RF rate of the activation.
    pub fn rate(&self) -> BitRate {
        self.rate
    }

    /// Host monotonic time.
    pub fn now(&self) -> Duration {
        self.reader.link.now()
    }

    /// Wait on the host before the next reader command.
    pub fn wait(&mut self, duration: Duration) {
        self.reader.link.wait(duration);
    }

    /// Send one packet without receiving a reply.
    pub fn send(&mut self, packet: &[u8]) -> Result<(), Error<T::Error>> {
        felica_packet::validate_length(packet, 2).map_err(Error::FelicaRequest)?;
        match self.role {
            FelicaRole::Initiator => {
                // A zero wait sends without receiving and reports RF timeout.
                let mut args = Vec::with_capacity(packet.len() + 2);
                args.extend_from_slice(&[0, 0]);
                args.extend_from_slice(packet);
                let response = self.reader.command(0xa0, &args, READER_WAIT)?;
                match response.first() {
                    Some(status) if status & 0x3f == 1 => Ok(()),
                    Some(0) => Err(Error::Response("send-only packet received a frame")),
                    _ => self.reader.rf_response(response).map(|_| ()),
                }
            }
            FelicaRole::Target => {
                match self.reader.command(0x90, packet, READER_WAIT)?.as_slice() {
                    [0] => Ok(()),
                    [status] => Err(Error::RfStatus(*status)),
                    _ => Err(Error::Response("target response status length")),
                }
            }
        }
    }

    /// Receive one packet; `None` means `wait` ended without a frame.
    pub fn receive(&mut self, wait: RfTimeout) -> Result<Option<Vec<u8>>, Error<T::Error>> {
        let response = match self.role {
            FelicaRole::Initiator => {
                self.reader
                    .command(0xa0, &wait.ticks().to_le_bytes(), wait.host_wait())?
            }
            FelicaRole::Target => self.reader.command(0x88, &[], wait.host_wait())?,
        };
        self.packet(response)
    }

    /// Send one packet and receive the next one in the same `A0` command;
    /// `None` means `wait` ended without a frame.
    pub fn send_receive(
        &mut self,
        packet: &[u8],
        wait: RfTimeout,
    ) -> Result<Option<Vec<u8>>, Error<T::Error>> {
        felica_packet::validate_length(packet, 2).map_err(Error::FelicaRequest)?;
        let mut args = Vec::with_capacity(packet.len() + 2);
        args.extend_from_slice(&wait.ticks().to_le_bytes());
        args.extend_from_slice(packet);
        let response = self.reader.command(0xa0, &args, wait.host_wait())?;
        self.packet(response)
    }

    /// Leave the packet stream and reinitialize the reader.
    pub fn finish(self) -> Result<(), Error<T::Error>> {
        self.reader.initialize().map(|_| ())
    }

    /// Interpret a reader reply carrying an RF status and optional packet.
    fn packet(&mut self, response: Vec<u8>) -> Result<Option<Vec<u8>>, Error<T::Error>> {
        if matches!(response.first(), Some(status) if status & 0x3f == 1) {
            return Ok(None);
        }
        let packet = self.reader.rf_response(response)?;
        felica_packet::validate_length(&packet, 2).map_err(Error::FelicaResponse)?;
        Ok(Some(packet))
    }
}
