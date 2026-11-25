use super::{BitRate, Error, Field, RF_MARGIN, Reader, State};
use crate::{transport::Transport, wire};
use alloc::vec::Vec;
use core::{mem, time::Duration};
use felica_packet::{Idm, validate_length};
use iso14443::nfca::{self, PassiveTarget, PassiveTargetReader};

const EXCHANGE: u8 = 0x48;
const RECEIVE_TIMEOUT: u32 = 0x80;
const FIELD_OFF: u32 = 0x400;
const HEADER_BYTES: usize = 33;
const MAX_RESPONSE_BYTES: usize = wire::MAX_LENGTH - HEADER_BYTES - 2;

/// Finite wait for a passive target to receive an initiator command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetWait(u16);

impl TargetWait {
    /// Round a positive duration up to milliseconds. The last wire value
    /// is reserved for an unbounded wait.
    pub fn new(duration: Duration) -> Option<Self> {
        let units = duration.as_nanos().div_ceil(1_000_000);
        u16::try_from(units)
            .ok()
            .filter(|units| *units != 0 && *units != u16::MAX)
            .map(Self)
    }

    /// The wait after rounding.
    pub fn duration(self) -> Duration {
        Duration::from_millis(u64::from(self.0))
    }
}

/// Passive NFC-A target with a four-byte UID and no ISO-DEP.
#[derive(Debug)]
pub struct TypeATarget<'r, T: Transport> {
    link: TargetLink<'r, T>,
    uid: [u8; 4],
    first: Option<Vec<u8>>,
}

/// Passive FeliCa target. The reader answers the activation Polling with
/// the configured identity and hands later packets to the host.
#[derive(Debug)]
pub struct FelicaTarget<'r, T: Transport>(TargetLink<'r, T>);

/// Initiator command and one opportunity to reply. Dropping it sends nothing.
#[derive(Debug)]
pub struct TargetCommand<'a, 'r, T: Transport> {
    link: &'a mut TargetLink<'r, T>,
    data: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
enum TargetState {
    WaitingForActivation,
    Activated,
    Revoked,
}

#[derive(Clone, Copy, Debug)]
enum Radio {
    TypeA,
    Felica(BitRate),
}

impl Radio {
    const fn code(self) -> u8 {
        match self {
            Self::TypeA => 0x0b,
            Self::Felica(BitRate::Kbps212) => 0x0c,
            Self::Felica(BitRate::Kbps424) => 0x0d,
        }
    }
}

#[derive(Debug)]
struct TargetLink<'r, T: Transport> {
    reader: &'r mut Reader<T>,
    radio: Radio,
    activation: [u8; 24],
    has_activation_status: bool,
    state: TargetState,
}

impl<T: Transport> Reader<T> {
    /// Prepare a passive NFC-A target at 106 kbps and wait for its first
    /// command. The UID is `08` followed by the supplied suffix.
    /// If the reader first reports a prior field loss, rearming uses a
    /// second receive with the same per-command wait.
    pub fn listen_type_a(
        &mut self,
        suffix: [u8; 3],
        wait: TargetWait,
    ) -> Result<TypeATarget<'_, T>, Error<T::Error>> {
        let [a, b, c] = suffix;
        let mut activation = [0; 24];
        activation[..6].copy_from_slice(&[4, 0, a, b, c, 0]);
        let mut link = self.prepare_target(Radio::TypeA, activation)?;
        let first = match link.receive(wait) {
            // The chip can report a previous field loss immediately on
            // entry. Rearm before waiting for the first initiator.
            Err(Error::TargetFieldOff) => link.receive(wait)?,
            result => result?,
        };
        Ok(TypeATarget {
            link,
            uid: [8, a, b, c],
            first: Some(first),
        })
    }

    /// Configure a passive FeliCa target. Call [FelicaTarget::receive] to
    /// begin listening. The caller supplies the advertised identity.
    pub fn listen_felica(
        &mut self,
        rate: BitRate,
        idm: Idm,
        pmm: [u8; 8],
        system: u16,
    ) -> Result<FelicaTarget<'_, T>, Error<T::Error>> {
        let mut activation = [0; 24];
        activation[6..14].copy_from_slice(idm.as_bytes());
        activation[14..22].copy_from_slice(&pmm);
        activation[22..].copy_from_slice(&system.to_be_bytes());
        self.prepare_target(Radio::Felica(rate), activation)
            .map(FelicaTarget)
    }

    fn prepare_target(
        &mut self,
        radio: Radio,
        activation: [u8; 24],
    ) -> Result<TargetLink<'_, T>, Error<T::Error>> {
        let (firmware, field) = self.ready()?;
        if field != Field::Off {
            self.rf_off()?;
        }
        self.state = State::NeedsInitialization;
        self.status_command(0x40, &[8, radio.code()])?;
        self.status_command(0x42, &[0, 1, 1, 1, 2, 7])?;
        Ok(TargetLink {
            reader: self,
            radio,
            activation,
            has_activation_status: !firmware.at_most(0x619),
            state: TargetState::WaitingForActivation,
        })
    }
}

impl<'r, T: Transport> TypeATarget<'r, T> {
    /// The four-byte UID advertised to the initiator.
    pub fn uid(&self) -> [u8; 4] {
        self.uid
    }

    /// Receive an NFC-A command without CRC, starting with the first
    /// command captured during activation.
    pub fn receive(
        &mut self,
        wait: TargetWait,
    ) -> Result<TargetCommand<'_, 'r, T>, Error<T::Error>> {
        let data = match self.first.take() {
            Some(data) => data,
            None => self.link.receive(wait)?,
        };
        Ok(TargetCommand {
            link: &mut self.link,
            data,
        })
    }

    /// Stop target operation and reinitialize the reader.
    pub fn finish(self) -> Result<(), Error<T::Error>> {
        self.link.finish()
    }
}

impl<'r, T: Transport> FelicaTarget<'r, T> {
    /// Receive a FeliCa packet including its length byte and excluding CRC.
    /// After a timeout or field loss, call again to continue listening.
    pub fn receive(
        &mut self,
        wait: TargetWait,
    ) -> Result<TargetCommand<'_, 'r, T>, Error<T::Error>> {
        let data = self.0.receive(wait)?;
        Ok(TargetCommand {
            link: &mut self.0,
            data,
        })
    }

    /// Stop target operation and reinitialize the reader.
    pub fn finish(self) -> Result<(), Error<T::Error>> {
        self.0.finish()
    }
}

impl<T: Transport> TargetCommand<'_, '_, T> {
    /// Command data. FeliCa packets include their length byte.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Send the response without waiting for another command. The reader
    /// appends CRC. An uncertain send revokes this target.
    pub fn respond(self, response: &[u8]) -> Result<(), Error<T::Error>> {
        if response.is_empty() || response.len() > MAX_RESPONSE_BYTES {
            return Err(Error::InputLength {
                maximum: MAX_RESPONSE_BYTES,
                actual: response.len(),
            });
        }
        if matches!(self.link.radio, Radio::Felica(_)) {
            validate_length(response, 2).map_err(Error::FelicaRequest)?;
        }
        self.link.respond(response)
    }
}

impl<T: Transport> TargetLink<'_, T> {
    fn exchange(
        &mut self,
        activate: bool,
        receive_ms: u16,
        response: &[u8],
    ) -> Result<TargetReply, Error<T::Error>> {
        let mut header = [0; HEADER_BYTES];
        // No transmit guard; the host may answer after the chip's finite
        // transmit window has passed. Zero receive time is a send-only call.
        header[2..4].fill(0xff);
        header[4] = u8::from(activate);
        header[5..29].copy_from_slice(&self.activation);
        header[31..33].copy_from_slice(&receive_ms.to_le_bytes());
        let mut args = Vec::with_capacity(header.len() + response.len());
        args.extend_from_slice(&header);
        args.extend_from_slice(response);
        let reply = self.reader.command(
            EXCHANGE,
            &args,
            Duration::from_millis(u64::from(receive_ms)) + RF_MARGIN,
        )?;
        let status_at = 2 + usize::from(self.has_activation_status);
        let (prefix, data) = reply
            .split_at_checked(status_at + 4)
            .ok_or(Error::Response("TgCommRF header length"))?;
        let status = u32::from_le_bytes([
            prefix[status_at],
            prefix[status_at + 1],
            prefix[status_at + 2],
            prefix[status_at + 3],
        ]);
        Ok(TargetReply {
            rate: prefix[0],
            activated: self.has_activation_status.then(|| prefix[2] & 3 == 3),
            status,
            data: data.to_vec(),
        })
    }

    fn receive(&mut self, wait: TargetWait) -> Result<Vec<u8>, Error<T::Error>> {
        let prior = mem::replace(&mut self.state, TargetState::Revoked);
        let activate = match prior {
            TargetState::WaitingForActivation => true,
            TargetState::Activated => false,
            TargetState::Revoked => return Err(Error::NotInitialized),
        };
        let TargetReply {
            rate,
            activated,
            status,
            data,
        } = self.exchange(activate, wait.0, &[])?;
        match status {
            RECEIVE_TIMEOUT if data.is_empty() => {
                self.state = prior;
                Err(Error::TargetTimeout)
            }
            FIELD_OFF if data.is_empty() => {
                self.state = TargetState::WaitingForActivation;
                Err(Error::TargetFieldOff)
            }
            0 if rate == self.radio.code()
                && (!activate || activated != Some(false))
                && !data.is_empty() =>
            {
                if matches!(self.radio, Radio::Felica(_)) {
                    validate_length(&data, 2).map_err(Error::FelicaResponse)?;
                }
                self.state = TargetState::Activated;
                Ok(data)
            }
            0 => Err(Error::Response("TgCommRF receive format")),
            status => Err(Error::RfStatus(status)),
        }
    }

    fn respond(&mut self, response: &[u8]) -> Result<(), Error<T::Error>> {
        self.state = TargetState::Revoked;
        let reply = self.exchange(false, 0, response)?;
        match reply.status {
            0 if reply.data.is_empty() => {
                self.state = TargetState::Activated;
                Ok(())
            }
            0 => Err(Error::Response("TgCommRF send-only response")),
            status => Err(Error::RfStatus(status)),
        }
    }

    fn finish(self) -> Result<(), Error<T::Error>> {
        self.reader.initialize().map(|_| ())
    }
}

struct TargetReply {
    rate: u8,
    activated: Option<bool>,
    status: u32,
    data: Vec<u8>,
}

impl<T: Transport> PassiveTargetReader for Reader<T> {
    type Error = Error<T::Error>;
    type Wait = TargetWait;
    type Target<'a>
        = TypeATarget<'a, T>
    where
        T: 'a;

    fn listen_type_a(
        &mut self,
        suffix: [u8; 3],
        wait: TargetWait,
    ) -> Result<Self::Target<'_>, Self::Error> {
        Reader::listen_type_a(self, suffix, wait)
    }
}

impl<'r, T: Transport> PassiveTarget for TypeATarget<'r, T> {
    type Error = Error<T::Error>;
    type Wait = TargetWait;
    type Command<'a>
        = TargetCommand<'a, 'r, T>
    where
        Self: 'a;

    fn uid(&self) -> [u8; 4] {
        self.uid()
    }

    fn receive(&mut self, wait: TargetWait) -> Result<Self::Command<'_>, Self::Error> {
        self.receive(wait)
    }

    fn finish(self) -> Result<(), Self::Error> {
        self.finish()
    }
}

impl<T: Transport> nfca::TargetCommand for TargetCommand<'_, '_, T> {
    type Error = Error<T::Error>;

    fn data(&self) -> &[u8] {
        self.data()
    }

    fn respond(self, data: &[u8]) -> Result<(), Self::Error> {
        self.respond(data)
    }
}
