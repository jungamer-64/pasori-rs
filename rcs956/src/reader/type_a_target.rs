use super::{Error, Reader, RfTimeout, State};
use crate::transport::Transport;
use alloc::vec::Vec;
use core::{mem, time::Duration};
use iso14443::nfca::{PassiveTarget, PassiveTargetReader, TargetCommand, TargetEvent};

const CONTROL_WAIT: Duration = Duration::from_secs(1);
/// First NFCID1 byte that the firmware assigns to a target UID.
const UID_PREFIX: u8 = 0x08;
/// TgInitTarget SENS_RES for a single-size UID. The firmware rejects the
/// command unless the second byte has exactly one of bits 4..0 set and bits
/// 7..5 clear; an initiator's InListPassiveTarget reports the two bytes in
/// reverse order.
const SENS_RES: [u8; 2] = [0x00, 0x04];

/// Exclusive passive NFC-A target at 106 kbps without ISO-DEP (SEL_RES 00).
/// The reader answers anticollision; the host receives every later command.
#[derive(Debug)]
pub struct TypeATarget<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    uid: [u8; 4],
    state: TargetState,
}

#[derive(Debug)]
enum TargetState {
    /// The activation response carried this first command.
    Activated(Vec<u8>),
    Waiting,
    Revoked,
}

/// One command received by a [`TypeATarget`]. Dropping it leaves the
/// command unanswered.
#[derive(Debug)]
pub struct TypeACommand<'t, 'a, T: Transport> {
    target: &'t mut TypeATarget<'a, T>,
    data: Vec<u8>,
}

impl<T: Transport> Reader<T> {
    /// Reset the reader and listen as a passive NFC-A target whose UID is
    /// `08` followed by `uid_suffix`. `timeout` bounds the wait for an
    /// initiator. Activation changes the firmware mode, which
    /// [`TypeATarget::finish`] clears.
    pub fn listen_type_a(
        &mut self,
        uid_suffix: [u8; 3],
        timeout: RfTimeout,
    ) -> Result<TypeATarget<'_, T>, Error<T::Error>> {
        self.initialize()?;
        self.state = State::NeedsInitialization;
        // The 106A target RF profile needs the ROM-07 receiver gain instead
        // of the value copied from EEPROM on some reader variants.
        self.write_register(0x0328, 0x59)?;
        // Disable automatic mode detection before firmware anticollision.
        self.write_register(0x6301, 0x3f)?;
        let [a, b, c] = uid_suffix;
        let [sens_first, sens_second] = SENS_RES;
        let mut args = [0; 35];
        args[..7].copy_from_slice(&[0, sens_first, sens_second, a, b, c, 0]);
        let activation = self.command(0x8c, &args, timeout.host_wait())?;
        let command = match activation.as_slice() {
            [0, command @ ..] if !command.is_empty() => command.to_vec(),
            [0] | [] => return Err(Error::Response("target activation command")),
            [mode, ..] => return Err(Error::TargetMode(*mode)),
        };
        Ok(TypeATarget {
            reader: self,
            uid: [UID_PREFIX, a, b, c],
            state: TargetState::Activated(command),
        })
    }
}

impl<'a, T: Transport> TypeATarget<'a, T> {
    /// The four-byte UID the target answers anticollision with.
    pub fn uid(&self) -> [u8; 4] {
        self.uid
    }

    /// Return the next initiator command, beginning with the one carried by
    /// the activation. A failure revokes the target; reader initialization is
    /// then required.
    pub fn receive(
        &mut self,
        timeout: RfTimeout,
    ) -> Result<TypeACommand<'_, 'a, T>, Error<T::Error>> {
        let data = match mem::replace(&mut self.state, TargetState::Revoked) {
            TargetState::Activated(command) => command,
            TargetState::Waiting => {
                let response = self.reader.command(0x88, &[], timeout.host_wait())?;
                match response.as_slice() {
                    [0, command @ ..] if !command.is_empty() => command.to_vec(),
                    [status, ..] if *status != 0 => return Err(Error::RfStatus(*status)),
                    _ => return Err(Error::Response("target command layout")),
                }
            }
            TargetState::Revoked => return Err(Error::NotInitialized),
        };
        self.state = TargetState::Waiting;
        Ok(TypeACommand { target: self, data })
    }

    /// Stop listening and return the reader to RF-off readiness.
    pub fn finish(self) -> Result<(), Error<T::Error>> {
        self.reader.initialize().map(|_| ())
    }
}

impl<T: Transport> TypeACommand<'_, '_, T> {
    /// Received command bytes without CRC.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Answer the command. A failure revokes the target and can leave
    /// delivery of the response uncertain.
    pub fn respond(self, response: &[u8]) -> Result<(), Error<T::Error>> {
        let target = self.target;
        target.state = TargetState::Revoked;
        match target
            .reader
            .command(0x90, response, CONTROL_WAIT)?
            .as_slice()
        {
            [0] => {}
            [status] => return Err(Error::RfStatus(*status)),
            _ => return Err(Error::Response("target response status length")),
        }
        target.state = TargetState::Waiting;
        Ok(())
    }
}

impl<T: Transport> PassiveTargetReader for Reader<T> {
    type Error = Error<T::Error>;
    type Wait = RfTimeout;
    type Target<'a>
        = TypeATarget<'a, T>
    where
        T: 'a;

    fn listen_type_a(
        &mut self,
        suffix: [u8; 3],
        wait: RfTimeout,
    ) -> Result<Self::Target<'_>, Self::Error> {
        Reader::listen_type_a(self, suffix, wait)
    }
}

impl<'r, T: Transport> PassiveTarget for TypeATarget<'r, T> {
    type Error = Error<T::Error>;
    type Wait = RfTimeout;
    type Command<'a>
        = TypeACommand<'a, 'r, T>
    where
        Self: 'a;

    fn uid(&self) -> [u8; 4] {
        self.uid()
    }

    /// The firmware's target command returns a received command or a
    /// status, so every event is a command and the rest are failures.
    fn receive(&mut self, wait: RfTimeout) -> Result<TargetEvent<Self::Command<'_>>, Self::Error> {
        self.receive(wait).map(TargetEvent::Command)
    }

    fn finish(self) -> Result<(), Self::Error> {
        self.finish()
    }
}

impl<T: Transport> TargetCommand for TypeACommand<'_, '_, T> {
    type Error = Error<T::Error>;

    fn data(&self) -> &[u8] {
        self.data()
    }

    fn respond(self, data: &[u8]) -> Result<(), Self::Error> {
        self.respond(data)
    }
}
