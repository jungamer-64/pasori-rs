use super::{
    ActivationError, Error, MAX_TYPE_A_COMMAND_BYTES, Reader, ResponseTimeout, RfProtocol,
    RfTimeout, TargetExchangeError, admit_command,
};
use crate::transport::Transport;
use alloc::vec::Vec;

/// A selected NFC-A Type 1 target, whose commands the reader transceives
/// with their single response fragment.
///
/// If the reader reports a pending response fragment, reinitialize before
/// selecting another tag or sending another card command.
#[derive(Debug)]
pub struct Type1Target<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    target: u8,
    timeout: ResponseTimeout,
}

impl<T: Transport> Reader<T> {
    /// Activate one legacy Type 1 target at 106 kbps.
    pub fn poll_type1(
        &mut self,
        timeout: RfTimeout,
    ) -> Result<Option<Type1Target<'_, T>>, TargetExchangeError<T::Error>> {
        self.configure_rf(RfProtocol::TypeA, timeout)
            .map_err(TargetExchangeError::Preparation)?;
        let selection = self
            .list_passive_target(&[1, 4], timeout.host_wait())
            .map_err(|error| match error {
                ActivationError::BeforeRequest(error) => TargetExchangeError::Preparation(error),
                ActivationError::Request(error) => TargetExchangeError::Exchange(error),
            })?;
        let target = match selection.as_slice() {
            [0] => return Ok(None),
            [1, target, _, _, _, _, _, _] if *target != 0 => *target,
            _ => {
                self.require_field_cycle();
                return Err(TargetExchangeError::Exchange(Error::Response(
                    "Type 1 selection layout",
                )));
            }
        };
        Ok(Some(Type1Target {
            reader: self,
            target,
            timeout: ResponseTimeout::for_request(timeout),
        }))
    }
}

impl<T: Transport> Type1Target<'_, T> {
    /// Target identifier returned by the reader.
    pub fn target(&self) -> u8 {
        self.target
    }

    /// Make the next selection cycle the RF field before its request, because
    /// the tag now holds state that a selection request does not clear.
    pub fn require_field_cycle(&mut self) {
        self.reader.require_field_cycle();
    }

    /// Send one Type 1 command and return its response bytes. A nonzero
    /// reader status is reported as [`Error::RfStatus`] after the exchange.
    pub fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>, TargetExchangeError<T::Error>> {
        admit_command(command, MAX_TYPE_A_COMMAND_BYTES)?;
        let response = self.reader.exchange_single_response(
            RfProtocol::TypeA,
            self.target,
            command,
            self.timeout,
        )?;
        if response.status != 0 {
            return Err(TargetExchangeError::Exchange(Error::RfStatus(
                response.status,
            )));
        }
        Ok(response.data)
    }
}
