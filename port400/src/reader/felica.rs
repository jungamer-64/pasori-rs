//! FeliCa polling and packet exchange at 212 kbps.

use super::{Error, Field, IccResponsePolicy, Profile, Reader, ResponseWait, Session, apdu};
use crate::transport::Transport;
use alloc::vec::Vec;
use core::time::Duration;
use felica_packet::{PollRequest, PollResponse, Selection, validate_length};

const MAX_PACKET: usize = u8::MAX as usize;

impl<T: Transport> Reader<T> {
    /// Send FeliCa Polling at 212 kbps. The selected card uses the same wait
    /// for later exchanges. Returns `None` when the reader reports an RF timeout.
    /// If the reader returns multiple ICC Response objects, the last one
    /// supplies the card reply.
    ///
    /// # Errors
    ///
    /// Requires initialization. Setup, transport, and malformed replies
    /// are reported separately from an absent card.
    pub fn poll_felica(
        &mut self,
        request: PollRequest,
        wait: ResponseWait,
    ) -> Result<Option<FelicaCard<'_, T>>, Error<T::Error>> {
        if !matches!(
            self.field()?,
            Field::On {
                profile: Profile::Felica,
                cycle_before_poll: false
            }
        ) {
            self.session = Session::Active(Field::Uncertain);
            self.acknowledge(&Profile::Felica.switch_command())?;
            self.rf_off()?;
            self.acknowledge(&Profile::Felica.framing_command())?;
            self.energize()?;
            self.acknowledge(&apdu::speed(0x89))?;
            self.enable_profile(Profile::Felica);
        }
        let packet = request.encode();
        let response = match self.exchange_rf(&packet, wait, IccResponsePolicy::LastPollingReply) {
            Err(Error::NoResponse) => return Ok(None),
            result => result?,
        };
        // Leave the remaining Polling slots quiet before the next operation.
        let slots = u64::from(packet[5]) + 1;
        self.link
            .wait(Duration::from_millis((slots + 1) * 12 / 10 + 1));
        match PollResponse::parse(&response) {
            Ok(observation) => Ok(Some(FelicaCard {
                reader: self,
                request,
                observation,
                wait,
            })),
            Err(error) => {
                self.invalidate_field();
                Err(Error::FelicaResponse(error))
            }
        }
    }
}

/// A FeliCa card selected through one exclusively borrowed Port-400 reader.
#[derive(Debug)]
pub struct FelicaCard<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    request: PollRequest,
    observation: PollResponse,
    wait: ResponseWait,
}

impl<T: Transport> Selection for FelicaCard<'_, T> {
    type Error = Error<T::Error>;

    fn poll_request(&self) -> PollRequest {
        self.request
    }

    fn poll_response(&self) -> &PollResponse {
        &self.observation
    }

    fn max_packet_len(&self) -> usize {
        MAX_PACKET
    }

    fn exchange_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>, Self::Error> {
        validate_length(packet, 2).map_err(Error::FelicaRequest)?;
        let result = self
            .reader
            .exchange_rf(packet, self.wait, IccResponsePolicy::Unique)
            .and_then(|response| {
                validate_length(&response, 2).map_err(Error::FelicaResponse)?;
                Ok(response)
            });
        if result.is_err() {
            self.reader.invalidate_field();
        }
        result
    }

    fn require_field_cycle(&mut self) {
        self.reader.require_cycle();
    }
}
