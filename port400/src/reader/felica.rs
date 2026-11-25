//! FeliCa polling at 212 kbps and negotiated packet exchange.

use super::{Error, FelicaRate, Field, IccResponsePolicy, Profile, Reader, ResponseWait, Session};
use crate::transport::Transport;
use alloc::vec::Vec;
use core::time::Duration;
use felica_packet::{PollRequest, PollResponse, Selection, validate_length};

const MAX_PACKET: usize = u8::MAX as usize;

impl<T: Transport> Reader<T> {
    /// Send FeliCa Polling at 212 kbps. With request code `02`, switch to
    /// 424 kbps for subsequent exchanges if the card advertises automatic
    /// switching and 424 kbps support. The selected card uses the same wait
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
        let initial = Profile::Felica(FelicaRate::Kbps212);
        match self.field()? {
            Field::On {
                profile: Profile::Felica(FelicaRate::Kbps212),
                cycle_before_poll: false,
            } => {}
            Field::On {
                profile: Profile::Felica(FelicaRate::Kbps424),
                cycle_before_poll: false,
            } => self.apply_felica_rate(FelicaRate::Kbps212)?,
            _ => {
                self.session = Session::Active(Field::Uncertain);
                self.acknowledge(&initial.switch_command())?;
                self.rf_off()?;
                self.acknowledge(&initial.framing_command())?;
                self.energize()?;
                self.apply_felica_rate(FelicaRate::Kbps212)?;
            }
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
            Ok(observation) => {
                if request.request_code() == 2 && supports_automatic_424(observation) {
                    self.apply_felica_rate(FelicaRate::Kbps424)?;
                }
                Ok(Some(FelicaCard {
                    reader: self,
                    request,
                    observation,
                    wait,
                }))
            }
            Err(error) => {
                self.invalidate_field();
                Err(Error::FelicaResponse(error))
            }
        }
    }

    fn apply_felica_rate(&mut self, rate: FelicaRate) -> Result<(), Error<T::Error>> {
        self.invalidate_field();
        self.acknowledge(&rate.command())?;
        self.enable_profile(Profile::Felica(rate));
        Ok(())
    }
}

fn supports_automatic_424(observation: PollResponse) -> bool {
    const AUTOMATIC_AND_424: u8 = 0x82;
    // The driver's negotiation masks out 424 kbps for IC code 0B.
    observation.pmm[1] != 0x0b
        && observation
            .request_data
            .is_some_and(|[_, flags]| flags & AUTOMATIC_AND_424 == AUTOMATIC_AND_424)
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
