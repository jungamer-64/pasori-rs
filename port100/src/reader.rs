//! Reader initialization and lifetime-bound FeliCa card access.
//!
//! Initialization and the FeliCa RF and protocol settings follow what Sony's
//! NFC Port 5.6.9.0 driver package sends to Port-100 readers, including the
//! settings it withholds from older firmware.

use crate::transport::{Failure, Link, Progress, TransactionError, Transport};
use alloc::vec::Vec;
use core::{error, fmt, time::Duration};
use felica_packet::{PacketError, PollRequest, PollResponse, Selection};

/// Host wait of commands that do not reach a card.
const COMMAND_WAIT: Duration = Duration::from_secs(1);
/// Host wait for an InCommRF response beyond the RF wait the reader runs.
const RF_MARGIN: Duration = Duration::from_secs(1);
/// Time the RF field stays off so that a card loses its state.
const FIELD_OFF_SETTLE: Duration = Duration::from_millis(5);
/// InCommRF status for a card reply that did not arrive within the RF wait.
const RECEIVE_TIMEOUT: u32 = 0x80;
/// Highest command type that initialization selects.
const MAX_COMMAND_TYPE: u8 = 2;
/// InSetRF technology code of FeliCa.
const FELICA: u8 = 0x01;
/// InSetRF receive technology code meaning "same as the send technology".
const SAME_AS_SEND: u8 = 0x0f;

/// Failures of reader initialization, RF control, or card exchange.
#[derive(Debug)]
pub enum Error<E> {
    /// Host transport transaction failed. Unless its progress is
    /// [`Progress::NotSent`] and the stream was usable, the reader must be
    /// reinitialized.
    Transaction(TransactionError<E>),
    /// Reader initialization is required before the requested operation.
    NotInitialized,
    /// A command response did not have the required layout.
    Response(&'static str),
    /// A command returned a nonzero status byte.
    CommandStatus {
        /// Request command.
        command: u8,
        /// Returned status.
        status: u8,
    },
    /// The reader reported an RF failure other than a missing card reply.
    /// The packet was sent and may have taken effect; the next selection
    /// cycles the RF field.
    RfStatus(u32),
    /// A FeliCa packet was malformed before it was sent.
    FelicaRequest(PacketError),
    /// A FeliCa reply was malformed. The packet that caused it was sent and
    /// may have taken effect.
    FelicaResponse(PacketError),
    /// No card reply arrived within the wait. The card may have received the
    /// packet and taken effect; the reader remains usable.
    NoResponse,
}

impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transaction(_) => f.write_str("reader transaction failed"),
            Self::NotInitialized => f.write_str("reader requires initialization"),
            Self::Response(reason) => write!(f, "malformed reader response: {reason}"),
            Self::CommandStatus { command, status } => {
                write!(f, "command {command:02X} returned status {status:02X}")
            }
            Self::RfStatus(status) => write!(
                f,
                "RF status {status:08X}; the command may have taken effect"
            ),
            Self::FelicaRequest(_) => f.write_str("FeliCa request rejected before sending"),
            Self::FelicaResponse(_) => {
                f.write_str("FeliCa response failed; the command may have taken effect")
            }
            Self::NoResponse => f.write_str("no card reply; the command may have taken effect"),
        }
    }
}

impl<E: error::Error + 'static> error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Transaction(error) => Some(error),
            Self::FelicaRequest(error) | Self::FelicaResponse(error) => Some(error),
            _ => None,
        }
    }
}

/// Wait for a card reply that the reader runs, in its 100 µs unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseWait(u16);

impl ResponseWait {
    /// Longest finite wait; the next unit value means an unbounded wait.
    pub const MAX: Duration = Duration::from_micros(100 * 0xfffe);

    /// Round `duration` up to the 100 µs unit. Rejects zero and waits above
    /// [`Self::MAX`].
    pub fn new(duration: Duration) -> Option<Self> {
        let units = duration.as_nanos().div_ceil(100_000);
        u16::try_from(units)
            .ok()
            .filter(|units| *units != 0 && *units != u16::MAX)
            .map(Self)
    }

    /// The wait after rounding.
    pub fn duration(self) -> Duration {
        Duration::from_micros(u64::from(self.0) * 100)
    }

    fn host_wait(self) -> Duration {
        self.duration() + RF_MARGIN
    }
}

/// RF rate selected for FeliCa polling and subsequent exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BitRate {
    /// 212 kbps.
    Kbps212,
    /// 424 kbps.
    Kbps424,
}

impl BitRate {
    /// InSetRF bit-rate code, shared by every firmware.
    fn code(self) -> u8 {
        match self {
            Self::Kbps212 => 0x01,
            Self::Kbps424 => 0x02,
        }
    }
}

/// Hardware observations obtained by a completed initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderInfo {
    /// Command type selected with SetCommandType: the highest type up to 2
    /// that GetCommandType reports, or 0.
    pub command_type: u8,
    /// GetFirmwareVersion value.
    pub firmware: u16,
    /// GetFirmwareVersion value for option `60`. Its meaning is not
    /// established; it selects, together with [`Self::firmware`], the
    /// protocol settings that are withheld from older firmware.
    pub firmware_option_60: u16,
    /// GetPDDataVersion value.
    pub pd_data: u16,
}

/// Firmware observations that select the FeliCa protocol settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Firmware {
    version: u16,
    option_60: u16,
}

impl Firmware {
    /// Whether the firmware belongs to the older range that ends at `last`.
    /// Only option-60 values up to 5 have older ranges, and for them
    /// versions `0101`..`0199` compare as if shifted left by four bits, which
    /// places them above every range.
    fn at_most(self, last: u16) -> bool {
        if self.option_60 > 5 {
            return false;
        }
        let version = u32::from(self.version);
        let version = if (0x101..0x19a).contains(&version) {
            version << 4
        } else {
            version
        };
        (1..=u32::from(last)).contains(&version)
    }

    /// InSetProtocol pairs for FeliCa polling and exchange: CRC appended and
    /// checked, no parity or SOF/EOF, initial guard time 18 and guard time
    /// 6. Firmware up to 0599 receives tag 0D instead of tag 12, firmware up
    /// to 0609 receives the general receive settings for tags 0E to 10, and
    /// firmware up to 0619 does not receive tag 13.
    fn felica_protocol(self) -> Vec<u8> {
        let mut pairs = Vec::with_capacity(38);
        pairs.extend_from_slice(&[
            0x00, 0x18, 0x01, 0x01, 0x02, 0x01, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00,
            0x07, 0x08, 0x08, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00,
        ]);
        let older_tags = self.at_most(0x599);
        if older_tags {
            pairs.extend_from_slice(&[0x0d, 0x00]);
        }
        if self.at_most(0x609) {
            pairs.extend_from_slice(&[0x0e, 0x04, 0x0f, 0x00, 0x10, 0x00]);
        } else {
            pairs.extend_from_slice(&[0x0e, 0x00, 0x0f, 0x05, 0x10, 0xff]);
        }
        pairs.extend_from_slice(&[0x11, 0x00]);
        if !older_tags {
            pairs.extend_from_slice(&[0x12, 0x00]);
        }
        if !self.at_most(0x619) {
            pairs.extend_from_slice(&[0x13, 0x06]);
        }
        pairs
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// The field is off and no FeliCa settings are known to be in effect.
    Off,
    /// FeliCa settings for this rate were accepted.
    Felica(BitRate),
    /// The card can hold state that the next Polling does not clear, or an
    /// RF failure left the field state unknown, so the next selection
    /// switches the field off first.
    CycleRequired,
}

#[derive(Debug)]
enum State {
    NeedsInitialization,
    Ready { firmware: Firmware, field: Field },
}

/// Exclusive reader owner. Uncertain transport failures revoke readiness.
#[derive(Debug)]
pub struct Reader<T: Transport> {
    link: Link<T>,
    state: State,
}

impl<T: Transport> Reader<T> {
    /// Own a newly opened transport. Initialization sends no data until requested.
    pub fn new(transport: T) -> Self {
        Self {
            link: Link::new(transport),
            state: State::NeedsInitialization,
        }
    }

    fn command(&mut self, cc: u8, args: &[u8], wait: Duration) -> Result<Vec<u8>, Error<T::Error>> {
        match self.link.command(cc, args, wait) {
            Ok(response) => Ok(response.data),
            Err(e) => {
                // A rejected, never-sent request leaves reader and card state
                // unchanged unless the stream itself already requires recovery.
                if e.progress != Progress::NotSent || matches!(e.failure, Failure::RecoveryRequired)
                {
                    self.state = State::NeedsInitialization;
                }
                Err(Error::Transaction(e))
            }
        }
    }

    fn status_command(&mut self, cc: u8, args: &[u8]) -> Result<(), Error<T::Error>> {
        match self.command(cc, args, COMMAND_WAIT)?.as_slice() {
            [0] => Ok(()),
            [status] => Err(Error::CommandStatus {
                command: cc,
                status: *status,
            }),
            _ => Err(Error::Response("status length")),
        }
    }

    fn version(&mut self, cc: u8, args: &[u8]) -> Result<u16, Error<T::Error>> {
        match self.command(cc, args, COMMAND_WAIT)?.as_slice() {
            [low, high] => Ok(u16::from_le_bytes([*low, *high])),
            _ => Err(Error::Response("version length")),
        }
    }

    /// Cancel any unfinished reader command, select the command type, read
    /// the firmware and PD data versions, and switch the RF field off.
    /// Failure leaves the reader uninitialized; no command replay.
    ///
    /// # Errors
    ///
    /// Returns transport failures, nonzero statuses, and responses whose
    /// layout differs from the commands' fixed lengths.
    pub fn initialize(&mut self) -> Result<ReaderInfo, Error<T::Error>> {
        self.state = State::NeedsInitialization;
        self.link.recover().map_err(Error::Transaction)?;
        // Bit n of the big-endian bitmap reports command type n.
        let types = <[u8; 8]>::try_from(self.command(0x28, &[], COMMAND_WAIT)?.as_slice())
            .map(u64::from_be_bytes)
            .map_err(|_| Error::Response("command type length"))?;
        let command_type = (1..=MAX_COMMAND_TYPE)
            .rev()
            .find(|kind| types & (1_u64 << *kind) != 0)
            .unwrap_or(0);
        self.status_command(0x2a, &[command_type])?;
        let firmware = Firmware {
            option_60: self.version(0x20, &[0x60])?,
            version: self.version(0x20, &[])?,
        };
        let pd_data = self.version(0x22, &[])?;
        self.switch_field_off()?;
        self.state = State::Ready {
            firmware,
            field: Field::Off,
        };
        Ok(ReaderInfo {
            command_type,
            firmware: firmware.version,
            firmware_option_60: firmware.option_60,
            pd_data,
        })
    }

    fn switch_field_off(&mut self) -> Result<(), Error<T::Error>> {
        self.status_command(0x06, &[0x00])?;
        self.link.wait(FIELD_OFF_SETTLE);
        Ok(())
    }

    fn ready(&mut self) -> Result<(Firmware, &mut Field), Error<T::Error>> {
        match &mut self.state {
            State::Ready { firmware, field } => Ok((*firmware, field)),
            State::NeedsInitialization => Err(Error::NotInitialized),
        }
    }

    fn set_field(&mut self, value: Field) {
        if let State::Ready { field, .. } = &mut self.state {
            *field = value;
        }
    }

    /// Switch the RF field off. Call explicitly to observe failure; dropping
    /// a reader only releases the backend's OS resources.
    ///
    /// # Errors
    ///
    /// Requires initialization; a failed command leaves the reader requiring
    /// it again, and a nonzero status leaves the field state unknown.
    pub fn rf_off(&mut self) -> Result<(), Error<T::Error>> {
        self.ready()?;
        self.set_field(Field::CycleRequired);
        self.switch_field_off()?;
        self.set_field(Field::Off);
        Ok(())
    }

    /// Send the FeliCa RF and protocol settings for `rate` unless they are
    /// in effect. A rejected setting leaves the field state unknown.
    fn configure_felica(&mut self, rate: BitRate) -> Result<(), Error<T::Error>> {
        let (firmware, field) = self.ready()?;
        let current = *field;
        match current {
            Field::Felica(configured) if configured == rate => return Ok(()),
            Field::CycleRequired => self.rf_off()?,
            Field::Off | Field::Felica(_) => {}
        }
        self.set_field(Field::CycleRequired);
        self.status_command(0x00, &[FELICA, rate.code(), SAME_AS_SEND, rate.code()])?;
        self.status_command(0x02, &firmware.felica_protocol())?;
        self.set_field(Field::Felica(rate));
        Ok(())
    }

    /// Select one FeliCa card at `rate`. The returned card exclusively
    /// borrows this reader, and its exchanges wait as long as this Polling.
    ///
    /// Returns `None` when no card replies within `wait`. The reader receives
    /// one reply; time slots are carried in the packet, but how the reader
    /// handles several answering cards is not established here.
    ///
    /// # Errors
    ///
    /// Requires initialization. An RF failure or a malformed polling
    /// response requires a field cycle before the next selection.
    pub fn poll_felica(
        &mut self,
        rate: BitRate,
        request: PollRequest,
        wait: ResponseWait,
    ) -> Result<Option<FelicaCard<'_, T>>, Error<T::Error>> {
        self.configure_felica(rate)?;
        let Some(packet) = self.exchange(&request.encode(), wait)? else {
            return Ok(None);
        };
        match PollResponse::parse(&packet) {
            Ok(observation) => Ok(Some(FelicaCard {
                reader: self,
                request,
                observation,
                wait,
            })),
            Err(error) => {
                self.set_field(Field::CycleRequired);
                Err(Error::FelicaResponse(error))
            }
        }
    }

    /// Carry one packet with InCommRF and return the card's reply, or `None`
    /// when no reply arrived within `wait`.
    fn exchange(
        &mut self,
        packet: &[u8],
        wait: ResponseWait,
    ) -> Result<Option<Vec<u8>>, Error<T::Error>> {
        self.ready()?;
        let mut args = Vec::with_capacity(packet.len() + 2);
        args.extend_from_slice(&wait.0.to_le_bytes());
        args.extend_from_slice(packet);
        let response = self.command(0x04, &args, wait.host_wait())?;
        let Some((&[s0, s1, s2, s3, _], received)) = response.split_first_chunk::<5>() else {
            return Err(Error::Response("InCommRF length"));
        };
        match u32::from_le_bytes([s0, s1, s2, s3]) {
            0 if received.is_empty() => Ok(None),
            0 => {
                felica_packet::validate_length(received, 2).map_err(Error::FelicaResponse)?;
                Ok(Some(received.to_vec()))
            }
            RECEIVE_TIMEOUT => Ok(None),
            status => {
                self.set_field(Field::CycleRequired);
                Err(Error::RfStatus(status))
            }
        }
    }

    fn require_field_cycle(&mut self) {
        self.set_field(Field::CycleRequired);
    }
}

/// Selected FeliCa card whose operation authority is tied to one reader borrow.
///
/// [`Selection::exchange_packet`] carries one packet with InCommRF and waits
/// as long as the Polling that selected the card; a missing reply is
/// [`Error::NoResponse`].
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

    /// IDm is a session address, not a universal persistent ID.
    fn poll_response(&self) -> &PollResponse {
        &self.observation
    }

    fn exchange_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error<T::Error>> {
        felica_packet::validate_length(packet, 2).map_err(Error::FelicaRequest)?;
        self.reader
            .exchange(packet, self.wait)?
            .ok_or(Error::NoResponse)
    }

    fn require_field_cycle(&mut self) {
        self.reader.require_field_cycle();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn older_firmware_ranges_follow_option_60_and_the_shifted_versions() {
        let firmware = |option_60, version| Firmware { option_60, version };
        assert!(firmware(0, 0x0599).at_most(0x599));
        assert!(!firmware(0, 0x0600).at_most(0x599));
        assert!(!firmware(6, 0x0100).at_most(0x599));
        assert!(!firmware(0, 0x0000).at_most(0x599));
        assert!(firmware(5, 0x0100).at_most(0x199));
        assert!(!firmware(5, 0x0101).at_most(0x711));
        assert!(!firmware(5, 0x0199).at_most(0x711));
        assert!(!firmware(5, 0x019a).at_most(0x199));
        assert!(firmware(5, 0x019a).at_most(0x299));
    }

    #[test]
    fn response_waits_round_up_to_the_reader_unit() {
        assert_eq!(
            ResponseWait::new(Duration::from_micros(150)).map(ResponseWait::duration),
            Some(Duration::from_micros(200))
        );
        assert_eq!(ResponseWait::new(Duration::ZERO), None);
        assert_eq!(
            ResponseWait::new(ResponseWait::MAX).map(ResponseWait::duration),
            Some(ResponseWait::MAX)
        );
        assert_eq!(
            ResponseWait::new(ResponseWait::MAX + Duration::from_nanos(1)),
            None
        );
    }
}
