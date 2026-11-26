//! Reader initialization and lifetime-bound card access.
//!
//! Initialization and the RF and protocol settings follow what Sony's NFC
//! Port 5.6.9.0 driver package sends to Port-100 readers. The host runs NFC-A
//! anticollision, RATS and the NFC-B ATTRIB itself; the reader carries each
//! frame and, except where a card handle says otherwise, its CRC.

mod iso_dep;
mod settings;
mod target;
mod type_a;
mod type_b;

pub use iso_dep::{Activation, IsoDepBlocks, IsoDepCard, READER_FRAME_SIZE};
pub use target::{
    FelicaTarget, IsoDepATarget, PollingResponder, TargetCommand, TargetWait, TypeATarget,
};
pub use type_a::{TypeACard, TypeASelection};

use crate::transport::{Failure, Link, Progress, TransactionError, Transport};
use alloc::vec::Vec;
use core::{error, fmt, time::Duration};
use felica_packet::{PacketError, PollRequest, PollResponse, Selection};
use iso14443::{nfca, nfcb};
use settings::{Firmware, Settings};

/// Largest RF frame, without the CRC that the reader appends, that one
/// InCommRF carries.
pub const MAX_FRAME_BYTES: usize = 0x122;
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
    /// The frame was sent and may have taken effect; the next selection
    /// cycles the RF field.
    RfStatus(u32),
    /// A FeliCa packet was malformed before it was sent.
    FelicaRequest(PacketError),
    /// A FeliCa reply was malformed. The packet that caused it was sent and
    /// may have taken effect.
    FelicaResponse(PacketError),
    /// No card reply arrived within the wait. The card may have received the
    /// frame and taken effect; the reader remains usable.
    NoResponse,
    /// Type A target setup received no initiator command within its wait.
    NoInitiator,
    /// The initiator's field went away while a target responded. Delivery is
    /// unknown, and the next receive awaits a new activation.
    TargetFieldOff,
    /// NFC-A activation data failed validation.
    TypeA(nfca::Error),
    /// NFC-B activation data failed validation.
    TypeB(nfcb::Error),
    /// A card reply did not have the layout its command requires.
    CardReply(&'static str),
    /// An NFC-A reply that requires whole bytes reported this final bit count.
    CardReplyBitCount(u8),
    /// A card reply that the host checks failed its CRC.
    CardCrc,
    /// The RF settings this selection exchanges under are no longer known to
    /// be in effect; the card must be selected again.
    FieldReset,
    /// A frame exceeds what one InCommRF carries.
    InputLength {
        /// Maximum accepted bytes.
        maximum: usize,
        /// Supplied bytes.
        actual: usize,
    },
    /// A requested wait is zero or longer than [`ResponseWait::MAX`].
    WaitRange(Duration),
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
            Self::NoInitiator => f.write_str("no initiator command received within the wait"),
            Self::TargetFieldOff => f.write_str("the initiator's RF field went off"),
            Self::TypeA(_) => f.write_str("invalid NFC-A activation"),
            Self::TypeB(_) => f.write_str("invalid NFC-B activation"),
            Self::CardReply(reason) => write!(f, "malformed card reply: {reason}"),
            Self::CardReplyBitCount(bits) => {
                write!(
                    f,
                    "expected 8 bits in the last NFC-A reply byte, received {bits}"
                )
            }
            Self::CardCrc => f.write_str("card reply failed its CRC"),
            Self::FieldReset => f.write_str("RF settings of the selection were lost"),
            Self::InputLength { maximum, actual } => {
                write!(f, "input of {actual} bytes exceeds {maximum}")
            }
            Self::WaitRange(wait) => write!(f, "wait of {wait:?} cannot be encoded"),
        }
    }
}

impl<E: error::Error + 'static> error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Transaction(error) => Some(error),
            Self::FelicaRequest(error) | Self::FelicaResponse(error) => Some(error),
            Self::TypeA(error) => Some(error),
            Self::TypeB(error) => Some(error),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// The field is off and no settings are known to be in effect.
    Off,
    /// These settings were accepted. `cycle` makes the next selection switch
    /// the field off first, because a card can hold state that selection
    /// does not clear or an RF failure left the card state unknown.
    On { settings: Settings, cycle: bool },
    /// A rejected setting left the settings unknown; the next selection
    /// switches the field off first.
    Unknown,
}

#[derive(Debug)]
enum State {
    NeedsInitialization,
    Ready { firmware: Firmware, field: Field },
}

/// One card reply carried by InCommRF.
#[derive(Debug)]
struct Received {
    data: Vec<u8>,
    /// Response byte 5. The driver package accepts an NFC-A reply that the
    /// reader checked only when this byte is 8; reading it as the number of
    /// valid bits in the last byte is an inference, not an established
    /// meaning.
    last_bits: u8,
}

impl Received {
    fn whole_bytes<E>(self) -> Result<Vec<u8>, Error<E>> {
        if self.last_bits == 8 {
            Ok(self.data)
        } else {
            Err(Error::CardReplyBitCount(self.last_bits))
        }
    }
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

    fn ready(&self) -> Result<(Firmware, Field), Error<T::Error>> {
        match self.state {
            State::Ready { firmware, field } => Ok((firmware, field)),
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
        self.set_field(Field::Unknown);
        self.switch_field_off()?;
        self.set_field(Field::Off);
        Ok(())
    }

    /// Make the next selection switch the field off before its request.
    fn require_field_cycle(&mut self) {
        if let State::Ready {
            field: Field::On { cycle, .. },
            ..
        } = &mut self.state
        {
            *cycle = true;
        }
    }

    /// Send `settings` unless they are in effect, switching the field off
    /// first when a field cycle is required. A rejected setting leaves the
    /// settings unknown.
    fn configure(&mut self, settings: Settings) -> Result<(), Error<T::Error>> {
        let (firmware, field) = self.ready()?;
        match field {
            Field::On {
                settings: current,
                cycle: false,
            } if current == settings => return Ok(()),
            Field::On { cycle: true, .. } | Field::Unknown => self.rf_off()?,
            Field::Off | Field::On { .. } => {}
        }
        self.set_field(Field::Unknown);
        self.status_command(0x00, &settings.rf(firmware))?;
        self.status_command(0x02, &settings.protocol(firmware))?;
        self.set_field(Field::On {
            settings,
            cycle: false,
        });
        Ok(())
    }

    /// Start an NFC-A or NFC-B activation from a field that was off, so that
    /// every card in it starts from its idle state, under `settings`.
    fn begin_activation(&mut self, settings: Settings) -> Result<(), Error<T::Error>> {
        if self.ready()?.1 != Field::Off {
            self.rf_off()?;
        }
        self.configure(settings)
    }

    /// Apply protocol pairs within an activation, keeping the settings
    /// unknown until the activation publishes them.
    fn set_protocol(&mut self, pairs: &[u8]) -> Result<(), Error<T::Error>> {
        self.set_field(Field::Unknown);
        self.status_command(0x02, pairs)
    }

    /// Carry one frame of a selected card under `settings`. NFC-A switches
    /// between reader and host CRC checks as the frame requires; any other
    /// difference from the settings in effect means that the card's
    /// selection no longer holds.
    fn transceive(
        &mut self,
        settings: Settings,
        frame: &[u8],
        wait: ResponseWait,
    ) -> Result<Option<Received>, Error<T::Error>> {
        let (_, field) = self.ready()?;
        let Field::On {
            settings: current,
            cycle,
        } = field
        else {
            return Err(Error::FieldReset);
        };
        if current != settings {
            let (Settings::TypeA(_), Settings::TypeA(check)) = (current, settings) else {
                return Err(Error::FieldReset);
            };
            self.set_field(Field::Unknown);
            self.status_command(0x02, &settings::crc_check(check))?;
            self.set_field(Field::On { settings, cycle });
        }
        self.in_comm_rf(frame, wait)
    }

    /// Send one RF frame within an activation and require a card reply.
    fn card_reply(
        &mut self,
        frame: &[u8],
        wait: ResponseWait,
    ) -> Result<Received, Error<T::Error>> {
        self.in_comm_rf(frame, wait)?.ok_or(Error::NoResponse)
    }

    /// Send one RF frame with InCommRF and return the card's reply, or
    /// `None` when no reply arrived within `wait`.
    fn in_comm_rf(
        &mut self,
        frame: &[u8],
        wait: ResponseWait,
    ) -> Result<Option<Received>, Error<T::Error>> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(Error::InputLength {
                maximum: MAX_FRAME_BYTES,
                actual: frame.len(),
            });
        }
        let mut args = Vec::with_capacity(frame.len() + 2);
        args.extend_from_slice(&wait.0.to_le_bytes());
        args.extend_from_slice(frame);
        let response = self.command(0x04, &args, wait.host_wait())?;
        // Byte 5 and the card bytes follow the status only when the reader
        // received card bytes.
        let Some((&status, reply)) = response.split_first_chunk::<4>() else {
            return Err(Error::Response("InCommRF length"));
        };
        match (u32::from_le_bytes(status), reply) {
            (0, [] | [_]) => Ok(None),
            (0, [last_bits, data @ ..]) => Ok(Some(Received {
                data: data.to_vec(),
                last_bits: *last_bits,
            })),
            (RECEIVE_TIMEOUT, _) => Ok(None),
            (status, _) => {
                self.require_field_cycle();
                Err(Error::RfStatus(status))
            }
        }
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
        let settings = Settings::Felica(rate);
        self.configure(settings)?;
        let Some(packet) = self.felica_exchange(settings, &request.encode(), wait)? else {
            return Ok(None);
        };
        match PollResponse::parse(&packet) {
            Ok(observation) => Ok(Some(FelicaCard {
                reader: self,
                rate,
                request,
                observation,
                wait,
            })),
            Err(error) => {
                self.require_field_cycle();
                Err(Error::FelicaResponse(error))
            }
        }
    }

    /// Carry one FeliCa packet and return the card's packet, whose length
    /// byte has been checked.
    fn felica_exchange(
        &mut self,
        settings: Settings,
        packet: &[u8],
        wait: ResponseWait,
    ) -> Result<Option<Vec<u8>>, Error<T::Error>> {
        let Some(received) = self.transceive(settings, packet, wait)? else {
            return Ok(None);
        };
        felica_packet::validate_length(&received.data, 2).map_err(Error::FelicaResponse)?;
        Ok(Some(received.data))
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
    rate: BitRate,
    request: PollRequest,
    observation: PollResponse,
    wait: ResponseWait,
}

impl<T: Transport> Selection for FelicaCard<'_, T> {
    type Error = Error<T::Error>;

    fn max_packet_len(&self) -> usize {
        MAX_FRAME_BYTES.min(usize::from(u8::MAX))
    }

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
            .felica_exchange(Settings::Felica(self.rate), packet, self.wait)?
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
