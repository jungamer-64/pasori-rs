//! Reader initialization and lifetime-bound FeliCa card access.
//!
//! Initialization, the RF and protocol settings and the FeliCa transfers
//! follow what Sony's NFC Port 5.6.9.0 driver package sends to Port-110
//! readers. The driver runs no other card technology on these readers.

mod rf_table;

use crate::transport::{Failure, Link, Progress, TransactionError, Transport};
use alloc::vec::Vec;
use core::{error, fmt, time::Duration};
use felica_packet::{PacketError, PollRequest, PollResponse, Selection};
use rf_table::Table;

/// Largest FeliCa packet, including its length byte, that one InCommRF
/// carries in either direction.
pub const MAX_PACKET_BYTES: usize = 255;
/// Host wait of commands that do not reach a card, the shortest that the
/// driver gives the commands of its open sequence.
const COMMAND_WAIT: Duration = Duration::from_millis(2400);
/// Time the RF field stays off so that a card loses its state.
const FIELD_OFF_SETTLE: Duration = Duration::from_millis(5);
/// InCommRF status for a card reply that did not arrive within the RF wait.
const RECEIVE_TIMEOUT: u32 = 0x80;
/// Command type that the driver requires and selects.
const COMMAND_TYPE: u8 = 3;
/// Valid-bit count of the last byte that InCommRF reports with card bytes.
const WHOLE_BYTES: u8 = 8;
/// InSetProtocol pairs that the driver sends after every InSetRF.
const PROTOCOL: [u8; 6] = [0x0e, 0x00, 0x0f, 0x05, 0x10, 0xff];

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
    /// GetCommandType did not report command type 3, which the driver
    /// requires.
    MissingCommandType {
        /// Reported bitmap; bit `n` reports command type `n`.
        types: u64,
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
    /// A card reply reported this valid-bit count for its last byte instead
    /// of 8.
    CardReplyBitCount(u8),
    /// The RF settings this selection exchanges under are no longer known to
    /// be in effect; the card must be selected again.
    FieldReset,
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
            Self::MissingCommandType { types } => {
                write!(f, "command type 3 is not among {types:016X}")
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
            Self::CardReplyBitCount(bits) => {
                write!(f, "expected 8 bits in the last reply byte, received {bits}")
            }
            Self::FieldReset => f.write_str("RF settings of the selection were lost"),
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

    /// Host wait for an InCommRF that carries `packet`: the RF wait plus the
    /// allowance that Sony's driver gives the GATT transfers,
    /// `(10000 × n + 2890230) / 230 + 319` ms for `n` packet bytes after the
    /// length byte.
    fn host_wait(self, packet: &[u8]) -> Duration {
        let bytes = packet
            .first()
            .map_or(0, |length| u64::from(length.saturating_sub(1)));
        self.duration() + Duration::from_millis((10_000 * bytes + 2_890_230) / 230 + 319)
    }
}

/// RF rate of FeliCa polling and exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BitRate {
    /// 212 kbps.
    Kbps212,
    /// 424 kbps.
    Kbps424,
}

impl BitRate {
    /// InSetRF arguments: FeliCa at this rate for sending and receiving.
    fn rf(self) -> [u8; 4] {
        let code = match self {
            Self::Kbps212 => 0x01,
            Self::Kbps424 => 0x02,
        };
        [0x01, code, 0x01, code]
    }
}

/// BLE connection parameters that initialization asks the reader to use, in
/// the driver's registry names and order. The reader's interpretation of
/// the values is not established here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionParameters {
    /// First word of the request.
    pub interval_min: u16,
    /// Second word of the request.
    pub interval_max: u16,
    /// Third word of the request.
    pub slave_latency: u16,
    /// Fourth word of the request.
    pub timeout_multiplier: u16,
}

impl ConnectionParameters {
    /// The values the driver sends when its registry does not override them.
    pub const DRIVER_DEFAULT: Self = Self {
        interval_min: 0x0006,
        interval_max: 0x000c,
        slave_latency: 0x0000,
        timeout_multiplier: 0x003c,
    };

    fn encode(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        for (chunk, word) in bytes.as_chunks_mut::<2>().0.iter_mut().zip([
            self.interval_min,
            self.interval_max,
            self.slave_latency,
            self.timeout_multiplier,
        ]) {
            *chunk = word.to_le_bytes();
        }
        bytes
    }
}

/// Hardware observations obtained by a completed initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderInfo {
    /// GetFirmwareVersion value.
    pub firmware: u16,
    /// GetPDDataVersion value.
    pub pd_data: u16,
    /// GetProperty data. Bytes 14 and 15 select, together with
    /// [`Self::pd_data`], the RF table adjustment of the driver; the meaning
    /// of the other bytes is not established.
    pub property: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// The field is off.
    Off,
    /// The field may be on. `cycle` makes the next selection switch it off
    /// first, because a card can hold state that Polling does not clear or
    /// an RF failure left the card state unknown.
    On { cycle: bool },
    /// A rejected field switch left the field state unknown; the next
    /// selection switches the field off first.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Settings {
    /// InSetRF and InSetProtocol for this rate were accepted.
    Applied(BitRate),
    /// A rejected setting left the RF settings unknown.
    Unknown,
}

#[derive(Debug)]
struct Session {
    /// Key of the RF table adjustment, when the driver adjusts this reader.
    rf_table: Option<&'static rf_table::Key>,
    settings: Settings,
    field: Field,
}

#[derive(Debug)]
enum State {
    NeedsInitialization,
    Ready(Session),
}

/// Exclusive reader owner. Uncertain transport failures revoke readiness.
#[derive(Debug)]
pub struct Reader<T: Transport> {
    link: Link<T>,
    state: State,
}

impl<T: Transport> Reader<T> {
    /// Own a connected transport. Initialization sends no data until requested.
    pub fn new(transport: T) -> Self {
        Self {
            link: Link::new(transport),
            state: State::NeedsInitialization,
        }
    }

    fn command_waiting(
        &mut self,
        cc: u8,
        args: &[u8],
        wait: Duration,
    ) -> Result<Vec<u8>, Error<T::Error>> {
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

    fn command(&mut self, cc: u8, args: &[u8]) -> Result<Vec<u8>, Error<T::Error>> {
        self.command_waiting(cc, args, COMMAND_WAIT)
    }

    fn status_command(&mut self, cc: u8, args: &[u8]) -> Result<(), Error<T::Error>> {
        match self.command(cc, args)?.as_slice() {
            [0] => Ok(()),
            [status] => Err(Error::CommandStatus {
                command: cc,
                status: *status,
            }),
            _ => Err(Error::Response("status length")),
        }
    }

    fn version(&mut self, cc: u8) -> Result<u16, Error<T::Error>> {
        match self.command(cc, &[])?.as_slice() {
            [low, high] => Ok(u16::from_le_bytes([*low, *high])),
            _ => Err(Error::Response("version length")),
        }
    }

    /// Resynchronize the reader's frame parser, select command type 3, send
    /// the BLE connection parameters, read the firmware, PD data and
    /// property observations, apply the FeliCa settings at 212 kbps, and
    /// switch the RF field off. Failure leaves the reader uninitialized; no
    /// command replay.
    ///
    /// # Errors
    ///
    /// Returns transport failures, nonzero statuses, a command type bitmap
    /// without type 3, and responses whose layout differs from the
    /// commands' fixed lengths.
    pub fn initialize(
        &mut self,
        connection: ConnectionParameters,
    ) -> Result<ReaderInfo, Error<T::Error>> {
        self.state = State::NeedsInitialization;
        let result = self.start_session(connection);
        if result.is_err() {
            self.state = State::NeedsInitialization;
        }
        result
    }

    fn start_session(
        &mut self,
        connection: ConnectionParameters,
    ) -> Result<ReaderInfo, Error<T::Error>> {
        self.link.recover().map_err(Error::Transaction)?;
        // Bit n of the big-endian bitmap reports command type n.
        let types = <[u8; 8]>::try_from(self.command(0x28, &[])?.as_slice())
            .map(u64::from_be_bytes)
            .map_err(|_| Error::Response("command type length"))?;
        if types & (1 << COMMAND_TYPE) == 0 {
            return Err(Error::MissingCommandType { types });
        }
        self.status_command(0x2a, &[COMMAND_TYPE])?;
        self.status_command(0x1c, &connection.encode())?;
        let firmware = self.version(0x20)?;
        let pd_data = self.version(0x22)?;
        let property = <[u8; 32]>::try_from(self.command(0x24, &[])?.as_slice())
            .map_err(|_| Error::Response("property length"))?;
        self.state = State::Ready(Session {
            rf_table: rf_table::key(&property, pd_data),
            settings: Settings::Unknown,
            field: Field::Unknown,
        });
        self.apply(BitRate::Kbps212)?;
        self.rf_off()?;
        Ok(ReaderInfo {
            firmware,
            pd_data,
            property,
        })
    }

    fn session(&mut self) -> Result<&mut Session, Error<T::Error>> {
        match &mut self.state {
            State::Ready(session) => Ok(session),
            State::NeedsInitialization => Err(Error::NotInitialized),
        }
    }

    fn set_field(&mut self, field: Field) {
        if let State::Ready(session) = &mut self.state {
            session.field = field;
        }
    }

    /// Make the next selection switch the field off before its request.
    fn require_field_cycle(&mut self) {
        if let State::Ready(Session {
            field: Field::On { cycle },
            ..
        }) = &mut self.state
        {
            *cycle = true;
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
        self.session()?.field = Field::Unknown;
        self.status_command(0x06, &[0x00])?;
        self.link.wait(FIELD_OFF_SETTLE);
        self.set_field(Field::Off);
        Ok(())
    }

    /// Apply InSetRF for FeliCa at `rate`, adjust the RF table where the
    /// driver does, and apply InSetProtocol. A rejected step leaves the
    /// settings unknown.
    fn apply(&mut self, rate: BitRate) -> Result<(), Error<T::Error>> {
        let session = self.session()?;
        session.settings = Settings::Unknown;
        let key = session.rf_table;
        self.status_command(0x00, &rate.rf())?;
        if let Some(key) = key {
            self.adjust_rf_table(key)?;
        }
        self.status_command(0x02, &PROTOCOL)?;
        self.session()?.settings = Settings::Applied(rate);
        Ok(())
    }

    /// Read the RF table with InGetRCT and, when the adjustment changes it,
    /// write it back with InSetRCT.
    fn adjust_rf_table(&mut self, key: &rf_table::Key) -> Result<(), Error<T::Error>> {
        let data = self.command(0x32, key)?;
        let (&status, lists) = data
            .split_first()
            .ok_or(Error::Response("InGetRCT length"))?;
        if status != 0 {
            return Err(Error::CommandStatus {
                command: 0x32,
                status,
            });
        }
        let mut table = Table::parse(lists).map_err(|e| Error::Response(e.reason()))?;
        if table.adjust().map_err(|e| Error::Response(e.reason()))? {
            self.status_command(0x30, &table.encode(key))?;
        }
        Ok(())
    }

    /// Send one FeliCa packet with InCommRF and return the card's bytes, or
    /// `None` when no reply arrived within `wait`.
    fn in_comm_rf(
        &mut self,
        packet: &[u8],
        wait: ResponseWait,
    ) -> Result<Option<Vec<u8>>, Error<T::Error>> {
        let mut args = Vec::with_capacity(packet.len() + 2);
        args.extend_from_slice(&wait.0.to_le_bytes());
        args.extend_from_slice(packet);
        let response = self.command_waiting(0x04, &args, wait.host_wait(packet))?;
        // The bit count and the card bytes follow the status only when the
        // reader received card bytes.
        let Some((&status, reply)) = response.split_first_chunk::<4>() else {
            return Err(Error::Response("InCommRF length"));
        };
        match (u32::from_le_bytes(status), reply) {
            (0, [] | [_]) | (RECEIVE_TIMEOUT, _) => Ok(None),
            (0, [WHOLE_BYTES, data @ ..]) => Ok(Some(data.to_vec())),
            (0, [bits, ..]) => Err(Error::CardReplyBitCount(*bits)),
            (status, _) => {
                self.require_field_cycle();
                Err(Error::RfStatus(status))
            }
        }
    }

    /// Select one FeliCa card with Polling at 212 kbps. With request code
    /// `02`, exchanges switch to 424 kbps if the card advertises automatic
    /// switching and 424 kbps support and its IC code is not `0B`, as the
    /// driver decides. The returned card exclusively borrows this reader,
    /// and its exchanges wait as long as this Polling.
    ///
    /// Returns `None` when no card replies within `wait`. When cards answer
    /// in several time slots, the reader returns their responses one after
    /// another; the first selects the card and the others are not reported.
    ///
    /// # Errors
    ///
    /// Requires initialization. An RF failure or a malformed polling
    /// response requires a field cycle before the next selection.
    pub fn poll_felica(
        &mut self,
        request: PollRequest,
        wait: ResponseWait,
    ) -> Result<Option<FelicaCard<'_, T>>, Error<T::Error>> {
        let session = self.session()?;
        let (field, settings) = (session.field, session.settings);
        if matches!(field, Field::On { cycle: true } | Field::Unknown) {
            self.rf_off()?;
        }
        if settings != Settings::Applied(BitRate::Kbps212) {
            self.apply(BitRate::Kbps212)?;
        }
        // InCommRF switches the field on.
        self.set_field(Field::On { cycle: false });
        let Some(packet) = self.in_comm_rf(&request.encode(), wait)? else {
            return Ok(None);
        };
        let observation = match first_response(&packet) {
            Ok(observation) => observation,
            Err(error) => {
                self.require_field_cycle();
                return Err(Error::FelicaResponse(error));
            }
        };
        let rate = if request.request_code() == 2 && supports_automatic_424(&observation) {
            self.apply(BitRate::Kbps424)?;
            BitRate::Kbps424
        } else {
            BitRate::Kbps212
        };
        Ok(Some(FelicaCard {
            reader: self,
            rate,
            request,
            observation,
            wait,
        }))
    }

    /// Carry one FeliCa packet of a card selected at `rate`.
    fn felica_exchange(
        &mut self,
        rate: BitRate,
        packet: &[u8],
        wait: ResponseWait,
    ) -> Result<Vec<u8>, Error<T::Error>> {
        let session = self.session()?;
        if !matches!(session.field, Field::On { .. }) || session.settings != Settings::Applied(rate)
        {
            return Err(Error::FieldReset);
        }
        let reply = self.in_comm_rf(packet, wait)?.ok_or(Error::NoResponse)?;
        felica_packet::validate_length(&reply, 2).map_err(Error::FelicaResponse)?;
        Ok(reply)
    }
}

/// The first Polling response among the responses the reader returned.
fn first_response(packet: &[u8]) -> Result<PollResponse, PacketError> {
    let first = packet
        .first()
        .and_then(|length| packet.get(..usize::from(*length)))
        .unwrap_or(packet);
    PollResponse::parse(first)
}

/// Whether request data of request code `02` lets the exchange run at
/// 424 kbps.
fn supports_automatic_424(observation: &PollResponse) -> bool {
    const AUTOMATIC_AND_424: u8 = 0x82;
    // The driver withholds 424 kbps from IC code 0B.
    observation.pmm[1] != 0x0b
        && observation
            .request_data
            .is_some_and(|[_, flags]| flags & AUTOMATIC_AND_424 == AUTOMATIC_AND_424)
}

/// Selected FeliCa card whose operation authority is tied to one reader borrow.
///
/// [`Selection::exchange_packet`] carries one packet with InCommRF at the
/// rate the selection chose and waits as long as the Polling that selected
/// the card; a missing reply is [`Error::NoResponse`].
#[derive(Debug)]
pub struct FelicaCard<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    rate: BitRate,
    request: PollRequest,
    observation: PollResponse,
    wait: ResponseWait,
}

impl<T: Transport> FelicaCard<'_, T> {
    /// The rate of this card's exchanges.
    pub fn rate(&self) -> BitRate {
        self.rate
    }
}

impl<T: Transport> Selection for FelicaCard<'_, T> {
    type Error = Error<T::Error>;

    fn max_packet_len(&self) -> usize {
        MAX_PACKET_BYTES
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
        self.reader.felica_exchange(self.rate, packet, self.wait)
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

    #[test]
    fn the_host_wait_adds_the_driver_transfer_allowance() {
        let wait = ResponseWait(10);
        assert_eq!(
            wait.host_wait(&[6, 0, 0xff, 0xff, 0, 0]),
            Duration::from_millis(1 + 12_783 + 319)
        );
        assert_eq!(
            wait.host_wait(&[0xff; 255]),
            Duration::from_millis(1 + 23_609 + 319)
        );
    }

    #[test]
    fn negotiation_needs_both_flags_and_an_ic_code_other_than_0b() {
        let response = |ic, flags| PollResponse {
            idm: felica_packet::Idm::new([0; 8]),
            pmm: [0, ic, 0, 0, 0, 0, 0, 0],
            request_data: Some([0, flags]),
        };
        assert!(supports_automatic_424(&response(0x32, 0x83)));
        assert!(!supports_automatic_424(&response(0x32, 0x81)));
        assert!(!supports_automatic_424(&response(0x32, 0x02)));
        assert!(!supports_automatic_424(&response(0x0b, 0x83)));
    }
}
