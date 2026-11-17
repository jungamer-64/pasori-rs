//! Reader initialization and lifetime-bound FeliCa card access.

use crate::{
    device::{self, Descriptor, Family, Product, Variant},
    transport::{Failure, Link, Progress, TransactionError, Transport},
};
use alloc::vec::Vec;
use core::{error, fmt, time::Duration};
use felica_packet::{PacketError, PollRequest, PollResponse, Selection};

/// Largest FeliCa packet, including its length byte, that one `5C` command
/// carries in either direction.
pub const MAX_PACKET_BYTES: usize = 254;
/// Host wait of commands that do not reach a card.
const READER_WAIT: Duration = Duration::from_secs(1);
/// Time the RF field stays off so that a card loses its state.
const FIELD_OFF_SETTLE: Duration = Duration::from_millis(5);
/// Register write flag in the count byte of command `62`.
const REGISTER_WRITE: u8 = 0x20;
/// Largest register count of one `62` command.
const MAX_REGISTERS: usize = 0x1f;

/// Failures of reader initialization, RF control, or card exchange.
#[derive(Debug)]
pub enum Error<E> {
    /// Host transport transaction failed. Unless its progress is
    /// [`Progress::NotSent`] and the stream was usable, the reader must be
    /// reinitialized.
    Transaction(TransactionError<E>),
    /// Reader initialization is required before the requested operation.
    NotInitialized,
    /// The descriptor does not identify a supported reader.
    UnsupportedDevice(Descriptor),
    /// No initial register values are known for these observations.
    UnsupportedVariant(Variant),
    /// A command response did not have the required layout.
    Response(&'static str),
    /// A register command returned an error value.
    RegisterStatus(u8),
    /// A register write did not hold its value when read back.
    RegisterReadback,
    /// A FeliCa packet was malformed before it was sent.
    FelicaRequest(PacketError),
    /// A FeliCa reply was malformed. The packet that caused it was sent and
    /// may have taken effect.
    FelicaResponse(PacketError),
    /// The reader acknowledged the packet but returned no card reply before
    /// the wait elapsed. The card may have received the packet and taken
    /// effect; the reader remains usable.
    NoResponse,
    /// Packet exceeds what one `5C` command carries.
    InputLength {
        /// Maximum accepted bytes.
        maximum: usize,
        /// Supplied bytes.
        actual: usize,
    },
}

impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transaction(_) => f.write_str("reader transaction failed"),
            Self::NotInitialized => f.write_str("reader requires initialization"),
            Self::UnsupportedDevice(descriptor) => write!(
                f,
                "unsupported device {:04X}:{:04X} subclass {:02X}",
                descriptor.vendor_id, descriptor.product_id, descriptor.device_subclass
            ),
            Self::UnsupportedVariant(variant) => {
                write!(f, "no register values for release {:04X}", variant.release)
            }
            Self::Response(reason) => write!(f, "malformed reader response: {reason}"),
            Self::RegisterStatus(status) => write!(f, "register command returned {status:02X}"),
            Self::RegisterReadback => f.write_str("register write did not hold"),
            Self::FelicaRequest(_) => f.write_str("FeliCa request rejected before sending"),
            Self::FelicaResponse(_) => {
                f.write_str("FeliCa response failed; the command may have taken effect")
            }
            Self::NoResponse => f.write_str("no card reply; the command may have taken effect"),
            Self::InputLength { maximum, actual } => {
                write!(f, "input of {actual} bytes exceeds {maximum}")
            }
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

/// Host wait for a card reply, covering the reader's ACK and its response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseWait(Duration);

impl ResponseWait {
    /// Accept a nonzero wait.
    pub fn new(duration: Duration) -> Option<Self> {
        (!duration.is_zero()).then_some(Self(duration))
    }

    /// The wait.
    pub fn duration(self) -> Duration {
        self.0
    }
}

/// Hardware observations obtained by a completed initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderInfo {
    /// Descriptor fields of the device.
    pub descriptor: Descriptor,
    /// Product established from the descriptor and register observations.
    pub product: Product,
    /// The two bytes after the `59` response command, in wire order.
    pub firmware: [u8; 2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Off,
    On,
    /// The card can hold state that the next Polling does not clear, so the
    /// next selection switches the field off first.
    CycleRequired,
}

#[derive(Debug)]
enum State {
    NeedsInitialization,
    Ready(Field),
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

    /// Recover the transport, identify the reader, write the initial register
    /// values for its variant, and leave the RF field off. Failure leaves the
    /// reader uninitialized; no command replay.
    ///
    /// The register values are those that Sony's driver package writes for
    /// the same observations. `5A 80` is the form of command `5A` that the
    /// driver sends before a short card exchange. The device-side meaning of
    /// both is not established here.
    ///
    /// # Errors
    ///
    /// Rejects an unsupported descriptor before sending any command, and
    /// register observations without known initial values before writing.
    pub fn initialize(&mut self) -> Result<ReaderInfo, Error<T::Error>> {
        self.state = State::NeedsInitialization;
        let descriptor = self.link.descriptor();
        let family = Family::identify(descriptor).ok_or(Error::UnsupportedDevice(descriptor))?;
        self.link.recover().map_err(Error::Transaction)?;
        let firmware = match self.command(0x58, &[], READER_WAIT)?.as_slice() {
            [low, high] => [*low, *high],
            _ => return Err(Error::Response("firmware version length")),
        };
        let product = match family {
            Family::Rcs310Ed2 => Product::Rcs310Ed2,
            Family::Rcs310 => {
                let [register_82] = self.read_registers([0x82])?;
                let (values, product) = device::rcs310(descriptor.release, register_82).ok_or(
                    Error::UnsupportedVariant(Variant {
                        release: descriptor.release,
                        register_82,
                        register_87: None,
                    }),
                )?;
                self.write_registers(values)?;
                product
            }
            Family::Rcs320 => {
                let [register_80, register_81] = self.read_registers([0x80, 0x81])?;
                self.write_registers(&[0x80, register_80 & !0x10, 0x81, register_81 | 0x80])?;
                let [register_80, register_81] = self.read_registers([0x80, 0x81])?;
                if register_80 & 0x10 != 0 || register_81 & 0x80 == 0 {
                    return Err(Error::RegisterReadback);
                }
                let [register_82, register_87] = self.read_registers([0x82, 0x87])?;
                let (values, product) =
                    device::rcs320(descriptor.release, register_82, register_87).ok_or(
                        Error::UnsupportedVariant(Variant {
                            release: descriptor.release,
                            register_82,
                            register_87: Some(register_87),
                        }),
                    )?;
                self.write_registers(values)?;
                product
            }
        };
        if self.command(0x5a, &[0x80], READER_WAIT)? != [0] {
            return Err(Error::Response("5A status"));
        }
        self.switch_field_off()?;
        let info = ReaderInfo {
            descriptor,
            product,
            firmware,
        };
        self.state = State::Ready(Field::Off);
        Ok(info)
    }

    fn read_registers<const N: usize>(
        &mut self,
        addresses: [u8; N],
    ) -> Result<[u8; N], Error<T::Error>> {
        let count = u8::try_from(N)
            .ok()
            .filter(|count| usize::from(*count) <= MAX_REGISTERS)
            .ok_or(Error::InputLength {
                maximum: MAX_REGISTERS,
                actual: N,
            })?;
        let mut args = Vec::with_capacity(N + 1);
        args.push(count);
        args.extend_from_slice(&addresses);
        let response = self.command(0x62, &args, READER_WAIT)?;
        match response.split_first() {
            Some((0, values)) => values
                .try_into()
                .map_err(|_| Error::Response("register read length")),
            Some((status, _)) => Err(Error::RegisterStatus(*status)),
            None => Err(Error::Response("register read length")),
        }
    }

    /// Write address and value pairs in order.
    fn write_registers(&mut self, pairs: &[u8]) -> Result<(), Error<T::Error>> {
        let count = u8::try_from(pairs.len() / 2)
            .ok()
            .filter(|count| usize::from(*count) <= MAX_REGISTERS && pairs.len().is_multiple_of(2))
            .ok_or(Error::InputLength {
                maximum: MAX_REGISTERS * 2,
                actual: pairs.len(),
            })?;
        let mut args = Vec::with_capacity(pairs.len() + 1);
        args.push(count | REGISTER_WRITE);
        args.extend_from_slice(pairs);
        match self.command(0x62, &args, READER_WAIT)?.as_slice() {
            [0] => Ok(()),
            [status] => Err(Error::RegisterStatus(*status)),
            _ => Err(Error::Response("register write length")),
        }
    }

    fn switch_field_off(&mut self) -> Result<(), Error<T::Error>> {
        match self.command(0x54, &[], READER_WAIT)?.as_slice() {
            [0] => {}
            _ => return Err(Error::Response("RF off status")),
        }
        self.link.wait(FIELD_OFF_SETTLE);
        Ok(())
    }

    fn field(&mut self) -> Result<&mut Field, Error<T::Error>> {
        match &mut self.state {
            State::Ready(field) => Ok(field),
            State::NeedsInitialization => Err(Error::NotInitialized),
        }
    }

    /// Switch the RF field off. Call explicitly to observe failure; dropping
    /// a reader only releases the backend's OS resources.
    ///
    /// # Errors
    ///
    /// Requires initialization; a failed command leaves the reader requiring
    /// it again.
    pub fn rf_off(&mut self) -> Result<(), Error<T::Error>> {
        self.field()?;
        self.switch_field_off()?;
        *self.field()? = Field::Off;
        Ok(())
    }

    /// Select one FeliCa card. The returned card exclusively borrows this
    /// reader, and its exchanges wait as long as this Polling.
    ///
    /// Returns `None` when the reader acknowledges the Polling but sends no
    /// reply within `wait`. Time slots are carried in the packet; how the
    /// reader handles several answering cards is not established here.
    ///
    /// # Errors
    ///
    /// Requires initialization. A malformed polling response requires a field
    /// cycle before the next selection.
    pub fn poll_felica(
        &mut self,
        request: PollRequest,
        wait: ResponseWait,
    ) -> Result<Option<FelicaCard<'_, T>>, Error<T::Error>> {
        if *self.field()? == Field::CycleRequired {
            self.rf_off()?;
        }
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
                self.require_field_cycle();
                Err(Error::FelicaResponse(error))
            }
        }
    }

    /// Carry one packet with `5C` and return the `5D` reply, or `None` when
    /// the reader acknowledged the packet but sent no reply within `wait`.
    fn exchange(
        &mut self,
        packet: &[u8],
        wait: ResponseWait,
    ) -> Result<Option<Vec<u8>>, Error<T::Error>> {
        let field = *self.field()?;
        if packet.len() > MAX_PACKET_BYTES {
            return Err(Error::InputLength {
                maximum: MAX_PACKET_BYTES,
                actual: packet.len(),
            });
        }
        let response = match self.link.command(0x5c, packet, wait.duration()) {
            Ok(response) => response.data,
            Err(error) if error.is_unanswered() => {
                if field == Field::Off {
                    *self.field()? = Field::On;
                }
                return Ok(None);
            }
            Err(error) => {
                if error.progress != Progress::NotSent
                    || matches!(error.failure, Failure::RecoveryRequired)
                {
                    self.state = State::NeedsInitialization;
                }
                return Err(Error::Transaction(error));
            }
        };
        if field == Field::Off {
            *self.field()? = Field::On;
        }
        felica_packet::validate_length(&response, 2).map_err(Error::FelicaResponse)?;
        Ok(Some(response))
    }

    fn require_field_cycle(&mut self) {
        if let State::Ready(field) = &mut self.state {
            *field = Field::CycleRequired;
        }
    }
}

/// Selected FeliCa card whose operation authority is tied to one reader borrow.
///
/// [`Selection::exchange_packet`] carries one packet with `5C` and waits as
/// long as the Polling that selected the card; a missing reply is
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
