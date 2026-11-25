//! Transparent Session ownership, RF configuration, and card selection.

mod felica;
mod iso_dep;

pub use crate::apdu::ApduError;
pub use felica::FelicaCard;
pub use iso_dep::{Activation, IsoDepBlocks, IsoDepCard};

use crate::{
    apdu::{self, IccResponsePolicy, Objects},
    transport::{Link, READ_CAPACITY, TransactionError, Transport},
};
use alloc::vec::Vec;
use core::{error, fmt, time::Duration};
use felica_packet::PacketError;
use iso14443::{nfca, nfcb};

const START: u8 = 0x81;
const END: u8 = 0x82;
const RF_OFF: u8 = 0x83;
const RF_ON: u8 = 0x84;
const FIELD_OFF_SETTLE: Duration = Duration::from_millis(30);
const FIELD_ON_SETTLE: Duration = Duration::from_millis(21);

/// Failure at the reader or card activation boundary.
///
/// A rejected input, wait or unavailable selection prevents a card transfer.
/// A device response failure or unusable reply after a card transfer can
/// leave its effect unknown. USB failures report their confirmed progress.
#[derive(Debug)]
pub enum Error<E> {
    /// USB or CCID transaction failure.
    Ccid(TransactionError<E>),
    /// Reader device APDU or transparent RF exchange failure.
    DeviceApdu(ApduError),
    /// Device information did not match a known response layout.
    FirmwareLength(usize),
    /// The device is updating or has not booted normal firmware.
    FirmwareState {
        /// Firmware update state in wire order.
        update: [u8; 2],
        /// Boot state in wire order, if the firmware reports it.
        boot: Option<[u8; 2]>,
    },
    /// No initialized Transparent Session grants RF operations.
    NotInitialized,
    /// An earlier failure ended the current selection's transfer authority.
    SelectionInvalid,
    /// The card did not answer within the RF wait.
    NoResponse,
    /// Frame size is outside the operation's supported range.
    InputLength(usize),
    /// An invalid FeliCa packet was rejected before sending.
    FelicaRequest(PacketError),
    /// A received FeliCa packet is invalid.
    FelicaResponse(PacketError),
    /// The NFC-A activation returned an invalid ATS.
    TypeA(nfca::Error),
    /// The NFC-A response did not contain a final SAK.
    TypeASak(u8),
    /// The NFC-B activation returned invalid data.
    TypeB(nfcb::Error),
    /// The NFC-B ATTRIB response used a CID other than the assigned zero.
    AttribCid(u8),
    /// A card was selected at Layer 3 but did not advertise ISO-DEP.
    NotIsoDep,
    /// The RF reply length is invalid for the current operation.
    ReplyLength(usize),
    /// The requested RF wait is outside the supported range.
    WaitRange(Duration),
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ccid(error) => error.fmt(f),
            Self::DeviceApdu(error) => error.fmt(f),
            Self::FirmwareLength(actual) => {
                write!(f, "unexpected device information length {actual}")
            }
            Self::FirmwareState { update, boot } => {
                write!(
                    f,
                    "firmware is unavailable (update {update:02X?}, boot {boot:02X?})"
                )
            }
            Self::NotInitialized => f.write_str("initialize a Port-400 Transparent Session first"),
            Self::SelectionInvalid => {
                f.write_str("Port-400 card selection no longer grants RF transfers")
            }
            Self::NoResponse => f.write_str("no card response within the RF wait"),
            Self::InputLength(actual) => write!(f, "unsupported RF frame length {actual}"),
            Self::FelicaRequest(error) => write!(f, "invalid FeliCa request: {error}"),
            Self::FelicaResponse(error) => write!(f, "invalid FeliCa response: {error}"),
            Self::TypeA(error) => error.fmt(f),
            Self::TypeASak(sak) => write!(f, "SAK {sak:02X} has the cascade bit set"),
            Self::TypeB(error) => error.fmt(f),
            Self::AttribCid(cid) => write!(f, "ATTRIB returned CID {cid}, expected 0"),
            Self::NotIsoDep => f.write_str("selected card does not advertise ISO-DEP"),
            Self::ReplyLength(actual) => write!(f, "unexpected RF reply length {actual}"),
            Self::WaitRange(wait) => write!(f, "unsupported RF wait of {wait:?}"),
        }
    }
}

impl<E: error::Error + 'static> error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Ccid(error) => Some(error),
            Self::DeviceApdu(error) => Some(error),
            Self::FelicaRequest(error) | Self::FelicaResponse(error) => Some(error),
            Self::TypeA(error) => Some(error),
            Self::TypeB(error) => Some(error),
            _ => None,
        }
    }
}

/// Where explicit session cleanup stopped.
#[derive(Debug)]
pub enum FinishError<E> {
    /// RF off could not be confirmed. A subsequent finish can attempt End
    /// if the CCID connection still permits commands.
    FieldOff(Error<E>),
    /// End could not be confirmed.
    EndSession(Error<E>),
}

impl<E: fmt::Display> fmt::Display for FinishError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FieldOff(error) => write!(f, "failed to stop the RF field: {error}"),
            Self::EndSession(error) => write!(f, "failed to end the Transparent Session: {error}"),
        }
    }
}

impl<E: error::Error + 'static> error::Error for FinishError<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::FieldOff(error) | Self::EndSession(error) => Some(error),
        }
    }
}

/// RF response wait encoded in microseconds. The hardware timer has
/// millisecond accuracy. This wait is independent of the USB deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseWait(u32);

impl ResponseWait {
    /// Largest admitted RF wait, matching the USB firmware command profile.
    pub const MAX: Duration = Duration::from_millis(6600);

    /// Construct a positive wait at most [`Self::MAX`], rounding up to a
    /// whole microsecond for the timer field.
    pub fn new(duration: Duration) -> Option<Self> {
        if duration.is_zero() || duration > Self::MAX {
            return None;
        }
        Some(Self(
            u32::try_from(duration.as_nanos().div_ceil(1000)).ok()?,
        ))
    }

    /// Encoded wait, after rounding.
    pub fn duration(self) -> Duration {
        Duration::from_micros(u64::from(self.0))
    }
}

/// Firmware versions from a reader that is ready for normal operations.
/// Version fields preserve the bytes reported by firmware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderInfo {
    /// Combined firmware version.
    pub firmware: [u8; 4],
    /// Microcontroller firmware version.
    pub mcu: [u8; 2],
    /// Secure access module firmware version.
    pub sam: [u8; 2],
    /// RF front-end firmware version.
    pub rffe: [u8; 2],
    /// Bootloader version, when reported.
    pub bootloader: Option<[u8; 2]>,
    /// RF front-end EEPROM version, when reported.
    pub rffe_eeprom: Option<[u8; 2]>,
}

/// Exclusive Port-400 reader controller. After a CCID error that prevents
/// matching the final reply, recover the device outside this controller
/// before constructing a new reader. Drop releases the transport only.
#[derive(Debug)]
pub struct Reader<T: Transport> {
    link: Link<T>,
    session: Session,
}

#[derive(Debug, Clone, Copy)]
enum Session {
    Closed,
    NeedsEnd,
    Active(Field),
}

#[derive(Debug, Clone, Copy)]
enum Field {
    Off,
    Uncertain,
    On {
        profile: Profile,
        cycle_before_poll: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    Felica,
    TypeA,
    TypeB,
}

impl Profile {
    const fn switch_command(self) -> [u8; 10] {
        match self {
            Self::Felica => apdu::switch_protocol(3, 0),
            Self::TypeA => apdu::switch_protocol(0, 3),
            Self::TypeB => apdu::switch_protocol(1, 2),
        }
    }

    const fn framing_command(self) -> [u8; 10] {
        const HOST_PROLOGUE: u16 = 0x0010;
        const WITHOUT_PARITY: u16 = 0x000c;
        let flags = match self {
            Self::TypeA => HOST_PROLOGUE,
            Self::TypeB | Self::Felica => HOST_PROLOGUE | WITHOUT_PARITY,
        };
        apdu::framing(flags)
    }
}

impl<T: Transport> Reader<T> {
    /// Take ownership of a synchronized, exclusively held USB connection.
    pub fn new(transport: T) -> Self {
        Self {
            link: Link::new(transport),
            session: Session::Closed,
        }
    }

    /// Return the transport without issuing USB commands. Use [`Self::finish`]
    /// first when the session must be ended on the device.
    pub fn into_transport(self) -> T {
        self.link.into_transport()
    }

    /// Check firmware state, establish a new Transparent Session, and leave
    /// its field off.
    ///
    /// # Errors
    ///
    /// Returns failures from the firmware query, session reset, start or RF
    /// off. A failed initialization grants no RF exchange authority. Use
    /// [`Self::finish`] to attempt cleanup on a still-synchronized connection.
    pub fn initialize(&mut self) -> Result<ReaderInfo, Error<T::Error>> {
        if matches!(self.session, Session::Active(_)) {
            self.session = Session::NeedsEnd;
        }
        let mut response = [0; READ_CAPACITY];
        let response = self
            .link
            .escape(&apdu::READ_FIRMWARE, &mut response)
            .map_err(Error::Ccid)?;
        let info = firmware_info(apdu::response_body(response).map_err(Error::DeviceApdu)?)?;
        self.end_session()?;
        self.session = Session::NeedsEnd;
        self.acknowledge(&apdu::session_command(START))?;
        self.session = Session::Active(Field::Uncertain);
        if let Err(error) = self.rf_off() {
            self.session = Session::NeedsEnd;
            return Err(error);
        }
        Ok(info)
    }

    /// Switch off the field inside the active Transparent Session.
    ///
    /// # Errors
    ///
    /// Requires initialization. If the reader cannot confirm RF off, the
    /// previous selection is no longer valid.
    pub fn rf_off(&mut self) -> Result<(), Error<T::Error>> {
        if matches!(self.field()?, Field::Off) {
            return Ok(());
        }
        self.session = Session::Active(Field::Uncertain);
        self.acknowledge(&apdu::session_command(RF_OFF))?;
        self.link.wait(FIELD_OFF_SETTLE);
        self.session = Session::Active(Field::Off);
        Ok(())
    }

    /// Stop the field and end the Transparent Session. A completed end
    /// releases the reader for reinitialization.
    ///
    /// # Errors
    ///
    /// Reports the cleanup step that failed. If RF off fails, this call
    /// stops there and a subsequent finish may attempt End on a synchronized
    /// connection. No I/O occurs for a locally closed session.
    pub fn finish(&mut self) -> Result<(), FinishError<T::Error>> {
        match self.session {
            Session::Closed => return Ok(()),
            Session::Active(_) => {
                if let Err(error) = self.rf_off() {
                    self.session = Session::NeedsEnd;
                    return Err(FinishError::FieldOff(error));
                }
            }
            Session::NeedsEnd => {}
        }
        self.end_session().map_err(FinishError::EndSession)
    }

    fn end_session(&mut self) -> Result<(), Error<T::Error>> {
        self.session = Session::NeedsEnd;
        match self.acknowledge(&apdu::session_command(END)) {
            // End is the only object in this APDU. A sequence error here
            // means there is no Transparent Session to end.
            Ok(())
            | Err(Error::DeviceApdu(ApduError::ObjectStatus {
                index: 1,
                status: [0x63, 0x01],
            })) => {
                self.session = Session::Closed;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn field(&self) -> Result<Field, Error<T::Error>> {
        match self.session {
            Session::Active(field) => Ok(field),
            Session::Closed | Session::NeedsEnd => Err(Error::NotInitialized),
        }
    }

    fn require_configured_field(&self) -> Result<(), Error<T::Error>> {
        match self.session {
            Session::Active(Field::On { .. }) => Ok(()),
            _ => Err(Error::SelectionInvalid),
        }
    }

    fn require_cycle(&mut self) {
        if let Session::Active(Field::On {
            cycle_before_poll, ..
        }) = &mut self.session
        {
            *cycle_before_poll = true;
        }
    }

    fn invalidate_field(&mut self) {
        if matches!(self.session, Session::Active(_)) {
            self.session = Session::Active(Field::Uncertain);
        }
    }

    fn enable_profile(&mut self, profile: Profile) {
        self.session = Session::Active(Field::On {
            profile,
            cycle_before_poll: false,
        });
    }

    fn energize(&mut self) -> Result<(), Error<T::Error>> {
        self.session = Session::Active(Field::Uncertain);
        self.acknowledge(&apdu::session_command(RF_ON))?;
        self.link.wait(FIELD_ON_SETTLE);
        Ok(())
    }

    fn acknowledge(&mut self, command: &[u8]) -> Result<(), Error<T::Error>> {
        self.objects(command, IccResponsePolicy::Unique, |objects| {
            objects.require_success()
        })
    }

    fn objects<R>(
        &mut self,
        command: &[u8],
        response_policy: IccResponsePolicy,
        interpret: impl FnOnce(Objects<'_>) -> Result<R, ApduError>,
    ) -> Result<R, Error<T::Error>> {
        let mut response = [0; READ_CAPACITY];
        let response = self
            .link
            .escape(command, &mut response)
            .map_err(Error::Ccid)?;
        let result = Objects::parse(response, response_policy).and_then(interpret);
        if result
            .as_ref()
            .is_err_and(|error| error.session_sequence_invalid())
            && matches!(self.session, Session::Active(_))
        {
            self.session = Session::NeedsEnd;
        }
        result.map_err(Error::DeviceApdu)
    }

    fn exchange_rf(
        &mut self,
        packet: &[u8],
        wait: ResponseWait,
        response_policy: IccResponsePolicy,
    ) -> Result<Vec<u8>, Error<T::Error>> {
        self.require_configured_field()?;
        let mut buffer = [0; apdu::EXCHANGE_CAPACITY];
        let command =
            apdu::exchange(packet, wait.0, &mut buffer).ok_or(Error::InputLength(packet.len()))?;
        match self.objects(command, response_policy, |objects| {
            objects.received().map(<[u8]>::to_vec)
        }) {
            Err(Error::DeviceApdu(error)) if error.icc_timeout() => Err(Error::NoResponse),
            Err(error) => {
                self.invalidate_field();
                Err(error)
            }
            Ok(reply) => Ok(reply),
        }
    }
}

fn firmware_info<E>(body: &[u8]) -> Result<ReaderInfo, Error<E>> {
    let Some((&[a, b, c, d, mcu_a, mcu_b, sam_a, sam_b, rf_a, rf_b], tail)) =
        body.split_first_chunk::<10>()
    else {
        return Err(Error::FirmwareLength(body.len() + 2));
    };
    let (rffe_eeprom, bootloader, update, boot, normal_update) = match *tail {
        [u0, u1] => (None, None, [u0, u1], None, [0, 0]),
        [l0, l1, u0, u1] => (None, Some([l0, l1]), [u0, u1], None, [0, 0]),
        [e0, e1, l0, l1, u0, u1, b0, b1] => (
            Some([e0, e1]),
            Some([l0, l1]),
            [u0, u1],
            Some([b0, b1]),
            [0xff, 0xff],
        ),
        _ => return Err(Error::FirmwareLength(body.len() + 2)),
    };
    if update != normal_update || boot.is_some_and(|state| state != [0, 0]) {
        return Err(Error::FirmwareState { update, boot });
    }
    Ok(ReaderInfo {
        firmware: [a, b, c, d],
        mcu: [mcu_a, mcu_b],
        sam: [sam_a, sam_b],
        rffe: [rf_a, rf_b],
        bootloader,
        rffe_eeprom,
    })
}
