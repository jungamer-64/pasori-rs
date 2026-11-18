//! Reader configuration and lifetime-bound NFC card access.

mod dep;
mod felica_link;
mod identity;
mod type1;
mod type_a_target;

pub use dep::{
    DepActivation, DepError, DepInitiator, DepLink, DepMessage, DepMode, DepPeer, DepRate,
    DepRequest, DepTransferCause, MAX_DEP_MESSAGE_BYTES, PassiveDepTarget,
};
pub use felica_link::{FelicaActivation, FelicaLink, FelicaListen, FelicaRole};
pub use identity::{DeviceNameError, Model, Product};
pub use type_a_target::{TypeACommand, TypeATarget};
pub use type1::Type1Target;

use crate::{
    felica::BitRate,
    nfcb,
    transport::{Failure, Link, Progress, TransactionError, Transport},
};
use alloc::{string::String, vec, vec::Vec};
use core::{error, fmt, mem, time::Duration};
use felica_packet::{PacketError, PollRequest, PollResponse, Selection};
use iso14443::{iso_dep, nfca};

/// Maximum card-command bytes accepted by the reader's NFC-A exchange.
pub const MAX_TYPE_A_COMMAND_BYTES: usize = 262;
/// Maximum card-command bytes accepted by the reader's NFC-B `40` exchange.
pub const MAX_TYPE_B_FRAME_COMMAND_BYTES: usize = 63;
/// Reader block buffer of an NFC-B `A0` block transfer in each direction,
/// including the two CRC bytes that the reader appends and removes.
pub const MAX_TYPE_B_BLOCK_BYTES: usize = 64;
/// Status of an `A0` or `40` reply whose low six bits report an RF timeout.
const RF_TIMEOUT: u8 = 0x01;
const MAX_TYPE_A_RESPONSE_FRAGMENTS: usize = 256;
/// `40` reader status bit announcing a further response fragment.
const TARGET_MORE_INFORMATION: u8 = 0x40;

/// Failures of reader initialization, RF configuration, or card exchange.
#[derive(Debug)]
pub enum Error<E> {
    /// Host transport transaction failed. Unless its progress is
    /// [`Progress::NotSent`] and the stream was usable, the reader must be
    /// reinitialized.
    Transaction(TransactionError<E>),
    /// Recovery failed, preserving the phase of its out-of-band ACK transfer.
    Recovery(TransactionError<E>),
    /// Reader initialization is required before the requested operation.
    NotInitialized,
    /// A command response did not have the required layout.
    Response(&'static str),
    /// The configuration image failed validation.
    Configuration(ConfigurationError),
    /// Register write returned an error value.
    RegisterStatus(u8),
    /// Raw RF status and its command-specific classification. A masked `0D`
    /// requires reader initialization; a masked `0B` is returned only after a
    /// 10 ms settle wait.
    RfStatus(u8),
    /// A FeliCa packet was malformed before it was sent.
    FelicaRequest(PacketError),
    /// A FeliCa reply was malformed. The packet that caused it was sent and
    /// may have taken effect.
    FelicaResponse(PacketError),
    /// The requested RF wait cannot be encoded as nonzero half-ms ticks.
    Timeout(TimeoutRange),
    /// NFC-A activation data failed validation.
    TypeA(nfca::Error),
    /// NFC-B activation data failed validation.
    TypeB(iso14443::nfcb::Error),
    /// Target activation reported a mode other than the one the command set up.
    TargetMode(u8),
    /// Payload exceeds the selected reader command's supported limit.
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
            Self::Recovery(_) => f.write_str("reader recovery failed"),
            Self::NotInitialized => f.write_str("reader requires initialization"),
            Self::Response(reason) => write!(f, "malformed reader response: {reason}"),
            Self::Configuration(_) => f.write_str("invalid reader configuration"),
            Self::RegisterStatus(status) => write!(f, "register write returned {status:02X}"),
            Self::RfStatus(status) => write!(f, "RF status {status:02X}"),
            Self::FelicaRequest(_) => f.write_str("FeliCa request rejected before sending"),
            Self::FelicaResponse(_) => {
                f.write_str("FeliCa response failed; the command may have taken effect")
            }
            Self::Timeout(_) => f.write_str("invalid RF wait"),
            Self::TypeA(_) => f.write_str("invalid NFC-A activation"),
            Self::TypeB(_) => f.write_str("invalid NFC-B activation"),
            Self::TargetMode(mode) => write!(f, "unexpected target mode {mode:02X}"),
            Self::InputLength { maximum, actual } => {
                write!(f, "input of {actual} bytes exceeds {maximum}")
            }
        }
    }
}
impl<E: error::Error + 'static> error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Transaction(error) | Self::Recovery(error) => Some(error),
            Self::Configuration(error) => Some(error),
            Self::FelicaRequest(error) | Self::FelicaResponse(error) => Some(error),
            Self::Timeout(error) => Some(error),
            Self::TypeA(error) => Some(error),
            Self::TypeB(error) => Some(error),
            _ => None,
        }
    }
}
impl<E> Error<E> {
    /// Whether this is the RF status of a transfer that received no answer
    /// within its RF wait. Other RF statuses report a received but invalid frame.
    pub fn is_rf_timeout(&self) -> bool {
        matches!(self, Self::RfStatus(status) if status & 0x3f == RF_TIMEOUT)
    }
}
impl<E> From<TimeoutRange> for Error<E> {
    fn from(e: TimeoutRange) -> Self {
        Self::Timeout(e)
    }
}

/// The requested wait is zero or exceeds 65535 half-ms ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutRange;

impl fmt::Display for TimeoutRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RF wait must be positive and fit in 65535 half-ms ticks")
    }
}
impl error::Error for TimeoutRange {}

/// Positive RF timeout with a checked conversion to RC-S956 wire ticks.
#[derive(Debug, Clone, Copy)]
pub struct RfTimeout {
    ticks: u16,
}
impl RfTimeout {
    /// The longest wait the reader encodes, 65535 half-ms ticks.
    pub const MAX: Self = Self { ticks: u16::MAX };

    /// Round a positive duration up to half-ms ticks.
    ///
    /// # Errors
    ///
    /// Returns [`TimeoutRange`] for zero or a duration requiring more than 65535 ticks.
    pub fn new(duration: Duration) -> Result<Self, TimeoutRange> {
        let ticks = duration.as_nanos().div_ceil(500_000);
        if ticks == 0 {
            return Err(TimeoutRange);
        }
        Ok(Self {
            ticks: u16::try_from(ticks).map_err(|_| TimeoutRange)?,
        })
    }
    /// Encoded little-endian device timeout.
    pub fn ticks(self) -> u16 {
        self.ticks
    }
    fn host_wait(self) -> Duration {
        Duration::from_micros(u64::from(self.ticks) * 500) + Duration::from_secs(1)
    }
}

/// Invalid reader configuration image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationError {
    /// The configuration signature was absent.
    Signature,
    /// A checksummed region did not sum to zero.
    Checksum {
        /// Byte offset where the failing region begins.
        offset: usize,
    },
    /// The image's model class is unsupported.
    ModelClass,
}

impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signature => f.write_str("configuration signature is absent"),
            Self::Checksum { offset } => {
                write!(f, "configuration checksum fails at offset {offset:02X}")
            }
            Self::ModelClass => f.write_str("unsupported configuration model class"),
        }
    }
}
impl error::Error for ConfigurationError {}

/// Immutable, validated configuration read from one attached reader.
#[derive(Debug, Clone)]
pub struct ConfigImage {
    bytes: [u8; 256],
    model: Model,
}
impl ConfigImage {
    /// Check the signature, three defined checksum ranges, and model class.
    /// Bytes C0..FF are not covered by those checksums.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] if the image fails validation.
    pub fn parse(bytes: [u8; 256]) -> Result<Self, ConfigurationError> {
        if bytes[..2] != [0x55, 0xaa] {
            return Err(ConfigurationError::Signature);
        }
        for range in [0..16, 16..64, 64..192] {
            let offset = range.start;
            if bytes[range].iter().fold(0u8, |s, b| s.wrapping_add(*b)) != 0 {
                return Err(ConfigurationError::Checksum { offset });
            }
        }
        if !matches!(bytes[253], 1 | 2) {
            return Err(ConfigurationError::ModelClass);
        }
        let model = Model::new(u16::from_be_bytes([bytes[253], bytes[254]]));
        Ok(Self { bytes, model })
    }
    /// Model word from E[FD..FE].
    pub fn model(&self) -> Model {
        self.model
    }
    /// Device name stored in the image, if `E[03]` announces one.
    ///
    /// The name is outside the RF configuration; a malformed name does not
    /// invalidate the image.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceNameError`] if the announced name is malformed.
    pub fn device_name(&self) -> Result<Option<String>, DeviceNameError> {
        identity::device_name(&self.bytes)
    }
    /// Snapshot of the original 256 reader configuration bytes.
    pub fn bytes(&self) -> &[u8; 256] {
        &self.bytes
    }
    fn rf_configuration(&self, protocol: RfProtocol) -> Vec<Vec<u8>> {
        match protocol {
            RfProtocol::TypeA => {
                let mut item = vec![0x0a];
                item.extend_from_slice(&self.bytes[0x10..=0x1a]);
                vec![item]
            }
            RfProtocol::Felica => {
                let mut item = vec![0x0b];
                item.extend_from_slice(&self.bytes[0x1b..=0x22]);
                vec![item]
            }
            RfProtocol::TypeB(profile) => {
                let options = match profile {
                    nfcb::RfProfile::Standard => &self.bytes[0x23..=0x25],
                    nfcb::RfProfile::Alternate => &self.bytes[0xcf..=0xd1],
                };
                let mut analog = vec![
                    0x0a,
                    self.bytes[0xc0],
                    options[0],
                    self.bytes[0xc1],
                    options[1],
                    self.bytes[0xc2],
                    options[2],
                ];
                analog.extend_from_slice(&self.bytes[0x16..=0x1a]);
                vec![analog, vec![0x0c, options[0], options[1], options[2]]]
            }
        }
    }
}

/// Hardware observations obtained by a completed initialization.
#[derive(Debug, Clone)]
pub struct ReaderInfo {
    /// Raw firmware identification; not interpreted as another module's revision.
    pub firmware: [u8; 4],
    /// Raw byte from command 0C.
    pub flags: u8,
    /// Configuration read from this connection.
    pub configuration: ConfigImage,
}

/// Parameter of the reader's 1C timer, derived only from a validated RF wait.
/// This timer and the A0 half-ms field are different protocol representations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReaderTimer(u16);
impl ReaderTimer {
    fn for_rf_timeout(timeout: RfTimeout) -> Self {
        // The accepted tick range is 1..=65535, so this conversion yields
        // 1..=33 whole seconds and a parameter in 99..=3299.
        Self(timeout.ticks.div_ceil(2000) * 100 - 1)
    }

    fn args(self) -> [u8; 3] {
        let [lo, hi] = self.0.to_le_bytes();
        [0x80, lo, hi]
    }
}

/// The reader response selector is independent of each A0 block timeout.
/// Each variant fixes both a 32/02 selector and its effective milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum ResponseTimeout {
    Ms51 = 51,
    Ms102 = 102,
    Ms204 = 204,
    Ms409 = 409,
    Ms819 = 819,
    Ms1640 = 1640,
    Ms3280 = 3280,
}
impl ResponseTimeout {
    fn for_request(request: RfTimeout) -> Self {
        match request.ticks.div_ceil(2) {
            0..=51 => Self::Ms51,
            52..=102 => Self::Ms102,
            103..=204 => Self::Ms204,
            205..=409 => Self::Ms409,
            410..=819 => Self::Ms819,
            820..=1640 => Self::Ms1640,
            _ => Self::Ms3280,
        }
    }

    fn args(self) -> [u8; 4] {
        let code = match self {
            Self::Ms51 => 0x0a,
            Self::Ms102 => 0x0b,
            Self::Ms204 => 0x0c,
            Self::Ms409 => 0x0d,
            Self::Ms819 => 0x0e,
            Self::Ms1640 => 0x0f,
            Self::Ms3280 => 0x10,
        };
        [2, 0x0b, 0x0b, code]
    }

    fn wait(self) -> Duration {
        Duration::from_millis(u64::from(self as u16))
    }

    fn host_wait(self) -> Duration {
        self.wait() + Duration::from_secs(1)
    }
}

/// Card response bound of one `40` exchange and how the reader enforces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetWait {
    /// The reader transceives the data once within the `32/02` step.
    Step(ResponseTimeout),
    /// The reader runs ISO-DEP itself: block retransmission and WTX follow
    /// the card's FWT, and `32/02` does not shorten or extend them.
    IsoDep(Duration),
}
impl TargetWait {
    /// Bound of an exchange with an ISO-DEP target whose frame waiting time
    /// is `fwt`. The reader gave up on a silent ISO-DEP NFC-B target after
    /// about 4.4 FWT, so four FWT cover retransmission and two maximal FWT
    /// (FWI 14) leave room for WTX.
    fn iso_dep(fwt: Duration) -> Self {
        Self::IsoDep(fwt * 4 + iso14443::frame_wait(14) * 2)
    }

    /// Host deadline: the card bound plus the margin of every reader command.
    fn host_wait(self) -> Duration {
        match self {
            Self::Step(timeout) => timeout.host_wait(),
            Self::IsoDep(bound) => bound + Duration::from_secs(1),
        }
    }
}

/// Firmware parameters written by command `12`. Bits 3 and 4 are fixed to
/// one; bit 4 makes firmware send RATS while activating an ISO-DEP NFC-A
/// card, so `4B` reports its ATS. Reset changes only the operating mode and
/// leaves these parameters as last written.
#[derive(Debug, Clone, Copy)]
struct Parameters {
    node_address: bool,
    automatic_atr_response: bool,
}
impl Parameters {
    const DEFAULT: Self = Self {
        node_address: false,
        automatic_atr_response: true,
    };

    fn byte(self) -> u8 {
        0x18 | u8::from(self.node_address) | (u8::from(self.automatic_atr_response) << 2)
    }
}

/// `06` arguments reading CIU_Status1 and CIU_Command.
const RECEIVER_PROBE: [u8; 4] = [0x63, 0x37, 0x63, 0x31];
/// CIU_Status1 bit set while the receiver is stalled so that
/// InListPassiveTarget cannot send its first request.
const RECEIVER_STALLED: u8 = 0x08;
const CIU_COMMAND: u16 = 0x6331;
const CIU_RECEIVE: u8 = 0x08;
const CIU_IDLE: u8 = 0x00;

/// Failure of an InListPassiveTarget activation, split at the `4A` request.
#[derive(Debug)]
enum ActivationError<E> {
    /// Receiver preparation failed; no RF request was sent.
    BeforeRequest(Error<E>),
    /// The `4A` transaction or its response failed.
    Request(Error<E>),
}
impl<E> From<ActivationError<E>> for Error<E> {
    fn from(error: ActivationError<E>) -> Self {
        match error {
            ActivationError::BeforeRequest(error) | ActivationError::Request(error) => error,
        }
    }
}

/// RF configuration and the timer are published only after all writes succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RfProtocol {
    TypeA,
    Felica,
    TypeB(nfcb::RfProfile),
}

#[derive(Debug, Clone, Copy)]
enum RfMode {
    Off,
    Configured {
        protocol: RfProtocol,
        timer: ReaderTimer,
        selection: RfSelection,
    },
    RawTypeA(RawTypeAResponse),
}

#[derive(Debug, Clone, Copy)]
enum RawTypeAResponse {
    Idle,
    Pending { frames: usize },
}

#[derive(Debug, Clone, Copy)]
enum RfSelection {
    Ordinary,
    /// The card can hold state that the next selection request does not
    /// clear, so that selection cycles the RF field first. Firmware may have
    /// activated a target that this crate rejected without granting a handle,
    /// which can then ignore the next request; or the holder of a selection
    /// declared such a state change.
    FieldCycleRequired,
}

#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "One bounded configuration snapshot belongs to the reader state; inline storage avoids a separate session allocation"
)]
enum State {
    NeedsInitialization,
    Ready {
        info: ReaderInfo,
        rf: RfMode,
        // 32/02 is independent of RF protocol/timer configuration. Only a
        // completed write establishes it; reset or an uncertain failure revokes it.
        response_timeout: Option<ResponseTimeout>,
    },
}

/// Exclusive reader owner. Uncertain transport failures revoke RF readiness.
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
            Ok(r) => Ok(r.data),
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

    /// Recover the transport, reset the reader, read its configuration, and enter
    /// RF-off readiness. Failure leaves the reader uninitialized; no command replay.
    /// Reset restores neither firmware parameters nor the `63 0D` reception
    /// setting, so this rewrites the defaults that NFC-A activation and every
    /// 106 kbps role rely on after a target role that changed them. It also
    /// sets the firmware's RF retry count (`32 04`) to zero, so that a mute or
    /// failed exchange never resends card data behind the caller.
    pub fn initialize(&mut self) -> Result<ReaderInfo, Error<T::Error>> {
        self.state = State::NeedsInitialization;
        self.link.recover().map_err(Error::Recovery)?;
        let wait = Duration::from_secs(1);
        self.link
            .reset(wait)
            .and_then(|commit| commit.commit())
            .map_err(Error::Transaction)?;
        let firmware: [u8; 4] = self
            .command(2, &[], wait)?
            .try_into()
            .map_err(|_| Error::Response("firmware length"))?;
        let probe = self.command(6, &[0xa0, 0], wait)?;
        if probe.len() != 1 {
            return Err(Error::Response("configuration probe length"));
        }
        let mut config = [0u8; 256];
        for bank in 0u8..4 {
            let mut addresses = Vec::with_capacity(128);
            for i in 0u8..64 {
                addresses.extend_from_slice(&[0xa0, bank * 64 + i]);
            }
            let values = self.command(6, &addresses, wait)?;
            if values.len() != 64 {
                return Err(Error::Response("configuration bank length"));
            }
            let begin = usize::from(bank) * 64;
            config[begin..begin + 64].copy_from_slice(&values);
        }
        let configuration = ConfigImage::parse(config).map_err(Error::Configuration)?;
        let flags = self
            .command(0x0c, &[], wait)?
            .first()
            .copied()
            .ok_or(Error::Response("reader flags length"))?;
        self.set_parameters(Parameters::DEFAULT)?;
        if !self.command(0x32, &[4, 0], wait)?.is_empty() {
            return Err(Error::Response("RF retry response length"));
        }
        self.write_register(0x630a, 0x40)?;
        self.write_register(0x630d, 0)?;
        self.disable_rf()?;
        let info = ReaderInfo {
            firmware,
            flags,
            configuration,
        };
        self.state = State::Ready {
            info: info.clone(),
            rf: RfMode::Off,
            response_timeout: None,
        };
        Ok(info)
    }

    fn write_register(&mut self, address: u16, value: u8) -> Result<(), Error<T::Error>> {
        self.write_registers(&[(address, value)])
    }

    /// Write registers in order with one `08` command. The reader returns one
    /// status per register; the first nonzero status is reported.
    fn write_registers(&mut self, writes: &[(u16, u8)]) -> Result<(), Error<T::Error>> {
        let args: Vec<u8> = writes
            .iter()
            .flat_map(|&(address, value)| {
                let [hi, lo] = address.to_be_bytes();
                [hi, lo, value]
            })
            .collect();
        let reply = self.command(8, &args, Duration::from_secs(1))?;
        if reply.len() != writes.len() {
            return Err(Error::Response("register write length"));
        }
        match reply.iter().find(|status| **status != 0) {
            Some(status) => Err(Error::RegisterStatus(*status)),
            None => Ok(()),
        }
    }

    fn set_parameters(&mut self, parameters: Parameters) -> Result<(), Error<T::Error>> {
        let reply = self.command(0x12, &[parameters.byte()], Duration::from_secs(1))?;
        if reply.is_empty() {
            Ok(())
        } else {
            Err(Error::Response("parameter response length"))
        }
    }

    /// Send InListPassiveTarget (`4A`). The firmware can stall its receiver
    /// so that no request is sent and the command never finds a card; a
    /// stalled receiver is restarted (Receive, then Idle, keeping the upper
    /// command bits) before every activation.
    fn list_passive_target(
        &mut self,
        args: &[u8],
        wait: Duration,
    ) -> Result<Vec<u8>, ActivationError<T::Error>> {
        self.restart_stalled_receiver()
            .map_err(ActivationError::BeforeRequest)?;
        self.command(0x4a, args, wait)
            .map_err(ActivationError::Request)
    }

    /// Reading the probe changes nothing. Once the restart writes begin, a
    /// failure can leave the receiver in an unknown command state, so only
    /// both completed writes keep the configured mode published.
    fn restart_stalled_receiver(&mut self) -> Result<(), Error<T::Error>> {
        let [status, command]: [u8; 2] = self
            .command(6, &RECEIVER_PROBE, Duration::from_secs(1))?
            .try_into()
            .map_err(|_| Error::Response("receiver probe length"))?;
        if status & RECEIVER_STALLED == 0 {
            return Ok(());
        }
        let ready = mem::replace(&mut self.state, State::NeedsInitialization);
        if matches!(ready, State::NeedsInitialization) {
            return Err(Error::NotInitialized);
        }
        let kept = command & 0xf0;
        self.write_registers(&[
            (CIU_COMMAND, kept | CIU_RECEIVE),
            (CIU_COMMAND, kept | CIU_IDLE),
        ])?;
        self.state = ready;
        Ok(())
    }

    fn configure_rf(
        &mut self,
        protocol: RfProtocol,
        timeout: RfTimeout,
    ) -> Result<(), Error<T::Error>> {
        if let State::Ready { rf, .. } = self.state
            && !matches!(
                rf,
                RfMode::Off
                    | RfMode::Configured {
                        selection: RfSelection::Ordinary,
                        ..
                    }
            )
        {
            self.rf_off()?;
        }
        let timer = ReaderTimer::for_rf_timeout(timeout);
        let (info, apply_mode, response_timeout) = match &self.state {
            State::Ready {
                rf:
                    RfMode::Configured {
                        protocol: applied,
                        timer: old,
                        ..
                    },
                ..
            } if *applied == protocol && *old == timer => return Ok(()),
            State::Ready {
                info,
                rf,
                response_timeout,
            } => (
                info.clone(),
                !matches!(rf,
                RfMode::Configured { protocol: applied, .. } if *applied == protocol),
                *response_timeout,
            ),
            State::NeedsInitialization => return Err(Error::NotInitialized),
        };
        // Any partial configuration revokes the preceding published mode.
        self.state = State::NeedsInitialization;
        self.command(0x1c, &timer.args(), Duration::from_secs(1))?;
        if apply_mode {
            let (retry, timing) = if protocol == RfProtocol::Felica {
                (0, 0xb7)
            } else {
                (4, 0x8f)
            };
            self.command(0x32, &[5, 0, 0, retry], Duration::from_secs(1))?;
            self.command(0x32, &[0x81, timing], Duration::from_secs(1))?;
            for item in info.configuration.rf_configuration(protocol) {
                self.command(0x32, &item, Duration::from_secs(1))?;
            }
            self.write_register(0x630d, 0)?;
        }
        self.state = State::Ready {
            info,
            rf: RfMode::Configured {
                protocol,
                timer,
                selection: RfSelection::Ordinary,
            },
            response_timeout,
        };
        Ok(())
    }

    fn prepare_exchange_timing(
        &mut self,
        protocol: RfProtocol,
        wait: TargetWait,
    ) -> Result<(), Error<T::Error>> {
        let (step, rf_wait) = match wait {
            TargetWait::Step(timeout) => (Some(timeout), timeout.wait()),
            TargetWait::IsoDep(bound) => (None, bound),
        };
        let desired_timer = ReaderTimer::for_rf_timeout(RfTimeout::new(rf_wait)?);
        let (info, applied_timer, applied_timeout, selection) = match &self.state {
            State::Ready {
                rf:
                    RfMode::Configured {
                        protocol: applied_protocol,
                        timer,
                        ..
                    },
                response_timeout,
                ..
            } if *applied_protocol == protocol
                && *timer == desired_timer
                && step.is_none_or(|timeout| *response_timeout == Some(timeout)) =>
            {
                return Ok(());
            }
            State::Ready {
                info,
                rf:
                    RfMode::Configured {
                        protocol: applied,
                        timer,
                        selection,
                    },
                response_timeout,
            } if *applied == protocol => (info.clone(), *timer, *response_timeout, *selection),
            _ => return Err(Error::NotInitialized),
        };
        // Do not publish a partial pair. Even if 32/02 succeeds, failure of 1C
        // requires explicit initialization before another card command is sent.
        self.state = State::NeedsInitialization;
        if let Some(timeout) = step
            && applied_timeout != Some(timeout)
        {
            self.command(0x32, &timeout.args(), Duration::from_secs(1))?;
        }
        if applied_timer != desired_timer {
            self.command(0x1c, &desired_timer.args(), Duration::from_secs(1))?;
        }
        self.state = State::Ready {
            info,
            rf: RfMode::Configured {
                protocol,
                timer: desired_timer,
                selection,
            },
            response_timeout: step.or(applied_timeout),
        };
        Ok(())
    }

    /// Select one FeliCa card at the supplied rate. The returned card exclusively borrows
    /// this reader, so its identity cannot survive a reset/mode change through it.
    /// Unsupported Polling request data may be absent and is preserved as such.
    pub fn poll_felica(
        &mut self,
        rate: BitRate,
        request: PollRequest,
        timeout: RfTimeout,
    ) -> Result<Option<FelicaCard<'_, T>>, Error<T::Error>> {
        self.configure_rf(RfProtocol::Felica, timeout)?;
        let poll = request.encode();
        let mut args = vec![1, rate.selector()];
        args.extend_from_slice(&poll[1..]);
        let response = self.list_passive_target(&args, timeout.host_wait())?;
        match response.as_slice() {
            [0] => Ok(None),
            [1, target, packet @ ..] if *target != 0 => {
                let observation = match PollResponse::parse(packet) {
                    Ok(observation) => observation,
                    Err(error) => {
                        self.require_field_cycle();
                        return Err(Error::FelicaResponse(error));
                    }
                };
                Ok(Some(FelicaCard {
                    reader: self,
                    request,
                    observation,
                    target: *target,
                    timeout,
                    rate,
                }))
            }
            _ => {
                self.require_field_cycle();
                Err(Error::Response("poll target count/layout"))
            }
        }
    }

    /// Activate one NFC-A target at 106 kbps. UID, SAK and optional ATS are
    /// validated before granting the returned card access to this reader.
    /// A preceding raw NFC-A exchange requires a field cycle before selection.
    pub fn poll_type_a(
        &mut self,
        timeout: RfTimeout,
    ) -> Result<Option<TypeACard<'_, T>>, Error<T::Error>> {
        self.configure_rf(RfProtocol::TypeA, timeout)?;
        let response = self.list_passive_target(&[1, 0], timeout.host_wait())?;
        match response.as_slice() {
            [0] => Ok(None),
            [1, target, data @ ..] if *target != 0 => {
                let observation = match type_a_record(data) {
                    Ok(observation) => observation,
                    Err(error) => {
                        self.require_field_cycle();
                        return Err(Error::TypeA(error));
                    }
                };
                Ok(Some(TypeACard {
                    reader: self,
                    observation,
                    target: *target,
                    timeout,
                }))
            }
            _ => {
                self.require_field_cycle();
                Err(Error::Response("NFC-A target count/layout"))
            }
        }
    }

    /// Activate one NFC-B target at 106 kbps. ATQB determines which exchange
    /// authority the result grants. The caller chooses the RF table and AFI.
    /// `timeout` is the detection wait and the wait of frame exchanges.
    pub fn poll_type_b(
        &mut self,
        options: nfcb::PollOptions,
        timeout: RfTimeout,
    ) -> Result<Option<TypeBSelection<'_, T>>, Error<T::Error>> {
        let protocol = RfProtocol::TypeB(options.profile);
        self.configure_rf(protocol, timeout)?;
        let response = self.list_passive_target(&[1, 3, options.afi, 1], timeout.host_wait())?;
        match response.as_slice() {
            [0] => Ok(None),
            [1, target, data @ ..] if *target != 0 => {
                let observation = match type_b_record(data) {
                    Ok(observation) => observation,
                    Err(error) => {
                        self.require_field_cycle();
                        return Err(error);
                    }
                };
                self.apply_type_b_receiver()?;
                let parameters = observation.iso_dep();
                let target = TypeBTarget {
                    reader: self,
                    number: *target,
                    observation,
                    profile: options.profile,
                };
                Ok(Some(match parameters {
                    Some(parameters) => {
                        TypeBSelection::IsoDep(TypeBBlockCard { target, parameters })
                    }
                    None => TypeBSelection::Frame(TypeBFrameCard { target, timeout }),
                }))
            }
            _ => {
                self.require_field_cycle();
                Err(Error::Response("NFC-B target count/layout"))
            }
        }
    }

    /// Make the next selection cycle the RF field before its request.
    fn require_field_cycle(&mut self) {
        if let State::Ready {
            rf: RfMode::Configured { selection, .. },
            ..
        } = &mut self.state
        {
            *selection = RfSelection::FieldCycleRequired;
        }
    }

    /// Write the NFC-B receiver register (`63 03 = 8B`) that every activated
    /// Type B selection exchanges under. A selection handle exists only after
    /// this write succeeds; failure leaves the reader requiring initialization.
    /// Other protocols do not restore the register.
    fn apply_type_b_receiver(&mut self) -> Result<(), Error<T::Error>> {
        let State::Ready {
            info,
            rf,
            response_timeout,
        } = mem::replace(&mut self.state, State::NeedsInitialization)
        else {
            return Err(Error::NotInitialized);
        };
        self.write_register(0x6303, 0x8b)?;
        self.state = State::Ready {
            info,
            rf,
            response_timeout,
        };
        Ok(())
    }

    fn exchange_rf(
        &mut self,
        data: &[u8],
        timeout: RfTimeout,
        protocol: RfProtocol,
    ) -> Result<Vec<u8>, Error<T::Error>> {
        if !matches!(self.state, State::Ready { rf: RfMode::Configured { protocol: applied, .. }, .. } if applied == protocol)
        {
            return Err(Error::NotInitialized);
        }
        if data.len() > 255 {
            return Err(Error::InputLength {
                maximum: 255,
                actual: data.len(),
            });
        }
        let mut args = Vec::with_capacity(data.len() + 2);
        args.extend_from_slice(&timeout.ticks.to_le_bytes());
        args.extend_from_slice(data);
        let response = self.command(0xa0, &args, timeout.host_wait())?;
        self.rf_response(response)
    }

    fn rf_response(&mut self, response: Vec<u8>) -> Result<Vec<u8>, Error<T::Error>> {
        match response.split_first() {
            Some((status, body)) if status & 0x3f == 0 => Ok(body.to_vec()),
            Some((status, _)) => {
                if status & 0x3f == 0x0d {
                    self.state = State::NeedsInitialization;
                }
                if status & 0x3f == 0x0b {
                    // Settle this RF error before the caller can issue another
                    // exchange; returning the error alone does not impose a gap.
                    self.link.wait(Duration::from_millis(10));
                }
                Err(Error::RfStatus(*status))
            }
            None => Err(Error::Response("missing RF status")),
        }
    }

    fn exchange_target(
        &mut self,
        target: u8,
        data: &[u8],
        wait: TargetWait,
    ) -> Result<TargetResponse, Error<T::Error>> {
        let mut args = Vec::with_capacity(data.len() + 1);
        args.push(target);
        args.extend_from_slice(data);
        let response = self.command(0x40, &args, wait.host_wait())?;
        let status = response
            .first()
            .copied()
            .ok_or(Error::Response("missing RF status"))?;
        let data = self.rf_response(response)?;
        Ok(TargetResponse { status, data })
    }

    fn prepare_target_exchange(
        &mut self,
        protocol: RfProtocol,
        wait: TargetWait,
    ) -> Result<(), TargetExchangeError<T::Error>> {
        if !matches!(
            self.state,
            State::Ready {
                rf: RfMode::Configured { protocol: applied, .. },
                ..
            } if applied == protocol
        ) {
            return Err(TargetExchangeError::SessionInvalid);
        }
        self.prepare_exchange_timing(protocol, wait)
            .map_err(TargetExchangeError::Preparation)
    }

    /// Exchange one `40` command whose response is a single fragment.
    fn exchange_single_response(
        &mut self,
        protocol: RfProtocol,
        target: u8,
        data: &[u8],
        timeout: ResponseTimeout,
    ) -> Result<TargetResponse, TargetExchangeError<T::Error>> {
        let wait = TargetWait::Step(timeout);
        self.prepare_target_exchange(protocol, wait)?;
        let response = self.exchange_target(target, data, wait);
        // These commands cannot collect a pending fragment. A missing status
        // also leaves the continuation state unknown.
        if match &response {
            Ok(reply) => reply.status & TARGET_MORE_INFORMATION != 0,
            Err(Error::RfStatus(status)) => status & TARGET_MORE_INFORMATION != 0,
            Err(Error::Response(_)) => true,
            Err(_) => false,
        } {
            self.state = State::NeedsInitialization;
        }
        response.map_err(TargetExchangeError::Exchange)
    }

    fn disable_rf(&mut self) -> Result<(), Error<T::Error>> {
        let response = self.command(0x32, &[1, 0], Duration::from_secs(1))?;
        if !response.is_empty() {
            return Err(Error::Response("RF off response length"));
        }
        self.link.wait(Duration::from_millis(5));
        Ok(())
    }

    /// Disable RF and invalidate the configured mode. Call explicitly to observe
    /// failure; dropping a reader only releases the backend's OS resources.
    /// If a raw NFC-A response was left pending, use [`Self::initialize`] to
    /// recover the reader stream before issuing further commands.
    pub fn rf_off(&mut self) -> Result<(), Error<T::Error>> {
        let (info, response_timeout) = match &self.state {
            State::Ready {
                rf: RfMode::RawTypeA(RawTypeAResponse::Pending { .. }),
                ..
            }
            | State::NeedsInitialization => return Err(Error::NotInitialized),
            State::Ready {
                info,
                response_timeout,
                ..
            } => (info.clone(), *response_timeout),
        };
        self.state = State::NeedsInitialization;
        self.disable_rf()?;
        self.state = State::Ready {
            info,
            rf: RfMode::Off,
            response_timeout,
        };
        Ok(())
    }
}

/// Reply to a reader-managed target exchange. The complete reader status is
/// retained, including upper bits whose continuation semantics are not assumed.
#[derive(Debug, Clone)]
pub struct TargetResponse {
    /// Unmodified status byte of command 41; its low six bits are zero on success.
    pub status: u8,
    /// Card bytes returned by the reader, without a fabricated APDU status word.
    pub data: Vec<u8>,
}

/// Failure of one card command sent through the reader's `40` target
/// exchange, classified by its application effect.
#[derive(Debug)]
pub enum TargetExchangeError<E> {
    /// The supplied byte count is outside `1..=maximum` for the selection.
    /// Nothing was sent and the selection remains usable.
    InputLength {
        /// Largest command the selection admits.
        maximum: usize,
        /// Supplied bytes.
        actual: usize,
    },
    /// The selection has already lost its operation authority.
    SessionInvalid,
    /// A raw NFC-A exchange has a response fragment waiting to be collected.
    ResponsePending,
    /// The raw NFC-A response exceeded the fragment budget. Reinitialize the reader.
    FragmentLimit,
    /// Reader timing setup failed before any card command was sent.
    Preparation(Error<E>),
    /// The card command transaction or its response failed. Consult the cause
    /// for transport progress; the command may have taken effect.
    Exchange(Error<E>),
}

impl<E: fmt::Debug> fmt::Display for TargetExchangeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputLength { maximum, actual } => {
                write!(f, "card command of {actual} bytes is outside 1..={maximum}")
            }
            Self::SessionInvalid => f.write_str("card selection is no longer valid"),
            Self::ResponsePending => f.write_str("an NFC-A response fragment is pending"),
            Self::FragmentLimit => f.write_str("NFC-A response fragment limit exceeded"),
            Self::Preparation(_) => f.write_str("reader setup failed before the card command"),
            Self::Exchange(_) => {
                f.write_str("card exchange failed; the command may have taken effect")
            }
        }
    }
}

impl<E: error::Error + 'static> error::Error for TargetExchangeError<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Preparation(error) | Self::Exchange(error) => Some(error),
            Self::InputLength { .. }
            | Self::SessionInvalid
            | Self::ResponsePending
            | Self::FragmentLimit => None,
        }
    }
}

/// NFC-A selection tied to one exclusive reader borrow.
///
/// The selection's activation assumptions hold while the card keeps the
/// state that activation established. A command that leaves state which the
/// next selection request does not clear must be declared with
/// [`nfca::Selection::require_field_cycle`] before it is sent.
///
/// [`nfca::Selection::exchange`] is [`Self::exchange`] with the reader status
/// interpreted: status 0 yields the reply bytes, the RF timeout status yields
/// [`nfca::Reply::Silence`], and any other status is returned as
/// [`Error::RfStatus`].
#[derive(Debug)]
pub struct TypeACard<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    observation: nfca::Observation,
    target: u8,
    timeout: RfTimeout,
}
impl<'a, T: Transport> TypeACard<'a, T> {
    /// Target identifier returned by the reader.
    pub fn target(&self) -> u8 {
        self.target
    }
    /// Largest APDU [`Self::exchange_apdu`] admits. The reader performs ISO-DEP
    /// chaining, so this is its `40` command limit.
    pub fn maximum_apdu_bytes(&self) -> usize {
        MAX_TYPE_A_COMMAND_BYTES
    }
    /// Replace the card response wait of later card commands that the reader
    /// transceives directly, including those of [`Self::into_raw`]. It starts
    /// as the polling timeout, so a caller polling with a short wait can grant
    /// card commands a longer one. The `32/02` step rounding and `1C` timer of
    /// `40` exchanges apply unchanged. [`Self::exchange_apdu`] does not use it:
    /// the reader runs ISO-DEP for those exchanges, and their bound follows
    /// the ATS frame waiting time.
    pub fn set_exchange_timeout(&mut self, timeout: RfTimeout) {
        self.timeout = timeout;
    }
    /// Consume the typed selection and allow caller-defined card commands
    /// whose responses can span several reader fragments.
    pub fn into_raw(self) -> RawTypeACard<'a, T> {
        RawTypeACard {
            reader: self.reader,
            target: self.target,
            timeout: ResponseTimeout::for_request(self.timeout),
        }
    }

    /// Send one card command through `40` and return its single response
    /// fragment, including the unmodified reader status.
    ///
    /// Input must contain 1 to [`MAX_TYPE_A_COMMAND_BYTES`] bytes; rejection
    /// preserves the selection. A response announcing a further fragment, or
    /// lacking its reader status, cannot be collected through this handle and
    /// requires reader initialization. Use [`Self::into_raw`] for commands
    /// whose responses can continue.
    pub fn exchange(
        &mut self,
        data: &[u8],
    ) -> Result<TargetResponse, TargetExchangeError<T::Error>> {
        admit_command(data, MAX_TYPE_A_COMMAND_BYTES)?;
        let timeout = ResponseTimeout::for_request(self.timeout);
        self.reader
            .exchange_single_response(RfProtocol::TypeA, self.target, data, timeout)
    }

    /// Exchange one APDU through the reader's ISO-DEP and collect
    /// reader-reported continuation fragments. Requires completed activation
    /// with ATS. The APDU is sent once. Failure after submission returns any
    /// accumulated response and requires reader initialization before another
    /// command can be sent. Each fragment may take four ATS frame waiting
    /// times plus about 9.9 s for WTX before the host abandons it as a deadline.
    pub fn exchange_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, ApduError<T::Error>> {
        const MAX_RESPONSE_BYTES: usize = 65_536;
        let mut progress = ApduProgress::default();
        let mut output = Vec::new();
        let result = (|| {
            let ats = match self.observation.ats() {
                Some(ats) if self.observation.supports_iso_dep() => ats,
                _ => return Err(ApduCause::ActivationRequired),
            };
            if apdu.is_empty() || apdu.len() > MAX_TYPE_A_COMMAND_BYTES {
                return Err(ApduCause::InputLength {
                    actual: apdu.len(),
                    maximum: MAX_TYPE_A_COMMAND_BYTES,
                });
            }
            let wait = TargetWait::iso_dep(ats.frame_wait());
            match self.reader.prepare_target_exchange(RfProtocol::TypeA, wait) {
                Ok(()) => {}
                Err(TargetExchangeError::Preparation(error)) => {
                    return Err(ApduCause::Preparation(error));
                }
                Err(_) => return Err(ApduCause::SessionInvalid),
            }
            progress.fragments = 1;
            let mut response = self
                .reader
                .exchange_target(self.target, apdu, wait)
                .map_err(ApduCause::Exchange)?;
            progress.delivered = true;
            loop {
                if response.status & 0x80 != 0 {
                    return Err(ApduCause::NodeAddress);
                }
                if output.len() + response.data.len() > MAX_RESPONSE_BYTES {
                    return Err(ApduCause::ResponseBytes);
                }
                output.extend_from_slice(&response.data);
                progress.received_bytes = output.len();
                if response.status & TARGET_MORE_INFORMATION == 0 {
                    return Ok(());
                }
                if progress.fragments == MAX_TYPE_A_RESPONSE_FRAGMENTS {
                    return Err(ApduCause::Fragments);
                }
                progress.fragments += 1;
                response = self
                    .reader
                    .exchange_target(self.target, &[], wait)
                    .map_err(ApduCause::Exchange)?;
            }
        })();
        if let Err(cause) = result {
            if progress.fragments != 0 {
                self.reader.state = State::NeedsInitialization;
            }
            return Err(ApduError {
                cause,
                progress,
                partial_response: output,
            });
        }
        Ok(output)
    }
}

impl<T: Transport> nfca::Selection for TypeACard<'_, T> {
    type Error = TargetExchangeError<T::Error>;

    /// Validated activation data for this selection.
    fn observation(&self) -> &nfca::Observation {
        &self.observation
    }

    fn exchange(&mut self, command: &[u8]) -> Result<nfca::Reply, Self::Error> {
        match TypeACard::exchange(self, command) {
            Ok(reply) if reply.status == 0 => Ok(nfca::Reply::Data(reply.data)),
            Ok(reply) => Err(TargetExchangeError::Exchange(Error::RfStatus(reply.status))),
            Err(TargetExchangeError::Exchange(Error::RfStatus(RF_TIMEOUT))) => {
                Ok(nfca::Reply::Silence)
            }
            Err(error) => Err(error),
        }
    }

    fn require_field_cycle(&mut self) {
        self.reader.require_field_cycle();
    }
}

/// Why an APDU exchanged through the reader's NFC-A ISO-DEP did not complete.
#[derive(Debug)]
pub enum ApduCause<E> {
    /// The selection has no ISO-DEP activation with ATS. Nothing was sent.
    ActivationRequired,
    /// The APDU length is outside `1..=maximum`. Nothing was sent and the
    /// selection remains usable.
    InputLength {
        /// Supplied bytes.
        actual: usize,
        /// Largest APDU the reader command admits.
        maximum: usize,
    },
    /// The selection has already lost its operation authority.
    SessionInvalid,
    /// Reader timing setup failed before the APDU was sent.
    Preparation(Error<E>),
    /// The transaction carrying the APDU or a continuation failed; the APDU
    /// may have taken effect.
    Exchange(Error<E>),
    /// A response fragment announced a node address, which this selection
    /// never requests.
    NodeAddress,
    /// The accumulated response exceeded 65536 bytes.
    ResponseBytes,
    /// The response needed more than 256 reader fragments.
    Fragments,
}

/// Progress of one APDU through the reader's NFC-A ISO-DEP.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApduProgress {
    /// `40` transactions attempted, including unsuccessful ones. A nonzero
    /// count means the APDU was handed to the reader.
    pub fragments: usize,
    /// The first response fragment arrived, so the card received the APDU.
    pub delivered: bool,
    /// Response bytes accumulated before completion or failure.
    pub received_bytes: usize,
}

/// A failed reader-run ISO-DEP exchange with its partial response.
#[derive(Debug)]
pub struct ApduError<E> {
    /// Machine-readable failure classification.
    pub cause: ApduCause<E>,
    /// Observed progress; an error never implies the APDU had no effect.
    pub progress: ApduProgress,
    /// Response bytes accumulated before failure.
    pub partial_response: Vec<u8>,
}

impl<E: fmt::Debug> fmt::Display for ApduError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.cause {
            ApduCause::ActivationRequired => {
                return f.write_str("target has no ISO-DEP activation");
            }
            ApduCause::InputLength { actual, maximum } => {
                return write!(f, "APDU of {actual} bytes is outside 1..={maximum}");
            }
            ApduCause::SessionInvalid => return f.write_str("card selection is no longer valid"),
            ApduCause::Preparation(_) => {
                return f.write_str("reader setup failed before the APDU was sent");
            }
            ApduCause::Exchange(_) => f.write_str("reader ISO-DEP exchange failed")?,
            ApduCause::NodeAddress => f.write_str("response fragment announced a node address")?,
            ApduCause::ResponseBytes => f.write_str("APDU response exceeds its limit")?,
            ApduCause::Fragments => f.write_str("APDU response fragment limit exceeded")?,
        }
        let p = &self.progress;
        write!(
            f,
            " after {} fragments; delivered {}; response bytes {}",
            p.fragments, p.delivered, p.received_bytes,
        )
    }
}

impl<E: error::Error + 'static> error::Error for ApduError<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.cause {
            ApduCause::Preparation(error) | ApduCause::Exchange(error) => Some(error),
            _ => None,
        }
    }
}

/// Exclusive raw command access to a selected NFC-A target.
///
/// A pending response can only be continued through this handle. Abandoning
/// it requires reader initialization. A completed raw exchange requires RF
/// off before the next selection to clear card state such as the Type 2 sector.
#[derive(Debug)]
pub struct RawTypeACard<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    target: u8,
    timeout: ResponseTimeout,
}

impl<T: Transport> RawTypeACard<'_, T> {
    /// Submit one caller-defined card command and return its first fragment,
    /// including the unmodified reader status.
    ///
    /// Input must contain 1 to 262 bytes. Input rejection preserves the
    /// selection. When a response is pending, call [`Self::receive_continuation`].
    pub fn exchange(
        &mut self,
        data: &[u8],
    ) -> Result<TargetResponse, TargetExchangeError<T::Error>> {
        admit_command(data, MAX_TYPE_A_COMMAND_BYTES)?;
        match self.reader.state {
            State::Ready {
                rf: RfMode::RawTypeA(RawTypeAResponse::Pending { .. }),
                ..
            } => {
                return Err(TargetExchangeError::ResponsePending);
            }
            State::Ready {
                rf: RfMode::RawTypeA(RawTypeAResponse::Idle),
                ..
            } => {}
            _ => self
                .reader
                .prepare_target_exchange(RfProtocol::TypeA, TargetWait::Step(self.timeout))?,
        }
        // Record loss of typed selection before the first raw transfer. This
        // survives release of the handle and errors that leave the link usable.
        self.set_response(RawTypeAResponse::Idle);
        self.transfer(data, 1)
    }

    /// Receive the next fragment without sending card command data. Returns
    /// `None` when the selection has no pending response. An exchange can
    /// return up to 256 fragments. Continuation failure requires reinitialization.
    pub fn receive_continuation(
        &mut self,
    ) -> Result<Option<TargetResponse>, TargetExchangeError<T::Error>> {
        let frames = match self.reader.state {
            State::Ready {
                rf: RfMode::RawTypeA(RawTypeAResponse::Pending { frames }),
                ..
            } => frames,
            State::Ready { .. } => return Ok(None),
            State::NeedsInitialization => return Err(TargetExchangeError::SessionInvalid),
        };
        if frames == MAX_TYPE_A_RESPONSE_FRAGMENTS {
            self.reader.state = State::NeedsInitialization;
            return Err(TargetExchangeError::FragmentLimit);
        }
        self.transfer(&[], frames + 1).map(Some)
    }

    fn set_response(&mut self, response: RawTypeAResponse) {
        if let State::Ready { rf, .. } = &mut self.reader.state {
            *rf = RfMode::RawTypeA(response);
        }
    }

    fn transfer(
        &mut self,
        data: &[u8],
        frames: usize,
    ) -> Result<TargetResponse, TargetExchangeError<T::Error>> {
        let result = self
            .reader
            .exchange_target(self.target, data, TargetWait::Step(self.timeout));
        match &result {
            Ok(response) => {
                let next = if response.status & TARGET_MORE_INFORMATION != 0 {
                    RawTypeAResponse::Pending { frames }
                } else {
                    RawTypeAResponse::Idle
                };
                self.set_response(next);
            }
            Err(Error::RfStatus(status))
                if frames == 1 && status & TARGET_MORE_INFORMATION == 0 => {}
            Err(_) => self.reader.state = State::NeedsInitialization,
        }
        result.map_err(TargetExchangeError::Exchange)
    }
}

/// NFC-B selection whose ATQB advertises ISO-DEP. The host runs the block
/// protocol; the reader transfers each block and owns its CRC.
///
/// [`iso_dep::Selection::blocks`] applies the reader timing that every block
/// transfer runs under: `32/02` selector 0x10 (a 3280 ms response step) and
/// its `1C` timer. Each block keeps its own `A0` wait. Setup failure sends no
/// block and leaves the reader requiring initialization.
#[derive(Debug)]
pub struct TypeBBlockCard<'a, T: Transport> {
    target: TypeBTarget<'a, T>,
    parameters: iso_dep::Parameters,
}
impl<T: Transport> TypeBBlockCard<'_, T> {
    /// Validated activation data, including ATQB and negotiated CID.
    pub fn observation(&self) -> &iso14443::nfcb::Observation {
        &self.target.observation
    }
    /// Target identifier returned by the reader.
    pub fn target(&self) -> u8 {
        self.target.number
    }
}

impl<T: Transport> iso_dep::Selection for TypeBBlockCard<'_, T> {
    type Error = Error<T::Error>;
    type Blocks<'s>
        = TypeBBlocks<'s, T>
    where
        Self: 's;

    fn parameters(&self) -> iso_dep::Parameters {
        self.parameters
    }

    fn maximum_block_bytes(&self) -> usize {
        MAX_TYPE_B_BLOCK_BYTES
    }

    fn blocks(&mut self) -> Result<TypeBBlocks<'_, T>, Error<T::Error>> {
        let protocol = RfProtocol::TypeB(self.target.profile);
        self.target
            .reader
            .prepare_exchange_timing(protocol, TargetWait::Step(ResponseTimeout::Ms3280))?;
        Ok(TypeBBlocks {
            reader: self.target.reader,
            protocol,
        })
    }

    /// An RF status for which [`Error::is_rf_timeout`] holds.
    fn is_rf_timeout(error: &Error<T::Error>) -> bool {
        error.is_rf_timeout()
    }

    fn require_field_cycle(&mut self) {
        self.target.reader.require_field_cycle();
    }
}

/// Block transfer authority of an NFC-B ISO-DEP selection after its timing
/// setup. A block holds at most [`MAX_TYPE_B_BLOCK_BYTES`] including CRC,
/// and its wait must be encodable as an [`RfTimeout`].
#[derive(Debug)]
pub struct TypeBBlocks<'s, T: Transport> {
    reader: &'s mut Reader<T>,
    protocol: RfProtocol,
}
impl<T: Transport> iso_dep::Blocks for TypeBBlocks<'_, T> {
    type Error = Error<T::Error>;

    fn transfer(&mut self, block: &[u8], wait: Duration) -> Result<Vec<u8>, Error<T::Error>> {
        let maximum = MAX_TYPE_B_BLOCK_BYTES - 2;
        if block.len() > maximum {
            return Err(Error::InputLength {
                maximum,
                actual: block.len(),
            });
        }
        self.reader
            .exchange_rf(block, RfTimeout::new(wait)?, self.protocol)
    }
}

/// An NFC-B selection granting the operations of its advertised protocol.
#[derive(Debug)]
pub enum TypeBSelection<'a, T: Transport> {
    /// The card advertises ISO-DEP block exchange.
    IsoDep(TypeBBlockCard<'a, T>),
    /// The card advertises another protocol. The caller supplies its frames.
    Frame(TypeBFrameCard<'a, T>),
}

impl<'a, T: Transport> TypeBSelection<'a, T> {
    /// Validated ATQB and ATTRIB data common to both selections.
    pub fn observation(&self) -> &iso14443::nfcb::Observation {
        &self.target().observation
    }

    /// Target identifier returned by the reader.
    pub fn target_number(&self) -> u8 {
        self.target().number
    }

    fn target(&self) -> &TypeBTarget<'a, T> {
        match self {
            Self::IsoDep(card) => &card.target,
            Self::Frame(card) => &card.target,
        }
    }
}

#[derive(Debug)]
struct TypeBTarget<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    number: u8,
    observation: iso14443::nfcb::Observation,
    profile: nfcb::RfProfile,
}

/// A selected NFC-B target for caller-defined non-ISO-DEP commands.
#[derive(Debug)]
pub struct TypeBFrameCard<'a, T: Transport> {
    target: TypeBTarget<'a, T>,
    timeout: RfTimeout,
}

impl<T: Transport> TypeBFrameCard<'_, T> {
    /// Send one target command through `40` and return its single response
    /// fragment. The reader's Type B command limit is
    /// [`MAX_TYPE_B_FRAME_COMMAND_BYTES`]. Card-specific command semantics
    /// belong to the caller. A response announcing a further fragment, or
    /// lacking its reader status, cannot be collected through this handle and
    /// invalidates the selection.
    pub fn exchange(
        &mut self,
        data: &[u8],
    ) -> Result<TargetResponse, TargetExchangeError<T::Error>> {
        admit_command(data, MAX_TYPE_B_FRAME_COMMAND_BYTES)?;
        let protocol = RfProtocol::TypeB(self.target.profile);
        let timeout = ResponseTimeout::for_request(self.timeout);
        self.target
            .reader
            .exchange_single_response(protocol, self.target.number, data, timeout)
    }
}

/// Largest ATS that the reader's NFC-A activation reports.
const MAX_ATS_BYTES: usize = 62;

/// Parse an NFC-A `4A` target record after its target number: SENS_RES,
/// SEL_RES, the UID length, the UID and an optional ATS.
fn type_a_record(data: &[u8]) -> Result<nfca::Observation, nfca::Error> {
    let [sens_high, sens_low, sel_res, uid_length, rest @ ..] = data else {
        return Err(nfca::Error::Truncated {
            field: "NFC-A selection header",
            minimum: 4,
            actual: data.len(),
        });
    };
    let uid_length = usize::from(*uid_length);
    if !matches!(uid_length, 4 | 7 | 10) {
        return Err(nfca::Error::UidLength(uid_length));
    }
    let (uid, ats) = rest
        .split_at_checked(uid_length)
        .ok_or(nfca::Error::Truncated {
            field: "NFC-A UID",
            minimum: 4 + uid_length,
            actual: data.len(),
        })?;
    let ats = match ats {
        [] => None,
        [declared, ..] if ats.len() > MAX_ATS_BYTES => {
            return Err(nfca::Error::AtsLength {
                declared: usize::from(*declared),
                actual: ats.len(),
            });
        }
        ats => Some(nfca::Ats::parse(ats)?),
    };
    nfca::Observation::new([*sens_high, *sens_low], *sel_res, uid, ats)
}

/// Parse an NFC-B `4A` target record after its target number: the 12-byte
/// ATQB, the ATTRIB response length and the complete ATTRIB response.
fn type_b_record<E>(data: &[u8]) -> Result<iso14443::nfcb::Observation, Error<E>> {
    let Some((atqb, [declared, attrib @ ..])) = data.split_first_chunk::<12>() else {
        return Err(Error::Response("NFC-B target record length"));
    };
    let atqb = iso14443::nfcb::Atqb::new(*atqb).map_err(Error::TypeB)?;
    if usize::from(*declared) != attrib.len() {
        return Err(Error::Response("NFC-B ATTRIB response length"));
    }
    iso14443::nfcb::Observation::new(atqb, attrib).map_err(Error::TypeB)
}

/// Reject an empty or oversized card command before any reader setup.
fn admit_command<E>(data: &[u8], maximum: usize) -> Result<(), TargetExchangeError<E>> {
    if data.is_empty() || data.len() > maximum {
        return Err(TargetExchangeError::InputLength {
            maximum,
            actual: data.len(),
        });
    }
    Ok(())
}

/// Selected FeliCa card whose operation authority is tied to one reader borrow.
///
/// [`Selection::exchange_packet`] sends one packet using `A0` with the
/// polling timeout. A packet that leaves card state which a new Polling does
/// not clear, such as authentication, must be declared with
/// [`Selection::require_field_cycle`] before it is sent.
#[derive(Debug)]
pub struct FelicaCard<'a, T: Transport> {
    reader: &'a mut Reader<T>,
    request: PollRequest,
    observation: PollResponse,
    target: u8,
    timeout: RfTimeout,
    rate: BitRate,
}
impl<T: Transport> FelicaCard<'_, T> {
    /// Reader-selected target number.
    pub fn target(&self) -> u8 {
        self.target
    }
    /// RF rate of the polling that selected this card.
    pub fn rate(&self) -> BitRate {
        self.rate
    }
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
        let response = self
            .reader
            .exchange_rf(packet, self.timeout, RfProtocol::Felica)?;
        felica_packet::validate_length(&response, 2).map_err(Error::FelicaResponse)?;
        Ok(response)
    }
    fn require_field_cycle(&mut self) {
        self.reader.require_field_cycle();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn type_a_records_carry_uid_and_optional_ats() -> Result<(), nfca::Error> {
        let observation = type_a_record(&[
            0x04, 0x07, 0x28, 4, 0x00, 0xd4, 0x1e, 0x92, 6, 0x75, 0x80, 0x60, 2, 0x42,
        ])?;
        assert_eq!(observation.sens_res(), [4, 7]);
        assert_eq!(observation.uid(), [0, 0xd4, 0x1e, 0x92]);
        assert_eq!(observation.ats().map(nfca::Ats::fwi), Some(6));
        assert!(
            type_a_record(&[0, 0x44, 0, 7, 1, 2, 3, 4, 5, 6, 7])?
                .ats()
                .is_none()
        );
        assert!(matches!(
            type_a_record(&[0, 4, 0, 5]),
            Err(nfca::Error::UidLength(5))
        ));
        assert!(matches!(
            type_a_record(&[0, 4, 0, 10, 1]),
            Err(nfca::Error::Truncated { .. })
        ));
        let mut oversized = vec![0, 4, 0, 4, 1, 2, 3, 4, 63];
        oversized.resize(9 + 62, 0);
        assert!(matches!(
            type_a_record(&oversized),
            Err(nfca::Error::AtsLength {
                declared: 63,
                actual: 63
            })
        ));
        Ok(())
    }
    #[test]
    fn type_b_records_match_their_attrib_length() {
        let record = [
            0x50, 1, 2, 3, 4, 0x11, 0x22, 0x33, 0x44, 0, 0x51, 0x41, 1, 1,
        ];
        assert!(
            type_b_record::<()>(&record)
                .is_ok_and(|observation| observation.atqb().pupi() == [1, 2, 3, 4])
        );
        assert!(matches!(
            type_b_record::<()>(&record[..13]),
            Err(Error::Response(_))
        ));
        assert!(matches!(
            type_b_record::<()>(&record[..12]),
            Err(Error::Response(_))
        ));
        let mut empty = record;
        empty[12] = 0;
        assert!(matches!(
            type_b_record::<()>(&empty[..13]),
            Err(Error::TypeB(iso14443::nfcb::Error::MissingAttrib))
        ));
    }
    #[test]
    fn timeout_uses_ceil_and_rejects_overflow() {
        assert!(RfTimeout::new(Duration::ZERO).is_err());
        assert!(matches!(RfTimeout::new(Duration::from_micros(501)),Ok(t) if t.ticks()==2));
        assert!(RfTimeout::new(Duration::from_secs(33)).is_err());
    }
    #[test]
    fn config_checks_regions_and_model() {
        let mut e = [0u8; 256];
        e[0] = 0x55;
        e[1] = 0xaa;
        e[2] = 1;
        e[253] = 1;
        e[254] = 0x31;
        assert!(matches!(ConfigImage::parse(e),Ok(c) if c.model().word()==0x0131));
        e[0x40] = 1;
        assert!(matches!(
            ConfigImage::parse(e),
            Err(ConfigurationError::Checksum { offset: 0x40 })
        ));
    }

    #[test]
    fn reader_timer_wire_values_cover_second_boundaries() -> Result<(), TimeoutRange> {
        for (wait, expected) in [
            (Duration::from_millis(100), [0x80, 0x63, 0]),
            (Duration::from_secs(1), [0x80, 0x63, 0]),
            (Duration::from_micros(1_000_500), [0x80, 0xc7, 0]),
            (Duration::from_micros(32_767_500), [0x80, 0xe3, 0x0c]),
        ] {
            assert_eq!(
                ReaderTimer::for_rf_timeout(RfTimeout::new(wait)?).args(),
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn response_timeout_vectors_cover_quantization_and_saturation() -> Result<(), TimeoutRange> {
        // Independent boundary vectors from f:3B250's millisecond intervals.
        for (microseconds, selector, effective_ms, timer) in [
            (500, 0x0a, 51, [0x80, 0x63, 0]),
            (51_000, 0x0a, 51, [0x80, 0x63, 0]),
            (51_500, 0x0b, 102, [0x80, 0x63, 0]),
            (102_000, 0x0b, 102, [0x80, 0x63, 0]),
            (102_500, 0x0c, 204, [0x80, 0x63, 0]),
            (204_000, 0x0c, 204, [0x80, 0x63, 0]),
            (204_500, 0x0d, 409, [0x80, 0x63, 0]),
            (409_000, 0x0d, 409, [0x80, 0x63, 0]),
            (409_500, 0x0e, 819, [0x80, 0x63, 0]),
            (500_000, 0x0e, 819, [0x80, 0x63, 0]),
            (819_000, 0x0e, 819, [0x80, 0x63, 0]),
            (819_500, 0x0f, 1640, [0x80, 0xc7, 0]),
            (1_640_000, 0x0f, 1640, [0x80, 0xc7, 0]),
            (1_640_500, 0x10, 3280, [0x80, 0x8f, 1]),
            (32_767_500, 0x10, 3280, [0x80, 0x8f, 1]),
        ] {
            let timeout =
                ResponseTimeout::for_request(RfTimeout::new(Duration::from_micros(microseconds))?);
            assert_eq!(timeout.args(), [2, 0x0b, 0x0b, selector]);
            assert_eq!(timeout.wait(), Duration::from_millis(effective_ms));
            assert_eq!(
                timeout.host_wait(),
                Duration::from_millis(effective_ms + 1000)
            );
            assert_eq!(
                ReaderTimer::for_rf_timeout(RfTimeout::new(timeout.wait())?).args(),
                timer
            );
        }
        Ok(())
    }
}
