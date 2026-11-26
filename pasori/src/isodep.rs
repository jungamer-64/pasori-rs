//! Bounded ISO-DEP block exchange.
//!
//! The host runs the block protocol of every [`iso_dep::Selection`]; the
//! reader transfers each block and owns its CRC. The block engine owns
//! sequencing, CID, chaining and WTX; the transfer channel owns each
//! synchronous RF transfer and reports a missing reply as silence. RF
//! recovery requests a block within the same APDU exchange. Between APDUs, an R(NAK) probe
//! confirms that the card is still in the field. The RC-S956 firmware runs
//! ISO-DEP for its NFC-A cards itself, and [`ApduExchange`] covers both.
pub(crate) mod target;

use alloc::vec::Vec;
use core::{error, fmt, time::Duration};
use iso14443::{
    FrameSize, WaitIndex,
    iso_dep::{self, Cid, Reply},
};
use rcs956::{
    reader::{self, TypeACard},
    transport::Transport,
};

/// Local APDU size limit, before applying limits of the selected session.
pub const MAX_APDU_BYTES: usize = 65_535;
const MAX_RESPONSE: usize = 65_536;
const MAX_FRAMES: usize = 2048;
const MAX_WTX: usize = 32;
const MAX_RETRANSMISSIONS: usize = 2;
/// Block wait per FWI step: 330 µs covers the ISO-DEP FWT of 302 µs per
/// step with margin.
const BLOCK_WAIT_UNIT: Duration = Duration::from_micros(330);
const MAX_BLOCK_WAIT: Duration = WaitIndex::MAX.scaled(BLOCK_WAIT_UNIT);

/// Activation parameters cannot establish the supported block profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterError {
    /// Reserved node address encoding.
    Nad(u8),
    /// The selected card did not advertise NAD support.
    NadUnsupported,
}
impl fmt::Display for ParameterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nad(nad) => write!(f, "reserved node address {nad:02X}"),
            Self::NadUnsupported => f.write_str("card does not support node addressing"),
        }
    }
}
impl error::Error for ParameterError {}

/// ISO-DEP node address with validated source and destination fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeAddress(u8);

impl NodeAddress {
    /// Decode the NAD byte. Bits 4 and 8 and equal nonzero endpoints are reserved.
    pub fn from_byte(value: u8) -> Result<Self, ParameterError> {
        if value & 0x88 != 0 || (value != 0 && value & 7 == value >> 4) {
            return Err(ParameterError::Nad(value));
        }
        Ok(Self(value))
    }

    fn reply(self) -> u8 {
        self.0.rotate_left(4)
    }
}

/// Finite per-APDU policy exhausted before the next operation is admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Budget {
    /// Synchronous RF transfers, including WTX and block retransmissions.
    Frames,
    /// WTX requests accepted during this exchange.
    WaitExtensions,
    /// Duplicate transfers for one block; accepted block progress resets the count.
    Retransmissions,
    /// Accumulated response application bytes.
    ResponseBytes,
}

/// Why an APDU could not complete; transport failures retain their native type.
#[derive(Debug)]
pub enum Cause<E> {
    /// Reader setup or an RF exchange invalidated this selected session.
    SessionInvalid,
    /// The selected target did not complete ISO-DEP activation.
    ActivationRequired,
    /// Application input exceeds the local or advertised card buffer limit.
    /// No RF was attempted; the session remains reusable.
    InputLength {
        /// Supplied application bytes.
        actual: usize,
        /// Effective maximum after local and card limits are combined.
        maximum: usize,
    },
    /// Reader setup failed before any application block was attempted.
    Preparation(E),
    /// A transfer failed; its application effect can be uncertain.
    Transport(E),
    /// Recovery from missing replies exhausted its budget.
    RecoveryExhausted,
    /// A block violates the selected profile or current protocol phase.
    InvalidBlock(&'static str),
    /// The target requested deselection.
    Deselected,
    /// A finite protocol policy was exhausted.
    Budget(Budget),
}

/// Application progress observed during one APDU, separate from RF frame count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Progress {
    /// Largest application prefix included in a transfer attempt, not proof of delivery.
    pub attempted_application_bytes: usize,
    /// Prefix acknowledged by a valid R-ACK or the first response I-block.
    pub acknowledged_application_bytes: usize,
    /// Valid response application bytes accumulated before completion or failure.
    pub received_application_bytes: usize,
    /// Transfer callback invocations, including unsuccessful ones.
    pub frames: usize,
}

/// A failed exchange, with its partial response and uncertain-effect boundary.
#[derive(Debug)]
pub struct Error<E> {
    /// Machine-readable failure classification.
    pub cause: Cause<E>,
    /// Observed progress; an error never implies the APDU had no effect.
    pub progress: Progress,
    /// Valid response bytes accumulated before failure, without duplicate blocks.
    pub partial_response: Vec<u8>,
}
impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.cause {
            Cause::SessionInvalid => return f.write_str("ISO-DEP session is invalid"),
            Cause::ActivationRequired => return f.write_str("target has no ISO-DEP activation"),
            Cause::InputLength { actual, maximum } => {
                return write!(f, "APDU of {actual} bytes exceeds {maximum}");
            }
            Cause::Preparation(_) => {
                return f.write_str("reader setup failed before the APDU was sent");
            }
            Cause::Transport(_) => f.write_str("ISO-DEP transfer failed")?,
            Cause::RecoveryExhausted => f.write_str("ISO-DEP RF timeout recovery exhausted")?,
            Cause::InvalidBlock(reason) => write!(f, "invalid ISO-DEP block: {reason}")?,
            Cause::Deselected => f.write_str("card requested deselection")?,
            Cause::Budget(budget) => f.write_str(match budget {
                Budget::Frames => "ISO-DEP frame budget exhausted",
                Budget::WaitExtensions => "ISO-DEP WTX budget exhausted",
                Budget::Retransmissions => "ISO-DEP block retransmission budget exhausted",
                Budget::ResponseBytes => "ISO-DEP response exceeds its limit",
            })?,
        }
        let p = &self.progress;
        write!(
            f,
            " after {} frames; APDU bytes attempted {}, acknowledged {}; response bytes {}",
            p.frames,
            p.attempted_application_bytes,
            p.acknowledged_application_bytes,
            p.received_application_bytes,
        )
    }
}
impl<E: error::Error + 'static> error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.cause {
            Cause::Preparation(error) | Cause::Transport(error) => Some(error),
            _ => None,
        }
    }
}

/// Why a presence check did not confirm the selected card. Every variant
/// leaves the session invalid; a new selection is required.
#[derive(Debug)]
pub enum PresenceError<E> {
    /// An earlier failure invalidated this session.
    SessionInvalid,
    /// Reader setup failed before the presence probe was sent.
    Preparation(E),
    /// Neither the probe nor its bounded repetitions were answered.
    NoResponse,
    /// A transfer failed for a reason other than an RF timeout.
    Transport(E),
    /// The answer was not the R(ACK) that the block protocol requires.
    InvalidBlock(&'static str),
}
impl<E: fmt::Debug> fmt::Display for PresenceError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SessionInvalid => "ISO-DEP session is invalid",
            Self::Preparation(_) => "reader setup failed before the presence check",
            Self::NoResponse => "card did not answer the presence check",
            Self::Transport(_) => "presence check transfer failed",
            Self::InvalidBlock(_) => "presence answer is not the required R(ACK)",
        })
    }
}
impl<E: error::Error + 'static> error::Error for PresenceError<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Preparation(error) | Self::Transport(error) => Some(error),
            Self::SessionInvalid | Self::NoResponse | Self::InvalidBlock(_) => None,
        }
    }
}

#[derive(Debug)]
enum State {
    Active(u8),
    Invalid,
}

#[derive(Debug)]
pub(crate) struct Session {
    state: State,
    maximum_frame_bytes: usize,
    maximum_receive_bytes: usize,
    maximum_application_bytes: usize,
    cid: Option<Cid>,
    nad: Option<NodeAddress>,
    wait: Duration,
}

#[derive(Debug, Clone, Copy)]
enum Phase {
    Sending { end: usize, more: bool },
    Receiving { previous_was_first: bool },
}

#[derive(Clone, Copy)]
enum Outbound {
    Information,
    Acknowledge,
    RequestRetransmission,
    WaitExtension(u8),
}

impl Session {
    /// Transmitted blocks are bounded by the card frame size (FSC) and the
    /// reader frame size (FSD), and received blocks by the reader frame size.
    /// Every block waits as `fwi` grants until WTX extends one.
    pub(crate) fn new(
        card_frame_size: FrameSize,
        reader_frame_size: FrameSize,
        cid: Option<Cid>,
        fwi: WaitIndex,
        card_buffer: Option<usize>,
        nad: Option<NodeAddress>,
    ) -> Self {
        // Both sizes are at least 16 bytes, which leaves room for the CRC,
        // PCB, CID and NAD bytes and for application data.
        Self {
            state: State::Active(0),
            maximum_frame_bytes: usize::from(card_frame_size.min(reader_frame_size).bytes()) - 2,
            maximum_receive_bytes: usize::from(reader_frame_size.bytes()) - 2,
            maximum_application_bytes: card_buffer.unwrap_or(MAX_APDU_BYTES).min(MAX_APDU_BYTES),
            cid,
            nad,
            wait: fwi.scaled(BLOCK_WAIT_UNIT),
        }
    }

    fn frame(&self, pcb: u8, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len() + 2);
        result.push(pcb | if self.cid.is_some() { 8 } else { 0 });
        if let Some(cid) = self.cid {
            result.push(cid.get());
        }
        result.extend_from_slice(data);
        result
    }

    /// Validate a received block's size and CID, returning its PCB and body.
    fn split_block<'r>(&self, block: &'r [u8]) -> Result<(u8, &'r [u8]), &'static str> {
        if block.is_empty() || block.len() > self.maximum_receive_bytes {
            return Err("RF block size");
        }
        let pcb = block[0];
        let with_cid = pcb & 8 != 0;
        if with_cid != self.cid.is_some() {
            return Err("CID presence");
        }
        let header = 1 + usize::from(with_cid);
        if block.len() < header {
            return Err("truncated CID");
        }
        if let Some(cid) = self.cid
            && (block[1] & 0x3f != cid.get())
        {
            return Err("CID mismatch or reserved bits");
        }
        Ok((pcb, &block[header..]))
    }

    fn first_capacity(&self) -> usize {
        self.capacity() - usize::from(self.nad.is_some())
    }

    fn capacity(&self) -> usize {
        self.maximum_frame_bytes - 1 - usize::from(self.cid.is_some())
    }

    fn frame_budget_capacity(&self) -> usize {
        self.first_capacity() + (MAX_FRAMES - 1) * self.capacity()
    }

    pub(crate) fn maximum_apdu_bytes(&self) -> usize {
        self.maximum_application_bytes
            .min(self.frame_budget_capacity())
    }

    fn first_i_block(&self, pcb: u8, data: &[u8]) -> Vec<u8> {
        if let Some(address) = self.nad {
            let mut block = self.frame(pcb | 4, &[address.0]);
            block.extend_from_slice(data);
            block
        } else {
            self.frame(pcb, data)
        }
    }

    pub(crate) fn prepare<'s, 'a, E>(
        &'s mut self,
        apdu: &'a [u8],
    ) -> Result<PreparedExchange<'s, 'a>, Error<E>> {
        let number = match self.state {
            State::Active(number) => number,
            State::Invalid => {
                return Err(Error {
                    cause: Cause::SessionInvalid,
                    progress: Progress::default(),
                    partial_response: Vec::new(),
                });
            }
        };
        if apdu.is_empty() || apdu.len() > self.maximum_application_bytes {
            return Err(Error {
                cause: Cause::InputLength {
                    actual: apdu.len(),
                    maximum: self.maximum_application_bytes,
                },
                progress: Progress::default(),
                partial_response: Vec::new(),
            });
        }
        if apdu.len() > self.frame_budget_capacity() {
            return Err(Error {
                cause: Cause::Budget(Budget::Frames),
                progress: Progress::default(),
                partial_response: Vec::new(),
            });
        }
        self.state = State::Invalid;
        Ok(PreparedExchange {
            session: self,
            apdu,
            number,
        })
    }

    pub(crate) fn admit_presence_check<E>(
        &mut self,
    ) -> Result<PresenceCheck<'_>, PresenceError<E>> {
        let State::Active(number) = self.state else {
            return Err(PresenceError::SessionInvalid);
        };
        self.state = State::Invalid;
        Ok(PresenceCheck {
            session: self,
            number,
        })
    }
}

/// Exclusive session ownership for one presence probe. As with an APDU, only
/// a confirmed answer restores reuse.
#[derive(Debug)]
pub(crate) struct PresenceCheck<'s> {
    session: &'s mut Session,
    number: u8,
}

impl PresenceCheck<'_> {
    /// Send R(NAK) with the current block number. Between exchanges the card's
    /// block number differs from ours, so ISO/IEC 14443-4 requires it to answer
    /// R(ACK) carrying its own number without re-sending its last block. Neither
    /// side toggles, so a confirmed probe leaves the next APDU unaffected.
    pub(crate) fn run<C, E>(
        self,
        setup: Result<C, E>,
        mut transmit: impl FnMut(&mut C, &[u8], Duration) -> Result<Reply, E>,
    ) -> Result<(), PresenceError<E>> {
        let Self { session, number } = self;
        let mut channel = setup.map_err(PresenceError::Preparation)?;
        let probe = session.frame(0xb2 | number, &[]);
        let mut repetitions = 0;
        let response = loop {
            match transmit(&mut channel, &probe, session.wait) {
                Ok(Reply::Block(response)) => break response,
                Ok(Reply::Silence) => {
                    if repetitions == MAX_RETRANSMISSIONS {
                        return Err(PresenceError::NoResponse);
                    }
                    repetitions += 1;
                }
                Err(error) => return Err(PresenceError::Transport(error)),
            }
        };
        let (pcb, body) = session
            .split_block(&response)
            .map_err(PresenceError::InvalidBlock)?;
        if pcb & 0xf6 != 0xa2 {
            return Err(PresenceError::InvalidBlock("presence answer is not R(ACK)"));
        }
        if !body.is_empty() {
            return Err(PresenceError::InvalidBlock("R-block data"));
        }
        if pcb & 1 == number {
            return Err(PresenceError::InvalidBlock("R(ACK) block number"));
        }
        session.state = State::Active(number);
        Ok(())
    }
}

/// Admitted input with exclusive session ownership through reader setup and RF.
/// Setup failure or abandonment invalidates the session without claiming any
/// application bytes were sent. Only a complete response restores reuse.
#[derive(Debug)]
pub(crate) struct PreparedExchange<'s, 'a> {
    session: &'s mut Session,
    apdu: &'a [u8],
    number: u8,
}

impl PreparedExchange<'_, '_> {
    pub(crate) fn exchange<C, E>(
        self,
        setup: Result<C, E>,
        mut transmit: impl FnMut(&mut C, &[u8], Duration) -> Result<Reply, E>,
    ) -> Result<Vec<u8>, Error<E>> {
        let Self {
            session,
            apdu,
            mut number,
        } = self;
        let mut progress = Progress::default();
        let mut output = Vec::new();
        let mut channel = match setup {
            Ok(channel) => channel,
            Err(error) => {
                return Err(Error {
                    cause: Cause::Preparation(error),
                    progress,
                    partial_response: output,
                });
            }
        };
        let capacity = session.capacity();
        let first_end = apdu.len().min(session.first_capacity());
        let mut phase = Phase::Sending {
            end: first_end,
            more: first_end < apdu.len(),
        };
        let mut last_i = session.first_i_block(
            2 | number | if first_end < apdu.len() { 0x10 } else { 0 },
            &apdu[..first_end],
        );
        let mut outbound = Outbound::Information;
        let mut wait = session.wait;
        let mut extensions = 0;
        let mut retransmissions = 0;
        let result = (|| -> Result<(), Cause<E>> {
            loop {
                if progress.frames == MAX_FRAMES {
                    return Err(Cause::Budget(Budget::Frames));
                }
                progress.frames += 1;
                if let Phase::Sending { end, .. } = phase {
                    progress.attempted_application_bytes = end;
                }
                let transfer = match outbound {
                    Outbound::Information => transmit(&mut channel, &last_i, wait),
                    Outbound::Acknowledge => {
                        transmit(&mut channel, &session.frame(0xa2 | number, &[]), wait)
                    }
                    Outbound::RequestRetransmission => {
                        transmit(&mut channel, &session.frame(0xb2 | number, &[]), wait)
                    }
                    Outbound::WaitExtension(multiplier) => {
                        transmit(&mut channel, &session.frame(0xf2, &[multiplier]), wait)
                    }
                };
                let response = match transfer {
                    Ok(Reply::Block(response)) => response,
                    Ok(Reply::Silence) => {
                        if retransmissions == MAX_RETRANSMISSIONS {
                            return Err(Cause::RecoveryExhausted);
                        }
                        retransmissions += 1;
                        outbound = match phase {
                            Phase::Sending { .. } => Outbound::RequestRetransmission,
                            Phase::Receiving { .. } => Outbound::Acknowledge,
                        };
                        wait = session.wait;
                        continue;
                    }
                    Err(error) => return Err(Cause::Transport(error)),
                };
                wait = session.wait;
                let (pcb, body) = session
                    .split_block(&response)
                    .map_err(Cause::InvalidBlock)?;
                match pcb & 0xf7 {
                    0xf2 => {
                        if body.len() != 1 || !(1..=59).contains(&(body[0] & 0x3f)) {
                            return Err(Cause::InvalidBlock("WTX multiplier"));
                        }
                        if extensions == MAX_WTX {
                            return Err(Cause::Budget(Budget::WaitExtensions));
                        }
                        extensions += 1;
                        let multiplier = body[0] & 0x3f;
                        // Apply FWT_MAX in the same guarded reader units as the base wait.
                        wait = (session.wait * u32::from(multiplier)).min(MAX_BLOCK_WAIT);
                        outbound = Outbound::WaitExtension(multiplier);
                    }
                    0xc2 => return Err(Cause::Deselected),
                    0xb2 | 0xb3 => return Err(Cause::InvalidBlock("R-NAK from card")),
                    0xa2 | 0xa3 => {
                        if !body.is_empty() {
                            return Err(Cause::InvalidBlock("R-block data"));
                        }
                        let Phase::Sending { end, more } = phase else {
                            return Err(Cause::InvalidBlock("R-block during response"));
                        };
                        if pcb & 1 == number {
                            if !more {
                                return Err(Cause::InvalidBlock("R-ACK without command chaining"));
                            }
                            progress.acknowledged_application_bytes = end;
                            retransmissions = 0;
                            number ^= 1;
                            let next_end = (end + capacity).min(apdu.len());
                            phase = Phase::Sending {
                                end: next_end,
                                more: next_end < apdu.len(),
                            };
                            last_i = session.frame(
                                2 | number | if next_end < apdu.len() { 0x10 } else { 0 },
                                &apdu[end..next_end],
                            );
                            outbound = Outbound::Information;
                        } else {
                            // An unchained I-block may be repeated only when the
                            // card responds to our RF timeout recovery request.
                            if first_end == apdu.len()
                                && !matches!(outbound, Outbound::RequestRetransmission)
                            {
                                return Err(Cause::InvalidBlock("R-ACK for unchained command"));
                            }
                            if retransmissions == MAX_RETRANSMISSIONS {
                                return Err(Cause::Budget(Budget::Retransmissions));
                            }
                            retransmissions += 1;
                            outbound = Outbound::Information;
                        }
                    }
                    0x02 | 0x03 | 0x06 | 0x07 | 0x12 | 0x13 | 0x16 | 0x17 => {
                        if let Phase::Sending { more: true, .. } = phase {
                            return Err(Cause::InvalidBlock(
                                "response before command chain completed",
                            ));
                        }
                        let duplicate = pcb & 1 != number;
                        let first = match (phase, duplicate) {
                            (Phase::Sending { .. }, false) => true,
                            (Phase::Sending { .. }, true) => {
                                return Err(Cause::InvalidBlock("I-block number"));
                            }
                            (Phase::Receiving { previous_was_first }, true) => previous_was_first,
                            (Phase::Receiving { .. }, false) => false,
                        };
                        let expected_nad = session.nad.filter(|_| first).map(NodeAddress::reply);
                        let body = match (expected_nad, pcb & 4 != 0, body) {
                            (Some(expected), true, [actual, rest @ ..]) if *actual == expected => {
                                rest
                            }
                            (None, false, body) => body,
                            _ => return Err(Cause::InvalidBlock("NAD presence or address")),
                        };
                        if duplicate {
                            if retransmissions == MAX_RETRANSMISSIONS {
                                return Err(Cause::Budget(Budget::Retransmissions));
                            }
                            retransmissions += 1;
                            outbound = Outbound::Acknowledge;
                            continue;
                        }
                        progress.acknowledged_application_bytes = apdu.len();
                        if output.len() + body.len() > MAX_RESPONSE {
                            return Err(Cause::Budget(Budget::ResponseBytes));
                        }
                        output.extend_from_slice(body);
                        progress.received_application_bytes = output.len();
                        retransmissions = 0;
                        number ^= 1;
                        if pcb & 0x10 == 0 {
                            return Ok(());
                        }
                        phase = Phase::Receiving {
                            previous_was_first: first,
                        };
                        outbound = Outbound::Acknowledge;
                    }
                    _ => return Err(Cause::InvalidBlock("PCB")),
                }
            }
        })();
        match result {
            Ok(()) => {
                session.state = State::Active(number);
                Ok(output)
            }
            Err(cause) => Err(Error {
                cause,
                progress,
                partial_response: output,
            }),
        }
    }
}

/// APDU exchange with an activated ISO-DEP card, whichever side runs the
/// block protocol: the RC-S956 firmware for its NFC-A cards, this crate for
/// every [`iso_dep::Selection`].
pub trait ApduExchange {
    /// Failure of one exchange, with the progress its runner observes.
    type Error;

    /// Largest APDU [`Self::exchange_apdu`] admits.
    fn maximum_apdu_bytes(&self) -> usize;

    /// Exchange one APDU and return its complete response. The APDU is never
    /// replayed after it may have reached the card.
    fn exchange_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

impl<T: Transport> ApduExchange for TypeACard<'_, T> {
    type Error = reader::ApduError<T::Error>;

    fn maximum_apdu_bytes(&self) -> usize {
        TypeACard::maximum_apdu_bytes(self)
    }

    fn exchange_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Self::Error> {
        TypeACard::exchange_apdu(self, apdu)
    }
}

/// ISO-DEP session over one reader selection, with a block-number state that
/// cannot outlive the selection. Protocol failure poisons the session; it
/// never replays APDUs.
#[derive(Debug)]
pub struct IsoDepCard<S: iso_dep::Selection> {
    card: S,
    session: Session,
}

impl<S: iso_dep::Selection> IsoDepCard<S> {
    /// Establish the block protocol from the selection's activation
    /// parameters, optionally addressing `node_address`. A rejected node
    /// address ends the selection.
    ///
    /// # Errors
    ///
    /// Rejects a node address the card does not advertise.
    pub fn new(card: S, node_address: Option<NodeAddress>) -> Result<Self, ParameterError> {
        let session = session(&card, node_address)?;
        Ok(Self { card, session })
    }

    /// The reader selection, including its validated activation data.
    pub fn selection(&self) -> &S {
        &self.card
    }

    /// Largest APDU this session admits: the local limit, the card buffer
    /// advertised by the activation, and the frame budget, whichever is smallest.
    pub fn maximum_apdu_bytes(&self) -> usize {
        self.session.maximum_apdu_bytes()
    }

    /// Exchange one APDU, handling ISO-DEP chaining, R-blocks and bounded WTX.
    /// Errors distinguish reader setup (zero application progress) from RF
    /// transfer attempts. Each block uses its own FWI/WTX wait. Application
    /// APDUs are never retried.
    ///
    /// # Errors
    ///
    /// Returns the failure with its progress and partial response.
    pub fn exchange_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error<S::Error>> {
        let exchange = self.session.prepare(apdu)?;
        exchange.exchange(self.card.blocks(), transfer)
    }

    /// Confirm that the card still answers between APDUs, using the same
    /// reader setup as [`Self::exchange_apdu`]. The probe carries no
    /// application data and leaves block numbering unchanged. Any failure,
    /// including an absent card, invalidates the session.
    ///
    /// # Errors
    ///
    /// Returns why the card was not confirmed.
    pub fn check_presence(&mut self) -> Result<(), PresenceError<S::Error>> {
        let check = self.session.admit_presence_check()?;
        check.run(self.card.blocks(), transfer)
    }
}

impl<S: iso_dep::Selection> ApduExchange for IsoDepCard<S> {
    type Error = Error<S::Error>;

    fn maximum_apdu_bytes(&self) -> usize {
        IsoDepCard::maximum_apdu_bytes(self)
    }

    fn exchange_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Self::Error> {
        IsoDepCard::exchange_apdu(self, apdu)
    }
}

/// Validate the activation parameters and the session they grant.
fn session<S: iso_dep::Selection>(
    card: &S,
    node_address: Option<NodeAddress>,
) -> Result<Session, ParameterError> {
    let parameters = card.parameters();
    if node_address.is_some() && !parameters.nad_supported() {
        return Err(ParameterError::NadUnsupported);
    }
    Ok(Session::new(
        parameters.card_frame_size(),
        parameters.reader_frame_size(),
        parameters.cid(),
        parameters.fwi(),
        parameters.maximum_command_bytes(),
        node_address,
    ))
}

fn transfer<B: iso_dep::Blocks>(
    blocks: &mut B,
    block: &[u8],
    wait: Duration,
) -> Result<Reply, B::Error> {
    blocks.transfer(block, wait)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, collections::VecDeque, format, vec};
    use std::io;

    const FWI4: WaitIndex = match WaitIndex::new(4) {
        Some(index) => index,
        None => panic!("FWI 4 is defined"),
    };
    /// 330 µs times 2^4.
    const FWI4_WAIT: Duration = Duration::from_micros(5280);

    /// The frame size of `bytes`, which must be one that FSCI encodes.
    fn frame(bytes: u16) -> Result<FrameSize, Box<dyn std::error::Error>> {
        (0..=12)
            .map(FrameSize::from_index)
            .find(|size| size.bytes() == bytes)
            .ok_or_else(|| format!("no frame size of {bytes} bytes").into())
    }

    fn cid(value: Option<u8>) -> Result<Option<Cid>, Box<dyn std::error::Error>> {
        value
            .map(|value| Cid::new(value).ok_or_else(|| format!("CID {value}").into()))
            .transpose()
    }

    fn session(fsc: u16, carried: Option<u8>) -> Result<Session, Box<dyn std::error::Error>> {
        Ok(Session::new(
            frame(fsc)?,
            frame(64)?,
            cid(carried)?,
            FWI4,
            None,
            None,
        ))
    }

    #[test]
    fn smallest_reader_frame_carries_twelve_bytes_with_cid()
    -> Result<(), Box<dyn std::error::Error>> {
        // A 16-byte block with CID holds 12 application bytes.
        let mut link = Session::new(
            frame(4096)?,
            FrameSize::MIN,
            cid(Some(1))?,
            FWI4,
            None,
            None,
        );
        let mut first = vec![0x1a, 1];
        first.extend_from_slice(&[0x55; 12]);
        let mut steps = VecDeque::from([
            (first, vec![0xaa, 1]),
            (vec![0x0b, 1, 0x55], vec![0x0b, 1, 0x90, 0]),
        ]);
        let reply = link
            .prepare::<io::Error>(&[0x55; 13])?
            .exchange(Ok(()), |_, frame, _| {
                let (expected, reply) = steps
                    .pop_front()
                    .ok_or_else(|| io::Error::other("extra transfer"))?;
                assert_eq!(frame, expected);
                Ok::<_, io::Error>(Reply::Block(reply))
            })?;
        assert_eq!(reply, [0x90, 0]);
        assert!(steps.is_empty());
        Ok(())
    }

    #[test]
    fn large_card_frames_keep_the_channel_block_limit() -> Result<(), Box<dyn std::error::Error>> {
        let mut link = session(4096, None)?;
        let mut first = vec![0x12];
        first.extend_from_slice(&[0x55; 61]);
        let mut steps = VecDeque::from([(first, vec![0xa2]), (vec![3, 0x55], vec![3, 0x90, 0])]);
        let reply = link
            .prepare::<io::Error>(&[0x55; 62])?
            .exchange(Ok(()), |_, frame, _| {
                let (expected, reply) = steps
                    .pop_front()
                    .ok_or_else(|| io::Error::other("extra transfer"))?;
                assert_eq!(frame, expected);
                Ok::<_, io::Error>(Reply::Block(reply))
            })?;
        assert_eq!(reply, [0x90, 0]);
        assert!(steps.is_empty());
        Ok(())
    }

    #[test]
    fn command_and_response_chains_use_direction_specific_ack_numbers()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut link = session(16, None)?;
        let mut first = vec![0x12];
        first.extend_from_slice(&[0x55; 13]);
        let mut steps = VecDeque::from([
            (first, vec![0xa2]),
            (vec![3, 0x55], vec![0x13, 0xaa]),
            (vec![0xa2], vec![2, 0xbb]),
        ]);
        let result =
            link.prepare::<io::Error>(&[0x55; 14])?
                .exchange(Ok(()), |_, frame, wait| {
                    let (expected, reply) = steps
                        .pop_front()
                        .ok_or_else(|| io::Error::other("extra transfer"))?;
                    assert_eq!(frame, expected);
                    assert_eq!(wait, FWI4_WAIT);
                    Ok::<_, io::Error>(Reply::Block(reply))
                })?;
        assert_eq!(result, [0xaa, 0xbb]);
        assert!(steps.is_empty());
        assert_eq!(
            link.prepare::<io::Error>(&[0x22])?
                .exchange(Ok(()), |_, frame, _| {
                    assert_eq!(frame, [3, 0x22]);
                    Ok::<_, io::Error>(Reply::Block(vec![3, 0x90, 0]))
                })?,
            [0x90, 0]
        );
        Ok(())
    }

    #[test]
    fn wtx_and_cid_are_echoed_with_a_separate_wait() -> Result<(), Box<dyn std::error::Error>> {
        let mut link = session(256, Some(3))?;
        let mut calls = 0;
        let reply = link
            .prepare::<io::Error>(&[0xa4])?
            .exchange(Ok(()), |_, frame, wait| {
                calls += 1;
                match calls {
                    1 => {
                        assert_eq!(frame, [0x0a, 3, 0xa4]);
                        assert_eq!(wait, FWI4_WAIT);
                        Ok::<_, io::Error>(Reply::Block(vec![0xfa, 3, 3]))
                    }
                    _ => {
                        assert_eq!(frame, [0xfa, 3, 3]);
                        assert_eq!(wait, FWI4_WAIT * 3);
                        Ok(Reply::Block(vec![0x0a, 3, 0x90, 0]))
                    }
                }
            })?;
        assert_eq!(calls, 2);
        assert_eq!(reply, [0x90, 0]);
        Ok(())
    }

    #[test]
    fn chained_command_and_response_retry_only_the_current_block()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut link = session(16, None)?;
        let first = [&[0x12][..], &[0x55; 13]].concat();
        let mut steps = VecDeque::from([
            (first, vec![0xa2]),
            (vec![3, 0x55], vec![0xa2]),
            (vec![3, 0x55], vec![0x13, 0xaa]),
            (vec![0xa2], vec![0x13, 0xaa]),
            (vec![0xa2], vec![2, 0xbb]),
        ]);
        assert_eq!(
            link.prepare::<io::Error>(&[0x55; 14])?
                .exchange(Ok(()), |_, frame, _| {
                    let (expected, reply) = steps
                        .pop_front()
                        .ok_or_else(|| io::Error::other("extra transfer"))?;
                    assert_eq!(frame, expected);
                    Ok::<_, io::Error>(Reply::Block(reply))
                })?,
            [0xaa, 0xbb]
        );
        assert!(steps.is_empty());
        Ok(())
    }

    #[test]
    fn empty_chained_information_advances_number_without_appending_duplicates()
    -> Result<(), Box<dyn std::error::Error>> {
        for (cid, steps) in [
            (
                None,
                vec![
                    (vec![2, 0xa4], vec![0x12]),
                    (vec![0xa3], vec![0x12]),
                    (vec![0xa3], vec![0x13]),
                    (vec![0xa2], vec![2, 0x90, 0]),
                ],
            ),
            (
                Some(3),
                vec![
                    (vec![0x0a, 3, 0xa4], vec![0x1a, 3]),
                    (vec![0xab, 3], vec![0x1a, 3]),
                    (vec![0xab, 3], vec![0x1b, 3]),
                    (vec![0xaa, 3], vec![0x0a, 3, 0x90, 0]),
                ],
            ),
        ] {
            let mut link = session(64, cid)?;
            let mut steps = VecDeque::from(steps);
            let result = link
                .prepare::<io::Error>(&[0xa4])?
                .exchange(Ok(()), |_, frame, _| {
                    let (expected, response) = steps
                        .pop_front()
                        .ok_or_else(|| io::Error::other("extra RF block"))?;
                    assert_eq!(frame, expected);
                    Ok::<_, io::Error>(Reply::Block(response))
                })?;
            assert_eq!(result, [0x90, 0]);
            assert!(steps.is_empty());
        }
        Ok(())
    }

    #[test]
    fn transfer_failure_preserves_partial_response_and_invalidates_session()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut link = session(64, None)?;
        let mut calls = 0;
        let error = link
            .prepare::<io::Error>(&[0xa4])?
            .exchange(Ok(()), |_, _, _| {
                calls += 1;
                if calls == 1 {
                    Ok(Reply::Block(vec![0x12, 0xaa]))
                } else {
                    Err(io::Error::new(io::ErrorKind::TimedOut, "lost response"))
                }
            })
            .err()
            .ok_or("expected error")?;
        assert!(
            matches!(error.cause, Cause::Transport(ref e) if e.kind() == io::ErrorKind::TimedOut)
        );
        assert_eq!(
            error.progress,
            Progress {
                attempted_application_bytes: 1,
                acknowledged_application_bytes: 1,
                received_application_bytes: 1,
                frames: 2
            }
        );
        assert_eq!(error.partial_response, [0xaa]);
        let retry = link.prepare::<io::Error>(&[0xa4]);
        assert!(matches!(
            retry,
            Err(Error {
                cause: Cause::SessionInvalid,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn preflight_rejection_keeps_session_and_malformed_blocks_poison_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut link = session(64, None)?;
        assert!(matches!(
            link.prepare::<io::Error>(&[]),
            Err(Error {
                cause: Cause::InputLength { actual: 0, .. },
                ..
            })
        ));
        assert_eq!(
            link.prepare::<io::Error>(&[0xa4])?
                .exchange(Ok(()), |_, _, _| Ok::<_, io::Error>(Reply::Block(vec![2])))?,
            []
        );
        for reply in [
            vec![0xfa, 1, 1],
            vec![0xf2, 0],
            vec![0x06, 0],
            vec![0xa3, 0],
            vec![2; 63],
        ] {
            let mut link = session(64, None)?;
            assert!(matches!(
                link.prepare::<io::Error>(&[1])?
                    .exchange(Ok(()), |_, _, _| Ok::<_, io::Error>(Reply::Block(
                        reply.clone()
                    ))),
                Err(Error {
                    cause: Cause::InvalidBlock(_),
                    ..
                })
            ));
            assert!(matches!(link.state, State::Invalid));
        }
        Ok(())
    }

    #[test]
    fn wait_extensions_and_retransmissions_have_finite_budgets()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut link = session(64, None)?;
        let error = link
            .prepare::<io::Error>(&[1])?
            .exchange(Ok(()), |_, _, _| {
                Ok::<_, io::Error>(Reply::Block(vec![0xf2, 1]))
            })
            .err()
            .ok_or("expected exhaustion")?;
        assert!(matches!(error.cause, Cause::Budget(Budget::WaitExtensions)));
        assert_eq!(error.progress.frames, 33);
        let mut link = session(16, None)?;
        let error = link
            .prepare::<io::Error>(&[1; 14])?
            .exchange(Ok(()), |_, _, _| {
                Ok::<_, io::Error>(Reply::Block(vec![0xa3]))
            })
            .err()
            .ok_or("expected exhaustion")?;
        assert!(matches!(
            error.cause,
            Cause::Budget(Budget::Retransmissions)
        ));
        assert_eq!(error.progress.frames, 3);
        Ok(())
    }

    #[test]
    fn frame_and_response_limits_preserve_their_partial_progress()
    -> Result<(), Box<dyn std::error::Error>> {
        for (body_length, expected) in [
            (0, Budget::Frames),
            (1, Budget::Frames),
            (61, Budget::ResponseBytes),
        ] {
            let mut link = session(64, None)?;
            let mut number = 0u8;
            let error = link
                .prepare::<io::Error>(&[1])?
                .exchange(Ok(()), |_, _, _| {
                    let mut reply = vec![0x12 | number];
                    number ^= 1;
                    reply.resize(body_length + 1, 0xaa);
                    Ok::<_, io::Error>(Reply::Block(reply))
                })
                .err()
                .ok_or("expected exhaustion")?;
            assert!(matches!(error.cause, Cause::Budget(actual) if actual == expected));
            assert_eq!(
                error.partial_response.len(),
                error.progress.received_application_bytes
            );
            assert!(error.progress.acknowledged_application_bytes == 1);
            assert!(error.progress.received_application_bytes <= MAX_RESPONSE);
        }
        let mut link = session(16, None)?;
        let error = link
            .prepare::<io::Error>(&vec![0; MAX_APDU_BYTES])
            .err()
            .ok_or("expected admission failure")?;
        assert!(matches!(error.cause, Cause::Budget(Budget::Frames)));
        assert_eq!(error.progress.frames, 0);
        assert!(matches!(link.state, State::Active(0)));
        Ok(())
    }

    #[test]
    fn reader_receive_and_card_buffer_limits_are_distinct() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut link = Session::new(frame(16)?, frame(64)?, None, FWI4, Some(128), None);
        let error = link
            .prepare::<io::Error>(&[0; 129])
            .err()
            .ok_or("expected input rejection")?;
        assert!(matches!(
            error.cause,
            Cause::InputLength {
                actual: 129,
                maximum: 128
            }
        ));
        assert_eq!(error.progress.frames, 0);
        let error = link
            .prepare::<io::Error>(&[1])?
            .exchange(Ok(()), |_, _, _| {
                Ok::<_, io::Error>(Reply::Block(vec![2; 63]))
            })
            .err()
            .ok_or("expected receive limit")?;
        assert!(matches!(error.cause, Cause::InvalidBlock("RF block size")));
        Ok(())
    }

    #[test]
    fn presence_probe_expects_the_cards_opposite_block_number()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut link = session(64, Some(3))?;
        let mut probes = 0;
        link.admit_presence_check::<io::Error>()?.run(
            Ok::<(), io::Error>(()),
            |_, frame, wait| {
                probes += 1;
                assert_eq!(frame, [0xba, 3]);
                assert_eq!(wait, FWI4_WAIT);
                if probes == 1 {
                    Ok(Reply::Silence)
                } else {
                    Ok(Reply::Block(vec![0xab, 3]))
                }
            },
        )?;
        assert_eq!(probes, 2);
        // The probe neither toggles the block number nor consumes the session.
        assert_eq!(
            link.prepare::<io::Error>(&[0xa4])?
                .exchange(Ok(()), |_, frame, _| {
                    assert_eq!(frame, [0x0a, 3, 0xa4]);
                    Ok::<_, io::Error>(Reply::Block(vec![0x0a, 3, 0x90, 0]))
                })?,
            [0x90, 0]
        );
        link.admit_presence_check::<io::Error>()?
            .run(Ok(()), |_, frame, _| {
                assert_eq!(frame, [0xbb, 3]);
                Ok::<_, io::Error>(Reply::Block(vec![0xaa, 3]))
            })?;
        Ok(())
    }

    #[test]
    fn unconfirmed_presence_invalidates_the_session() -> Result<(), Box<dyn std::error::Error>> {
        for reply in [vec![0xa2], vec![0xa3, 0], vec![0xb3], vec![3, 0x90, 0]] {
            let mut link = session(64, None)?;
            let error = link
                .admit_presence_check::<io::Error>()?
                .run(Ok(()), |_, _, _| {
                    Ok::<_, io::Error>(Reply::Block(reply.clone()))
                })
                .err()
                .ok_or("expected an unconfirmed probe")?;
            assert!(matches!(error, PresenceError::InvalidBlock(_)));
            assert!(matches!(
                link.admit_presence_check::<io::Error>(),
                Err(PresenceError::SessionInvalid)
            ));
        }
        let mut link = session(64, None)?;
        let mut probes = 0;
        let error = link
            .admit_presence_check::<io::Error>()?
            .run(Ok(()), |_, _, _| {
                probes += 1;
                Ok::<_, io::Error>(Reply::Silence)
            })
            .err()
            .ok_or("expected no response")?;
        assert!(matches!(error, PresenceError::NoResponse));
        assert_eq!(probes, MAX_RETRANSMISSIONS + 1);
        assert!(matches!(link.state, State::Invalid));
        let mut link = session(64, None)?;
        let error = link
            .admit_presence_check::<io::Error>()?
            .run(Err::<(), _>(io::Error::other("setup")), |_, _, _| {
                Err::<Reply, _>(io::Error::other("unexpected transfer"))
            })
            .err()
            .ok_or("expected setup failure")?;
        assert!(matches!(error, PresenceError::Preparation(_)));
        assert!(matches!(link.state, State::Invalid));
        Ok(())
    }
}
