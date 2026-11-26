//! Target exchanges against independently encoded Port-100 responses.

use pasori::iso14443::nfca::TargetEvent;
use pasori::{
    felica_packet::Idm,
    ndef::{
        MAX_TYPE4_EMULATED_NDEF_BYTES, Type3EmulationError, Type3Event, Type3NdefChange,
        Type3NdefMemory, Type3NdefMemoryError, Type3Target, Type4EmulationError, Type4Event,
        Type4NdefChange, Type4NdefFile, Type4Target,
    },
    port100::reader::{BitRate, Error, PollingResponder, Reader, TargetWait},
    type2::{Type2EmulationError, Type2Event, Type2Target},
};
use reader_script::port100::{Script, Step, command, initialization, initialization_with};
use std::{error::Error as StdError, num::NonZeroU16, time::Duration};

const MESSAGE: [u8; 3] = [0xd0, 0, 0];
const IDENTITY: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const PMM: [u8; 8] = [1, 0x20, 0x22, 4, 0x27, 0x67, 0x4e, 0xff];
const WAIT_MS: u16 = 330;

fn wait() -> Result<TargetWait, Box<dyn StdError>> {
    TargetWait::new(Duration::from_millis(u64::from(WAIT_MS))).ok_or_else(|| "target wait".into())
}

fn configure(rate: u8) -> [Step; 2] {
    [
        command(0x40, &[8, rate], &[0]),
        command(0x42, &[0, 1, 1, 1, 2, 7], &[0]),
    ]
}

fn exchange(parameters: &[u8; 24], mdaa: u8, transmit: &[u8], reply: &[u8]) -> Step {
    // Send-only and receive-only forms from the split Type 3 capture.
    let receive = if transmit.is_empty() { WAIT_MS } else { 0 };
    exchange_receiving(parameters, mdaa, receive, transmit, reply)
}

fn exchange_receiving(
    parameters: &[u8; 24],
    mdaa: u8,
    receive_ms: u16,
    transmit: &[u8],
    reply: &[u8],
) -> Step {
    let mut args = vec![0, 0, 0xff, 0xff, mdaa];
    args.extend_from_slice(parameters);
    args.extend([0, 0]);
    args.extend(receive_ms.to_le_bytes());
    args.extend_from_slice(transmit);
    command(0x48, &args, reply)
}

#[test]
fn serves_type2_reads_on_port100_across_silence_and_field_loss() -> Result<(), Box<dyn StdError>> {
    let mut parameters = [0; 24];
    parameters[..6].copy_from_slice(&[4, 0, 1, 2, 3, 0]);
    let page_three = [
        0xe1, 0x10, 6, 0x0f, 3, 3, 0xd0, 0, 0, 0xfe, 0, 0, 0, 0, 0, 0,
    ];
    let page_fifteen = [0, 0, 0, 0, 8, 1, 2, 3, 8, 0, 0, 0, 0, 0, 0xff, 0xff];
    let mut steps = initialization();
    steps.extend(configure(0x0b));
    steps.extend([
        exchange(&parameters, 1, &[], &[0, 0, 0, 0, 4, 0, 0]),
        exchange(&parameters, 1, &[], &[0x0b, 0, 3, 0, 0, 0, 0, 0x30, 3]),
        exchange(&parameters, 0, &page_three, &[0x0b, 0, 0, 0, 0, 0, 0]),
        exchange(&parameters, 0, &[], &[0x0b, 0, 0, 0x80, 0, 0, 0]),
        exchange(&parameters, 0, &[], &[0x0b, 0, 0, 0, 4, 0, 0]),
        exchange(&parameters, 1, &[], &[0x0b, 0, 3, 0, 0, 0, 0, 0x30, 15]),
        exchange(&parameters, 0, &page_fifteen, &[0x0b, 0, 0, 0, 0, 0, 0]),
        exchange(&parameters, 0, &[], &[0x0b, 0, 0, 0, 0, 0, 0, 0x50, 0]),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut target = Type2Target::listen(&mut reader, [1, 2, 3], &MESSAGE, wait()?)?;
    assert_eq!(target.serve_next(wait()?)?, Type2Event::Read(3));
    assert_eq!(target.serve_next(wait()?)?, Type2Event::Silence);
    assert_eq!(target.serve_next(wait()?)?, Type2Event::FieldOff);
    assert_eq!(target.serve_next(wait()?)?, Type2Event::Read(15));
    assert_eq!(target.serve_next(wait()?)?, Type2Event::Halted);
    assert!(matches!(
        target.serve_next(wait()?),
        Err(Type2EmulationError::Halted)
    ));
    target.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn serves_type3_attribute_and_message_blocks_across_field_cycles() -> Result<(), Box<dyn StdError>>
{
    let mut parameters = [0; 24];
    parameters[6..14].copy_from_slice(&IDENTITY);
    parameters[14..22].copy_from_slice(&PMM);
    parameters[22..].copy_from_slice(&[0x12, 0xfc]);
    let attribute = [0x10, 12, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0x20];
    let incoming = |mode: u8, address: &[u8]| {
        let mut reply = vec![
            0x0c,
            0,
            mode,
            0,
            0,
            0,
            0,
            if address.len() == 2 { 16 } else { 17 },
            6,
        ];
        reply.extend(IDENTITY);
        reply.extend([1, 0x0b, 0, 1]);
        reply.extend_from_slice(address);
        reply
    };
    let outgoing = |block: [u8; 16]| {
        let mut reply = vec![29, 7];
        reply.extend(IDENTITY);
        reply.extend([0, 0, 1]);
        reply.extend(block);
        reply
    };
    let mut body = [0; 16];
    body[..3].copy_from_slice(&MESSAGE);
    let mut steps = initialization();
    steps.extend(configure(0x0c));
    steps.extend([
        exchange(&parameters, 1, &[], &[0x0c, 0, 0, 0x80, 0, 0, 0]),
        exchange(&parameters, 1, &[], &incoming(3, &[0x80, 0])),
        exchange(
            &parameters,
            0,
            &outgoing(attribute),
            &[0x0c, 0, 0, 0, 0, 0, 0],
        ),
        exchange(&parameters, 0, &[], &incoming(0, &[0, 2, 0])),
        exchange(
            &parameters,
            0,
            &status_reply(7, 1, 0xa8),
            &[0x0c, 0, 0, 0, 0, 0, 0],
        ),
        exchange(&parameters, 0, &[], &[0x0c, 0, 0, 0, 4, 0, 0]),
        exchange(&parameters, 1, &[], &incoming(3, &[0, 1, 0])),
        exchange(&parameters, 0, &outgoing(body), &[0x0c, 0, 0, 0, 0, 0, 0]),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut target = Type3Target::listen(
        &mut reader,
        PollingResponder::Reader(BitRate::Kbps212),
        Idm::new(IDENTITY),
        PMM,
        &MESSAGE,
    )?;
    assert!(matches!(
        target.serve_next(wait()?),
        Ok(Type3Event::Silence)
    ));
    assert_eq!(target.serve_next(wait()?)?, Type3Event::Read);
    assert_eq!(
        target.serve_next(wait()?)?,
        Type3Event::Rejected {
            flag1: 1,
            flag2: 0xa8
        }
    );
    assert_eq!(target.serve_next(wait()?)?, Type3Event::FieldOff);
    assert_eq!(target.serve_next(wait()?)?, Type3Event::Read);
    target.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

/// A FeliCa status response with `code` and both status flags.
fn status_reply(code: u8, flag1: u8, flag2: u8) -> Vec<u8> {
    let mut packet = vec![12, code];
    packet.extend(IDENTITY);
    packet.extend([flag1, flag2]);
    packet
}

fn felica_parameters() -> [u8; 24] {
    let mut parameters = [0; 24];
    parameters[6..14].copy_from_slice(&IDENTITY);
    parameters[14..22].copy_from_slice(&PMM);
    parameters[22..].copy_from_slice(&[0x12, 0xfc]);
    parameters
}

/// TgCommRF reply carrying `packet` in receive `mode`, with activation bits.
fn felica_frame(mode: u8, activation: u8, packet: &[u8]) -> Vec<u8> {
    let mut reply = vec![mode, 0, activation, 0, 0, 0, 0];
    reply.extend_from_slice(packet);
    reply
}

fn attribute_read() -> Vec<u8> {
    let mut packet = vec![16, 6];
    packet.extend(IDENTITY);
    packet.extend([1, 0x0b, 0, 1, 0x80, 0]);
    packet
}

fn attribute_reply() -> Vec<u8> {
    let mut packet = vec![29, 7];
    packet.extend(IDENTITY);
    packet.extend([0, 0, 1]);
    packet.extend([0x10, 12, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0x20]);
    packet
}

#[test]
fn a_type3_target_configured_for_424_serves_an_initiator_at_212() -> Result<(), Box<dyn StdError>> {
    let parameters = felica_parameters();
    let mut steps = initialization();
    steps.extend(configure(0x0d));
    steps.extend([
        exchange(
            &parameters,
            1,
            &[],
            &felica_frame(0x0c, 3, &attribute_read()),
        ),
        exchange(
            &parameters,
            0,
            &attribute_reply(),
            &[0x0c, 0, 0, 0, 0, 0, 0],
        ),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut target = Type3Target::listen(
        &mut reader,
        PollingResponder::Reader(BitRate::Kbps424),
        Idm::new(IDENTITY),
        PMM,
        &MESSAGE,
    )?;
    assert_eq!(target.serve_next(wait()?)?, Type3Event::Read);
    target.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_felica_target_keeps_a_frame_received_at_the_initiators_rate_with_its_response()
-> Result<(), Box<dyn StdError>> {
    let parameters = felica_parameters();
    let mut steps = initialization();
    steps.extend(configure(0x0d));
    steps.extend([
        exchange(
            &parameters,
            1,
            &[],
            &felica_frame(0x0c, 3, &attribute_read()),
        ),
        // The response arms reception, which captures the next 212 kbps packet.
        exchange_receiving(
            &parameters,
            0,
            WAIT_MS,
            &attribute_reply(),
            &felica_frame(0x0c, 0, &attribute_read()),
        ),
        exchange(
            &parameters,
            0,
            &attribute_reply(),
            &[0x0c, 0, 0, 0, 0, 0, 0],
        ),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut target = reader.listen_felica(
        PollingResponder::Reader(BitRate::Kbps424),
        Idm::new(IDENTITY),
        PMM,
        0x12fc,
    )?;
    let TargetEvent::Command(command) = target.receive(wait()?)? else {
        return Err("expected a command".into());
    };
    assert_eq!(command.data(), attribute_read());
    command.respond_and_wait(&attribute_reply(), wait()?)?;
    let TargetEvent::Command(command) = target.receive(wait()?)? else {
        return Err("expected a command".into());
    };
    assert_eq!(command.data(), attribute_read());
    command.respond(&attribute_reply())?;
    target.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_host_activated_type3_target_advertises_424_and_follows_the_initiator()
-> Result<(), Box<dyn StdError>> {
    let parameters = felica_parameters();
    let polling_reply = |data: &[u8]| {
        let mut packet = vec![if data.is_empty() { 18 } else { 20 }, 1];
        packet.extend(IDENTITY);
        packet.extend(PMM);
        packet.extend_from_slice(data);
        packet
    };
    let sent = |mode: u8| [mode, 0, 0, 0, 0, 0, 0];
    let mut steps = initialization();
    steps.extend(configure(0x0c));
    steps.extend([
        // Another system's Polling stays unanswered; FF matches any byte.
        exchange(
            &parameters,
            0,
            &[],
            &felica_frame(0x0c, 0, &[6, 0, 0x88, 0xb4, 0, 0]),
        ),
        exchange(
            &parameters,
            0,
            &[],
            &felica_frame(0x0c, 0, &[6, 0, 0x12, 0xff, 1, 0]),
        ),
        exchange(&parameters, 0, &polling_reply(&[0x12, 0xfc]), &sent(0x0c)),
        exchange(
            &parameters,
            0,
            &[],
            &felica_frame(0x0c, 0, &[6, 0, 0xff, 0xff, 2, 0]),
        ),
        exchange(&parameters, 0, &polling_reply(&[0, 0x83]), &sent(0x0c)),
    ]);
    steps.extend(configure(0x0d));
    steps.extend([
        exchange(
            &parameters,
            0,
            &[],
            &felica_frame(0x0d, 0, &attribute_read()),
        ),
        exchange(&parameters, 0, &attribute_reply(), &sent(0x0d)),
        exchange(&parameters, 0, &[], &[0x0d, 0, 0, 0, 4, 0, 0]),
    ]);
    // After the field loss the target receives at 212 kbps again.
    steps.extend(configure(0x0c));
    steps.extend([
        exchange(
            &parameters,
            0,
            &[],
            &felica_frame(0x0c, 0, &[6, 0, 0x12, 0xfc, 0, 0]),
        ),
        exchange(&parameters, 0, &polling_reply(&[]), &sent(0x0c)),
        exchange(&parameters, 0, &[], &[0x0c, 0, 0, 0x80, 0, 0, 0]),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut target = Type3Target::listen(
        &mut reader,
        PollingResponder::Host,
        Idm::new(IDENTITY),
        PMM,
        &MESSAGE,
    )?;
    assert_eq!(target.serve_next(wait()?)?, Type3Event::Read);
    assert_eq!(target.serve_next(wait()?)?, Type3Event::FieldOff);
    assert_eq!(target.serve_next(wait()?)?, Type3Event::Silence);
    target.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_failed_send_on_older_firmware_revokes_the_target() -> Result<(), Box<dyn StdError>> {
    let mut parameters = [0; 24];
    parameters[..6].copy_from_slice(&[4, 0, 1, 2, 3, 0]);
    let initialization = || initialization_with(&[0, 0, 0, 0, 0, 0, 0, 3], 1, [5, 0], 0x0619);
    let mut steps = initialization();
    steps.extend(configure(0x0b));
    steps.extend([
        exchange(&parameters, 1, &[], &[0x0b, 0, 0, 0, 0, 0, 0x30, 3]),
        exchange(&parameters, 0, &[0xaa], &[0x0b, 0, 0, 8, 0, 0]),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut target = reader.listen_type_a([1, 2, 3], wait()?)?;
    let TargetEvent::Command(request) = target.receive(wait()?)? else {
        return Err("expected a command".into());
    };
    assert_eq!(request.data(), [0x30, 3]);
    assert!(matches!(
        request.respond(&[0xaa]),
        Err(Error::RfStatus(0x800))
    ));
    assert!(matches!(
        target.receive(wait()?),
        Err(Error::NotInitialized)
    ));
    target.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type3_validates_ndef_before_configuring_the_reader() {
    let (script, journal) = Script::new(vec![]);
    let mut reader = Reader::new(script);
    assert!(matches!(
        Type3Target::listen(
            &mut reader,
            PollingResponder::Reader(BitRate::Kbps212),
            Idm::new(IDENTITY),
            PMM,
            &[0xd0]
        ),
        Err(Type3EmulationError::Message(_))
    ));
    assert!(journal.borrow().commands.is_empty());
}

// A 20-byte short record of TNF Unknown that spans two data blocks.
const UPDATE: [u8; 20] = *b"\xd5\x00\x11written by the PC";

/// Attribute block of a writable mapping, checksum included.
fn writable_attribute(flag: u8, length: u8, blocks: u8) -> [u8; 16] {
    let mut block = [
        0x10, 12, 12, 0, blocks, 0, 0, 0, 0, flag, 1, 0, 0, length, 0, 0,
    ];
    let sum: u16 = block[..14].iter().map(|&byte| u16::from(byte)).sum();
    block[14..].copy_from_slice(&sum.to_be_bytes());
    block
}

/// A Read (`06`) or Write (`08`) Without Encryption packet for one service.
fn block_request(code: u8, service: u16, count: u8, elements: &[u8], data: &[[u8; 16]]) -> Vec<u8> {
    let mut packet = vec![0, code];
    packet.extend(IDENTITY);
    packet.push(1);
    packet.extend(service.to_le_bytes());
    packet.push(count);
    packet.extend_from_slice(elements);
    packet.extend(data.iter().flatten());
    packet[0] = packet.len() as u8;
    packet
}

fn read_reply(blocks: &[[u8; 16]]) -> Vec<u8> {
    let mut packet = vec![13 + 16 * blocks.len() as u8, 7];
    packet.extend(IDENTITY);
    packet.extend([0, 0, blocks.len() as u8]);
    packet.extend(blocks.iter().flatten());
    packet
}

fn split_update() -> [[u8; 16]; 2] {
    let mut blocks = [[0; 16]; 2];
    blocks[0].copy_from_slice(&UPDATE[..16]);
    blocks[1][..4].copy_from_slice(&UPDATE[16..]);
    blocks
}

/// Reception of `packet`. Activation bits 3 mark the first packet after the
/// reader answered Polling.
fn received(activation: u8, packet: &[u8]) -> Step {
    exchange(
        &felica_parameters(),
        activation >> 1,
        &[],
        &felica_frame(0x0c, activation, packet),
    )
}

fn sent(packet: &[u8]) -> Step {
    exchange(&felica_parameters(), 0, packet, &[0x0c, 0, 0, 0, 0, 0, 0])
}

fn two_blocks() -> Result<NonZeroU16, Box<dyn StdError>> {
    NonZeroU16::new(2).ok_or_else(|| "two blocks".into())
}

#[test]
fn a_writable_type3_target_stages_an_update_and_publishes_it() -> Result<(), Box<dyn StdError>> {
    let [first, second] = split_update();
    let mut steps = initialization();
    steps.extend(configure(0x0c));
    steps.extend([
        received(
            3,
            &block_request(8, 9, 1, &[0x80, 0], &[writable_attribute(0x0f, 3, 2)]),
        ),
        sent(&status_reply(9, 0, 0)),
        received(
            0,
            &block_request(8, 9, 2, &[0x80, 1, 0x80, 2], &[first, second]),
        ),
        sent(&status_reply(9, 0, 0)),
        received(0, &block_request(6, 9, 1, &[0x80, 0], &[])),
        sent(&read_reply(&[writable_attribute(0x0f, 3, 2)])),
        received(
            0,
            &block_request(8, 9, 1, &[0x80, 0], &[writable_attribute(0, 20, 2)]),
        ),
        sent(&status_reply(9, 0, 0)),
        received(0, &block_request(6, 0x0b, 2, &[0x80, 1, 0, 2, 0], &[])),
        sent(&read_reply(&[first, second])),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut memory = Type3NdefMemory::new(two_blocks()?, &MESSAGE)?;
    let mut target = Type3Target::listen_writable(
        &mut reader,
        PollingResponder::Reader(BitRate::Kbps212),
        Idm::new(IDENTITY),
        PMM,
        &mut memory,
    )?;
    assert_eq!(
        target.serve_next(wait()?)?,
        Type3Event::NdefChanged(Type3NdefChange::UpdateStarted)
    );
    assert_eq!(target.message(), None);
    assert_eq!(target.serve_next(wait()?)?, Type3Event::Written);
    assert_eq!(target.serve_next(wait()?)?, Type3Event::Read);
    assert_eq!(
        target.serve_next(wait()?)?,
        Type3Event::NdefChanged(Type3NdefChange::Published { length: 20 })
    );
    assert_eq!(target.message(), Some(&UPDATE[..]));
    assert_eq!(target.serve_next(wait()?)?, Type3Event::Read);
    target.finish()?;
    assert_eq!(memory.message(), Some(&UPDATE[..]));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_writable_type3_target_refuses_writes_that_would_break_the_mapping()
-> Result<(), Box<dyn StdError>> {
    let rejected = |position: u8, code: u8| Type3Event::Rejected {
        flag1: position,
        flag2: code,
    };
    let mut original = [0; 16];
    original[..3].copy_from_slice(&MESSAGE);
    let mut other_idm = block_request(8, 9, 1, &[0x80, 1], &[[0; 16]]);
    other_idm[9] ^= 1;
    let mut steps = initialization();
    steps.extend(configure(0x0c));
    steps.extend([
        // A data block outside an update.
        received(3, &block_request(8, 9, 1, &[0x80, 1], &[[0; 16]])),
        sent(&status_reply(9, 1, 0xa5)),
        // An attribute that changes the advertised block count.
        received(
            0,
            &block_request(8, 9, 1, &[0x80, 0], &[writable_attribute(0, 3, 3)]),
        ),
        sent(&status_reply(9, 1, 0xa5)),
        // Publishing bytes that are not an NDEF message undoes the command.
        received(
            0,
            &block_request(
                8,
                9,
                3,
                &[0x80, 0, 0x80, 1, 0x80, 0],
                &[
                    writable_attribute(0x0f, 3, 2),
                    [0xff; 16],
                    writable_attribute(0, 16, 2),
                ],
            ),
        ),
        sent(&status_reply(9, 3, 0xa5)),
        received(0, &block_request(6, 0x0b, 2, &[0x80, 0, 0x80, 1], &[])),
        sent(&read_reply(&[writable_attribute(0, 3, 2), original])),
        // The read-only service, the block count and the block number.
        received(0, &block_request(8, 0x0b, 1, &[0x80, 1], &[[0; 16]])),
        sent(&status_reply(9, 1, 0xa6)),
        received(0, &block_request(8, 9, 13, &[], &[])),
        sent(&status_reply(9, 0xff, 0xa2)),
        received(0, &block_request(8, 9, 1, &[0x80, 3], &[[0; 16]])),
        sent(&status_reply(9, 1, 0xa8)),
        received(0, &other_idm),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut memory = Type3NdefMemory::new(two_blocks()?, &MESSAGE)?;
    let mut target = Type3Target::listen_writable(
        &mut reader,
        PollingResponder::Reader(BitRate::Kbps212),
        Idm::new(IDENTITY),
        PMM,
        &mut memory,
    )?;
    assert_eq!(target.serve_next(wait()?)?, rejected(1, 0xa5));
    assert_eq!(target.serve_next(wait()?)?, rejected(1, 0xa5));
    assert_eq!(target.serve_next(wait()?)?, rejected(3, 0xa5));
    assert_eq!(target.message(), Some(&MESSAGE[..]));
    assert_eq!(target.serve_next(wait()?)?, Type3Event::Read);
    assert_eq!(target.serve_next(wait()?)?, rejected(1, 0xa6));
    assert_eq!(target.serve_next(wait()?)?, rejected(0xff, 0xa2));
    assert_eq!(target.serve_next(wait()?)?, rejected(1, 0xa8));
    assert_eq!(target.serve_next(wait()?)?, Type3Event::Ignored);
    target.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_read_only_type3_target_has_no_writable_service() -> Result<(), Box<dyn StdError>> {
    let mut steps = initialization();
    steps.extend(configure(0x0c));
    steps.extend([
        received(3, &block_request(8, 9, 1, &[0x80, 1], &[[0; 16]])),
        sent(&status_reply(9, 1, 0xa6)),
        received(0, &block_request(6, 9, 1, &[0x80, 1], &[])),
        sent(&status_reply(7, 1, 0xa6)),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut target = Type3Target::listen(
        &mut reader,
        PollingResponder::Reader(BitRate::Kbps212),
        Idm::new(IDENTITY),
        PMM,
        &MESSAGE,
    )?;
    let rejected = Type3Event::Rejected {
        flag1: 1,
        flag2: 0xa6,
    };
    assert_eq!(target.serve_next(wait()?)?, rejected);
    assert_eq!(target.serve_next(wait()?)?, rejected);
    target.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_failed_type3_response_reports_the_published_change() -> Result<(), Box<dyn StdError>> {
    let mut steps = initialization();
    steps.extend(configure(0x0c));
    steps.extend([
        received(
            3,
            &block_request(8, 9, 1, &[0x80, 0], &[writable_attribute(0x0f, 3, 2)]),
        ),
        sent(&status_reply(9, 0, 0)),
        received(
            0,
            &block_request(8, 9, 1, &[0x80, 0], &[writable_attribute(0, 3, 2)]),
        ),
        exchange(
            &felica_parameters(),
            0,
            &status_reply(9, 0, 0),
            &[0x0c, 0, 0, 1, 0, 0, 0],
        ),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut memory = Type3NdefMemory::new(two_blocks()?, &MESSAGE)?;
    let mut target = Type3Target::listen_writable(
        &mut reader,
        PollingResponder::Reader(BitRate::Kbps212),
        Idm::new(IDENTITY),
        PMM,
        &mut memory,
    )?;
    assert_eq!(
        target.serve_next(wait()?)?,
        Type3Event::NdefChanged(Type3NdefChange::UpdateStarted)
    );
    assert!(matches!(
        target.serve_next(wait()?),
        Err(Type3EmulationError::NdefResponse {
            change: Type3NdefChange::Published { length: 3 },
            cause: Error::RfStatus(1),
        })
    ));
    assert_eq!(target.message(), Some(&MESSAGE[..]));
    target.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_type3_memory_validates_its_initial_message() -> Result<(), Box<dyn StdError>> {
    let one = NonZeroU16::new(1).ok_or("one block")?;
    assert!(matches!(
        Type3NdefMemory::new(one, &[0xd0]),
        Err(Type3NdefMemoryError::Message(_))
    ));
    assert!(matches!(
        Type3NdefMemory::new(one, &UPDATE),
        Err(Type3NdefMemoryError::MessageLength {
            length: 20,
            capacity: 16
        })
    ));
    assert_eq!(Type3NdefMemory::new(one, &[])?.message(), Some(&[][..]));
    Ok(())
}

fn type4_exchange(mdaa: u8, send: &[u8], receive_ms: u16, status: u32, frame: &[u8]) -> Step {
    let mut args = vec![0, 0, 0xff, 0xff, mdaa, 4, 0, 1, 2, 3, 0x20];
    args.extend([0; 20]);
    args.extend(receive_ms.to_le_bytes());
    args.extend_from_slice(send);
    let mut reply = vec![0x0b, 0, if mdaa != 0 && status == 0 { 3 } else { 0 }];
    reply.extend(status.to_le_bytes());
    reply.extend_from_slice(frame);
    command(0x48, &args, &reply)
}

#[test]
fn type4a_reads_ndef_over_chained_blocks_and_deselects() -> Result<(), Box<dyn StdError>> {
    use Type4Event::{Activated, Block, Deselected, Exchange, FieldOff, Ignored};
    let initial = type4_exchange(1, &[], WAIT_MS, 0x400, &[]);
    let receive_rats = type4_exchange(1, &[], WAIT_MS, 0, &[0xe0, 0]);
    let transfer = |send: &[u8], receive: &[u8]| type4_exchange(0, send, WAIT_MS, 0, receive);
    let first = [0x12, 0, 0xa4, 4, 0, 7, 0xd2, 0x76];
    let middle = [0x13, 0, 0, 0x85];
    let last = [0x02, 1, 1, 0];
    let cc_part = [0x12, 0, 15, 0x20, 0, 0xff, 0, 0xff, 4, 6, 0xe1, 4, 0, 5];
    let mut steps = initialization();
    steps.extend(configure(0x0b));
    steps.extend([
        initial,
        receive_rats,
        transfer(&[4, 0x68, 0x80, 0], &first),
        transfer(&[0xa2], &first),
        transfer(&[0xa2], &[0xa3]),
        transfer(&[], &middle),
        transfer(&[0xa3], &last),
        transfer(&[0x02, 0x90, 0], &[0x03, 0, 0xa4, 0, 0x0c, 2, 0xe1, 3]),
        transfer(&[0x03, 0x90, 0], &[0x02, 0, 0xb0, 0, 0, 15]),
        transfer(&cc_part, &[0xa2]),
        transfer(&cc_part, &[0xa3]),
        transfer(
            &[0x03, 0, 0xff, 0x90, 0],
            &[0x02, 0, 0xa4, 0, 0x0c, 2, 0xe1, 4],
        ),
        transfer(&[0x02, 0x90, 0], &[0x03, 0, 0xb0, 0, 0, 2]),
        transfer(&[0x03, 0, 3, 0x90, 0], &[0x02, 0, 0xb0, 0, 2, 3]),
        transfer(&[0x02, 0xd0, 0, 0, 0x90, 0], &[0x03, 0, 0xd6, 0, 0, 1, 42]),
        transfer(&[0x03, 0x69, 0x82], &[0x02, 0, 0xb0, 0, 5, 1]),
        transfer(&[0x02, 0x6b, 0], &[0xc2]),
        type4_exchange(0, &[0xc2], 0, 0, &[]),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut target = Type4Target::listen(&mut reader, [1, 2, 3], &MESSAGE)?;
    let wait = wait()?;
    for expected in [
        FieldOff, Activated, Block, Block, Ignored, Block, Exchange, Exchange, Block, Block,
        Exchange, Exchange, Exchange, Exchange, Exchange, Exchange, Deselected,
    ] {
        assert_eq!(target.serve_next(wait)?, expected);
    }
    assert!(matches!(
        target.serve_next(wait),
        Err(Type4EmulationError::Inactive)
    ));
    target.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type4a_field_loss_clears_selection_and_transmit_failure_revokes() -> Result<(), Box<dyn StdError>>
{
    let mut steps = initialization();
    steps.extend(configure(0x0b));
    steps.extend([
        type4_exchange(1, &[], WAIT_MS, 0x80, &[]),
        type4_exchange(1, &[], WAIT_MS, 0, &[0xe0, 0x50]),
        type4_exchange(0, &[4, 0x68, 0x80, 0], WAIT_MS, 0x80, &[]),
        type4_exchange(
            0,
            &[],
            WAIT_MS,
            0,
            &[2, 0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1, 0],
        ),
        type4_exchange(0, &[2, 0x90, 0], WAIT_MS, 0x400, &[]),
        type4_exchange(1, &[], WAIT_MS, 0, &[0xe0, 0x50]),
        type4_exchange(
            0,
            &[4, 0x68, 0x80, 0],
            WAIT_MS,
            0,
            &[2, 0, 0xa4, 0, 0x0c, 2, 0xe1, 4],
        ),
        type4_exchange(0, &[2, 0x6a, 0x82], WAIT_MS, 0x880, &[]),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut target = Type4Target::listen(&mut reader, [1, 2, 3], &[])?;
    let wait = wait()?;
    assert_eq!(target.serve_next(wait)?, Type4Event::Silence);
    assert_eq!(target.serve_next(wait)?, Type4Event::Activated);
    assert!(matches!(
        target.serve_next(wait),
        Err(Type4EmulationError::ResponseFieldOff)
    ));
    assert_eq!(target.serve_next(wait)?, Type4Event::Activated);
    assert!(matches!(
        target.serve_next(wait),
        Err(Type4EmulationError::Reader(Error::RfStatus(0x880)))
    ));
    assert!(matches!(
        target.serve_next(wait),
        Err(Type4EmulationError::Inactive)
    ));
    target.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

const TYPE4_ATS: [u8; 4] = [4, 0x68, 0x80, 0];
const SELECT_TYPE4_APP: [u8; 14] = [2, 0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1, 0];
const SELECT_TYPE4_NDEF_EVEN: [u8; 8] = [2, 0, 0xa4, 0, 0x0c, 2, 0xe1, 4];
const SELECT_TYPE4_NDEF_ODD: [u8; 8] = [3, 0, 0xa4, 0, 0x0c, 2, 0xe1, 4];

#[test]
fn type4a_writes_and_reads_ndef_with_chaining_and_replay() -> Result<(), Box<dyn StdError>> {
    use Type4Event::{Activated, Block, Deselected, Exchange, NdefChanged};
    use Type4NdefChange::{Cleared, Published};
    let message = [0xd5, 0, 5, 1, 2, 3, 4, 5];
    let transfer = |send: &[u8], receive: &[u8]| type4_exchange(0, send, WAIT_MS, 0, receive);
    let begin = [3, 0, 0xd6, 0, 0, 4, 0, 0, 0xd5, 0];
    let publish = [3, 0, 0xd6, 0, 0, 2, 0, 8];
    let mut steps = initialization();
    steps.extend(configure(0x0b));
    steps.extend([
        type4_exchange(1, &[], WAIT_MS, 0, &[0xe0, 0x50]),
        transfer(&TYPE4_ATS, &SELECT_TYPE4_APP),
        transfer(&[2, 0x90, 0], &[3, 0, 0xa4, 0, 0x0c, 2, 0xe1, 3]),
        transfer(&[3, 0x90, 0], &[2, 0, 0xb0, 0, 0, 15]),
        transfer(
            &[
                2, 0, 15, 0x20, 0, 255, 0, 255, 4, 6, 0xe1, 4, 0, 18, 0, 0, 0x90, 0,
            ],
            &[3, 0, 0xd6, 0, 0, 2, 0, 0],
        ),
        transfer(&[3, 0x69, 0x82], &SELECT_TYPE4_NDEF_EVEN),
        transfer(&[2, 0x90, 0], &begin),
        transfer(&[3, 0x90, 0], &begin),
        transfer(&[3, 0x90, 0], &[0x12, 0, 0xd6, 0, 4, 6, 5, 1]),
        transfer(&[0xa2], &[3, 2, 3, 4, 5]),
        transfer(&[3, 0x90, 0], &[2, 0, 0xb0, 0, 0, 10]),
        transfer(&[2, 0, 0, 0xd5, 0, 5, 1, 2, 3, 4, 5, 0x90, 0], &publish),
        transfer(&[3, 0x90, 0], &publish),
        transfer(&[3, 0x90, 0], &[2, 0, 0xb0, 0, 0, 10]),
        transfer(
            &[2, 0, 8, 0xd5, 0, 5, 1, 2, 3, 4, 5, 0x90, 0],
            &[3, 0, 0xd6, 0, 0, 5, 0, 3, 0xd0, 0, 0],
        ),
        transfer(&[3, 0x90, 0], &[0xc2]),
        type4_exchange(0, &[0xc2], 0, 0, &[]),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut file = Type4NdefFile::new(16, &[])?;
    let mut target = Type4Target::listen_writable(&mut reader, [1, 2, 3], &mut file)?;
    let wait = wait()?;
    for expected in [
        Activated,
        Exchange,
        Exchange,
        Exchange,
        Exchange,
        Exchange,
        NdefChanged(Cleared),
        Block,
        Block,
        Exchange,
        Exchange,
        NdefChanged(Published { length: 8 }),
        Block,
        Exchange,
        NdefChanged(Published { length: 3 }),
        Deselected,
    ] {
        assert_eq!(target.serve_next(wait)?, expected);
        match expected {
            NdefChanged(Cleared) => assert!(target.message().is_empty()),
            NdefChanged(Published { length: 8 }) => assert_eq!(target.message(), message),
            _ => {}
        }
    }
    target.finish()?;
    assert_eq!(file.message(), MESSAGE);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type4a_discards_staged_bytes_and_retains_publication_after_field_loss()
-> Result<(), Box<dyn StdError>> {
    use Type4Event::{Activated, Exchange, FieldOff, NdefChanged};
    use Type4NdefChange::{Cleared, Published};
    let transfer = |send: &[u8], receive: &[u8]| type4_exchange(0, send, WAIT_MS, 0, receive);
    let rats = || type4_exchange(1, &[], WAIT_MS, 0, &[0xe0, 0x50]);
    let read = [2, 0, 0xb0, 0, 0, 6];
    let mut steps = initialization();
    steps.extend(configure(0x0b));
    steps.extend([
        rats(),
        transfer(&TYPE4_ATS, &SELECT_TYPE4_APP),
        transfer(&[2, 0x90, 0], &SELECT_TYPE4_NDEF_ODD),
        transfer(
            &[3, 0x90, 0],
            &[2, 0, 0xd6, 0, 0, 6, 0, 0, 0xd5, 0, 1, 0x77],
        ),
        type4_exchange(0, &[2, 0x90, 0], WAIT_MS, 0x80, &[]),
        type4_exchange(0, &[], WAIT_MS, 0x400, &[]),
        rats(),
        transfer(&TYPE4_ATS, &SELECT_TYPE4_APP),
        transfer(&[2, 0x90, 0], &SELECT_TYPE4_NDEF_ODD),
        transfer(&[3, 0x90, 0], &read),
        transfer(
            &[2, 0, 0, 0, 0, 0, 0, 0x90, 0],
            &[3, 0, 0xd6, 0, 0, 2, 0, 4],
        ),
        transfer(
            &[3, 0x69, 0x85],
            &[2, 0, 0xd6, 0, 0, 6, 0, 4, 0xd5, 0, 1, 0x99],
        ),
        type4_exchange(0, &[2, 0x90, 0], WAIT_MS, 0x400, &[]),
        rats(),
        transfer(&TYPE4_ATS, &SELECT_TYPE4_APP),
        transfer(&[2, 0x90, 0], &SELECT_TYPE4_NDEF_ODD),
        transfer(&[3, 0x90, 0], &read),
        transfer(
            &[2, 0, 4, 0xd5, 0, 1, 0x99, 0x90, 0],
            &[3, 0, 0xd6, 0, 0, 2, 0, 0],
        ),
        type4_exchange(0, &[3, 0x90, 0], WAIT_MS, 0x880, &[]),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut file = Type4NdefFile::new(8, &MESSAGE)?;
    let mut target = Type4Target::listen_writable(&mut reader, [1, 2, 3], &mut file)?;
    let wait = wait()?;
    for expected in [
        Activated,
        Exchange,
        Exchange,
        NdefChanged(Cleared),
        FieldOff,
        Activated,
        Exchange,
        Exchange,
        Exchange,
        Exchange,
    ] {
        assert_eq!(target.serve_next(wait)?, expected);
    }
    assert!(target.message().is_empty());
    assert!(matches!(
        target.serve_next(wait),
        Err(Type4EmulationError::NdefResponse {
            change: Published { length: 4 },
            cause: Error::TargetFieldOff,
        })
    ));
    for expected in [Activated, Exchange, Exchange, Exchange] {
        assert_eq!(target.serve_next(wait)?, expected);
    }
    assert_eq!(target.message(), [0xd5, 0, 1, 0x99]);
    assert!(matches!(
        target.serve_next(wait),
        Err(Type4EmulationError::NdefResponse {
            change: Cleared,
            cause: Error::RfStatus(0x880),
        })
    ));
    assert!(matches!(
        target.serve_next(wait),
        Err(Type4EmulationError::Inactive)
    ));
    target.finish()?;
    assert!(file.message().is_empty());
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type4a_validates_read_only_ndef_before_configuring_the_reader() {
    let (script, journal) = Script::new(Vec::new());
    let mut reader = Reader::new(script);
    let long = vec![0; MAX_TYPE4_EMULATED_NDEF_BYTES + 1];
    assert!(matches!(
        Type4Target::listen(&mut reader, [1, 2, 3], &long),
        Err(Type4EmulationError::MessageLength(_))
    ));
    assert!(matches!(
        Type4Target::listen(&mut reader, [1, 2, 3], &[0xd0]),
        Err(Type4EmulationError::Message(_))
    ));
    assert!(journal.borrow().commands.is_empty());
}
