//! Reader-level wire scenarios with independent response construction.
//!
//! These model command/response contracts, not physical device operation.

use felica_packet::{Idm, PacketError, PollRequest, Selection};
use port100::{
    reader::{BitRate, Error, Reader, ReaderInfo, ResponseWait},
    transport::{Failure, Link, Progress},
};
use reader_script::port100::{
    Answer, FELICA_212, FELICA_PROTOCOL, FIRMWARE, IDENTITY, Journal, PARAMETERS, PD_DATA, Script,
    Step, WAIT_UNITS, command, felica_212_configuration, in_comm_rf, initialization,
    initialization_with, polling_reply, wait,
};
use std::{cell::RefCell, error::Error as _, io, rc::Rc, time::Duration};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const WILDCARD_POLLING: [u8; 6] = [6, 0, 0xff, 0xff, 0, 0];
const RECEIVE_TIMEOUT: u32 = 0x80;

fn wildcard() -> Result<PollRequest, Box<dyn std::error::Error>> {
    Ok(PollRequest::new(0xffff, 0, 0)?)
}

fn card_wait() -> Result<ResponseWait, Box<dyn std::error::Error>> {
    Ok(wait().ok_or("wait")?)
}

/// An initialized reader and the journal of its script.
type Session = (Reader<Script>, Rc<RefCell<Journal>>);

fn initialized(extra: Vec<Step>) -> Result<Session, Box<dyn std::error::Error>> {
    let mut steps = initialization();
    steps.extend(extra);
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    Ok((reader, journal))
}

fn polling(status: u32, received: &[u8]) -> Step {
    in_comm_rf(WAIT_UNITS, &WILDCARD_POLLING, status, received)
}

fn read_request() -> Vec<u8> {
    let mut packet = vec![16, 6];
    packet.extend_from_slice(&IDENTITY);
    packet.extend_from_slice(&[1, 0x0b, 0, 1, 0x80, 0]);
    packet
}

fn read_reply() -> Vec<u8> {
    let mut packet = vec![29, 7];
    packet.extend_from_slice(&IDENTITY);
    packet.extend_from_slice(&[0, 0, 1]);
    packet.extend_from_slice(&[0x5a; 16]);
    packet
}

fn steps(parts: impl IntoIterator<Item = Vec<Step>>) -> Vec<Step> {
    parts.into_iter().flatten().collect()
}

#[test]
fn initialization_cancels_selects_the_command_type_and_switches_the_field_off() -> TestResult {
    let (transport, journal) = Script::new(initialization());
    let mut reader = Reader::new(transport);
    assert_eq!(
        reader.initialize()?,
        ReaderInfo {
            command_type: 1,
            firmware: FIRMWARE,
            firmware_option_60: 0,
            pd_data: PD_DATA,
        }
    );
    let journal = journal.borrow();
    assert_eq!(journal.remaining, 0);
    assert_eq!(journal.cancels, 1);
    assert_eq!(journal.recoveries, 2);
    Ok(())
}

#[test]
fn selects_the_highest_reported_command_type_up_to_two() -> TestResult {
    for (bitmap, selected) in [(0x07, 2), (0x00, 0), (0x20, 0), (0x24, 2)] {
        let types = [0, 0, 0, 0, 0, 0, 0, bitmap];
        let (transport, journal) =
            Script::new(initialization_with(&types, selected, [0, 0], FIRMWARE));
        let mut reader = Reader::new(transport);
        assert_eq!(reader.initialize()?.command_type, selected);
        assert_eq!(journal.borrow().remaining, 0);
    }
    Ok(())
}

#[test]
fn a_rejected_command_type_leaves_the_reader_uninitialized() -> TestResult {
    let steps = vec![
        command(0x28, &[], &[0, 0, 0, 0, 0, 0, 0, 0x03]),
        command(0x2a, &[1], &[1]),
    ];
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    assert!(matches!(
        reader.initialize(),
        Err(Error::CommandStatus {
            command: 0x2a,
            status: 1
        })
    ));
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?),
        Err(Error::NotInitialized)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn accepts_normal_response_frames() -> TestResult {
    let mut steps = initialization();
    steps[1].answer = Answer::NormalData(vec![0]);
    let (transport, journal) = Script::new(steps);
    Reader::new(transport).initialize()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn polls_and_exchanges_packets_at_the_polling_wait() -> TestResult {
    let (mut reader, journal) = initialized(steps([
        felica_212_configuration(),
        vec![
            polling(0, &polling_reply()),
            in_comm_rf(WAIT_UNITS, &read_request(), 0, &read_reply()),
            polling(0, &polling_reply()),
        ],
    ]))?;
    let mut card = reader
        .poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?)?
        .ok_or("card absent")?;
    assert_eq!(card.poll_response().idm, Idm::new(IDENTITY));
    assert_eq!(card.poll_response().pmm, PARAMETERS);
    assert_eq!(card.poll_request(), wildcard()?);
    assert_eq!(card.exchange_packet(&read_request())?, read_reply());
    // Settings in effect are not sent again.
    reader
        .poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?)?
        .ok_or("card absent")?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn older_firmware_receives_its_protocol_settings() -> TestResult {
    let older = [
        0x00, 0x18, 0x01, 0x01, 0x02, 0x01, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07,
        0x08, 0x08, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x0e, 0x04,
        0x0f, 0x00, 0x10, 0x00, 0x11, 0x00,
    ];
    let types = [0, 0, 0, 0, 0, 0, 0, 0x03];
    let (transport, journal) = Script::new(steps([
        initialization_with(&types, 1, [5, 0], 0x0200),
        vec![
            command(0x00, &FELICA_212, &[0]),
            command(0x02, &older, &[0]),
            polling(RECEIVE_TIMEOUT, &[]),
        ],
    ]));
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    assert!(
        reader
            .poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?)?
            .is_none()
    );
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_missing_card_reply_keeps_the_reader_usable() -> TestResult {
    let (mut reader, journal) = initialized(steps([
        felica_212_configuration(),
        vec![
            polling(RECEIVE_TIMEOUT, &[]),
            polling(0, &polling_reply()),
            in_comm_rf(WAIT_UNITS, &read_request(), RECEIVE_TIMEOUT, &[]),
            in_comm_rf(WAIT_UNITS, &read_request(), 0, &read_reply()),
        ],
    ]))?;
    assert!(
        reader
            .poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?)?
            .is_none()
    );
    let mut card = reader
        .poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?)?
        .ok_or("card absent")?;
    assert!(matches!(
        card.exchange_packet(&read_request()),
        Err(Error::NoResponse)
    ));
    assert_eq!(card.exchange_packet(&read_request())?, read_reply());
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn an_rf_failure_cycles_the_field_and_resends_the_settings() -> TestResult {
    let (mut reader, journal) = initialized(steps([
        felica_212_configuration(),
        vec![polling(0x04, &[]), command(0x06, &[0], &[0])],
        felica_212_configuration(),
        vec![polling(0, &polling_reply())],
    ]))?;
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?),
        Err(Error::RfStatus(0x04))
    ));
    reader
        .poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?)?
        .ok_or("card absent")?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_declared_card_state_cycles_the_field_before_the_next_polling() -> TestResult {
    let (mut reader, journal) = initialized(steps([
        felica_212_configuration(),
        vec![polling(0, &polling_reply()), command(0x06, &[0], &[0])],
        felica_212_configuration(),
        vec![polling(0, &polling_reply())],
    ]))?;
    reader
        .poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?)?
        .ok_or("card absent")?
        .require_field_cycle();
    reader
        .poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?)?
        .ok_or("card absent")?;
    let journal = journal.borrow();
    assert_eq!(journal.remaining, 0);
    let times = &journal.command_times;
    let off = times.len() - 4;
    assert!(times[off + 1] - times[off] >= Duration::from_millis(5));
    Ok(())
}

#[test]
fn a_malformed_polling_reply_requires_a_field_cycle() -> TestResult {
    let mut malformed = polling_reply();
    malformed[1] = 3;
    let (mut reader, journal) = initialized(steps([
        felica_212_configuration(),
        vec![polling(0, &malformed), command(0x06, &[0], &[0])],
        felica_212_configuration(),
        vec![polling(0, &polling_reply())],
    ]))?;
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?),
        Err(Error::FelicaResponse(PacketError::ResponseCode {
            expected: 1,
            actual: 3
        }))
    ));
    assert!(
        reader
            .poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?)?
            .is_some()
    );
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_rate_change_resends_the_settings() -> TestResult {
    let (mut reader, journal) = initialized(steps([
        felica_212_configuration(),
        vec![
            polling(RECEIVE_TIMEOUT, &[]),
            command(0x00, &[0x01, 0x02, 0x0f, 0x02], &[0]),
            command(0x02, &FELICA_PROTOCOL, &[0]),
            polling(RECEIVE_TIMEOUT, &[]),
        ],
    ]))?;
    assert!(
        reader
            .poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?)?
            .is_none()
    );
    assert!(
        reader
            .poll_felica(BitRate::Kbps424, wildcard()?, card_wait()?)?
            .is_none()
    );
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_rejected_setting_leaves_the_field_to_be_cycled() -> TestResult {
    let (mut reader, journal) = initialized(steps([
        vec![command(0x00, &FELICA_212, &[1]), command(0x06, &[0], &[0])],
        felica_212_configuration(),
        vec![polling(RECEIVE_TIMEOUT, &[])],
    ]))?;
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?),
        Err(Error::CommandStatus {
            command: 0x00,
            status: 1
        })
    ));
    assert!(
        reader
            .poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?)?
            .is_none()
    );
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_silent_reader_requires_initialization_after_the_rf_wait_and_margin() -> TestResult {
    let (mut reader, journal) = initialized(steps([
        felica_212_configuration(),
        vec![Step {
            command: 0x04,
            args: [&WAIT_UNITS.to_le_bytes()[..], &WILDCARD_POLLING].concat(),
            answer: Answer::Silence,
        }],
        initialization(),
    ]))?;
    let Err(Error::Transaction(error)) =
        reader.poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?)
    else {
        return Err("a silent reader was accepted".into());
    };
    assert_eq!(error.progress, Progress::Acknowledged);
    assert!(matches!(error.failure, Failure::<io::Error>::Deadline));
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?),
        Err(Error::NotInitialized)
    ));
    let cancels = journal.borrow().cancels;
    reader.initialize()?;
    let journal = journal.borrow();
    assert_eq!(journal.cancels, cancels + 1);
    assert_eq!(journal.remaining, 0);
    let times = &journal.command_times;
    let polled = times.len() - 7;
    assert_eq!(
        times[polled + 1] - times[polled],
        Duration::from_millis(1100 + 10)
    );
    Ok(())
}

#[test]
fn a_reader_error_requires_initialization() -> TestResult {
    let (mut reader, journal) = initialized(steps([
        felica_212_configuration(),
        vec![Step {
            command: 0x04,
            args: [&WAIT_UNITS.to_le_bytes()[..], &WILDCARD_POLLING].concat(),
            answer: Answer::ReaderError,
        }],
    ]))?;
    let Err(Error::Transaction(error)) =
        reader.poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?)
    else {
        return Err("reader error frame accepted".into());
    };
    assert_eq!(error.progress, Progress::Acknowledged);
    assert!(matches!(error.failure, Failure::<io::Error>::ReaderError));
    assert!(error.source().is_none());
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?),
        Err(Error::NotInitialized)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn the_link_rejects_commands_without_an_ordinary_response() -> TestResult {
    let (transport, journal) = Script::new(Vec::new());
    let mut link = Link::new(transport);
    for command in [0x12, 0xff] {
        let Err(error) = link.command(command, &[], Duration::from_secs(1)) else {
            return Err(format!("command {command:02X} was sent").into());
        };
        assert_eq!(error.progress, Progress::NotSent);
        assert!(matches!(error.failure, Failure::UnsupportedCommand(c) if c == command));
    }
    assert!(journal.borrow().commands.is_empty());
    Ok(())
}

#[test]
fn rejects_malformed_packets_before_sending() -> TestResult {
    let (mut reader, journal) = initialized(steps([
        felica_212_configuration(),
        vec![polling(0, &polling_reply())],
    ]))?;
    let mut card = reader
        .poll_felica(BitRate::Kbps212, wildcard()?, card_wait()?)?
        .ok_or("card absent")?;
    assert!(matches!(
        card.exchange_packet(&[3, 0]),
        Err(Error::FelicaRequest(PacketError::Length { .. }))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}
