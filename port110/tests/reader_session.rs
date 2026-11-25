//! Reader-level wire scenarios with independent response construction.
//!
//! These model command/response contracts, not physical device operation.

use felica_packet::{PollRequest, Selection};
use port110::{
    reader::{BitRate, ConnectionParameters, Error, Reader, ReaderInfo, ResponseWait},
    transport::{Failure, Progress},
};
use reader_script::port110::{
    Answer, FELICA_212, FELICA_424, FIRMWARE, IDENTITY, Journal, PARAMETERS, PD_DATA, Script, Step,
    WAIT_UNITS, command, in_comm_rf, initialization, initialization_with, polling_reply, property,
    rate_configuration, wait,
};
use std::{cell::RefCell, rc::Rc};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const WILDCARD_POLLING: [u8; 6] = [6, 0, 0xff, 0xff, 0, 0];
const RECEIVE_TIMEOUT: u32 = 0x80;
/// Table key of the reader whose GetProperty bytes 14 and 15 are `00 13`
/// and whose PD data version is 0200.
const KEY: [u8; 16] = [
    0xf7, 0x1a, 0xd8, 0x22, 0x37, 0xeb, 0x0f, 0xb1, 0xae, 0xcf, 0xb0, 0x4b, 0x3a, 0xff, 0x07, 0x12,
];

fn wildcard() -> Result<PollRequest, Box<dyn std::error::Error>> {
    Ok(PollRequest::new(0xffff, 0, 0)?)
}

fn card_wait() -> Result<ResponseWait, Box<dyn std::error::Error>> {
    Ok(wait().ok_or("wait")?)
}

type Session = (Reader<Script>, Rc<RefCell<Journal>>);

fn initialized(extra: Vec<Step>) -> Result<Session, Box<dyn std::error::Error>> {
    let mut steps = initialization();
    steps.extend(extra);
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize(ConnectionParameters::DRIVER_DEFAULT)?;
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

fn adjusting_property() -> [u8; 32] {
    let mut property = property();
    property[14..16].copy_from_slice(&[0x00, 0x13]);
    property
}

#[test]
fn initialization_resynchronizes_selects_type_three_and_switches_the_field_off() -> TestResult {
    let (transport, journal) = Script::new(initialization());
    let mut reader = Reader::new(transport);
    assert_eq!(
        reader.initialize(ConnectionParameters::DRIVER_DEFAULT)?,
        ReaderInfo {
            firmware: FIRMWARE,
            pd_data: PD_DATA,
            property: property(),
        }
    );
    let journal = journal.borrow();
    assert_eq!(journal.remaining, 0);
    assert_eq!(journal.resyncs, 1);
    Ok(())
}

#[test]
fn sends_the_requested_connection_parameters() -> TestResult {
    let mut steps = initialization();
    steps[2] = command(0x1c, &[0x10, 0, 0x20, 0, 0x01, 0, 0x90, 0x01], &[0]);
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize(ConnectionParameters {
        interval_min: 0x10,
        interval_max: 0x20,
        slave_latency: 1,
        timeout_multiplier: 0x190,
    })?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_reader_without_command_type_three_stays_uninitialized() -> TestResult {
    let (transport, journal) = Script::new(vec![command(0x28, &[], &[0, 0, 0, 0, 0, 0, 0, 0x07])]);
    let mut reader = Reader::new(transport);
    assert!(matches!(
        reader.initialize(ConnectionParameters::DRIVER_DEFAULT),
        Err(Error::MissingCommandType { types: 0x07 })
    ));
    assert!(matches!(
        reader.poll_felica(wildcard()?, card_wait()?),
        Err(Error::NotInitialized)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_rejected_setting_leaves_the_reader_uninitialized() -> TestResult {
    let mut steps = initialization();
    steps.truncate(7);
    steps[6] = command(0x00, &FELICA_212, &[0x03]);
    let (transport, _) = Script::new(steps);
    let mut reader = Reader::new(transport);
    assert!(matches!(
        reader.initialize(ConnectionParameters::DRIVER_DEFAULT),
        Err(Error::CommandStatus {
            command: 0x00,
            status: 0x03
        })
    ));
    assert!(matches!(reader.rf_off(), Err(Error::NotInitialized)));
    Ok(())
}

#[test]
fn adjusts_the_rf_table_of_the_firmware_the_driver_adjusts() -> TestResult {
    let lists = [1, 0x10, 0x20, 0x30, 1, 0x1a, 0xc0, 0x00];
    let mut written = KEY.to_vec();
    written.extend_from_slice(&[1, 0x10, 0x20, 0x30, 1, 0x1a, 0xc0, 0x40]);
    let steps = initialization_with(
        0x0200,
        &adjusting_property(),
        vec![
            command(0x32, &KEY, &[&[0][..], &lists].concat()),
            command(0x30, &written, &[0]),
        ],
    );
    let (transport, journal) = Script::new(steps);
    Reader::new(transport).initialize(ConnectionParameters::DRIVER_DEFAULT)?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn leaves_an_adjusted_rf_table_unwritten() -> TestResult {
    let steps = initialization_with(
        0x0200,
        &adjusting_property(),
        vec![command(0x32, &KEY, &[0, 0, 1, 0x1a, 0xc0, 0x40])],
    );
    let (transport, journal) = Script::new(steps);
    Reader::new(transport).initialize(ConnectionParameters::DRIVER_DEFAULT)?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_rejected_rf_table_read_fails_initialization() -> TestResult {
    let mut steps = initialization_with(
        0x0200,
        &adjusting_property(),
        vec![command(0x32, &KEY, &[0x05])],
    );
    steps.truncate(8);
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    assert!(matches!(
        reader.initialize(ConnectionParameters::DRIVER_DEFAULT),
        Err(Error::CommandStatus {
            command: 0x32,
            status: 0x05
        })
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn polls_and_exchanges_packets_at_the_polling_wait() -> TestResult {
    let (mut reader, journal) = initialized(vec![
        polling(0, &polling_reply()),
        in_comm_rf(WAIT_UNITS, &read_request(), 0, &read_reply()),
        polling(0, &polling_reply()),
    ])?;
    let mut card = reader
        .poll_felica(wildcard()?, card_wait()?)?
        .ok_or("card absent")?;
    assert_eq!(card.rate(), BitRate::Kbps212);
    assert_eq!(card.poll_response().idm.as_bytes(), &IDENTITY);
    assert_eq!(card.poll_response().pmm, PARAMETERS);
    assert_eq!(card.exchange_packet(&read_request())?, read_reply());
    reader
        .poll_felica(wildcard()?, card_wait()?)?
        .ok_or("card absent")?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn an_absent_card_is_none_and_a_silent_card_is_no_response() -> TestResult {
    let (mut reader, journal) = initialized(vec![
        polling(RECEIVE_TIMEOUT, &[]),
        polling(0, &[]),
        polling(0, &polling_reply()),
        in_comm_rf(WAIT_UNITS, &read_request(), RECEIVE_TIMEOUT, &[]),
    ])?;
    assert!(reader.poll_felica(wildcard()?, card_wait()?)?.is_none());
    assert!(reader.poll_felica(wildcard()?, card_wait()?)?.is_none());
    let mut card = reader
        .poll_felica(wildcard()?, card_wait()?)?
        .ok_or("card absent")?;
    assert!(matches!(
        card.exchange_packet(&read_request()),
        Err(Error::NoResponse)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn the_first_of_several_polling_responses_selects_the_card() -> TestResult {
    let mut second = polling_reply();
    second[2] = 0x99;
    let (mut reader, _) = initialized(vec![polling(0, &[polling_reply(), second].concat())])?;
    let card = reader
        .poll_felica(wildcard()?, card_wait()?)?
        .ok_or("card absent")?;
    assert_eq!(card.poll_response().idm.as_bytes(), &IDENTITY);
    Ok(())
}

#[test]
fn an_rf_failure_cycles_the_field_before_the_next_polling() -> TestResult {
    let (mut reader, journal) = initialized(vec![
        polling(0x0000_0400, &[]),
        command(0x06, &[0], &[0]),
        polling(0, &polling_reply()),
    ])?;
    assert!(matches!(
        reader.poll_felica(wildcard()?, card_wait()?),
        Err(Error::RfStatus(0x400))
    ));
    reader
        .poll_felica(wildcard()?, card_wait()?)?
        .ok_or("card absent")?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_declared_field_cycle_switches_the_field_off_first() -> TestResult {
    let (mut reader, journal) = initialized(vec![
        polling(0, &polling_reply()),
        command(0x06, &[0], &[0]),
        polling(0, &polling_reply()),
    ])?;
    reader
        .poll_felica(wildcard()?, card_wait()?)?
        .ok_or("card absent")?
        .require_field_cycle();
    reader
        .poll_felica(wildcard()?, card_wait()?)?
        .ok_or("card absent")?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn request_code_two_switches_capable_cards_to_424_kbps() -> TestResult {
    let request = [6, 0, 0xff, 0xff, 2, 0];
    let mut reply = polling_reply();
    reply[0] = 20;
    reply.extend_from_slice(&[0x00, 0x83]);
    let steps = [
        vec![in_comm_rf(WAIT_UNITS, &request, 0, &reply)],
        rate_configuration(FELICA_424),
        vec![in_comm_rf(WAIT_UNITS, &read_request(), 0, &read_reply())],
        rate_configuration(FELICA_212),
        vec![polling(0, &polling_reply())],
    ]
    .into_iter()
    .flatten()
    .collect();
    let (mut reader, journal) = initialized(steps)?;
    let mut card = reader
        .poll_felica(PollRequest::new(0xffff, 2, 0)?, card_wait()?)?
        .ok_or("card absent")?;
    assert_eq!(card.rate(), BitRate::Kbps424);
    assert_eq!(card.exchange_packet(&read_request())?, read_reply());
    let card = reader
        .poll_felica(wildcard()?, card_wait()?)?
        .ok_or("card absent")?;
    assert_eq!(card.rate(), BitRate::Kbps212);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn malformed_card_replies_are_classified() -> TestResult {
    let mut partial = in_comm_rf(WAIT_UNITS, &read_request(), 0, &read_reply());
    if let Answer::Data(data) = &mut partial.answer {
        data[4] = 7;
    }
    let (mut reader, journal) = initialized(vec![
        polling(0, &polling_reply()[..17]),
        command(0x06, &[0], &[0]),
        polling(0, &polling_reply()),
        partial,
    ])?;
    assert!(matches!(
        reader.poll_felica(wildcard()?, card_wait()?),
        Err(Error::FelicaResponse(_))
    ));
    // The malformed polling response cycles the field first.
    let mut card = reader
        .poll_felica(wildcard()?, card_wait()?)?
        .ok_or("card absent")?;
    assert!(matches!(
        card.exchange_packet(&read_request()),
        Err(Error::CardReplyBitCount(7))
    ));
    assert!(matches!(
        card.exchange_packet(&[3, 0]),
        Err(Error::FelicaRequest(_))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_transport_failure_requires_initialization() -> TestResult {
    let (mut reader, journal) = initialized(vec![Step {
        command: 0x04,
        args: [&WAIT_UNITS.to_le_bytes()[..], &WILDCARD_POLLING].concat(),
        answer: Answer::Silence,
    }])?;
    let Err(Error::Transaction(error)) = reader.poll_felica(wildcard()?, card_wait()?) else {
        return Err("polling unexpectedly succeeded".into());
    };
    assert_eq!(error.progress, Progress::Acknowledged);
    assert!(matches!(error.failure, Failure::Deadline));
    assert!(matches!(
        reader.poll_felica(wildcard()?, card_wait()?),
        Err(Error::NotInitialized)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}
