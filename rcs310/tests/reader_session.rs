//! Reader-level wire scenarios with independent response construction.
//!
//! These model command/response contracts, not physical device operation.

use felica_packet::{Idm, PacketError, PollRequest, Selection};
use rcs310::{
    device::{Descriptor, Product, Variant},
    reader::{Error, MAX_PACKET_BYTES, Reader},
    transport::{Failure, Progress},
};
use reader_script::rcs310::{
    Answer, FIRMWARE, IDENTITY, Journal, PARAMETERS, Script, Step, command, polling_reply, rcs320,
    rcs320_initialization, unanswered, wait,
};
use std::{cell::RefCell, error::Error as _, io, rc::Rc, time::Duration};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const WILDCARD_POLLING: [u8; 6] = [6, 0, 0xff, 0xff, 0, 0];
const RCS310_0121: [u8; 18] = [
    0x89, 0x11, 0x25, 0xf0, 0xa0, 0x02, 0xa1, 0x00, 0xa2, 0x89, 0xa3, 0x10, 0xa4, 0x03, 0xa5, 0x89,
    0xa6, 0x10,
];

fn wildcard() -> Result<PollRequest, Box<dyn std::error::Error>> {
    Ok(PollRequest::new(0xffff, 0, 0)?)
}

fn rcs310(release: u16, subclass: u8) -> Descriptor {
    Descriptor {
        vendor_id: 0x054c,
        product_id: 0x006c,
        device_subclass: subclass,
        release,
    }
}

/// An initialized reader and the journal of its script.
type Session = (Reader<Script>, Rc<RefCell<Journal>>);

fn initialized(extra: Vec<Step>) -> Result<Session, Box<dyn std::error::Error>> {
    let mut steps = rcs320_initialization();
    steps.extend(extra);
    let (transport, journal) = Script::new(rcs320(), steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    Ok((reader, journal))
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

#[test]
fn initializes_an_rcs320_with_its_register_values() -> TestResult {
    let (transport, journal) = Script::new(rcs320(), rcs320_initialization());
    let mut reader = Reader::new(transport);
    let info = reader.initialize()?;
    assert_eq!(info.product, Product::Rcs320);
    assert_eq!(info.firmware, FIRMWARE);
    assert_eq!(info.descriptor, rcs320());
    let journal = journal.borrow();
    assert_eq!(journal.remaining, 0);
    assert_eq!(journal.recoveries, 1);
    Ok(())
}

#[test]
fn identifies_an_rcs600_on_the_rcs320_product_id() -> TestResult {
    let steps = vec![
        command(0x58, &[], &FIRMWARE),
        command(0x62, &[2, 0x80, 0x81], &[0, 0xdc, 0x08]),
        command(0x62, &[0x22, 0x80, 0xcc, 0x81, 0x88], &[0]),
        command(0x62, &[2, 0x80, 0x81], &[0, 0xcc, 0x88]),
        command(0x62, &[2, 0x82, 0x87], &[0, 0x30, 0x08]),
        command(0x62, &[&[0x29][..], &RCS310_0121].concat(), &[0]),
        command(0x5a, &[0x80], &[0]),
        command(0x54, &[], &[0]),
    ];
    let (transport, journal) = Script::new(rcs320(), steps);
    let mut reader = Reader::new(transport);
    assert_eq!(reader.initialize()?.product, Product::Rcs600);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn initializes_an_rcs310_by_release_without_5a() -> TestResult {
    let steps = vec![
        command(0x58, &[], &[0x21, 0x01]),
        command(0x62, &[1, 0x82], &[0, 0x28]),
        command(0x62, &[&[0x29][..], &RCS310_0121].concat(), &[0]),
        command(0x54, &[], &[0]),
    ];
    let (transport, journal) = Script::new(rcs310(0x0121, 0), steps);
    let mut reader = Reader::new(transport);
    assert_eq!(reader.initialize()?.product, Product::Rcs310);
    assert_eq!(journal.borrow().remaining, 0);

    let steps = vec![command(0x58, &[], &FIRMWARE), command(0x54, &[], &[0])];
    let (transport, journal) = Script::new(rcs310(0x0100, 1), steps);
    let mut reader = Reader::new(transport);
    assert_eq!(reader.initialize()?.product, Product::Rcs310Ed2);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn rejects_unknown_devices_and_variants_before_writing() -> TestResult {
    let rcs330 = Descriptor {
        vendor_id: 0x054c,
        product_id: 0x02e1,
        device_subclass: 0,
        release: 0x0130,
    };
    let (transport, journal) = Script::new(rcs330, Vec::new());
    let mut reader = Reader::new(transport);
    assert!(matches!(
        reader.initialize(),
        Err(Error::UnsupportedDevice(descriptor)) if descriptor == rcs330
    ));
    assert!(journal.borrow().commands.is_empty());
    assert_eq!(journal.borrow().recoveries, 0);

    let steps = vec![
        command(0x58, &[], &FIRMWARE),
        command(0x62, &[1, 0x82], &[0, 0x00]),
    ];
    let (transport, journal) = Script::new(rcs310(0x0121, 0), steps);
    let mut reader = Reader::new(transport);
    assert!(matches!(
        reader.initialize(),
        Err(Error::UnsupportedVariant(Variant {
            release: 0x0121,
            register_82: 0,
            register_87: None
        }))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    assert!(matches!(
        reader.poll_felica(wildcard()?, wait().ok_or("wait")?),
        Err(Error::NotInitialized)
    ));
    Ok(())
}

#[test]
fn rejects_a_register_write_that_does_not_hold() -> TestResult {
    let steps = vec![
        command(0x58, &[], &FIRMWARE),
        command(0x62, &[2, 0x80, 0x81], &[0, 0xcc, 0x88]),
        command(0x62, &[0x22, 0x80, 0xcc, 0x81, 0x88], &[0]),
        command(0x62, &[2, 0x80, 0x81], &[0, 0xcc, 0x08]),
    ];
    let (transport, _) = Script::new(rcs320(), steps);
    let mut reader = Reader::new(transport);
    assert!(matches!(reader.initialize(), Err(Error::RegisterReadback)));
    Ok(())
}

#[test]
fn polls_and_exchanges_packets_at_the_polling_wait() -> TestResult {
    let (mut reader, journal) = initialized(vec![
        command(0x5c, &WILDCARD_POLLING, &polling_reply()),
        command(0x5c, &read_request(), &read_reply()),
    ])?;
    let mut card = reader
        .poll_felica(wildcard()?, wait().ok_or("wait")?)?
        .ok_or("card absent")?;
    assert_eq!(card.poll_response().idm, Idm::new(IDENTITY));
    assert_eq!(card.poll_response().pmm, PARAMETERS);
    assert_eq!(card.poll_request(), wildcard()?);
    assert_eq!(card.exchange_packet(&read_request())?, read_reply());
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn an_unanswered_polling_selects_nothing_and_discards_a_late_reply() -> TestResult {
    let (mut reader, journal) = initialized(vec![
        Step {
            command: 0x5c,
            args: WILDCARD_POLLING.to_vec(),
            answer: Answer::UnansweredThenLate(polling_reply()),
        },
        command(0x5c, &WILDCARD_POLLING, &polling_reply()),
    ])?;
    let wait = wait().ok_or("wait")?;
    assert!(reader.poll_felica(wildcard()?, wait)?.is_none());
    let recoveries = journal.borrow().recoveries;
    assert!(reader.poll_felica(wildcard()?, wait)?.is_some());
    assert_eq!(journal.borrow().recoveries, recoveries + 1);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_missing_card_reply_keeps_the_reader_usable() -> TestResult {
    let (mut reader, journal) = initialized(vec![
        command(0x5c, &WILDCARD_POLLING, &polling_reply()),
        unanswered(0x5c, &read_request()),
        command(0x5c, &read_request(), &read_reply()),
    ])?;
    let mut card = reader
        .poll_felica(wildcard()?, wait().ok_or("wait")?)?
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
fn a_declared_card_state_cycles_the_field_before_the_next_polling() -> TestResult {
    let (mut reader, journal) = initialized(vec![
        command(0x5c, &WILDCARD_POLLING, &polling_reply()),
        command(0x54, &[], &[0]),
        command(0x5c, &WILDCARD_POLLING, &polling_reply()),
    ])?;
    let wait = wait().ok_or("wait")?;
    reader
        .poll_felica(wildcard()?, wait)?
        .ok_or("card absent")?
        .require_field_cycle();
    reader
        .poll_felica(wildcard()?, wait)?
        .ok_or("card absent")?;
    let journal = journal.borrow();
    assert_eq!(journal.remaining, 0);
    let times = &journal.command_times;
    assert!(times[times.len() - 1] - times[times.len() - 2] >= Duration::from_millis(5));
    Ok(())
}

#[test]
fn a_malformed_polling_reply_requires_a_field_cycle() -> TestResult {
    let mut malformed = polling_reply();
    malformed[1] = 3;
    let (mut reader, journal) = initialized(vec![
        command(0x5c, &WILDCARD_POLLING, &malformed),
        command(0x54, &[], &[0]),
        command(0x5c, &WILDCARD_POLLING, &polling_reply()),
    ])?;
    let wait = wait().ok_or("wait")?;
    assert!(matches!(
        reader.poll_felica(wildcard()?, wait),
        Err(Error::FelicaResponse(PacketError::ResponseCode {
            expected: 1,
            actual: 3
        }))
    ));
    assert!(reader.poll_felica(wildcard()?, wait)?.is_some());
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_reader_error_requires_initialization() -> TestResult {
    let (mut reader, journal) = initialized(vec![Step {
        command: 0x5c,
        args: WILDCARD_POLLING.to_vec(),
        answer: Answer::ReaderError,
    }])?;
    let wait = wait().ok_or("wait")?;
    let Err(Error::Transaction(error)) = reader.poll_felica(wildcard()?, wait) else {
        return Err("reader error frame accepted".into());
    };
    assert_eq!(error.progress, Progress::Acknowledged);
    assert!(matches!(error.failure, Failure::<io::Error>::ReaderError));
    assert!(error.source().is_none());
    assert!(matches!(
        reader.poll_felica(wildcard()?, wait),
        Err(Error::NotInitialized)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn rejects_packets_that_one_command_cannot_carry() -> TestResult {
    let (mut reader, journal) =
        initialized(vec![command(0x5c, &WILDCARD_POLLING, &polling_reply())])?;
    let mut card = reader
        .poll_felica(wildcard()?, wait().ok_or("wait")?)?
        .ok_or("card absent")?;
    let mut packet = vec![0; MAX_PACKET_BYTES + 1];
    packet[0] = 255;
    assert!(matches!(
        card.exchange_packet(&packet),
        Err(Error::InputLength {
            maximum: MAX_PACKET_BYTES,
            actual: 255
        })
    ));
    assert!(matches!(
        card.exchange_packet(&[3, 0]),
        Err(Error::FelicaRequest(PacketError::Length { .. }))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}
