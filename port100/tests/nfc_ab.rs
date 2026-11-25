//! NFC-A and NFC-B activation and exchange scenarios with independent
//! response construction.
//!
//! These model command/response contracts, not physical device operation.

use iso14443::{
    iso_dep::{Blocks, Selection as _},
    nfca::{self, Reply, Selection as _},
    nfcb,
};
use port100::reader::{Activation, Error, MAX_BLOCK_BYTES, Reader, TypeASelection};
use reader_script::port100::{
    Journal, Script, Step, WAIT_UNITS, command, field_off, in_comm_rf, in_comm_rf_bits,
    initialization, type_a_activation, type_a_configuration, type_b_configuration, wait,
    with_crc_a,
};
use std::{cell::RefCell, rc::Rc, time::Duration};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const RECEIVE_TIMEOUT: u32 = 0x80;
const UID: [u8; 4] = [0x04, 0x11, 0x22, 0x33];
const LONG_UID: [u8; 7] = [0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
const ATS: [u8; 5] = [0x05, 0x78, 0x80, 0x70, 0x02];
const ATQB: [u8; 12] = [0x50, 1, 2, 3, 4, 0x11, 0x22, 0x33, 0x44, 0x00, 0x81, 0x41];

type Session = (Reader<Script>, Rc<RefCell<Journal>>);

fn initialized(
    parts: impl IntoIterator<Item = Vec<Step>>,
) -> Result<Session, Box<dyn std::error::Error>> {
    let mut steps = initialization();
    steps.extend(parts.into_iter().flatten());
    let (transport, journal) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    Ok((reader, journal))
}

fn card_wait() -> Result<port100::reader::ResponseWait, Box<dyn std::error::Error>> {
    Ok(wait().ok_or("wait")?)
}

#[test]
fn a_type_two_card_exchanges_commands_with_host_checked_crc() -> TestResult {
    let page = [0x5a; 16];
    let (mut reader, journal) = initialized([
        type_a_configuration(),
        type_a_activation(&UID, 0x00),
        vec![
            command(0x02, &[0x02, 0x00], &[0]),
            in_comm_rf(WAIT_UNITS, &[0x30, 0x04], 0, &with_crc_a(&page)),
            in_comm_rf_bits(WAIT_UNITS, &[0xa2, 0x04, 1, 2, 3, 4], 0, 4, &[0x0a]),
            in_comm_rf(WAIT_UNITS, &[0x01, 0, 0, 0], RECEIVE_TIMEOUT, &[]),
            in_comm_rf(WAIT_UNITS, &[0x30, 0x04], 0, &[0x5a, 0x5a, 0x00, 0x00]),
        ],
    ])?;
    let Some(TypeASelection::Command(mut card)) = reader.poll_type_a(card_wait()?)? else {
        return Err("expected a command selection".into());
    };
    let observation = card.observation();
    assert_eq!(observation.uid(), UID);
    assert_eq!(observation.sens_res(), [0x44, 0x00]);
    assert_eq!(observation.sel_res(), 0);
    assert!(observation.ats().is_none());
    assert_eq!(card.exchange(&[0x30, 0x04])?, Reply::Data(page.to_vec()));
    assert_eq!(
        card.exchange(&[0xa2, 0x04, 1, 2, 3, 4])?,
        Reply::Data(vec![0x0a])
    );
    assert_eq!(card.exchange(&[0x01, 0, 0, 0])?, Reply::Silence);
    assert!(matches!(card.exchange(&[0x30, 0x04]), Err(Error::CardCrc)));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_double_size_uid_is_selected_over_two_cascade_levels() -> TestResult {
    let (mut reader, journal) =
        initialized([type_a_configuration(), type_a_activation(&LONG_UID, 0x00)])?;
    let Some(TypeASelection::Command(card)) = reader.poll_type_a(card_wait()?)? else {
        return Err("expected a command selection".into());
    };
    assert_eq!(card.observation().uid(), LONG_UID);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn an_iso_dep_card_is_activated_with_rats_and_carries_blocks() -> TestResult {
    let (mut reader, journal) = initialized([
        type_a_configuration(),
        type_a_activation(&UID, 0x20),
        vec![
            in_comm_rf(WAIT_UNITS, &[0xe0, 0x80], 0, &ATS),
            in_comm_rf(100, &[0x02, 0x00, 0xa4], 0, &[0x02, 0x90, 0x00]),
            in_comm_rf(100, &[0xb2], RECEIVE_TIMEOUT, &[]),
            in_comm_rf_bits(100, &[0xb2], 0, 4, &[0x02, 0x90, 0x00]),
        ],
        field_off(),
        type_a_configuration(),
        vec![
            command(0x02, &[0x01, 0x00, 0x02, 0x00, 0x07, 0x07], &[0]),
            in_comm_rf(WAIT_UNITS, &[0x26], RECEIVE_TIMEOUT, &[]),
        ],
    ])?;
    {
        let Some(TypeASelection::IsoDep(mut card)) = reader.poll_type_a(card_wait()?)? else {
            return Err("expected an ISO-DEP selection".into());
        };
        let Activation::TypeA(observation) = card.activation() else {
            return Err("expected NFC-A activation".into());
        };
        assert_eq!(observation.ats().map(nfca::Ats::bytes), Some(&ATS[..]));
        let parameters = card.parameters();
        assert_eq!(parameters.frame_size(), 256);
        assert_eq!(parameters.fwi(), 7);
        assert_eq!(parameters.cid(), None);
        assert_eq!(card.maximum_block_bytes(), MAX_BLOCK_BYTES);
        let mut blocks = card.blocks()?;
        let wait = Duration::from_millis(10);
        assert_eq!(
            blocks.transfer(&[0x02, 0x00, 0xa4], wait)?,
            [0x02, 0x90, 0x00]
        );
        let missing = blocks.transfer(&[0xb2], wait);
        assert!(matches!(missing, Err(Error::NoResponse)));
        assert!(matches!(
            blocks.transfer(&[0xb2], wait),
            Err(Error::CardReplyBitCount(4))
        ));
        assert!(matches!(
            blocks.transfer(&[0; MAX_BLOCK_BYTES - 1], wait),
            Err(Error::InputLength { .. })
        ));
        assert!(matches!(
            blocks.transfer(&[0xb2], Duration::from_secs(7)),
            Err(Error::WaitRange(_))
        ));
    }
    // A new activation starts from a field that was switched off.
    assert!(reader.poll_type_a(card_wait()?)?.is_none());
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_partial_ats_cannot_activate_an_iso_dep_card() -> TestResult {
    let (mut reader, journal) = initialized([
        type_a_configuration(),
        type_a_activation(&UID, 0x20),
        vec![in_comm_rf_bits(WAIT_UNITS, &[0xe0, 0x80], 0, 4, &ATS)],
    ])?;
    assert!(matches!(
        reader.poll_type_a(card_wait()?),
        Err(Error::CardReplyBitCount(4))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_damaged_anticollision_reply_cycles_the_field_before_the_next_selection() -> TestResult {
    let (mut reader, journal) = initialized([
        type_a_configuration(),
        vec![
            command(0x02, &[0x01, 0x00, 0x02, 0x00, 0x07, 0x07], &[0]),
            in_comm_rf(WAIT_UNITS, &[0x26], 0, &[0x44, 0x00]),
            command(0x02, &[0x07, 0x08], &[0]),
            in_comm_rf(WAIT_UNITS, &[0x93, 0x20], 0, &[1, 2, 3, 4, 0]),
        ],
        field_off(),
        type_a_configuration(),
        vec![
            command(0x02, &[0x01, 0x00, 0x02, 0x00, 0x07, 0x07], &[0]),
            in_comm_rf(WAIT_UNITS, &[0x26], 0, &[0x44, 0x00]),
            command(0x02, &[0x07, 0x08], &[0]),
            in_comm_rf(WAIT_UNITS, &[0x93, 0x20], 0x08, &[]),
        ],
    ])?;
    assert!(matches!(
        reader.poll_type_a(card_wait()?),
        Err(Error::CardReply("SDD_RES BCC"))
    ));
    assert!(matches!(
        reader.poll_type_a(card_wait()?),
        Err(Error::RfStatus(0x08))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn an_iso_dep_type_b_card_is_activated_with_attrib() -> TestResult {
    let (mut reader, journal) = initialized([
        type_b_configuration(),
        vec![
            in_comm_rf(WAIT_UNITS, &[0x05, 0x00, 0x00], 0, &ATQB),
            in_comm_rf(
                WAIT_UNITS,
                &[0x1d, 1, 2, 3, 4, 0x00, 0x08, 0x01, 0x00],
                0,
                &[0x10],
            ),
            in_comm_rf(100, &[0x02, 0x90], 0, &[0x02, 0x6a, 0x82]),
        ],
    ])?;
    let mut card = reader.poll_type_b(0, card_wait()?)?.ok_or("card absent")?;
    let Activation::TypeB(observation) = card.activation() else {
        return Err("expected NFC-B activation".into());
    };
    assert_eq!(observation.atqb().pupi(), [1, 2, 3, 4]);
    let parameters = card.parameters();
    assert_eq!(parameters.frame_size(), 256);
    assert_eq!(parameters.maximum_command_bytes(), Some(256));
    assert_eq!(parameters.cid(), None);
    assert_eq!(
        card.blocks()?
            .transfer(&[0x02, 0x90], Duration::from_millis(10))?,
        [0x02, 0x6a, 0x82]
    );
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_type_b_card_without_iso_dep_is_rejected_before_attrib() -> TestResult {
    let mut proprietary = ATQB;
    proprietary[10] = 0x80;
    let (mut reader, journal) = initialized([
        type_b_configuration(),
        vec![in_comm_rf(WAIT_UNITS, &[0x05, 0x00, 0x00], 0, &proprietary)],
        field_off(),
        type_b_configuration(),
        vec![in_comm_rf(
            WAIT_UNITS,
            &[0x05, 0x00, 0x00],
            RECEIVE_TIMEOUT,
            &[],
        )],
    ])?;
    assert!(matches!(
        reader.poll_type_b(0, card_wait()?),
        Err(Error::NotIsoDep)
    ));
    assert!(reader.poll_type_b(0, card_wait()?)?.is_none());
    let mut damaged = ATQB;
    damaged[0] = 0x51;
    assert!(matches!(
        nfcb::Atqb::new(damaged),
        Err(nfcb::Error::AtqbResponseCode(0x51))
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_rejected_crc_switch_ends_the_selection() -> TestResult {
    let (mut reader, journal) = initialized([
        type_a_configuration(),
        type_a_activation(&UID, 0x00),
        vec![command(0x02, &[0x02, 0x00], &[1])],
    ])?;
    let Some(TypeASelection::Command(mut card)) = reader.poll_type_a(card_wait()?)? else {
        return Err("expected a command selection".into());
    };
    assert!(matches!(
        card.exchange(&[0x30, 0x04]),
        Err(Error::CommandStatus {
            command: 0x02,
            status: 1
        })
    ));
    assert!(matches!(
        card.exchange(&[0x30, 0x04]),
        Err(Error::FieldReset)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}
