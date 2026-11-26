//! NFC-A and NFC-B card protocols over a Port-100 reader, with independent
//! response construction.

use pasori::{
    isodep::{self, IsoDepCard},
    ndef,
    type2::Type2Tag,
};
use port100::reader::{Error as ReaderError, Reader, TypeASelection};
use reader_script::port100::{
    Script, Step, WAIT_UNITS, command, in_comm_rf, in_comm_rf_bits, initialization,
    type_a_activation, type_a_configuration, type_b_configuration, wait, with_crc_a,
};
use std::error::Error;

const RECEIVE_TIMEOUT: u32 = 0x80;
const UID: [u8; 7] = [0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
/// ATS with FSCI 8, FWI 7, SFGI 0 and CID support.
const ATS: [u8; 5] = [0x05, 0x78, 0x80, 0x70, 0x02];

fn reader(parts: impl IntoIterator<Item = Vec<Step>>) -> Result<Reader<Script>, Box<dyn Error>> {
    let mut steps = initialization();
    steps.extend(parts.into_iter().flatten());
    let (transport, _) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    Ok(reader)
}

/// Reader wait units of the block engine's wait for FWI `fwi`: 330 µs per
/// FWI step, rounded up to the 100 µs unit.
fn block_units(fwi: u32) -> u16 {
    u16::try_from((330u32 << fwi).div_ceil(100)).unwrap_or(u16::MAX)
}

/// One unchained I-block exchange of block number `number`.
fn i_block(units: u16, number: u8, apdu: &[u8], response: &[u8]) -> Step {
    in_comm_rf(
        units,
        &[&[0x02 | number][..], apdu].concat(),
        0,
        &[&[0x02 | number][..], response].concat(),
    )
}

fn type_two_page(page: u8, data: [u8; 16]) -> Step {
    in_comm_rf(WAIT_UNITS, &[0x30, page], 0, &with_crc_a(&data))
}

fn type_two_write(page: u8, data: [u8; 4]) -> Step {
    in_comm_rf_bits(
        WAIT_UNITS,
        &[&[0xa2, page][..], &data].concat(),
        0,
        4,
        &[0x0a],
    )
}

#[test]
fn type_two_ndef_reads_and_clears_through_a_port100_reader() -> Result<(), Box<dyn Error>> {
    let mut header = [0; 16];
    header[12..].copy_from_slice(&[0xe1, 0x10, 6, 0]);
    let mut data = [0; 16];
    data[..6].copy_from_slice(&[3, 3, 0xd0, 0, 0, 0xfe]);
    let mut reader = reader([
        type_a_configuration(),
        type_a_activation(&UID, 0x00),
        vec![
            command(0x02, &[0x02, 0x00], &[0]),
            type_two_page(0, header),
            type_two_page(4, data),
            type_two_page(0, header),
            type_two_page(4, data),
            type_two_write(4, [3, 0, 0xd0, 0]),
            type_two_write(4, [3, 0, 0xfe, 0]),
            type_two_write(4, [3, 0, 0xfe, 0]),
        ],
    ])?;
    let Some(TypeASelection::Command(card)) = reader.poll_type_a(wait().ok_or("wait")?)? else {
        return Err("expected a Type 2 selection".into());
    };
    let mut tag = Type2Tag::new(card);
    assert_eq!(tag.read_ndef()?, Some(vec![0xd0, 0, 0]));
    tag.write_ndef(&[])?;
    Ok(())
}

#[test]
fn type_two_reports_a_missing_reply_and_a_damaged_frame() -> Result<(), Box<dyn Error>> {
    let mut reader = reader([
        type_a_configuration(),
        type_a_activation(&UID, 0x00),
        vec![
            command(0x02, &[0x02, 0x00], &[0]),
            in_comm_rf(WAIT_UNITS, &[0x30, 0], RECEIVE_TIMEOUT, &[]),
            in_comm_rf(WAIT_UNITS, &[0x30, 0], 0, &[0; 18]),
        ],
    ])?;
    let Some(TypeASelection::Command(card)) = reader.poll_type_a(wait().ok_or("wait")?)? else {
        return Err("expected a Type 2 selection".into());
    };
    let mut tag = Type2Tag::new(card);
    assert!(matches!(tag.read_ndef(), Err(ndef::Error::NoResponse)));
    assert!(matches!(
        tag.read_ndef(),
        Err(ndef::Error::Exchange(ReaderError::CardCrc))
    ));
    Ok(())
}

#[test]
fn type_four_ndef_reads_over_host_run_iso_dep_on_nfc_a() -> Result<(), Box<dyn Error>> {
    let units = block_units(7);
    let select = [0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1, 0];
    let ok = [0x90, 0];
    let mut reader = reader([
        type_a_configuration(),
        type_a_activation(&UID, 0x20),
        vec![
            in_comm_rf(WAIT_UNITS, &[0xe0, 0x80], 0, &ATS),
            i_block(units, 0, &select, &ok),
            i_block(units, 1, &[0, 0xa4, 0, 0x0c, 2, 0xe1, 3], &ok),
            i_block(
                units,
                0,
                &[0, 0xb0, 0, 0, 7],
                &[0, 15, 0x20, 0, 15, 0, 15, 0x90, 0],
            ),
            i_block(
                units,
                1,
                &[0, 0xb0, 0, 7, 8],
                &[4, 6, 0xe1, 4, 0, 0x80, 0, 0xff, 0x90, 0],
            ),
            i_block(units, 0, &[0, 0xa4, 0, 0x0c, 2, 0xe1, 4], &ok),
            i_block(units, 1, &[0, 0xb0, 0, 0, 2], &[0, 3, 0x90, 0]),
            i_block(units, 0, &[0, 0xb0, 0, 2, 3], &[0xd0, 0, 0, 0x90, 0]),
            in_comm_rf(units, &[0xb3], RECEIVE_TIMEOUT, &[]),
            in_comm_rf(units, &[0xb3], RECEIVE_TIMEOUT, &[]),
            in_comm_rf(units, &[0xb3], RECEIVE_TIMEOUT, &[]),
        ],
    ])?;
    let Some(TypeASelection::IsoDep(card)) = reader.poll_type_a(wait().ok_or("wait")?)? else {
        return Err("expected an ISO-DEP selection".into());
    };
    let mut card = IsoDepCard::new(card, None)?;
    assert_eq!(ndef::read_type4(&mut card)?, [0xd0, 0, 0]);
    assert!(matches!(
        card.check_presence(),
        Err(isodep::PresenceError::NoResponse)
    ));
    Ok(())
}

#[test]
fn nfc_b_iso_dep_exchanges_apdus_through_a_port100_reader() -> Result<(), Box<dyn Error>> {
    let atqb = [0x50, 1, 2, 3, 4, 0x11, 0x22, 0x33, 0x44, 0x00, 0x81, 0x41];
    let units = block_units(4);
    let mut reader = reader([
        type_b_configuration(),
        vec![
            in_comm_rf(WAIT_UNITS, &[0x05, 0x00, 0x00], 0, &atqb),
            in_comm_rf(
                WAIT_UNITS,
                &[0x1d, 1, 2, 3, 4, 0x00, 0x08, 0x01, 0x00],
                0,
                &[0x10],
            ),
            i_block(units, 0, &[0x00, 0xca, 0x00, 0x00], &[0x6a, 0x82]),
        ],
    ])?;
    let card = reader
        .poll_type_b(0, wait().ok_or("wait")?)?
        .ok_or("card absent")?;
    let mut card = IsoDepCard::new(card, None)?;
    assert_eq!(card.maximum_apdu_bytes(), 256);
    assert_eq!(card.exchange_apdu(&[0x00, 0xca, 0x00, 0x00])?, [0x6a, 0x82]);
    Ok(())
}
