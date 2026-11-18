//! FeliCa protocols over a Port-100 reader, with independent response construction.

use felica_packet::PollRequest;
use pasori::{
    felica::{self, Card},
    ndef::{TYPE3_POLLING, Type3Tag},
};
use port100::reader::{BitRate, Error as ReaderError, Reader};
use reader_script::port100::{
    IDENTITY, Script, Step, WAIT_UNITS, felica_212_configuration, in_comm_rf, initialization,
    polling_reply, wait,
};
use std::error::Error;

const RECEIVE_TIMEOUT: u32 = 0x80;

fn reader(extra: Vec<Step>) -> Result<Reader<Script>, Box<dyn Error>> {
    let mut steps = initialization();
    steps.extend(felica_212_configuration());
    steps.extend(extra);
    let (transport, _) = Script::new(steps);
    let mut reader = Reader::new(transport);
    reader.initialize()?;
    Ok(reader)
}

fn read(block: u8, data: [u8; 16]) -> Step {
    let mut request = vec![16, 6];
    request.extend(IDENTITY);
    request.extend([1, 0x0b, 0, 1, 0x80, block]);
    let mut reply = vec![29, 7];
    reply.extend(IDENTITY);
    reply.extend([0, 0, 1]);
    reply.extend(data);
    in_comm_rf(WAIT_UNITS, &request, 0, &reply)
}

#[test]
fn type_three_ndef_reads_through_a_port100_reader() -> Result<(), Box<dyn Error>> {
    let attribute = [0x10, 1, 1, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 3, 0, 0x18];
    let mut reader = reader(vec![
        in_comm_rf(WAIT_UNITS, &[6, 0, 0x12, 0xfc, 0, 0], 0, &polling_reply()),
        read(0, attribute),
        read(1, [0x32; 16]),
    ])?;
    let card = reader
        .poll_felica(BitRate::Kbps212, TYPE3_POLLING, wait().ok_or("wait")?)?
        .ok_or("Type 3 tag absent")?;
    let mut tag = Type3Tag::new(Card::new(card)).map_err(|_| "Type 3 polling rejected")?;
    assert_eq!(tag.read_ndef()?, [0x32; 3]);
    Ok(())
}

#[test]
fn a_missing_card_reply_reaches_the_card_protocol() -> Result<(), Box<dyn Error>> {
    let mut reader = reader(vec![
        in_comm_rf(WAIT_UNITS, &[6, 0, 0xff, 0xff, 0, 0], 0, &polling_reply()),
        in_comm_rf(
            WAIT_UNITS,
            &[10, 4, 1, 2, 3, 4, 5, 6, 7, 8],
            RECEIVE_TIMEOUT,
            &[],
        ),
    ])?;
    let card = reader
        .poll_felica(
            BitRate::Kbps212,
            PollRequest::new(0xffff, 0, 0)?,
            wait().ok_or("wait")?,
        )?
        .ok_or("card absent")?;
    let mut card = Card::new(card);
    assert!(matches!(
        card.request_response(),
        Err(felica::Error::Reader(ReaderError::NoResponse))
    ));
    Ok(())
}
