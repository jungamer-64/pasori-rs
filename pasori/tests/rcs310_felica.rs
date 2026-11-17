//! FeliCa protocols over an RC-S320 reader, with independent response construction.

use felica_packet::PollRequest;
use pasori::{
    felica::{self, Card},
    ndef::{TYPE3_POLLING, Type3Tag},
};
use rcs310::reader::{Error as ReaderError, Reader};
use reader_script::rcs310::{
    IDENTITY, Script, Step, command, polling_reply, rcs320, rcs320_initialization, unanswered, wait,
};
use std::error::Error;

fn reader(extra: Vec<Step>) -> Result<Reader<Script>, Box<dyn Error>> {
    let mut steps = rcs320_initialization();
    steps.extend(extra);
    let (transport, _) = Script::new(rcs320(), steps);
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
    command(0x5c, &request, &reply)
}

#[test]
fn type_three_ndef_reads_through_an_rcs320() -> Result<(), Box<dyn Error>> {
    let attribute = [0x10, 1, 1, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 3, 0, 0x18];
    let mut reader = reader(vec![
        command(0x5c, &[6, 0, 0x12, 0xfc, 0, 0], &polling_reply()),
        read(0, attribute),
        read(1, [0x32; 16]),
    ])?;
    let card = reader
        .poll_felica(TYPE3_POLLING, wait().ok_or("wait")?)?
        .ok_or("Type 3 tag absent")?;
    let mut tag = Type3Tag::new(Card::new(card)).map_err(|_| "Type 3 polling rejected")?;
    assert_eq!(tag.read_ndef()?, [0x32; 3]);
    Ok(())
}

#[test]
fn type_three_requires_a_polling_of_its_system() -> Result<(), Box<dyn Error>> {
    let mut reader = reader(vec![
        command(0x5c, &[6, 0, 0xff, 0xff, 0, 0], &polling_reply()),
        unanswered(0x5c, &[10, 4, 1, 2, 3, 4, 5, 6, 7, 8]),
    ])?;
    let card = reader
        .poll_felica(PollRequest::new(0xffff, 0, 0)?, wait().ok_or("wait")?)?
        .ok_or("card absent")?;
    let Err(mut card) = Type3Tag::new(Card::new(card)) else {
        return Err("a wildcard polling was accepted as Type 3".into());
    };
    assert!(matches!(
        card.request_response(),
        Err(felica::Error::Reader(ReaderError::NoResponse))
    ));
    Ok(())
}
