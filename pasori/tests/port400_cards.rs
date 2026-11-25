//! Card protocols over Port-400 USB Escape through the public reader API.

use pasori::{
    felica::Card,
    isodep::IsoDepCard,
    ndef::{self, TYPE3_POLLING, Type3Tag},
    port400::reader::{Activation, Reader, ResponseWait},
};
use reader_script::port400::{
    Script, Step, WAIT_US, exchange, felica, finish, initialization, type_a, type_b,
};
use std::{error::Error, time::Duration};

fn reader(steps: impl IntoIterator<Item = Step>) -> Result<Reader<Script>, Box<dyn Error>> {
    let mut reader = Reader::new(Script::new(
        initialization().into_iter().chain(steps).chain(finish()),
    ));
    reader.initialize()?;
    Ok(reader)
}

fn wait() -> Result<ResponseWait, Box<dyn Error>> {
    ResponseWait::new(Duration::from_micros(u64::from(WAIT_US)))
        .ok_or_else(|| "invalid test wait".into())
}

#[test]
fn reads_type_three_over_port400_felica() -> Result<(), Box<dyn Error>> {
    fn read_block(block: u8, data: [u8; 16]) -> Step {
        let request = [16, 6, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0x0b, 0, 1, 0x80, block];
        let mut reply = vec![29, 7, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 1];
        reply.extend(data);
        exchange(WAIT_US, &request, &reply)
    }
    let polled = [18, 1, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0];
    let attribute = [0x10, 1, 1, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 3, 0, 0x18];
    let mut reader = reader(felica().into_iter().chain([
        exchange(WAIT_US, &[6, 0, 0x12, 0xfc, 0, 0], &polled),
        read_block(0, attribute),
        read_block(1, [0x32; 16]),
    ]))?;
    {
        let card = reader
            .poll_felica(TYPE3_POLLING, wait()?)?
            .ok_or("Type 3 tag absent")?;
        let mut tag = Type3Tag::new(Card::new(card)).map_err(|_| "Type 3 polling rejected")?;
        assert_eq!(tag.read_ndef()?, [0x32; 3]);
    }
    reader.finish()?;
    assert!(reader.into_transport().is_exhausted());
    Ok(())
}

fn type_four_reads() -> [Step; 8] {
    fn i_block(number: u8, apdu: &[u8], response: &[u8]) -> Step {
        let pcb = [0x02 | number];
        let request_block = [pcb.as_slice(), apdu].concat();
        let response_block = [pcb.as_slice(), response].concat();
        exchange(5280, &request_block, &response_block)
    }
    let select = [2, 0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1, 0];
    let success = [0x90, 0];
    [
        exchange(5280, &select, &[0xf2, 2]),
        exchange(10560, &[0xf2, 2], &[2, 0x90, 0]),
        i_block(1, &[0, 0xa4, 0, 0x0c, 2, 0xe1, 3], &success),
        i_block(
            0,
            &[0, 0xb0, 0, 0, 7],
            &[0, 15, 0x20, 0, 15, 0, 15, 0x90, 0],
        ),
        i_block(
            1,
            &[0, 0xb0, 0, 7, 8],
            &[4, 6, 0xe1, 4, 0, 0x80, 0, 0xff, 0x90, 0],
        ),
        i_block(0, &[0, 0xa4, 0, 0x0c, 2, 0xe1, 4], &success),
        i_block(1, &[0, 0xb0, 0, 0, 2], &[0, 3, 0x90, 0]),
        i_block(0, &[0, 0xb0, 0, 2, 3], &[0xd0, 0, 0, 0x90, 0]),
    ]
}

#[test]
fn reads_type_four_over_port400_nfc_a() -> Result<(), Box<dyn Error>> {
    let ats = [2, 8];
    let mut reader = reader(
        type_a(false)
            .into_iter()
            .chain([exchange(WAIT_US, &[0xe0, 0x80], &ats)])
            .chain(type_four_reads()),
    )?;
    {
        let selection = reader.poll_type_a(wait()?)?.ok_or("Type A tag absent")?;
        assert!(
            matches!(selection.activation(), Activation::TypeA { sak: 0x20, ats: reply } if reply.bytes() == ats)
        );
        let mut card = IsoDepCard::new(selection, None)?;
        assert_eq!(ndef::read_type4(&mut card)?, [0xd0, 0, 0]);
    }
    reader.finish()?;
    assert!(reader.into_transport().is_exhausted());
    Ok(())
}

#[test]
fn reads_type_four_over_port400_nfc_b() -> Result<(), Box<dyn Error>> {
    let atqb = [0x50, 1, 2, 3, 4, 0x11, 0x22, 0x33, 0x44, 0, 0x81, 0x41];
    let mut reader = reader(
        type_b(false)
            .into_iter()
            .chain([
                exchange(WAIT_US, &[0x05, 0, 0], &atqb),
                exchange(WAIT_US, &[0x1d, 1, 2, 3, 4, 0, 8, 1, 0], &[0x10]),
            ])
            .chain(type_four_reads()),
    )?;
    {
        let selection = reader.poll_type_b(0, wait()?)?.ok_or("Type B tag absent")?;
        assert!(
            matches!(selection.activation(), Activation::TypeB(reply) if reply.atqb().bytes() == &atqb && reply.mbli() == 1)
        );
        let mut card = IsoDepCard::new(selection, None)?;
        assert_eq!(card.maximum_apdu_bytes(), 256);
        assert_eq!(ndef::read_type4(&mut card)?, [0xd0, 0, 0]);
    }
    reader.finish()?;
    assert!(reader.into_transport().is_exhausted());
    Ok(())
}
