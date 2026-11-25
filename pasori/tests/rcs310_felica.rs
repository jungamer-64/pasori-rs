//! FeliCa protocols over an RC-S320 reader, with independent response construction.

use felica_packet::PollRequest;
use pasori::{
    felica::{self, BlockAddress, BlockWrite, Card, CardError, V2KeyVersions},
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

#[test]
fn standard_queries_decode_versions_and_mac_properties() -> Result<(), Box<dyn Error>> {
    let mut reader = reader(vec![
        command(0x5c, &[6, 0, 0xff, 0xff, 0, 0], &polling_reply()),
        command(
            0x5c,
            &[15, 2, 1, 2, 3, 4, 5, 6, 7, 8, 2, 0xff, 0xff, 0x0a, 0],
            &[15, 3, 1, 2, 3, 4, 5, 6, 7, 8, 2, 0x34, 0x12, 0xff, 0xff],
        ),
        command(
            0x5c,
            &[15, 0x32, 1, 2, 3, 4, 5, 6, 7, 8, 2, 0xff, 0xff, 0x0a, 0],
            &[
                22, 0x33, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0x43, 2, 0x34, 0x12, 0x78, 0x56, 0xff,
                0xff, 0x19, 0x23,
            ],
        ),
        command(
            0x5c,
            &[13, 0x32, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0x0a, 0],
            &[16, 0x33, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0x4f, 1, 0x78, 0x56],
        ),
        command(
            0x5c,
            &[12, 0x3c, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0],
            &[
                26, 0x3d, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0x85, 5, 0, 0x81, 0, 0, 0, 0, 0, 0,
                0x01, 0x81,
            ],
        ),
        command(
            0x5c,
            &[16, 0x28, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 0x09, 0, 0x49, 0],
            &[15, 0x29, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 2, 0, 1],
        ),
    ])?;
    let mut card = Card::new(
        reader
            .poll_felica(PollRequest::new(0xffff, 0, 0)?, wait().ok_or("wait")?)?
            .ok_or("card absent")?,
    );
    assert!(matches!(
        card.request_service(&[0; 33]),
        Err(felica::Error::Request(CardError::CodeCount {
            maximum: 32,
            actual: 33
        }))
    ));
    let legacy = card.request_service(&[0xffff, 0x0a])?;
    assert_eq!(
        legacy.iter().map(|v| v.value()).collect::<Vec<_>>(),
        [Some(0x1234), None]
    );
    let V2KeyVersions::AesAndDes {
        identifier,
        aes,
        des,
    } = card.request_service_v2(&[0xffff, 0x0a])?
    else {
        return Err("expected dual key versions".into());
    };
    assert_eq!(identifier, 0x43);
    assert_eq!(
        aes.iter().map(|v| v.value()).collect::<Vec<_>>(),
        [Some(0x1234), Some(0x5678)]
    );
    assert_eq!(
        des.iter().map(|v| v.value()).collect::<Vec<_>>(),
        [None, Some(0x2319)]
    );
    let V2KeyVersions::Aes(versions) = card.request_service_v2(&[0x0a])? else {
        return Err("expected AES key versions".into());
    };
    assert_eq!(
        versions.iter().map(|v| v.value()).collect::<Vec<_>>(),
        [Some(0x5678)]
    );
    let specification = card.request_specification_version()?;
    assert_eq!(specification.basic, 0x8500);
    assert_eq!(specification.options, [0x8100, 0, 0, 0, 0x8101]);
    assert_eq!(card.mac_service_properties(&[0x09, 0x49])?, [false, true]);
    Ok(())
}

#[test]
fn standard_queries_reject_wrong_identity_count_status_and_length() -> Result<(), Box<dyn Error>> {
    let v2 = &[13, 0x32, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0x0a, 0];
    let mut reader = reader(vec![
        command(0x5c, &[6, 0, 0xff, 0xff, 0, 0], &polling_reply()),
        command(0x5c, v2, &[12, 0x33, 0xff, 2, 3, 4, 5, 6, 7, 8, 0xff, 0xa1]),
        command(0x5c, v2, &[12, 0x33, 1, 2, 3, 4, 5, 6, 7, 8, 0xff, 0xa1]),
        command(0x5c, v2, &[14, 0x33, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0x4f, 2]),
        command(
            0x5c,
            v2,
            &[16, 0x33, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0x41, 1, 1, 2],
        ),
        command(
            0x5c,
            v2,
            &[16, 0x33, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0x20, 1, 1, 2],
        ),
    ])?;
    let mut card = Card::new(
        reader
            .poll_felica(PollRequest::new(0xffff, 0, 0)?, wait().ok_or("wait")?)?
            .ok_or("card absent")?,
    );
    assert!(matches!(
        card.request_service_v2(&[0x0a]),
        Err(felica::Error::Response(CardError::IdentityMismatch { .. }))
    ));
    assert!(matches!(
        card.request_service_v2(&[0x0a]),
        Err(felica::Error::Response(CardError::Status {
            flag1: 0xff,
            flag2: 0xa1
        }))
    ));
    assert!(matches!(
        card.request_service_v2(&[0x0a]),
        Err(felica::Error::Response(CardError::ResponseCount {
            expected: 1,
            actual: 2
        }))
    ));
    assert!(matches!(
        card.request_service_v2(&[0x0a]),
        Err(felica::Error::Response(CardError::Length {
            expected: 18,
            actual: 16
        }))
    ));
    assert!(matches!(
        card.request_service_v2(&[0x0a]),
        Err(felica::Error::Response(CardError::CryptoIdentifier(0x20)))
    ));
    Ok(())
}

#[test]
fn multiple_services_use_the_rcs320_packet_budget() -> Result<(), Box<dyn Error>> {
    let mut read_reply = vec![45, 7, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 2];
    read_reply.extend([0x32; 16]);
    read_reply.extend([0x76; 16]);
    let mut write = vec![254, 8, 1, 2, 3, 4, 5, 6, 7, 8, 2, 9, 0, 0x49, 0, 13];
    for n in 0..4 {
        write.extend([1, n, 1]);
    }
    for n in 4..13 {
        write.extend([0x80, n]);
    }
    write.extend([0x71; 13 * 16]);
    let mut reader = reader(vec![
        command(0x5c, &[6, 0, 0xff, 0xff, 0, 0], &polling_reply()),
        command(
            0x5c,
            &[
                21, 6, 1, 2, 3, 4, 5, 6, 7, 8, 2, 0x0b, 0, 0x4b, 0, 2, 0x81, 255, 0, 0, 1,
            ],
            &read_reply,
        ),
        command(0x5c, &write, &[12, 9, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0]),
    ])?;
    let mut card = Card::new(
        reader
            .poll_felica(PollRequest::new(0xffff, 0, 0)?, wait().ok_or("wait")?)?
            .ok_or("card absent")?,
    );
    let request = [BlockAddress::new(1, 255)?, BlockAddress::first(256)];
    assert!(matches!(
        card.read_without_encryption(&[0x0b], &request),
        Err(felica::Error::Request(CardError::ServiceIndex(1)))
    ));
    assert_eq!(
        card.read_without_encryption(&[0x0b, 0x4b], &request)?
            .blocks(),
        &[[0x32; 16], [0x76; 16]]
    );
    let mut blocks = (0..13)
        .map(|n| BlockWrite {
            address: BlockAddress::first(n),
            data: [0x71; 16],
        })
        .collect::<Vec<_>>();
    for (n, block) in (256..).zip(&mut blocks[..4]) {
        block.address = BlockAddress::new(1, n)?;
    }
    blocks[4].address = BlockAddress::new(1, 260)?;
    assert!(matches!(
        card.write_without_encryption(&[0x09, 0x49], &blocks),
        Err(felica::Error::Request(CardError::PacketBudget {
            maximum: 254,
            required: 255
        }))
    ));
    blocks[4].address = BlockAddress::first(4);
    card.write_without_encryption(&[0x09, 0x49], &blocks)?;
    Ok(())
}
