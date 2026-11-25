//! FeliCa protocols over an RC-S320 reader, with independent response construction.

use felica_packet::{PollRequest, PollResponse, Selection};
use pasori::{
    felica::{
        self, BlockAddress, BlockWrite, Card, CardError, V2KeyVersions, ValueLimitedPurseProperty,
    },
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
                26, 0x3d, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0x85, 5, 0, 0x81, 0, 0, 0, 0, 0x23,
                0x81, 0x01, 0x81,
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
    assert_eq!(specification.options, [0x8100, 0, 0, 0x8123, 0x8101]);
    assert_eq!(specification.value_limited_purse_version(), Some(0x8123));
    assert_eq!(specification.mac_communication_version(), Some(0x8101));
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
fn specification_version_preserves_unrecognized_and_missing_options() -> Result<(), Box<dyn Error>>
{
    let request = &[12, 0x3c, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0];
    let mut reader = reader(vec![
        command(0x5c, &[6, 0, 0xff, 0xff, 0, 0], &polling_reply()),
        command(
            0x5c,
            request,
            &[16, 0x3d, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0x85, 0],
        ),
        command(
            0x5c,
            request,
            &[
                26, 0x3d, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0x85, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0x80,
            ],
        ),
        command(
            0x5c,
            request,
            &[
                26, 0x3d, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0x85, 5, 0, 0, 0, 0, 0, 0, 1, 0x91,
                0xaf, 0x81,
            ],
        ),
    ])?;
    let mut card = Card::new(
        reader
            .poll_felica(PollRequest::new(0xffff, 0, 0)?, wait().ok_or("wait")?)?
            .ok_or("card absent")?,
    );
    for options in [&[][..], &[0, 0, 0, 0, 0x8000], &[0, 0, 0, 0x9101, 0x81af]] {
        let version = card.request_specification_version()?;
        assert_eq!(version.options, options);
        assert_eq!(version.value_limited_purse_version(), None);
        assert_eq!(version.mac_communication_version(), None);
    }
    Ok(())
}

#[test]
fn value_limited_purse_properties_follow_service_order() -> Result<(), Box<dyn Error>> {
    let mut reader = reader(vec![
        command(0x5c, &[6, 0, 0xff, 0xff, 0, 0], &polling_reply()),
        command(
            0x5c,
            &[
                18, 0x28, 1, 2, 3, 4, 5, 6, 7, 8, 0, 3, 0x11, 1, 0x15, 2, 0x17, 3,
            ],
            &[
                43, 0x29, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 3, 1, 0xff, 0xff, 0xff, 0x7f, 0, 0, 0,
                0x80, 0xff, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 0x34, 0x12,
                0, 0, 0xd2, 0xff, 0xff, 0xff, 2,
            ],
        ),
    ])?;
    let mut card = Card::new(
        reader
            .poll_felica(PollRequest::new(0xffff, 0, 0)?, wait().ok_or("wait")?)?
            .ok_or("card absent")?,
    );
    assert_eq!(
        card.value_limited_purse_properties(&[0x0111, 0x0215, 0x0317])?,
        [
            ValueLimitedPurseProperty::Enabled {
                upper_limit: i32::MAX,
                lower_limit: i32::MIN,
                generation: 0xff,
            },
            ValueLimitedPurseProperty::Disabled,
            ValueLimitedPurseProperty::Enabled {
                upper_limit: 0x1234,
                lower_limit: -46,
                generation: 2,
            },
        ]
    );
    Ok(())
}

#[test]
fn value_limited_purse_admits_at_most_sixteen_requests() -> Result<(), Box<dyn Error>> {
    let mut request = vec![44, 0x28, 1, 2, 3, 4, 5, 6, 7, 8, 0, 16];
    let mut reply = vec![173, 0x29, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 16];
    for _ in 0..16 {
        request.extend([0x11, 1]);
        reply.extend([0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    }
    let mut reader = reader(vec![
        command(0x5c, &[6, 0, 0xff, 0xff, 0, 0], &polling_reply()),
        command(0x5c, &request, &reply),
    ])?;
    let mut card = Card::new(
        reader
            .poll_felica(PollRequest::new(0xffff, 0, 0)?, wait().ok_or("wait")?)?
            .ok_or("card absent")?,
    );
    let services = [0x0111; 17];
    for actual in [0, 17] {
        assert!(matches!(
            card.value_limited_purse_properties(&services[..actual]),
            Err(felica::Error::Request(CardError::CodeCount { maximum: 16, actual: count }))
                if count == actual
        ));
    }
    assert_eq!(
        card.value_limited_purse_properties(&services[..16])?,
        [ValueLimitedPurseProperty::Disabled; 16]
    );
    Ok(())
}

#[test]
fn value_limited_purse_checks_reply_before_exchanging() -> Result<(), Box<dyn Error>> {
    struct LimitedSelection {
        request: PollRequest,
        response: PollResponse,
        exchanges: usize,
    }

    impl Selection for LimitedSelection {
        type Error = &'static str;

        fn poll_request(&self) -> PollRequest {
            self.request
        }

        fn poll_response(&self) -> &PollResponse {
            &self.response
        }

        fn max_packet_len(&self) -> usize {
            22
        }

        fn exchange_packet(&mut self, _: &[u8]) -> Result<Vec<u8>, Self::Error> {
            self.exchanges += 1;
            Err("unexpected exchange")
        }

        fn require_field_cycle(&mut self) {}
    }

    let mut card = Card::new(LimitedSelection {
        request: PollRequest::new(0xffff, 0, 0)?,
        response: PollResponse::parse(&polling_reply())?,
        exchanges: 0,
    });
    assert!(matches!(
        card.value_limited_purse_properties(&[0x0111]),
        Err(felica::Error::Request(CardError::PacketBudget {
            maximum: 22,
            required: 23
        }))
    ));
    assert_eq!(card.selection().exchanges, 0);
    Ok(())
}

#[test]
fn value_limited_purse_rejects_malformed_replies() -> Result<(), Box<dyn Error>> {
    let request = &[14, 0x28, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 0x11, 1];
    let mut enabled = vec![
        23, 0x29, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut other_card = enabled.clone();
    other_card[2] = 0xff;
    let mut wrong_command = enabled.clone();
    wrong_command[1] = 0x2b;
    let mut truncated = enabled[..22].to_vec();
    truncated[0] = 22;
    let mut extra = enabled.clone();
    extra[0] = 24;
    extra.push(0);
    let mut wrong_count = enabled.clone();
    wrong_count[12] = 2;
    let mut unknown_flag = enabled.clone();
    unknown_flag[13] = 2;
    enabled[13] = 0;
    let replies = [
        (
            other_card,
            CardError::IdentityMismatch {
                expected: felica_packet::Idm::new(IDENTITY),
                actual: felica_packet::Idm::new([0xff, 2, 3, 4, 5, 6, 7, 8]),
            },
        ),
        (
            wrong_command,
            CardError::ResponseCode {
                expected: 0x29,
                actual: 0x2b,
            },
        ),
        (
            vec![12, 0x29, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0xa2],
            CardError::Status {
                flag1: 1,
                flag2: 0xa2,
            },
        ),
        (
            wrong_count,
            CardError::ResponseCount {
                expected: 1,
                actual: 2,
            },
        ),
        (
            truncated,
            CardError::Length {
                expected: 23,
                actual: 22,
            },
        ),
        (
            extra,
            CardError::Length {
                expected: 23,
                actual: 24,
            },
        ),
        (unknown_flag, CardError::PursePropertyFlag(2)),
        (enabled, CardError::PursePropertyDisabledFields),
    ];
    let mut steps = vec![command(0x5c, &[6, 0, 0xff, 0xff, 0, 0], &polling_reply())];
    steps.extend(
        replies
            .iter()
            .map(|(reply, _)| command(0x5c, request, reply)),
    );
    let mut reader = reader(steps)?;
    let mut card = Card::new(
        reader
            .poll_felica(PollRequest::new(0xffff, 0, 0)?, wait().ok_or("wait")?)?
            .ok_or("card absent")?,
    );
    for (_, expected) in replies {
        assert!(matches!(
            card.value_limited_purse_properties(&[0x0111]),
            Err(felica::Error::Response(actual)) if actual == expected
        ));
    }
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
