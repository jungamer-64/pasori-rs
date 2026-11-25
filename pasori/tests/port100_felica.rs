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

#[cfg(feature = "felica-standard-des")]
mod standard_des {
    use super::*;
    use pasori::felica::{
        BlockAddress, BlockWrite, CardError, StandardError, StandardSession,
        standard_des::{AreaKey, ServiceKey},
    };
    use reader_script::port100::field_off;

    // Independent OpenSSL DES-ECB, two-key 3DES and DES-CBC vectors.
    const AUTH1: &[u8] = &[
        0x1a, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x00, 0x00, 0x02, 0x09,
        0x00, 0x08, 0x00, 0x6a, 0x07, 0x85, 0x11, 0x39, 0x3c, 0xb4, 0x4b,
    ];
    const PROOF: &[u8] = &[
        0x1a, 0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xdc, 0xc1, 0x7b, 0x9b, 0x7b,
        0x4a, 0x01, 0x32, 0xa2, 0xc7, 0xe3, 0x66, 0x68, 0xac, 0x99, 0xdf,
    ];
    const AUTH2: &[u8] = &[
        0x12, 0x12, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xc4, 0x08, 0x74, 0xe0, 0x17,
        0xf3, 0xbb, 0x1b,
    ];
    const ISSUE: &[u8] = &[
        0x22, 0x13, 0x0e, 0x13, 0x5c, 0xff, 0xaf, 0x6a, 0xb9, 0xbc, 0xa7, 0x2b, 0xaf, 0x0f, 0xc1,
        0x8b, 0x11, 0x02, 0x8b, 0xaf, 0x6a, 0x38, 0x7d, 0xc9, 0x8a, 0x1f, 0x75, 0xc9, 0xfd, 0x0d,
        0xea, 0xa2, 0x89, 0x2f,
    ];
    const WRONG_TID: &[u8] = &[
        0x22, 0x13, 0xca, 0x09, 0x2b, 0xda, 0x00, 0xbf, 0x9c, 0xc8, 0x9c, 0xd6, 0x12, 0xa6, 0x4c,
        0xb4, 0x11, 0x00, 0xeb, 0x6e, 0x0e, 0xe1, 0x93, 0x78, 0x42, 0x12, 0x02, 0xe4, 0x81, 0x34,
        0x1d, 0x38, 0x15, 0x7d,
    ];
    const EXHAUSTED: &[u8] = &[
        0x22, 0x13, 0x24, 0x4d, 0x02, 0xab, 0x18, 0x73, 0xcf, 0x18, 0x2d, 0xb3, 0x4c, 0x38, 0xa7,
        0xa8, 0x2e, 0xcc, 0xd5, 0x1c, 0x4d, 0xf7, 0x6a, 0x54, 0x8e, 0xb2, 0xb9, 0x0f, 0xff, 0xf0,
        0x05, 0xdc, 0x1e, 0xac,
    ];
    const READ: &[u8] = &[
        0x1a, 0x14, 0xd0, 0x5d, 0x7b, 0x7f, 0x2b, 0x41, 0xa8, 0x4a, 0xa6, 0x89, 0x0d, 0x11, 0x74,
        0x5d, 0x80, 0x98, 0xd8, 0x87, 0x48, 0x12, 0x5f, 0x2d, 0x5a, 0x58,
    ];
    const DATA: &[u8] = &[
        0x3a, 0x15, 0x6f, 0x8b, 0x35, 0x74, 0xa0, 0xff, 0x6c, 0xa9, 0x10, 0x3d, 0xaa, 0x73, 0x0d,
        0x09, 0x06, 0x34, 0x7d, 0x88, 0x39, 0x29, 0xa7, 0x95, 0x31, 0x70, 0xde, 0x72, 0x2a, 0x04,
        0x74, 0xbd, 0x3b, 0xe9, 0xe8, 0x81, 0x77, 0xd0, 0x8f, 0x7b, 0xcc, 0xbf, 0xd2, 0xfb, 0xc3,
        0x24, 0x7d, 0x57, 0x0d, 0x06, 0xb1, 0x31, 0xc9, 0x5c, 0x7e, 0x06, 0xfd, 0x90,
    ];
    const INVALID_MAC: &[u8] = &[
        0x3a, 0x15, 0x6f, 0x8b, 0x35, 0x74, 0xa0, 0xff, 0x6c, 0xa9, 0x10, 0x3d, 0xaa, 0x73, 0x0d,
        0x09, 0x06, 0x34, 0x7d, 0x88, 0x39, 0x29, 0xa7, 0x95, 0x31, 0x70, 0xde, 0x72, 0x2a, 0x04,
        0x74, 0xbd, 0x3b, 0xe9, 0xe8, 0x81, 0x77, 0xd0, 0x8f, 0x7b, 0xcc, 0xbf, 0xb9, 0x71, 0x72,
        0xcc, 0xb0, 0x07, 0xe5, 0xde, 0xf1, 0x64, 0xce, 0x37, 0x97, 0x16, 0x8d, 0x73,
    ];
    const WRITE: &[u8] = &[
        0x2a, 0x16, 0xe5, 0xf8, 0x12, 0x3f, 0xe2, 0x72, 0x6f, 0xbf, 0xe2, 0xb6, 0xf7, 0x64, 0xad,
        0x55, 0xfd, 0x76, 0x34, 0x44, 0xbd, 0x3d, 0xf7, 0xfb, 0xa2, 0x36, 0xbd, 0x1e, 0x8a, 0x48,
        0x34, 0x51, 0x97, 0x64, 0x86, 0x47, 0x9d, 0x60, 0x5b, 0xd8, 0xb4, 0xbf,
    ];
    const WRITTEN: &[u8] = &[
        0x1a, 0x17, 0x3f, 0x43, 0xdc, 0xd9, 0xd0, 0x11, 0xc9, 0x08, 0x35, 0x17, 0x9c, 0x03, 0xad,
        0x1b, 0x71, 0xa5, 0x12, 0xd4, 0x47, 0xa1, 0xb5, 0x98, 0x5f, 0x02,
    ];
    const REJECTED: &[u8] = &[
        0x1a, 0x17, 0x3f, 0x43, 0xdc, 0xd9, 0xd0, 0x11, 0xc9, 0x08, 0x6b, 0xe6, 0xb9, 0x57, 0x9b,
        0x88, 0x2f, 0x9a, 0x25, 0xb9, 0x59, 0x5c, 0x96, 0x77, 0xa7, 0xee,
    ];

    fn exchange(packet: &[u8], reply: &[u8]) -> Step {
        in_comm_rf(WAIT_UNITS, packet, 0, reply)
    }

    fn poll() -> Step {
        exchange(&[6, 0, 0xff, 0xff, 0, 0], &polling_reply())
    }

    fn select(
        reader: &mut Reader<Script>,
    ) -> Result<Card<port100::reader::FelicaCard<'_, Script>>, Box<dyn Error>> {
        Ok(Card::new(
            reader
                .poll_felica(
                    BitRate::Kbps212,
                    PollRequest::new(0xffff, 0, 0)?,
                    wait().ok_or("wait")?,
                )?
                .ok_or("card absent")?,
        ))
    }

    fn authentication(
        card: Card<port100::reader::FelicaCard<'_, Script>>,
    ) -> Result<
        StandardSession<port100::reader::FelicaCard<'_, Script>>,
        StandardError<ReaderError<std::io::Error>>,
    > {
        card.authenticate_standard_des(
            &0x2a4c6e8012345678u64.to_be_bytes(),
            &[AreaKey {
                code: 0,
                key: &0x6574839201abcdefu64.to_be_bytes(),
            }],
            &[
                ServiceKey::AuthenticationFree(9),
                ServiceKey::Authenticated {
                    code: 8,
                    key: &0x131d274f6193a7b5u64.to_be_bytes(),
                },
            ],
            0x98af76bb0155c928u64.to_be_bytes(),
        )
    }

    fn verify_reselection(steps: &mut Vec<Step>) {
        steps.extend(field_off());
        steps.extend(felica_212_configuration());
        steps.push(poll());
    }

    fn addresses() -> Result<[BlockAddress; 2], CardError> {
        Ok([BlockAddress::first(255), BlockAddress::new(1, 256)?])
    }

    #[test]
    fn des_authentication_read_write_and_reset() -> Result<(), Box<dyn Error>> {
        let mut steps = vec![
            poll(),
            exchange(AUTH1, PROOF),
            exchange(AUTH2, ISSUE),
            exchange(READ, DATA),
            exchange(WRITE, WRITTEN),
            exchange(
                &[12, 0x3e, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0],
                &[12, 0x3f, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0],
            ),
            exchange(
                &[10, 4, 1, 2, 3, 4, 5, 6, 7, 8],
                &[11, 5, 1, 2, 3, 4, 5, 6, 7, 8, 0],
            ),
        ];
        verify_reselection(&mut steps);
        let mut reader = reader(steps)?;
        let mut session = authentication(select(&mut reader)?)?;
        assert_eq!(session.issue().id, 0xa011223344556677u64.to_be_bytes());
        assert_eq!(
            session.issue().parameters,
            0x8899aabbccddeeffu64.to_be_bytes()
        );
        let blocks = addresses()?;
        assert!(matches!(
            session.read_blocks(&[blocks[0]; 15]),
            Err(StandardError::Request(CardError::PacketBudget {
                maximum: 255,
                required: 266
            }))
        ));
        assert_eq!(session.read_blocks(&blocks)?, [[0x33; 16], [0x57; 16]]);
        session.write_blocks(&[BlockWrite {
            address: blocks[1],
            data: [0x42; 16],
        }])?;
        assert_eq!(session.reset_mode()?.request_response()?, 0);
        select(&mut reader)?;
        Ok(())
    }

    #[test]
    fn des_rejects_a_wrong_proof_before_sending_authentication2() -> Result<(), Box<dyn Error>> {
        let mut wrong_proof = PROOF.to_vec();
        wrong_proof[10] ^= 1;
        let mut steps = vec![poll(), exchange(AUTH1, &wrong_proof)];
        verify_reselection(&mut steps);
        let mut reader = reader(steps)?;
        assert!(matches!(
            authentication(select(&mut reader)?),
            Err(StandardError::CardProof)
        ));
        select(&mut reader)?;
        Ok(())
    }

    #[test]
    fn des_requires_matching_transaction_id_and_counter_space() -> Result<(), Box<dyn Error>> {
        let mut reader = reader(vec![
            poll(),
            exchange(AUTH1, PROOF),
            exchange(AUTH2, WRONG_TID),
        ])?;
        assert!(matches!(
            authentication(select(&mut reader)?),
            Err(StandardError::TransactionId)
        ));

        let mut steps = vec![poll(), exchange(AUTH1, PROOF), exchange(AUTH2, EXHAUSTED)];
        verify_reselection(&mut steps);
        let mut exhausted = super::reader(steps)?;
        let mut session = authentication(select(&mut exhausted)?)?;
        assert!(matches!(
            session.read_blocks(&addresses()?),
            Err(StandardError::CounterExhausted)
        ));
        drop(session);
        select(&mut exhausted)?;
        Ok(())
    }

    #[test]
    fn des_bad_mac_revokes_the_session() -> Result<(), Box<dyn Error>> {
        let mut steps = vec![
            poll(),
            exchange(AUTH1, PROOF),
            exchange(AUTH2, ISSUE),
            exchange(READ, INVALID_MAC),
        ];
        verify_reselection(&mut steps);
        let mut reader = reader(steps)?;
        let mut session = authentication(select(&mut reader)?)?;
        assert!(matches!(
            session.read_blocks(&addresses()?),
            Err(StandardError::Mac)
        ));
        assert!(matches!(
            session.reset_mode(),
            Err(StandardError::SessionUnavailable)
        ));
        select(&mut reader)?;
        Ok(())
    }

    #[test]
    fn des_distinguishes_authenticated_write_status_from_lost_reply() -> Result<(), Box<dyn Error>>
    {
        for reply in [Some(REJECTED), None] {
            let write = match reply {
                Some(reply) => exchange(WRITE, reply),
                None => in_comm_rf(WAIT_UNITS, WRITE, RECEIVE_TIMEOUT, &[]),
            };
            let mut steps = vec![
                poll(),
                exchange(AUTH1, PROOF),
                exchange(AUTH2, ISSUE),
                exchange(READ, DATA),
                write,
            ];
            verify_reselection(&mut steps);
            let mut reader = reader(steps)?;
            let mut session = authentication(select(&mut reader)?)?;
            let blocks = addresses()?;
            session.read_blocks(&blocks)?;
            let update = [BlockWrite {
                address: blocks[1],
                data: [0x42; 16],
            }];
            let outcome = session.write_blocks(&update);
            assert!(matches!(
                (reply, outcome),
                (
                    Some(_),
                    Err(StandardError::Status {
                        first: 1,
                        second: 0xa8
                    })
                ) | (
                    None,
                    Err(StandardError::Exchange {
                        command: 0x16,
                        cause: felica::Error::Reader(ReaderError::NoResponse)
                    })
                )
            ));
            assert!(matches!(
                session.write_blocks(&update),
                Err(StandardError::SessionUnavailable)
            ));
            drop(session);
            select(&mut reader)?;
        }
        Ok(())
    }
}
