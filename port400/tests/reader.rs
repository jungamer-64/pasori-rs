//! Port-400 reader transactions against independent USB responses.

use core::time::Duration;
use felica_packet::{PollRequest, Selection};
use iso14443::nfcb;
use port400::{
    reader::{ApduError, Error, FinishError, Reader, ResponseWait},
    transport::{Failure, Progress, TransactionError},
};
use reader_script::port400::{
    END, FIRMWARE, OK, Outcome, READ_FIRMWARE, RF_OFF, RF_ON, RF_TIMEOUT, Reply, Script, Step,
    WAIT_US, command, exchange, felica, finish, initialization, rf_apdu, type_b,
};
use std::error::Error as StdError;

const POLL: [u8; 6] = [6, 0, 0xff, 0xff, 0, 0];
const POLLED: [u8; 18] = [18, 1, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 2, 3, 4, 5, 6, 7];
const SET_212: [u8; 12] = [0xff, 0x50, 0, 0, 6, 0xff, 0x6e, 3, 5, 1, 0x89, 0];
const SET_424: [u8; 12] = [0xff, 0x50, 0, 0, 6, 0xff, 0x6e, 3, 5, 1, 0x92, 0];

fn response_wait() -> Result<ResponseWait, Box<dyn StdError>> {
    ResponseWait::new(Duration::from_micros(u64::from(WAIT_US)))
        .ok_or_else(|| "invalid test wait".into())
}

fn firmware_response(replies: Vec<Reply>) -> Step {
    Step {
        apdu: READ_FIRMWARE.to_vec(),
        outcome: Outcome::Replies(replies),
    }
}

fn ccid_reply(status: u8, error: u8, payload: &[u8], seconds: u64) -> Reply {
    Reply::Ccid {
        status,
        error,
        payload: payload.to_vec(),
        delay: Duration::from_secs(seconds),
    }
}

#[test]
fn admits_all_normal_firmware_formats_and_checks_the_update_state() -> Result<(), Box<dyn StdError>>
{
    let replies = [
        ([&FIRMWARE[..10], &[0, 0, 0x90, 0]].concat(), None, None),
        (
            [&FIRMWARE[..12], &[0, 0, 0x90, 0]].concat(),
            Some([11, 12]),
            None,
        ),
        (FIRMWARE.to_vec(), Some([13, 14]), Some([11, 12])),
    ];
    for (reply, bootloader, eeprom) in replies {
        let mut steps = initialization();
        steps[0] = command(&READ_FIRMWARE, &reply);
        steps[1] = command(&END, &[0xc0, 3, 1, 0x63, 1, 0x90, 0]);
        steps.push(command(&END, &OK));
        let mut reader = Reader::new(Script::new(steps));
        assert!(matches!(reader.rf_off(), Err(Error::NotInitialized)));
        let info = reader.initialize()?;
        assert_eq!(info.firmware, [1, 2, 3, 4]);
        assert_eq!(info.bootloader, bootloader);
        assert_eq!(info.rffe_eeprom, eeprom);
        reader.finish()?;
        reader.finish()?;
        assert!(reader.into_transport().is_exhausted());
    }

    let mut bootloader = FIRMWARE;
    bootloader[17] = 1;
    let mut reader = Reader::new(Script::new([command(&READ_FIRMWARE, &bootloader)]));
    assert!(matches!(
        reader.initialize(),
        Err(Error::FirmwareState {
            boot: Some([0, 1]),
            ..
        })
    ));
    assert!(reader.into_transport().is_exhausted());
    Ok(())
}

#[test]
fn extensions_are_reads_with_the_original_usb_deadline() -> Result<(), Box<dyn StdError>> {
    let mut steps = initialization();
    steps[0] = firmware_response(vec![
        ccid_reply(0x82, 1, &[], 2),
        ccid_reply(0x82, 1, &[], 3),
        ccid_reply(0x02, 0, &FIRMWARE, 1),
    ]);
    let mut reader = Reader::new(Script::new(steps));
    reader.initialize()?;
    assert!(reader.into_transport().is_exhausted());

    let mut reader = Reader::new(Script::new([firmware_response(vec![
        ccid_reply(0x82, 1, &[], 8),
        ccid_reply(0x02, 0, &FIRMWARE, 2),
    ])]));
    assert!(matches!(
        reader.initialize(),
        Err(Error::Ccid(TransactionError {
            progress: Progress::AwaitingCompletion,
            failure: Failure::Deadline,
        }))
    ));
    assert!(matches!(
        reader.initialize(),
        Err(Error::Ccid(TransactionError {
            progress: Progress::NotSent,
            failure: Failure::RecoveryRequired,
        }))
    ));
    assert!(reader.into_transport().is_exhausted());
    Ok(())
}

#[test]
fn malformed_ccid_reply_blocks_later_writes() {
    let invalid = [
        vec![0x83],
        vec![0x83, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        vec![0x83, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        vec![0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        vec![0x83, 0, 0, 0, 0, 1, 0, 0, 0, 0],
        vec![0x83, 0, 0, 0, 0, 0, 0xff, 0, 0, 0],
        vec![0x83, 0, 0, 0, 0, 0, 0, 0xc2, 0, 0],
        vec![0x83, 0, 0, 0, 0, 0, 0, 0x02, 0, 1],
        vec![0x83, 1, 0, 0, 0, 0, 0, 0x82, 1, 0, 0],
    ];
    for response in invalid {
        let mut reader = Reader::new(Script::new([firmware_response(vec![Reply::Raw(response)])]));
        assert!(matches!(
            reader.initialize(),
            Err(Error::Ccid(TransactionError {
                progress: Progress::Sent,
                failure: Failure::ResponseLength { .. }
                    | Failure::UnexpectedResponse { .. }
                    | Failure::InvalidStatus { .. },
            }))
        ));
        assert!(matches!(
            reader.initialize(),
            Err(Error::Ccid(TransactionError {
                progress: Progress::NotSent,
                failure: Failure::RecoveryRequired,
            }))
        ));
        assert!(reader.into_transport().is_exhausted());
    }
}

#[test]
fn a_matched_busy_reply_requires_an_explicit_next_operation() -> Result<(), Box<dyn StdError>> {
    let steps = [firmware_response(vec![ccid_reply(0x42, 0xe0, &[], 0)])]
        .into_iter()
        .chain(initialization());
    let mut reader = Reader::new(Script::new(steps));
    assert!(matches!(
        reader.initialize(),
        Err(Error::Ccid(TransactionError {
            progress: Progress::Completed,
            failure: Failure::CommandFailed { error: 0xe0, .. },
        }))
    ));
    reader.initialize()?;
    assert!(reader.into_transport().is_exhausted());
    Ok(())
}

#[test]
fn sequence_wraps_across_sessions() -> Result<(), Box<dyn StdError>> {
    let steps = (0..53).flat_map(|_| initialization().into_iter().chain([command(&END, &OK)]));
    let mut reader = Reader::new(Script::new(steps));
    for _ in 0..53 {
        reader.initialize()?;
        reader.finish()?;
    }
    assert!(reader.into_transport().is_exhausted());
    Ok(())
}

#[test]
fn partial_write_and_disconnect_preserve_the_confirmed_phase() -> Result<(), Box<dyn StdError>> {
    let mut reader = Reader::new(Script::new([Step {
        apdu: READ_FIRMWARE.to_vec(),
        outcome: Outcome::ShortWrite(4),
    }]));
    assert!(matches!(
        reader.initialize(),
        Err(Error::Ccid(TransactionError {
            progress: Progress::Writing,
            failure: Failure::WriteLength {
                requested: 15,
                actual: 4
            },
        }))
    ));
    assert!(reader.into_transport().is_exhausted());

    let request = PollRequest::new(0xffff, 0, 0)?;
    let packet = [2, 0x04];
    let steps = initialization().into_iter().chain(felica()).chain([
        exchange(WAIT_US, &POLL, &POLLED),
        Step {
            apdu: rf_apdu(WAIT_US, &packet),
            outcome: Outcome::Replies(vec![Reply::Disconnected]),
        },
    ]);
    let mut reader = Reader::new(Script::new(steps));
    reader.initialize()?;
    {
        let mut card = reader
            .poll_felica(request, response_wait()?)?
            .ok_or("card absent")?;
        assert!(matches!(
            card.exchange_packet(&packet),
            Err(Error::Ccid(TransactionError {
                progress: Progress::Sent,
                failure: Failure::Io(_),
            }))
        ));
        assert!(matches!(
            card.exchange_packet(&packet),
            Err(Error::SelectionInvalid)
        ));
    }
    assert!(matches!(
        reader.finish(),
        Err(FinishError::FieldOff(Error::Ccid(TransactionError {
            progress: Progress::NotSent,
            failure: Failure::RecoveryRequired,
        })))
    ));
    assert!(reader.into_transport().is_exhausted());
    Ok(())
}

#[test]
fn no_card_is_distinct_from_reader_status_and_broken_tlvs() -> Result<(), Box<dyn StdError>> {
    let request = PollRequest::new(0xffff, 0, 0)?;
    let apdu = rf_apdu(WAIT_US, &POLL);
    let samples: &[(&[u8], ApduError)] = &[
        (&[0x6f, 0], ApduError::Status([0x6f, 0])),
        (
            &[0xc0, 3, 1, 0x64, 0, 0x90, 0],
            ApduError::ObjectStatus {
                index: 1,
                status: [0x64, 0],
            },
        ),
        (
            &[0xc0, 3, 0, 0x90, 0, 0x96, 2, 2, 5, 0x90, 0],
            ApduError::RfStatus {
                flags: 2,
                detail: 5,
            },
        ),
        (
            &[0xc0, 3, 0, 0x90, 0, 0x92, 1, 4, 0x90, 0],
            ApduError::PartialByte(4),
        ),
        (&[0xc0, 3, 0, 0x90, 0, 0x90, 0], ApduError::MissingTag(0x97)),
        (
            &[0xc0, 3, 2, 0x64, 1, 0x97, 1, 1, 0x90, 0],
            ApduError::UnexpectedIccResponse,
        ),
        (
            &[0xc0, 3, 0, 0x90, 0, 0x97, 0x82, 1, 0, 0x90, 0],
            ApduError::InvalidTlv,
        ),
    ];
    for &(response, error) in samples {
        let steps = initialization()
            .into_iter()
            .chain(felica())
            .chain([command(&apdu, &RF_TIMEOUT), command(&apdu, response)]);
        let mut reader = Reader::new(Script::new(steps));
        reader.initialize()?;
        assert!(reader.poll_felica(request, response_wait()?)?.is_none());
        assert!(
            matches!(reader.poll_felica(request, response_wait()?), Err(Error::DeviceApdu(actual)) if actual == error)
        );
        assert!(reader.into_transport().is_exhausted());
    }
    Ok(())
}

#[test]
fn polling_uses_the_last_icc_response_object() -> Result<(), Box<dyn StdError>> {
    let mut first_reply = POLLED;
    first_reply[2] = 0xab;
    let multiple_replies = [
        &[0xc0, 3, 0, 0x90, 0, 0x97, 18][..],
        &first_reply,
        &[0x97, 18],
        &POLLED,
        &[0x90, 0],
    ]
    .concat();
    let packet = [3, 0x81, 0xaa];
    let steps = initialization().into_iter().chain(felica()).chain([
        command(&rf_apdu(WAIT_US, &POLL), &multiple_replies),
        command(&rf_apdu(WAIT_US, &packet), &multiple_replies),
    ]);
    let mut reader = Reader::new(Script::new(steps));
    reader.initialize()?;
    let mut card = reader
        .poll_felica(PollRequest::new(0xffff, 0, 0)?, response_wait()?)?
        .ok_or("missing card")?;
    assert_eq!(
        card.poll_response().idm,
        felica_packet::Idm::new([1, 2, 3, 4, 5, 6, 7, 8])
    );
    assert!(matches!(
        card.exchange_packet(&packet),
        Err(Error::DeviceApdu(ApduError::DuplicateTag(0x97)))
    ));
    assert!(reader.into_transport().is_exhausted());
    Ok(())
}

#[test]
fn negotiates_424_after_polling_and_restores_212_before_the_next_poll()
-> Result<(), Box<dyn StdError>> {
    let poll = [6, 0, 0xff, 0xff, 2, 0];
    let mut capable = [0; 20];
    capable[..18].copy_from_slice(&POLLED);
    capable[0] = 20;
    capable[19] = 0x82;
    let packet = [3, 0x81, 0xaa];
    let response = [3, 0x82, 0xbb];
    let steps = initialization().into_iter().chain(felica()).chain([
        exchange(WAIT_US, &poll, &capable),
        command(&SET_424, &OK),
        exchange(WAIT_US, &packet, &response),
        command(&SET_212, &OK),
        exchange(WAIT_US, &POLL, &POLLED),
    ]);
    let mut reader = Reader::new(Script::new(steps));
    reader.initialize()?;
    {
        let mut card = reader
            .poll_felica(PollRequest::new(0xffff, 2, 0)?, response_wait()?)?
            .ok_or("missing capable card")?;
        assert_eq!(card.exchange_packet(&packet)?, response);
    }
    assert!(
        reader
            .poll_felica(PollRequest::new(0xffff, 0, 0)?, response_wait()?)?
            .is_some()
    );
    assert!(reader.into_transport().is_exhausted());
    Ok(())
}

#[test]
fn requires_both_speed_flags_and_excludes_ic_code_0b() -> Result<(), Box<dyn StdError>> {
    let poll = [6, 0, 0xff, 0xff, 2, 0];
    let mut reply = [0; 20];
    reply[..18].copy_from_slice(&POLLED);
    reply[0] = 20;
    let steps =
        [(2, 1, 0x02), (2, 1, 0x80), (2, 0x0b, 0x82), (1, 1, 0x82)].map(|(code, ic, flags)| {
            reply[11] = ic;
            reply[19] = flags;
            let mut request = poll;
            request[4] = code;
            exchange(WAIT_US, &request, &reply)
        });
    let mut reader = Reader::new(Script::new(
        initialization().into_iter().chain(felica()).chain(steps),
    ));
    reader.initialize()?;
    for code in [2, 2, 2, 1] {
        assert!(
            reader
                .poll_felica(PollRequest::new(0xffff, code, 0)?, response_wait()?)?
                .is_some()
        );
    }
    assert!(reader.into_transport().is_exhausted());
    Ok(())
}

#[test]
fn an_unconfirmed_424_switch_never_publishes_a_card() -> Result<(), Box<dyn StdError>> {
    let poll = [6, 0, 0xff, 0xff, 2, 0];
    let mut capable = [0; 20];
    capable[..18].copy_from_slice(&POLLED);
    capable[0] = 20;
    capable[19] = 0x82;
    let steps = initialization()
        .into_iter()
        .chain(felica())
        .chain([
            exchange(WAIT_US, &poll, &capable),
            command(&SET_424, &[0xc0, 3, 1, 0x6a, 0x81, 0x90, 0]),
        ])
        .chain(felica())
        .chain([exchange(WAIT_US, &POLL, &POLLED)]);
    let mut reader = Reader::new(Script::new(steps));
    reader.initialize()?;
    assert!(matches!(
        reader.poll_felica(PollRequest::new(0xffff, 2, 0)?, response_wait()?),
        Err(Error::DeviceApdu(_))
    ));
    assert!(
        reader
            .poll_felica(PollRequest::new(0xffff, 0, 0)?, response_wait()?)?
            .is_some()
    );
    assert!(reader.into_transport().is_exhausted());
    Ok(())
}

#[test]
fn reads_the_rc_s300_p_polling_response_shape() -> Result<(), Box<dyn StdError>> {
    // USB trace shape from https://sakura-system.com/archives/3120.
    // The fixture assigns the sequence and the card identity independently.
    let command = [
        0xff, 0x50, 0, 1, 0, 0, 0x11, 0x5f, 0x46, 4, 0xa0, 0x86, 1, 0, 0x95, 0x82, 0, 6, 6, 0,
        0xff, 0xff, 1, 0, 0, 0, 0,
    ];
    let response = [
        0x83, 0x24, 0, 0, 0, 0, 9, 2, 0, 0, 0xc0, 3, 0, 0x90, 0, 0x92, 1, 0, 0x96, 2, 0, 0, 0x97,
        0x14, 0x14, 1, 1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1, 0x12, 0x34, 0x90, 0,
    ];
    let steps = initialization()
        .into_iter()
        .chain(felica())
        .chain([Step {
            apdu: command.to_vec(),
            outcome: Outcome::Replies(vec![Reply::Raw(response.to_vec())]),
        }])
        .chain(finish());
    let mut reader = Reader::new(Script::new(steps));
    reader.initialize()?;
    {
        let card = reader
            .poll_felica(
                PollRequest::new(0xffff, 1, 0)?,
                ResponseWait::new(Duration::from_millis(100)).ok_or("invalid test wait")?,
            )?
            .ok_or("missing card")?;
        let observation = card.poll_response();
        assert_eq!(observation.pmm, [8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(observation.request_data, Some([0x12, 0x34]));
    }
    reader.finish()?;
    assert!(reader.into_transport().is_exhausted());
    Ok(())
}

#[test]
fn selected_felica_enforces_packet_length_and_cycles_when_required() -> Result<(), Box<dyn StdError>>
{
    let request = PollRequest::new(0xffff, 0, 0)?;
    let mut packet = [0; 255];
    packet[0] = 255;
    let answer = [3, 1, 2];
    let steps = initialization()
        .into_iter()
        .chain(felica())
        .chain([
            exchange(WAIT_US, &POLL, &POLLED),
            exchange(WAIT_US, &packet, &answer),
        ])
        .chain(felica())
        .chain([exchange(WAIT_US, &POLL, &POLLED)])
        .chain(finish());
    let mut reader = Reader::new(Script::new(steps));
    reader.initialize()?;
    {
        let mut card = reader
            .poll_felica(request, response_wait()?)?
            .ok_or("card absent")?;
        assert_eq!(card.max_packet_len(), 255);
        assert!(matches!(
            card.exchange_packet(&[1, 0]),
            Err(Error::FelicaRequest(_))
        ));
        card.require_field_cycle();
        assert_eq!(card.exchange_packet(&packet)?, answer);
    }
    assert!(reader.poll_felica(request, response_wait()?)?.is_some());
    reader.finish()?;
    let script = reader.into_transport();
    assert!(script.is_exhausted());
    assert_eq!(
        script
            .waits()
            .iter()
            .map(Duration::as_millis)
            .collect::<Vec<_>>(),
        [30, 30, 21, 3, 30, 21, 3, 30]
    );
    Ok(())
}

#[test]
fn activation_timeout_and_cid_mismatch_have_different_outcomes() -> Result<(), Box<dyn StdError>> {
    let switch_a = [0xff, 0x50, 0, 2, 4, 0x8f, 2, 0, 3, 0];
    let mut steps = initialization();
    steps.extend([
        command(&RF_ON, &OK),
        command(&switch_a, &[0xc0, 3, 1, 0x64, 1, 0x90, 0]),
    ]);
    steps.extend(type_b(true));
    steps.extend([
        exchange(
            WAIT_US,
            &[0x05, 0x42, 0],
            &[0x50, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0x81, 0x41],
        ),
        exchange(WAIT_US, &[0x1d, 1, 2, 3, 4, 0, 8, 1, 0], &[0x11]),
    ]);
    let mut reader = Reader::new(Script::new(steps));
    reader.initialize()?;
    assert!(reader.poll_type_a(response_wait()?)?.is_none());
    assert!(matches!(
        reader.poll_type_b(0x42, response_wait()?),
        Err(Error::TypeB(nfcb::Error::CidMismatch {
            assigned: 0,
            returned: 1
        }))
    ));
    assert!(reader.into_transport().is_exhausted());
    Ok(())
}

#[test]
fn failed_cleanup_remains_observable_and_allows_explicit_end() -> Result<(), Box<dyn StdError>> {
    let rejection = [0xc0, 3, 1, 0x69, 0x85, 0x90, 0];
    let steps = initialization().into_iter().chain(felica()).chain([
        command(&rf_apdu(WAIT_US, &POLL), &RF_TIMEOUT),
        command(&RF_OFF, &rejection),
        command(&END, &rejection),
        command(&END, &OK),
    ]);
    let mut reader = Reader::new(Script::new(steps));
    reader.initialize()?;
    let poll = PollRequest::new(0xffff, 0, 0)?;
    assert!(reader.poll_felica(poll, response_wait()?)?.is_none());
    assert!(matches!(
        reader.finish(),
        Err(FinishError::FieldOff(Error::DeviceApdu(_)))
    ));
    assert!(matches!(
        reader.poll_felica(poll, response_wait()?),
        Err(Error::NotInitialized)
    ));
    assert!(matches!(
        reader.finish(),
        Err(FinishError::EndSession(Error::DeviceApdu(_)))
    ));
    reader.finish()?;
    assert!(reader.into_transport().is_exhausted());
    Ok(())
}

#[test]
fn rf_wait_admission_rounds_without_exceeding_the_supported_range() {
    assert_eq!(
        ResponseWait::new(Duration::from_nanos(1001)).map(ResponseWait::duration),
        Some(Duration::from_micros(2))
    );
    assert!(ResponseWait::new(Duration::ZERO).is_none());
    assert!(ResponseWait::new(ResponseWait::MAX).is_some());
    assert!(ResponseWait::new(ResponseWait::MAX + Duration::from_nanos(1)).is_none());
}
