//! Reader-level wire scenarios with independent response construction.
//!
//! These model command/response contracts, not physical device operation.

use felica_packet::Idm;
use iso14443::nfca::Selection as _;
use rcs956::{
    felica::BitRate,
    mifare,
    nfcb::{PollOptions, RfProfile},
    reader::{
        ApduCause, ApduError, ConfigurationError, DepActivation, DepError, DepMode, DepRate,
        DepTransferCause, Error as ReaderError, FelicaListen, FelicaRole, MAX_DEP_MESSAGE_BYTES,
        Reader, RfTimeout, TargetExchangeError, TypeBSelection,
    },
    transport::{Failure, Progress, TransactionError},
};
use reader_script::rcs956::{
    Answer, Request, Script, Step, ab_config_image, ab_mode, bank_addresses, command, config_image,
    idle_receiver, initialization, mode_configuration, poll_request, poll_response, timeout,
    type_a_response, type_b_response,
};
use std::{error::Error, time::Duration};

#[test]
fn initialization_commits_reset_and_loads_four_distinct_banks() -> Result<(), Box<dyn Error>> {
    let expected = config_image();
    let (script, journal) = Script::new(initialization(&expected));
    let mut reader = Reader::new(script);
    let info = reader.initialize()?;
    assert_eq!(info.firmware, [0x32, 1, 6, 7]);
    assert_eq!(info.flags, 0x1c);
    assert_eq!(info.configuration.model().word(), 0x0131);
    assert_eq!(info.configuration.bytes(), &expected);
    assert_eq!(journal.borrow().recoveries, 2);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn partial_configuration_failure_keeps_reader_uninitialized() -> Result<(), Box<dyn Error>> {
    let config = config_image();
    let mut steps = initialization(&config);
    let bank = steps
        .iter()
        .position(|s| s.request == Request::Command(6, bank_addresses(1)))
        .ok_or("missing bank 1")?;
    steps.truncate(bank + 1);
    steps[bank].answer = Answer::LostAfterAck;
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    let result = reader.initialize();
    assert!(matches!(
        result,
        Err(ReaderError::Transaction(TransactionError {
            progress: Progress::Acknowledged,
            ..
        }))
    ));
    let sent = journal.borrow().requests.len();
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, poll_request()?, timeout()?),
        Err(ReaderError::NotInitialized)
    ));
    assert!(matches!(reader.rf_off(), Err(ReaderError::NotInitialized)));
    assert_eq!(journal.borrow().requests.len(), sent);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn short_configuration_bank_is_rejected_without_publishing_readiness() -> Result<(), Box<dyn Error>>
{
    let config = config_image();
    let mut steps = initialization(&config);
    let bank = steps
        .iter()
        .position(|s| s.request == Request::Command(6, bank_addresses(0)))
        .ok_or("missing bank 0")?;
    steps.truncate(bank + 1);
    steps[bank].answer = Answer::Data(config[..63].to_vec());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    assert!(matches!(
        reader.initialize(),
        Err(ReaderError::Response("configuration bank length"))
    ));
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, poll_request()?, timeout()?),
        Err(ReaderError::NotInitialized)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn invalid_configuration_checksum_is_not_published() -> Result<(), Box<dyn Error>> {
    let mut config = config_image();
    config[0x40] ^= 1;
    let mut steps = initialization(&config);
    let bank = steps
        .iter()
        .position(|s| s.request == Request::Command(6, bank_addresses(3)))
        .ok_or("missing bank 3")?;
    steps.truncate(bank + 1);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    assert!(matches!(
        reader.initialize(),
        Err(ReaderError::Configuration(ConfigurationError::Checksum {
            offset: 0x40
        }))
    ));
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, poll_request()?, timeout()?),
        Err(ReaderError::NotInitialized)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn rejected_rf_retry_setting_is_not_published() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&config_image());
    let retry = steps
        .iter()
        .position(|s| s.request == Request::Command(0x32, vec![4, 0]))
        .ok_or("missing RF retry setting")?;
    steps.truncate(retry + 1);
    steps[retry].answer = Answer::Data(vec![0]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    assert!(matches!(
        reader.initialize(),
        Err(ReaderError::Response("RF retry response length"))
    ));
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, poll_request()?, timeout()?),
        Err(ReaderError::NotInitialized)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn mode_register_failure_does_not_publish_a_configured_reader() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&config_image());
    let mut settings = mode_configuration();
    settings[4].answer = Answer::Data(vec![1]);
    steps.extend(settings);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, poll_request()?, timeout()?),
        Err(ReaderError::RegisterStatus(1))
    ));
    let sent = journal.borrow().requests.len();
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, poll_request()?, timeout()?),
        Err(ReaderError::NotInitialized)
    ));
    assert_eq!(journal.borrow().requests.len(), sent);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn failed_timer_change_revokes_preceding_mode() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]));
    steps.push(Step {
        request: Request::Command(0x1c, vec![0x80, 0xc7, 0]),
        answer: Answer::LostAfterAck,
    });
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert!(
        reader
            .poll_felica(BitRate::Kbps212, poll_request()?, timeout()?)?
            .is_none()
    );
    assert!(matches!(
        reader.poll_felica(
            BitRate::Kbps212,
            poll_request()?,
            RfTimeout::new(Duration::from_millis(1500))?
        ),
        Err(ReaderError::Transaction(_))
    ));
    let sent = journal.borrow().requests.len();
    assert!(matches!(
        reader.poll_felica(BitRate::Kbps212, poll_request()?, timeout()?),
        Err(ReaderError::NotInitialized)
    ));
    assert_eq!(journal.borrow().requests.len(), sent);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_a_apdu_wait_follows_the_ats_frame_wait_not_the_exchange_timeout()
-> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.push(idle_receiver());
    steps.push(command(
        0x4a,
        &[1, 0],
        &[1, 7, 4, 0, 0x20, 4, 1, 2, 3, 4, 3, 0x20, 0x40],
    ));
    // The reader runs ISO-DEP: 4 FWT (FWI 4) + 2 FWT (FWI 14) = 9.92 s, so
    // the 1C timer rounds up to 10 s and no 32/02 selector is programmed.
    steps.push(command(0x1c, &[0x80, 0xe7, 3], &[]));
    steps.push(command(0x40, &[7, 0, 0xa4, 4, 0], &[0, 0x90, 0]));
    steps.push(command(0x40, &[7, 0, 0xb0, 0, 0], &[0, 0x6a, 0x82]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?;
    card.set_exchange_timeout(RfTimeout::new(Duration::from_millis(3280))?);
    assert_eq!(card.exchange_apdu(&[0, 0xa4, 4, 0])?, [0x90, 0]);
    assert_eq!(card.exchange_apdu(&[0, 0xb0, 0, 0])?, [0x6a, 0x82]);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn raw_type_a_recovers_pending_fragments_before_sending_another_command()
-> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.push(idle_receiver());
    steps.push(command(
        0x4a,
        &[1, 0],
        &[1, 7, 4, 0, 0x20, 4, 1, 2, 3, 4, 3, 0x20, 0x40],
    ));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]));
    steps.push(command(0x40, &[7, 0, 0xa4, 4, 0], &[0x40, 0x90, 0]));
    steps.push(command(0x40, &[7], &[0xc0, 0x11]));
    steps.push(command(0x40, &[7], &[0, 0x22]));
    steps.push(command(0x40, &[7, 0x30, 0], &[0x0d]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let card = reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?;
    assert_eq!(card.observation().uid(), &[1, 2, 3, 4]);
    assert_eq!(card.target(), 7);
    let mut card = card.into_raw();
    let before = journal.borrow().requests.len();
    assert!(matches!(
        card.exchange(&vec![0; 263]),
        Err(TargetExchangeError::InputLength {
            maximum: 262,
            actual: 263
        })
    ));
    assert!(card.receive_continuation()?.is_none());
    assert_eq!(journal.borrow().requests.len(), before);
    let reply = card.exchange(&[0, 0xa4, 4, 0])?;
    assert_eq!(reply.status, 0x40);
    assert_eq!(reply.data, [0x90, 0]);
    let before = journal.borrow().requests.len();
    assert!(matches!(
        card.exchange(&[0x30, 0]),
        Err(TargetExchangeError::ResponsePending)
    ));
    assert_eq!(journal.borrow().requests.len(), before);
    let reply = card
        .receive_continuation()?
        .ok_or("expected second fragment")?;
    assert_eq!(reply.status, 0xc0);
    assert_eq!(reply.data, [0x11]);
    assert!(matches!(
        card.exchange(&[0x30, 0]),
        Err(TargetExchangeError::ResponsePending)
    ));
    let reply = card
        .receive_continuation()?
        .ok_or("expected final fragment")?;
    assert_eq!(reply.status, 0);
    assert_eq!(reply.data, [0x22]);
    assert!(card.receive_continuation()?.is_none());
    assert!(matches!(
        card.exchange(&[0x30, 0]),
        Err(TargetExchangeError::Exchange(ReaderError::RfStatus(0x0d)))
    ));
    let before = journal.borrow().requests.len();
    assert!(matches!(
        card.exchange(&[0x30, 0]),
        Err(TargetExchangeError::SessionInvalid)
    ));
    assert_eq!(journal.borrow().requests.len(), before);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn incomplete_raw_type_a_response_requires_reader_recovery() -> Result<(), Box<dyn Error>> {
    for read_continuation in [false, true] {
        let mut steps = initialization(&ab_config_image());
        steps.extend(ab_mode(false));
        steps.extend([
            idle_receiver(),
            command(0x4a, &[1, 0], &type_a_response(7)),
            command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
            command(0x40, &[7, 0xa4], &[0x40, 0x11]),
        ]);
        if read_continuation {
            steps.push(command(0x40, &[7], &[1]));
        }
        steps.extend(initialization(&ab_config_image()));
        steps.extend(ab_mode(false));
        steps.push(idle_receiver());
        steps.push(command(0x4a, &[1, 0], &[0]));
        let (script, journal) = Script::new(steps);
        let mut reader = Reader::new(script);
        reader.initialize()?;
        {
            let mut card = reader
                .poll_type_a(timeout()?)?
                .ok_or("expected NFC-A card")?
                .into_raw();
            assert_eq!(card.exchange(&[0xa4])?.status, 0x40);
            if read_continuation {
                assert!(matches!(
                    card.receive_continuation(),
                    Err(TargetExchangeError::Exchange(ReaderError::RfStatus(1)))
                ));
                assert!(matches!(
                    card.exchange(&[0xa4]),
                    Err(TargetExchangeError::SessionInvalid)
                ));
            }
        }
        let before = journal.borrow().requests.len();
        assert!(matches!(reader.rf_off(), Err(ReaderError::NotInitialized)));
        assert!(matches!(
            reader.poll_type_a(timeout()?),
            Err(ReaderError::NotInitialized)
        ));
        assert_eq!(journal.borrow().requests.len(), before);
        reader.initialize()?;
        assert!(reader.poll_type_a(timeout()?)?.is_none());
        assert_eq!(journal.borrow().remaining, 0);
    }
    Ok(())
}

#[test]
fn raw_type_a_stops_collecting_at_the_fragment_limit() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &type_a_response(7)),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(0x40, &[7, 0xa4], &[0x40]),
    ]);
    steps.extend((1..256).map(|_| command(0x40, &[7], &[0x40])));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut raw = reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?
        .into_raw();
    raw.exchange(&[0xa4])?;
    for _ in 1..256 {
        assert_eq!(
            raw.receive_continuation()?
                .ok_or("expected fragment")?
                .status,
            0x40
        );
    }
    assert!(matches!(
        raw.receive_continuation(),
        Err(TargetExchangeError::FragmentLimit)
    ));
    assert!(matches!(
        raw.exchange(&[0xa4]),
        Err(TargetExchangeError::SessionInvalid)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn failed_field_cycle_does_not_grant_a_new_typed_selection() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &type_a_response(7)),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(0x40, &[7, 0xa4], &[0]),
        command(0x32, &[1, 0], &[1]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?
        .into_raw()
        .exchange(&[0xa4])?;
    assert!(matches!(
        reader.poll_type_a(timeout()?),
        Err(ReaderError::Response("RF off response length"))
    ));
    let before = journal.borrow().requests.len();
    assert!(matches!(
        reader.poll_type_a(timeout()?),
        Err(ReaderError::NotInitialized)
    ));
    assert_eq!(journal.borrow().requests.len(), before);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn protocol_changes_reapply_rf_settings_and_absence_is_not_activation() -> Result<(), Box<dyn Error>>
{
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 0], &[0]));
    steps.extend(ab_mode(true));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 3, 0, 1], &[0]));
    steps.extend(mode_configuration());
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert!(reader.poll_type_a(timeout()?)?.is_none());
    assert!(
        reader
            .poll_type_b(PollOptions::default(), timeout()?)?
            .is_none()
    );
    assert!(
        reader
            .poll_felica(BitRate::Kbps212, poll_request()?, timeout()?)?
            .is_none()
    );
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_b_activation_register_failure_revokes_readiness() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(true));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 3, 0, 1], &type_b_response()));
    steps.push(command(8, &[0x63, 3, 0x8b], &[1]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    assert!(matches!(
        reader.poll_type_b(PollOptions::default(), timeout()?),
        Err(ReaderError::RegisterStatus(1))
    ));
    let before = journal.borrow().requests.len();
    assert!(matches!(
        reader.poll_type_a(timeout()?),
        Err(ReaderError::NotInitialized)
    ));
    assert_eq!(journal.borrow().requests.len(), before);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn alternate_type_b_profile_exchanges_a_proprietary_target_command() -> Result<(), Box<dyn Error>> {
    let mut response = type_b_response();
    response[12] = 0x50; // ATQB protocol type 0, FSCI5.
    let mut image = ab_config_image();
    image[0xcf..=0xd1].copy_from_slice(&[0xa1, 0xa2, 0xa3]);
    let mut steps = initialization(&image);
    steps.extend([
        command(0x1c, &[0x80, 0x63, 0], &[]),
        command(0x32, &[5, 0, 0, 4], &[]),
        command(0x32, &[0x81, 0x8f], &[]),
        command(
            0x32,
            &[0x0a, 0x41, 0xa1, 0x42, 0xa2, 0x43, 0xa3, 16, 17, 18, 19, 20],
            &[],
        ),
        command(0x32, &[0x0c, 0xa1, 0xa2, 0xa3], &[]),
        command(8, &[0x63, 0x0d, 0], &[0]),
        idle_receiver(),
        command(0x4a, &[1, 3, 0x12, 1], &response),
        command(8, &[0x63, 3, 0x8b], &[0]),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(0x40, &[9, 0x42, 0x43], &[0, 0xa5]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let options = PollOptions {
        profile: RfProfile::Alternate,
        afi: 0x12,
    };
    let Some(TypeBSelection::Frame(mut card)) = reader.poll_type_b(options, timeout()?)? else {
        return Err("expected a frame selection".into());
    };
    assert!(matches!(
        card.exchange(&[0; 64]),
        Err(TargetExchangeError::InputLength {
            maximum: 63,
            actual: 64
        })
    ));
    assert_eq!(card.exchange(&[0x42, 0x43])?.data, [0xa5]);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_b_frame_response_that_cannot_complete_revokes_the_selection() -> Result<(), Box<dyn Error>>
{
    let mut response = type_b_response();
    response[12] = 0x50; // ATQB protocol type 0, FSCI5.
    // A further fragment and an absent status both leave the reader's
    // continuation state unknown.
    for reply in [vec![0x40, 0xa5], vec![]] {
        let mut steps = initialization(&ab_config_image());
        steps.extend(ab_mode(true));
        steps.extend([
            idle_receiver(),
            command(0x4a, &[1, 3, 0, 1], &response),
            command(8, &[0x63, 3, 0x8b], &[0]),
            command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
            command(0x40, &[9, 0x42], &reply),
        ]);
        let (script, journal) = Script::new(steps);
        let mut reader = Reader::new(script);
        reader.initialize()?;
        let Some(TypeBSelection::Frame(mut card)) =
            reader.poll_type_b(PollOptions::default(), timeout()?)?
        else {
            return Err("expected a frame selection".into());
        };
        let first = card.exchange(&[0x42]);
        assert!(match reply.as_slice() {
            [0x40, ..] => matches!(first, Ok(ref r) if r.status == 0x40),
            _ => matches!(
                first,
                Err(TargetExchangeError::Exchange(ReaderError::Response(_)))
            ),
        });
        assert!(matches!(
            card.exchange(&[0x43]),
            Err(TargetExchangeError::SessionInvalid)
        ));
        assert_eq!(journal.borrow().remaining, 0);
    }
    Ok(())
}

#[test]
fn type_a_apdu_continuation_sends_no_second_application_command() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &type_a_response(7)),
        command(0x1c, &[0x80, 0xe7, 3], &[]),
        command(0x40, &[7, 0xa4], &[0x40, 0x11]),
        command(0x40, &[7], &[0, 0x22, 0x90, 0]),
        command(0x40, &[7, 0xb0], &[0x40, 0x33]),
        command(0x40, &[7], &[1]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?;
    assert_eq!(card.exchange_apdu(&[0xa4])?, [0x11, 0x22, 0x90, 0]);
    let error = card
        .exchange_apdu(&[0xb0])
        .err()
        .ok_or("expected continuation failure")?;
    assert!(matches!(
        error.cause,
        ApduCause::Exchange(ReaderError::RfStatus(1))
    ));
    assert_eq!(error.partial_response, [0x33]);
    assert!(error.progress.delivered);
    assert_eq!(error.progress.fragments, 2);
    assert!(matches!(
        card.exchange_apdu(&[0xb0]),
        Err(ApduError {
            cause: ApduCause::SessionInvalid,
            ..
        })
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_a_apdu_response_overflow_reports_delivery_without_bytes() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &type_a_response(7)),
        command(0x1c, &[0x80, 0xe7, 3], &[]),
        command(0x40, &[7, 0xb0], &[0x0e]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?;
    let error = card
        .exchange_apdu(&[0xb0])
        .err()
        .ok_or("expected response overflow")?;
    assert!(matches!(error.cause, ApduCause::ReaderResponseLimit));
    assert!(error.partial_response.is_empty());
    assert!(error.progress.delivered);
    assert_eq!(error.progress.fragments, 1);
    assert_eq!(error.progress.received_bytes, 0);
    assert!(matches!(
        card.exchange_apdu(&[0xb0]),
        Err(ApduError {
            cause: ApduCause::SessionInvalid,
            ..
        })
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn mifare_classic_authority_is_limited_to_the_authenticated_sector() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    let mut write = vec![7, 0xa0, 130];
    write.extend([0x5a; 16]);
    let mut read_response = vec![0];
    read_response.extend([0x44; 16]);
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 0], &[1, 7, 4, 0, 0x18, 7, 1, 2, 3, 4, 5, 6, 7]),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(0x40, &[7, 0x61, 129, 1, 2, 3, 4, 5, 6, 4, 5, 6, 7], &[0]),
        command(0x40, &[7, 0x30, 143], &read_response),
        command(0x40, &write, &[0x0b]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut card = reader
        .poll_type_a(timeout()?)?
        .ok_or("expected NFC-A card")?;
    let mut sector =
        card.authenticate_mifare_classic(129, mifare::KeyKind::B, &[1, 2, 3, 4, 5, 6])?;
    assert!(matches!(
        sector.read_block(144),
        Err(mifare::Error::Block(144))
    ));
    assert_eq!(sector.read_block(143)?, [0x44; 16]);
    assert!(matches!(
        sector.write_block(130, &[0x5a; 16]),
        Err(mifare::Error::Exchange(TargetExchangeError::Exchange(
            ReaderError::RfStatus(0x0b)
        )))
    ));
    assert!(matches!(
        sector.read_block(143),
        Err(mifare::Error::AuthenticationLost)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn passive_dep_owns_activation_and_one_response_at_a_time() -> Result<(), Box<dyn Error>> {
    let configuration = ab_config_image();
    let mut steps = initialization(&configuration);
    steps.extend([
        command(8, &[0x63, 0x0b, 0x80], &[0]),
        command(0x32, &[0x82, 8, 2, 8], &[]),
        command(0x12, &[0x18], &[]),
        command(8, &[0x63, 1, 0x7b], &[0]),
        command(8, &[0x63, 2, 0xb0], &[0]),
        command(8, &[0x63, 3, 0xb0], &[0]),
        command(8, &[0x63, 0x0d, 8], &[0]),
        command(
            0x8c,
            &[
                2, 1, 1, 0x31, 0x32, 0x33, 0x40, 1, 0xfe, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 0xfe, 0x31, 0x32, 0x33,
                0x34, 0x35, 0x36, 0, 0,
            ],
            &[
                0x10, 19, 0xd4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 2, 0x46, 0x66,
            ],
        ),
        command(0x92, &[0x46, 0x66, 0x6d], &[0]),
        command(0x86, &[], &[0xc0, 0x12, 0x11]),
        command(0x86, &[], &[0, 0x22]),
        command(0x94, &[0x12; 252], &[0]),
        command(0x8e, &[0x12; 2], &[0]),
        command(0x86, &[], &[0x40, 0x44]),
        command(0x86, &[], &[0x01]),
    ]);
    steps.extend(initialization(&configuration));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    let mut target = reader.listen_passive_dep(*b"123456", b"Ffm", timeout()?)?;
    assert_eq!(target.initiator().rate, DepRate::Kbps212);
    assert_eq!(target.initiator().general_bytes, [0x46, 0x66]);
    {
        let mut request = target.receive(timeout()?)?;
        assert_eq!(request.payload(), [0x11, 0x22]);
        assert_eq!(request.node_address(), Some(0x12));
        assert!(matches!(
            request.respond(&[0; MAX_DEP_MESSAGE_BYTES + 1]),
            Err(DepError::MessageLength(_))
        ));
        request.respond(&[0x12; 253])?;
        assert!(matches!(
            request.respond(&[0x33]),
            Err(DepError::SessionUnavailable)
        ));
    }
    assert!(matches!(
        target.receive(timeout()?),
        Err(DepError::Transfer {
            attempted: 0, accepted: 0, received,
            cause: DepTransferCause::Status(1),
        }) if received.payload == [0x44]
    ));
    assert!(matches!(
        target.receive(timeout()?),
        Err(DepError::SessionUnavailable)
    ));
    target.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn stalled_receiver_is_restarted_before_activation() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&config_image());
    steps.extend(mode_configuration());
    steps.extend([
        command(6, &[0x63, 0x37, 0x63, 0x31], &[0x08, 0x2c]),
        command(8, &[0x63, 0x31, 0x28, 0x63, 0x31, 0x20], &[0, 0]),
        command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]),
        idle_receiver(),
        command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &[0]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    for _ in 0..2 {
        assert!(
            reader
                .poll_felica(BitRate::Kbps212, poll_request()?, timeout()?)?
                .is_none()
        );
    }
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn failed_receiver_restart_sends_no_activation() -> Result<(), Box<dyn Error>> {
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.extend([
        command(6, &[0x63, 0x37, 0x63, 0x31], &[0]),
        command(6, &[0x63, 0x37, 0x63, 0x31], &[0x08, 0]),
        command(8, &[0x63, 0x31, 0x08, 0x63, 0x31, 0], &[0, 5]),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    // A malformed probe wrote nothing, so the configured mode stays usable.
    assert!(matches!(
        reader.poll_type1(timeout()?),
        Err(TargetExchangeError::Preparation(ReaderError::Response(_)))
    ));
    // A partially applied restart leaves the receiver state unknown.
    assert!(matches!(
        reader.poll_type_a(timeout()?),
        Err(ReaderError::RegisterStatus(5))
    ));
    assert!(matches!(
        reader.poll_type_a(timeout()?),
        Err(ReaderError::NotInitialized)
    ));
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn passive_dep_at_106_kbps_prepares_target_registers_and_restores_parameters()
-> Result<(), Box<dyn Error>> {
    let configuration = ab_config_image();
    let mut steps = initialization(&configuration);
    steps.extend([
        command(8, &[0x63, 0x0b, 0x80], &[0]),
        command(0x32, &[0x82, 8, 2, 8], &[]),
        command(0x12, &[0x18], &[]),
        command(8, &[0x63, 1, 0x7b], &[0]),
        command(8, &[0x63, 2, 0xb0], &[0]),
        command(8, &[0x63, 3, 0xb0], &[0]),
        command(8, &[0x63, 0x0d, 8], &[0]),
        command(
            0x8c,
            &[
                2, 1, 1, 0x31, 0x32, 0x33, 0x40, 1, 0xfe, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 0xfe, 0x31, 0x32, 0x33,
                0x34, 0x35, 0x36, 0, 0,
            ],
            &[
                0, 19, 0xd4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 2, 0x46, 0x66,
            ],
        ),
        command(8, &[0x63, 0x0d, 0], &[0]),
        command(8, &[0x63, 1, 0x3b], &[0]),
        command(0x92, &[], &[0]),
    ]);
    steps.extend(initialization(&configuration));
    steps.extend(ab_mode(false));
    steps.extend([idle_receiver(), command(0x4a, &[1, 0], &type_a_response(7))]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    let target = reader.listen_passive_dep(*b"123456", &[], timeout()?)?;
    assert_eq!(target.initiator().rate, DepRate::Kbps106);
    target.finish()?;
    let card = reader.poll_type_a(timeout()?)?.ok_or("NFC-A card absent")?;
    assert!(card.observation().ats().is_some());
    let parameters: Vec<Vec<u8>> = journal
        .borrow()
        .requests
        .iter()
        .filter_map(|request| match request {
            Request::Command(0x12, args) => Some(args.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(parameters, [[0x1c], [0x18], [0x1c]]);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn initialization_restores_reception_setting_left_by_a_212_kbps_target()
-> Result<(), Box<dyn Error>> {
    let configuration = ab_config_image();
    let mut steps = initialization(&configuration);
    steps.extend([
        command(8, &[0x63, 0x0b, 0x80], &[0]),
        command(0x32, &[0x82, 8, 2, 8], &[]),
        command(0x12, &[0x18], &[]),
        command(8, &[0x63, 1, 0x7b], &[0]),
        command(8, &[0x63, 2, 0xb0], &[0]),
        command(8, &[0x63, 3, 0xb0], &[0]),
        command(8, &[0x63, 0x0d, 8], &[0]),
        command(
            0x8c,
            &[
                2, 1, 1, 0x31, 0x32, 0x33, 0x40, 1, 0xfe, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 0xfe, 0x31, 0x32, 0x33,
                0x34, 0x35, 0x36, 0, 0,
            ],
            &[0x10, 17, 0xd4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0],
        ),
        command(0x92, &[], &[0]),
    ]);
    // Finishing the 212 kbps target, then the initiator's own initialization.
    steps.extend(initialization(&configuration));
    steps.extend(initialization(&configuration));
    steps.extend([
        command(0x12, &[0x1c], &[]),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(0x32, &[5, 0, 0, 0], &[]),
        command(
            0x56,
            &[0, 0, 0],
            &[0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 8, 0],
        ),
    ]);
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    let target = reader.listen_passive_dep(*b"123456", &[], timeout()?)?;
    assert_eq!(target.initiator().rate, DepRate::Kbps212);
    target.finish()?;
    reader.activate_dep(
        DepActivation {
            mode: DepMode::Passive,
            rate: DepRate::Kbps106,
            nfcid3: None,
            general_bytes: &[],
            node_address: None,
        },
        timeout()?,
    )?;
    let journal = journal.borrow();
    let activation = journal
        .requests
        .iter()
        .position(|request| matches!(request, Request::Command(0x56, _)))
        .ok_or("NFC-DEP activation not sent")?;
    let reception = journal.requests[..activation]
        .iter()
        .rev()
        .find_map(|request| match request {
            Request::Command(8, args) if args.starts_with(&[0x63, 0x0d]) => Some(args.clone()),
            _ => None,
        });
    assert_eq!(reception, Some(vec![0x63, 0x0d, 0]));
    assert_eq!(journal.remaining, 0);
    Ok(())
}

#[test]
fn dep_initiator_uses_meta_chaining_and_retains_partial_failure() -> Result<(), Box<dyn Error>> {
    let configuration = ab_config_image();
    let mut steps = initialization(&configuration);
    let mut first = vec![0x41, 0x31];
    first.extend([0xa5; 251]);
    steps.extend([
        command(0x12, &[0x1d], &[]),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(0x32, &[5, 0, 0, 0], &[]),
        command(
            0x56,
            &[1, 1, 4, 0x46, 0x66, 0x6d],
            &[0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 8, 3, 0x46],
        ),
        command(0x40, &first, &[0]),
        command(0x40, &[1, 0xa5, 0xa5], &[0xc0, 0x31, 0xab]),
        command(0x40, &[1], &[0, 0xcd]),
        command(0x40, &[1, 0x31, 0x22], &[0xc0, 0x31, 0xef]),
        command(0x40, &[1], &[0x01]),
    ]);
    steps.extend(initialization(&configuration));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    let mut link = reader.activate_dep(
        DepActivation {
            mode: DepMode::Active,
            rate: DepRate::Kbps212,
            nfcid3: None,
            general_bytes: b"Ffm",
            node_address: Some(0x31),
        },
        timeout()?,
    )?;
    assert_eq!(link.peer().general_bytes, b"F");
    let reply = link.exchange(&[0xa5; 253])?;
    assert_eq!(reply.node_address, Some(0x31));
    assert_eq!(reply.payload, [0xab, 0xcd]);
    assert!(matches!(
        link.exchange(&[0x22]),
        Err(DepError::Transfer {
            attempted: 1, accepted: 1, received,
            cause: DepTransferCause::Status(1),
        }) if received.payload == [0xef] && received.node_address == Some(0x31)
    ));
    assert!(matches!(
        link.exchange(&[]),
        Err(DepError::SessionUnavailable)
    ));
    link.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn dep_initiator_transfers_252_byte_groups_in_both_directions() -> Result<(), Box<dyn Error>> {
    let configuration = ab_config_image();
    let mut steps = initialization(&configuration);
    steps.extend([
        command(0x12, &[0x1c], &[]),
        command(0x32, &[2, 0x0b, 0x0b, 0x0b], &[]),
        command(0x32, &[5, 0, 0, 0], &[]),
        command(
            0x56,
            &[1, 1, 0],
            &[0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 8, 0],
        ),
    ]);
    let mut outgoing = Vec::new();
    let mut incoming = Vec::new();
    for index in 0..8 {
        let mut fragment = vec![0x41];
        fragment.extend([index; 252]);
        steps.push(command(0x40, &fragment, &[0]));
        outgoing.extend([index; 252]);
    }
    let mut tail = vec![0x01];
    tail.extend([8; 32]);
    outgoing.extend([8; 32]);
    for index in 0..8 {
        let mut response = vec![0x40];
        response.extend([0xa0 + index; 252]);
        let command_data = if index == 0 { tail.as_slice() } else { &[1] };
        steps.push(command(0x40, command_data, &response));
        incoming.extend([0xa0 + index; 252]);
    }
    let mut response = vec![0];
    response.extend([0xa8; 32]);
    steps.push(command(0x40, &[1], &response));
    steps.push(command(0x40, &[1, 0x77], &[0, 0xaa]));
    incoming.extend([0xa8; 32]);
    steps.extend(initialization(&configuration));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    let mut link = reader.activate_dep(
        DepActivation {
            mode: DepMode::Active,
            rate: DepRate::Kbps212,
            nfcid3: None,
            general_bytes: &[],
            node_address: None,
        },
        timeout()?,
    )?;
    assert_eq!(link.exchange(&outgoing)?.payload, incoming);
    assert_eq!(link.exchange(&[0x77])?.payload, [0xaa]);
    link.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_a_timeout_applies_the_official_500ms_selector_before_exchange() -> Result<(), Box<dyn Error>>
{
    let mut steps = initialization(&ab_config_image());
    steps.extend(ab_mode(false));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 0], &type_a_response(7)));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x0e], &[]));
    steps.push(command(0x40, &[7, 0, 0xa4, 4, 0], &[0, 0x90, 0]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let wait = RfTimeout::new(Duration::from_millis(500))?;
    let mut card = reader
        .poll_type_a(wait)?
        .ok_or("expected NFC-A card")?
        .into_raw();
    assert_eq!(card.exchange(&[0, 0xa4, 4, 0])?.data, [0x90, 0]);
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_a_apdu_host_wait_covers_the_reader_iso_dep_bound() -> Result<(), Box<dyn Error>> {
    // FWI 12: 4 FWT + 2 FWT (FWI 14) = 14.85 s; the host adds one second.
    let mut activation = type_a_response(7);
    activation[12] = 0xc0;
    for (delay, completes) in [
        (Duration::from_secs(12), true),
        (Duration::from_secs(16), false),
    ] {
        let mut steps = initialization(&ab_config_image());
        steps.extend(ab_mode(false));
        steps.push(idle_receiver());
        steps.push(command(0x4a, &[1, 0], &activation));
        steps.push(command(0x1c, &[0x80, 0xdb, 5], &[]));
        steps.push(Step {
            request: Request::Command(0x40, vec![7, 0, 0xa4, 4, 0]),
            answer: Answer::Late(delay, vec![0, 0x90, 0]),
        });
        let (script, journal) = Script::new(steps);
        let mut reader = Reader::new(script);
        reader.initialize()?;
        let mut card = reader
            .poll_type_a(timeout()?)?
            .ok_or("expected NFC-A card")?;
        assert_eq!(card.observation().ats().map(|ats| ats.fwi()), Some(12));
        let result = card.exchange_apdu(&[0, 0xa4, 4, 0]);
        if completes {
            assert_eq!(result?, [0x90, 0]);
        } else {
            assert!(matches!(
                result,
                Err(ApduError {
                    cause: ApduCause::Exchange(ReaderError::Transaction(TransactionError {
                        progress: Progress::Acknowledged,
                        failure: Failure::Deadline,
                    })),
                    ..
                })
            ));
        }
        assert_eq!(journal.borrow().remaining, 0);
    }
    Ok(())
}

#[test]
fn type_a_quantized_timer_and_selector_cache_have_independent_lifetimes()
-> Result<(), Box<dyn Error>> {
    let two_second_mode = || {
        let mut setup = ab_mode(false);
        setup[0] = command(0x1c, &[0x80, 0xc7, 0], &[]);
        setup
    };
    let mut steps = initialization(&ab_config_image());
    steps.extend(two_second_mode());
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 0], &type_a_response(7)));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x10], &[]));
    steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
    steps.push(command(0x40, &[7, 0xa4], &[0, 0x90, 0]));
    steps.push(command(0x40, &[7, 0xb0], &[0, 0x90, 0]));
    // Selecting after raw commands cycles the field and restores the polling
    // timer. The raw command then restores the effective quantized timer; the
    // successfully applied 32/02 selector is still valid.
    steps.push(command(0x32, &[1, 0], &[]));
    steps.extend(two_second_mode());
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 0], &type_a_response(9)));
    steps.push(command(0x1c, &[0x80, 0x8f, 1], &[]));
    steps.push(command(0x40, &[9, 0xa4], &[0, 0x90, 0]));
    // A different timing step changes 32/02. RF-off retains that independent
    // setting; reset must invalidate it even if the next requested step matches.
    steps.push(command(0x32, &[1, 0], &[]));
    steps.extend(ab_mode(false));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 0], &type_a_response(5)));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x0e], &[]));
    steps.push(command(0x40, &[5, 0xa4], &[0, 0x90, 0]));
    steps.push(command(0x32, &[1, 0], &[]));
    steps.extend(ab_mode(false));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 0], &type_a_response(6)));
    steps.push(command(0x40, &[6, 0xa4], &[0, 0x90, 0]));
    // Reset revokes the selector; a later activation must program it again.
    steps.extend(initialization(&ab_config_image()));
    steps.extend(ab_mode(false));
    steps.push(idle_receiver());
    steps.push(command(0x4a, &[1, 0], &type_a_response(3)));
    steps.push(command(0x32, &[2, 0x0b, 0x0b, 0x0e], &[]));
    steps.push(command(0x40, &[3, 0xa4], &[0, 0x90, 0]));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let wait = RfTimeout::new(Duration::from_secs(2))?;
    {
        let mut card = reader
            .poll_type_a(wait)?
            .ok_or("expected NFC-A card")?
            .into_raw();
        card.exchange(&[0xa4])?;
        card.exchange(&[0xb0])?;
    }
    reader
        .poll_type_a(wait)?
        .ok_or("expected NFC-A card")?
        .into_raw()
        .exchange(&[0xa4])?;
    let short_wait = RfTimeout::new(Duration::from_millis(500))?;
    reader
        .poll_type_a(short_wait)?
        .ok_or("expected NFC-A card")?
        .into_raw()
        .exchange(&[0xa4])?;
    reader.rf_off()?;
    reader
        .poll_type_a(short_wait)?
        .ok_or("expected NFC-A card")?
        .into_raw()
        .exchange(&[0xa4])?;
    reader.initialize()?;
    reader
        .poll_type_a(short_wait)?
        .ok_or("expected NFC-A card")?
        .into_raw()
        .exchange(&[0xa4])?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type_a_failures_distinguish_timing_setup_from_card_exchange() -> Result<(), Box<dyn Error>> {
    for lost_command in [0x32, 0x1c, 0x40] {
        let mut steps = initialization(&ab_config_image());
        let mut setup = ab_mode(false);
        setup[0] = command(0x1c, &[0x80, 0xc7, 0], &[]);
        steps.extend(setup);
        steps.push(idle_receiver());
        steps.push(command(0x4a, &[1, 0], &type_a_response(7)));
        let selector = [2, 0x0b, 0x0b, 0x10];
        let timer = [0x80, 0x8f, 1];
        let args = match lost_command {
            0x32 => selector.to_vec(),
            0x1c => {
                steps.push(command(0x32, &selector, &[]));
                timer.to_vec()
            }
            _ => {
                steps.push(command(0x32, &selector, &[]));
                steps.push(command(0x1c, &timer, &[]));
                vec![7, 0xa4]
            }
        };
        let request = Request::Command(lost_command, args);
        steps.push(Step {
            request: request.clone(),
            answer: Answer::LostAfterAck,
        });
        let (script, journal) = Script::new(steps);
        let mut reader = Reader::new(script);
        reader.initialize()?;
        let mut card = reader
            .poll_type_a(RfTimeout::new(Duration::from_secs(2))?)?
            .ok_or("expected NFC-A card")?
            .into_raw();
        let result = card.exchange(&[0xa4]);
        let error = match result {
            Err(TargetExchangeError::Exchange(error)) if lost_command == 0x40 => error,
            Err(TargetExchangeError::Preparation(error)) if lost_command != 0x40 => error,
            other => {
                return Err(
                    format!("unexpected error phase for {lost_command:02x}: {other:?}").into(),
                );
            }
        };
        assert!(matches!(
            error,
            ReaderError::Transaction(TransactionError {
                progress: Progress::Acknowledged,
                ..
            })
        ));
        assert_eq!(journal.borrow().requests.last(), Some(&request));
        let count = journal.borrow().requests.len();
        assert!(matches!(
            card.exchange(&[0xa4]),
            Err(TargetExchangeError::SessionInvalid)
        ));
        assert_eq!(journal.borrow().requests.len(), count);
        assert_eq!(journal.borrow().remaining, 0);
    }
    Ok(())
}

#[test]
fn felica_target_listens_right_after_reset_and_streams_packets() -> Result<(), Box<dyn Error>> {
    let configuration = config_image();
    let mut steps = initialization(&configuration);
    let mut args = vec![0, 0, 1, 1, 2, 3, 0];
    args.extend([2, 0xfe, 1, 2, 3, 4, 5, 6]);
    args.extend([0, 0x22, 3, 3, 3, 3, 3, 3, 0x12, 0xfc]);
    args.extend([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x55]);
    steps.extend([
        command(0x8c, &args, &[0x22, 3, 0xaa, 1]),
        command(0x90, &[3, 0xab, 2], &[0]),
        command(0x88, &[], &[0, 2, 0xbc]),
    ]);
    steps.extend(initialization(&configuration));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    let listen = FelicaListen {
        idm: Idm::new([2, 0xfe, 1, 2, 3, 4, 5, 6]),
        pmm: [0, 0x22, 3, 3, 3, 3, 3, 3],
        system_code: 0x12fc,
    };
    let mut activation = reader.listen_felica(listen, timeout()?)?;
    assert_eq!(activation.packet, [3, 0xaa, 1]);
    assert_eq!(activation.link.role(), FelicaRole::Target);
    assert_eq!(activation.link.rate(), BitRate::Kbps424);
    activation.link.send(&[3, 0xab, 2])?;
    assert_eq!(activation.link.receive(timeout()?)?, Some(vec![2, 0xbc]));
    activation.link.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn polled_felica_card_becomes_a_link_without_a_reader_command() -> Result<(), Box<dyn Error>> {
    let configuration = config_image();
    let mut steps = initialization(&configuration);
    steps.extend(mode_configuration());
    steps.extend([
        idle_receiver(),
        command(0x4a, &[1, 1, 0, 0x12, 0x34, 1, 0], &poll_response()),
        command(0xa0, &[0xc8, 0, 2, 0xaa], &[0, 2, 0xab]),
    ]);
    steps.extend(initialization(&configuration));
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let card = reader
        .poll_felica(BitRate::Kbps212, poll_request()?, timeout()?)?
        .ok_or("FeliCa card absent")?;
    let mut link = card.into_link();
    assert_eq!(link.role(), FelicaRole::Initiator);
    assert_eq!(link.rate(), BitRate::Kbps212);
    assert_eq!(
        link.send_receive(&[2, 0xaa], timeout()?)?,
        Some(vec![2, 0xab])
    );
    link.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}
