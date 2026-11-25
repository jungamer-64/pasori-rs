//! GATT transaction scenarios with independent frame construction.

use port110::transport::{Failure, Link, Progress, TransactionError};
use reader_script::port110::{
    ACK, Answer, FILL, Script, Step, command, extended_frame, response_payload,
};
use std::{error::Error, io, time::Duration};

type TestResult = Result<(), Box<dyn Error>>;
/// Whether a failure is the one a case expects.
type Expected = fn(&Failure<io::Error>) -> bool;

const TIMEOUT: Duration = Duration::from_secs(2);

fn step(command: u8, args: &[u8], answer: Answer) -> Step {
    Step {
        command,
        args: args.to_vec(),
        answer,
    }
}

fn response(command: u8, data: &[u8]) -> Result<Vec<u8>, io::Error> {
    extended_frame(&response_payload(command, data)?)
}

fn failure(
    result: Result<port110::transport::Response, TransactionError<io::Error>>,
) -> Result<TransactionError<io::Error>, &'static str> {
    result.err().ok_or("transaction unexpectedly succeeded")
}

#[test]
fn splits_frames_into_twenty_byte_writes_and_joins_split_responses() -> TestResult {
    let args = [0x5a; 255];
    let data = [0xa5; 40];
    let (transport, journal) = Script::new(vec![command(0x04, &args, &data)]);
    let mut link = Link::new(transport);
    let response = link.command(0x04, &args, TIMEOUT)?;
    assert_eq!(
        (response.command, response.data.as_slice()),
        (0x05, &data[..])
    );
    let journal = journal.borrow();
    // 267 frame bytes in 20-byte values; ACK plus 52 response bytes in three values.
    assert_eq!(journal.writes, 14);
    assert_eq!(journal.received, 4);
    Ok(())
}

#[test]
fn discards_values_that_precede_the_ack() -> TestResult {
    let stale = response(0x28, &[0; 8])?;
    let (transport, journal) = Script::new(vec![step(
        0x06,
        &[0],
        Answer::Indications(vec![
            stale[..20].to_vec(),
            stale[20..].to_vec(),
            ACK.to_vec(),
            response(0x06, &[0])?,
        ]),
    )]);
    let mut link = Link::new(transport);
    assert_eq!(link.command(0x06, &[0], TIMEOUT)?.data, [0]);
    assert_eq!(journal.borrow().received, 4);
    Ok(())
}

#[test]
fn an_ack_joined_to_the_response_does_not_acknowledge() -> TestResult {
    let joined = [&ACK[..], &response(0x06, &[0])?].concat();
    let (transport, _) = Script::new(vec![step(0x06, &[0], Answer::Indications(vec![joined]))]);
    let mut link = Link::new(transport);
    let error = failure(link.command(0x06, &[0], TIMEOUT))?;
    assert_eq!(error.progress, Progress::Sent);
    assert!(matches!(error.failure, Failure::Deadline));
    Ok(())
}

#[test]
fn classifies_failures_after_the_ack() -> TestResult {
    let mismatched = response(0x20, &[0])?;
    let trailing = [&response(0x06, &[0])?[..], &[0]].concat();
    let cases: Vec<(Answer, Expected)> = vec![
        (Answer::ReaderError, |f| matches!(f, Failure::ReaderError)),
        (Answer::Silence, |f| matches!(f, Failure::Deadline)),
        (Answer::Indications(vec![ACK.to_vec(), mismatched]), |f| {
            matches!(
                f,
                Failure::ResponseCommand {
                    expected: 0x07,
                    actual: 0x21
                }
            )
        }),
        (Answer::Indications(vec![ACK.to_vec(), trailing]), |f| {
            matches!(f, Failure::TrailingData)
        }),
        (Answer::Indications(vec![ACK.to_vec(), ACK.to_vec()]), |f| {
            matches!(f, Failure::UnexpectedFrame)
        }),
    ];
    for (answer, expected) in cases {
        let (transport, _) = Script::new(vec![step(0x06, &[0], answer)]);
        let mut link = Link::new(transport);
        let error = failure(link.command(0x06, &[0], TIMEOUT))?;
        assert_eq!(error.progress, Progress::Acknowledged);
        assert!(expected(&error.failure), "{:?}", error.failure);
        let error = failure(link.command(0x06, &[0], TIMEOUT))?;
        assert_eq!(error.progress, Progress::NotSent);
        assert!(matches!(error.failure, Failure::RecoveryRequired));
    }
    Ok(())
}

#[test]
fn rejects_commands_without_a_response_before_sending() -> TestResult {
    let (transport, journal) = Script::new(Vec::new());
    let mut link = Link::new(transport);
    let error = failure(link.command(0xff, &[], TIMEOUT))?;
    assert_eq!(error.progress, Progress::NotSent);
    assert!(matches!(error.failure, Failure::UnsupportedCommand(0xff)));
    let error = failure(link.command(0x06, &[0; 1002], TIMEOUT))?;
    assert!(matches!(error.failure, Failure::Frame(_)));
    assert_eq!(journal.borrow().writes, 0);
    // Rejections before sending leave the stream usable.
    assert!(matches!(
        failure(link.command(0x06, &[0], Duration::ZERO))?.failure,
        Failure::Deadline
    ));
    Ok(())
}

#[test]
fn recovery_writes_the_fill_and_an_ack_then_waits_for_silence() -> TestResult {
    let (transport, journal) = Script::new(vec![
        step(0x06, &[0], Answer::Silence),
        command(0x06, &[0], &[0]),
    ]);
    let mut link = Link::new(transport);
    failure(link.command(0x06, &[0], TIMEOUT))?;
    link.recover()?;
    assert_eq!(link.command(0x06, &[0], TIMEOUT)?.data, [0]);
    let journal = journal.borrow();
    assert_eq!(journal.resyncs, 1);
    // One command, the fill in 20-byte values, the ACK, and one command.
    assert_eq!(journal.writes, 1 + FILL.div_ceil(20) + 1 + 1);
    // The deadline of the failed command, then 2.8 s of silence.
    assert_eq!(
        journal.command_times[1],
        TIMEOUT + Duration::from_millis(2800)
    );
    Ok(())
}
