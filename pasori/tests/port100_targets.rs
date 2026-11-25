//! Target exchanges against independently encoded Port-100 responses.

use pasori::{
    felica_packet::Idm,
    ndef::{Type3EmulationError, Type3Event, Type3Target},
    port100::reader::{BitRate, Error, Reader, TargetWait},
    type2::{Type2EmulationError, Type2Event, Type2Target},
};
use reader_script::port100::{Script, Step, command, initialization, initialization_with};
use std::{error::Error as StdError, time::Duration};

const MESSAGE: [u8; 3] = [0xd0, 0, 0];
const IDENTITY: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const PMM: [u8; 8] = [1, 0x20, 0x22, 4, 0x27, 0x67, 0x4e, 0xff];
const WAIT_MS: u16 = 330;

fn wait() -> Result<TargetWait, Box<dyn StdError>> {
    TargetWait::new(Duration::from_millis(u64::from(WAIT_MS))).ok_or_else(|| "target wait".into())
}

fn configure(rate: u8) -> [Step; 2] {
    [
        command(0x40, &[8, rate], &[0]),
        command(0x42, &[0, 1, 1, 1, 2, 7], &[0]),
    ]
}

fn exchange(parameters: &[u8; 24], mdaa: u8, transmit: &[u8], reply: &[u8]) -> Step {
    // Send-only and receive-only forms from the split Type 3 capture.
    let mut args = vec![0, 0, 0xff, 0xff, mdaa];
    args.extend_from_slice(parameters);
    let receive = if transmit.is_empty() { WAIT_MS } else { 0 };
    args.extend([0, 0]);
    args.extend(receive.to_le_bytes());
    args.extend_from_slice(transmit);
    command(0x48, &args, reply)
}

#[test]
fn serves_a_type2_read_on_port100_after_a_stale_field_loss() -> Result<(), Box<dyn StdError>> {
    let mut parameters = [0; 24];
    parameters[..6].copy_from_slice(&[4, 0, 1, 2, 3, 0]);
    let page_three = [
        0xe1, 0x10, 6, 0x0f, 3, 3, 0xd0, 0, 0, 0xfe, 0, 0, 0, 0, 0, 0,
    ];
    let page_fifteen = [0, 0, 0, 0, 8, 1, 2, 3, 8, 0, 0, 0, 0, 0, 0xff, 0xff];
    let mut steps = initialization();
    steps.extend(configure(0x0b));
    steps.extend([
        exchange(&parameters, 1, &[], &[0, 0, 0, 0, 4, 0, 0]),
        exchange(&parameters, 1, &[], &[0x0b, 0, 3, 0, 0, 0, 0, 0x30, 3]),
        exchange(&parameters, 0, &page_three, &[0x0b, 0, 0, 0, 0, 0, 0]),
        exchange(&parameters, 0, &[], &[0x0b, 0, 0, 0, 0, 0, 0, 0x30, 15]),
        exchange(&parameters, 0, &page_fifteen, &[0x0b, 0, 0, 0, 0, 0, 0]),
        exchange(&parameters, 0, &[], &[0x0b, 0, 0, 0, 0, 0, 0, 0x50, 0]),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut target = Type2Target::listen(&mut reader, [1, 2, 3], &MESSAGE, wait()?)?;
    assert_eq!(target.serve_next(wait()?)?, Type2Event::Read(3));
    assert_eq!(target.serve_next(wait()?)?, Type2Event::Read(15));
    assert_eq!(target.serve_next(wait()?)?, Type2Event::Halted);
    assert!(matches!(
        target.serve_next(wait()?),
        Err(Type2EmulationError::Halted)
    ));
    target.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn serves_type3_attribute_and_message_blocks_across_field_cycles() -> Result<(), Box<dyn StdError>>
{
    let mut parameters = [0; 24];
    parameters[6..14].copy_from_slice(&IDENTITY);
    parameters[14..22].copy_from_slice(&PMM);
    parameters[22..].copy_from_slice(&[0x12, 0xfc]);
    let attribute = [0x10, 12, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0x20];
    let incoming = |mode: u8, address: &[u8]| {
        let mut reply = vec![
            0x0c,
            0,
            mode,
            0,
            0,
            0,
            0,
            if address.len() == 2 { 16 } else { 17 },
            6,
        ];
        reply.extend(IDENTITY);
        reply.extend([1, 0x0b, 0, 1]);
        reply.extend_from_slice(address);
        reply
    };
    let outgoing = |block: [u8; 16]| {
        let mut reply = vec![29, 7];
        reply.extend(IDENTITY);
        reply.extend([0, 0, 1]);
        reply.extend(block);
        reply
    };
    let mut body = [0; 16];
    body[..3].copy_from_slice(&MESSAGE);
    let mut steps = initialization();
    steps.extend(configure(0x0c));
    steps.extend([
        exchange(&parameters, 1, &[], &[0x0c, 0, 0, 0x80, 0, 0, 0]),
        exchange(&parameters, 1, &[], &incoming(3, &[0x80, 0])),
        exchange(
            &parameters,
            0,
            &outgoing(attribute),
            &[0x0c, 0, 0, 0, 0, 0, 0],
        ),
        exchange(&parameters, 0, &[], &incoming(0, &[0, 2, 0])),
        exchange(&parameters, 0, &[], &[0x0c, 0, 0, 0, 4, 0, 0]),
        exchange(&parameters, 1, &[], &incoming(3, &[0, 1, 0])),
        exchange(&parameters, 0, &outgoing(body), &[0x0c, 0, 0, 0, 0, 0, 0]),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut target = Type3Target::listen(
        &mut reader,
        BitRate::Kbps212,
        Idm::new(IDENTITY),
        PMM,
        &MESSAGE,
    )?;
    assert!(matches!(
        target.serve_next(wait()?),
        Err(Type3EmulationError::Reader(Error::TargetTimeout))
    ));
    assert_eq!(target.serve_next(wait()?)?, Type3Event::Read);
    assert_eq!(target.serve_next(wait()?)?, Type3Event::Ignored);
    assert!(matches!(
        target.serve_next(wait()?),
        Err(Type3EmulationError::Reader(Error::TargetFieldOff))
    ));
    assert_eq!(target.serve_next(wait()?)?, Type3Event::Read);
    target.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn a_failed_send_on_older_firmware_revokes_the_target() -> Result<(), Box<dyn StdError>> {
    let mut parameters = [0; 24];
    parameters[..6].copy_from_slice(&[4, 0, 1, 2, 3, 0]);
    let initialization = || initialization_with(&[0, 0, 0, 0, 0, 0, 0, 3], 1, [5, 0], 0x0619);
    let mut steps = initialization();
    steps.extend(configure(0x0b));
    steps.extend([
        exchange(&parameters, 1, &[], &[0x0b, 0, 0, 0, 0, 0, 0x30, 3]),
        exchange(&parameters, 0, &[0xaa], &[0x0b, 0, 0, 8, 0, 0]),
    ]);
    steps.extend(initialization());
    let (script, journal) = Script::new(steps);
    let mut reader = Reader::new(script);
    reader.initialize()?;
    let mut target = reader.listen_type_a([1, 2, 3], wait()?)?;
    let request = target.receive(wait()?)?;
    assert_eq!(request.data(), [0x30, 3]);
    assert!(matches!(
        request.respond(&[0xaa]),
        Err(Error::RfStatus(0x800))
    ));
    assert!(matches!(
        target.receive(wait()?),
        Err(Error::NotInitialized)
    ));
    target.finish()?;
    assert_eq!(journal.borrow().remaining, 0);
    Ok(())
}

#[test]
fn type3_validates_ndef_before_configuring_the_reader() {
    let (script, journal) = Script::new(vec![]);
    let mut reader = Reader::new(script);
    assert!(matches!(
        Type3Target::listen(
            &mut reader,
            BitRate::Kbps212,
            Idm::new(IDENTITY),
            PMM,
            &[0xd0]
        ),
        Err(Type3EmulationError::Message(_))
    ));
    assert!(journal.borrow().commands.is_empty());
}
