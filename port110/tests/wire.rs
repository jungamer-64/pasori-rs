//! Frame encoding and decoding against hand-computed vectors.

use port110::wire::{self, Frame, FrameError, MAX_FRAME, MAX_LENGTH};

#[test]
fn encodes_extended_host_frames() -> Result<(), FrameError> {
    assert_eq!(
        wire::encode(0x28, &[])?,
        [
            0x00, 0x00, 0xff, 0xff, 0xff, 0x02, 0x00, 0xfe, 0xd6, 0x28, 0x02, 0x00
        ]
    );
    assert_eq!(
        wire::encode(0x20, &[])?,
        [
            0x00, 0x00, 0xff, 0xff, 0xff, 0x02, 0x00, 0xfe, 0xd6, 0x20, 0x0a, 0x00
        ]
    );
    // Polling for system code FFFF with request code 01 and a 5 ms RF wait.
    assert_eq!(
        wire::encode(0x04, &[0x32, 0x00, 0x06, 0x00, 0xff, 0xff, 0x01, 0x00])?,
        [
            0x00, 0x00, 0xff, 0xff, 0xff, 0x0a, 0x00, 0xf6, 0xd6, 0x04, 0x32, 0x00, 0x06, 0x00,
            0xff, 0xff, 0x01, 0x00, 0xef, 0x00
        ]
    );
    let longest = wire::encode(0x04, &[0; MAX_LENGTH - 2])?;
    assert_eq!(longest.len(), MAX_FRAME);
    assert_eq!(&longest[5..8], &[0xeb, 0x03, 0x12]);
    assert_eq!(
        wire::encode(0x04, &[0; MAX_LENGTH - 1]),
        Err(FrameError::PayloadTooLarge {
            length: MAX_LENGTH + 1
        })
    );
    Ok(())
}

#[test]
fn decodes_acknowledgements_error_frames_and_both_response_forms() -> Result<(), FrameError> {
    assert_eq!(wire::parse(&[0, 0, 0xff, 0, 0xff, 0])?, Frame::Ack);
    assert_eq!(wire::parse(&[0, 0, 0xff, 0xff, 0, 0])?, Frame::Nak);
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 1, 0xff, 0x7f, 0x81, 0])?,
        Frame::ReaderError
    );
    let status = Frame::Data {
        command: 0x2b,
        data: &[0],
    };
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 3, 0xfd, 0xd7, 0x2b, 0x00, 0xfe, 0])?,
        status
    );
    assert_eq!(
        wire::parse(&[
            0, 0, 0xff, 0xff, 0xff, 3, 0, 0xfd, 0xd7, 0x2b, 0x00, 0xfe, 0
        ])?,
        status
    );
    Ok(())
}

#[test]
fn rejects_integrity_failures() {
    assert_eq!(
        wire::parse(&[
            0, 0, 0xff, 0xff, 0xff, 3, 0, 0xfc, 0xd7, 0x2b, 0x00, 0xfe, 0
        ]),
        Err(FrameError::LengthChecksum)
    );
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 3, 0xfd, 0xd7, 0x2b, 0x00, 0xff, 0]),
        Err(FrameError::DataChecksum)
    );
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 3, 0xfd, 0xd7, 0x2b, 0x00, 0xfe, 1]),
        Err(FrameError::Postamble)
    );
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 3, 0xfd, 0xd5, 0x2b, 0x00, 0x00, 0]),
        Err(FrameError::Direction(0xd5))
    );
    assert_eq!(
        wire::frame_length(&[0, 0, 0xff, 0xff, 0xff, 0xec, 0x03, 0x11]),
        Err(FrameError::PayloadTooLarge {
            length: MAX_LENGTH + 1
        })
    );
    assert_eq!(wire::frame_length(&[0, 1]), Err(FrameError::Preamble));
    assert_eq!(wire::frame_length(&[0, 0, 0xff, 0xff]), Ok(None));
}
