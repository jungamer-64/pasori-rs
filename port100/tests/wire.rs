//! Frame encoding and decoding against hand-computed vectors.

use port100::wire::{self, Frame, FrameError, MAX_LENGTH};

#[test]
fn encodes_extended_host_frames() -> Result<(), FrameError> {
    assert_eq!(
        wire::encode(0x28, &[])?,
        [
            0x00, 0x00, 0xff, 0xff, 0xff, 0x02, 0x00, 0xfe, 0xd6, 0x28, 0x02, 0x00
        ]
    );
    assert_eq!(
        wire::encode(0x06, &[0x00])?,
        [
            0x00, 0x00, 0xff, 0xff, 0xff, 0x03, 0x00, 0xfd, 0xd6, 0x06, 0x00, 0x24, 0x00
        ]
    );
    assert_eq!(
        wire::encode(0x2a, &[0x01])?,
        [
            0x00, 0x00, 0xff, 0xff, 0xff, 0x03, 0x00, 0xfd, 0xd6, 0x2a, 0x01, 0xff, 0x00
        ]
    );
    let longest = wire::encode(0x04, &[0; MAX_LENGTH - 2])?;
    assert_eq!(longest.len(), MAX_LENGTH + 10);
    assert_eq!(&longest[5..8], &[0x16, 0x03, 0xe7]);
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
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 0xff, 0xff, 1, 0, 0xff, 0x7f, 0x81, 0])?,
        Frame::ReaderError
    );
    Ok(())
}

#[test]
fn rejects_damaged_and_host_frames() {
    assert_eq!(
        wire::parse(&[0, 1, 0xff, 3, 0xfd, 0xd7, 0x2b, 0x00, 0xfe, 0]),
        Err(FrameError::Preamble)
    );
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 3, 0xfe, 0xd7, 0x2b, 0x00, 0xfe, 0]),
        Err(FrameError::LengthChecksum)
    );
    assert_eq!(
        wire::parse(&[
            0, 0, 0xff, 0xff, 0xff, 3, 0, 0xfe, 0xd7, 0x2b, 0x00, 0xfe, 0
        ]),
        Err(FrameError::LengthChecksum)
    );
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 3, 0xfd, 0xd7, 0x2b, 0x00, 0xfd, 0]),
        Err(FrameError::DataChecksum)
    );
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 3, 0xfd, 0xd7, 0x2b, 0x00, 0xfe, 1]),
        Err(FrameError::Postamble)
    );
    assert_eq!(
        wire::parse(&[
            0, 0, 0xff, 0xff, 0xff, 3, 0, 0xfd, 0xd6, 0x2a, 0x01, 0xff, 0
        ]),
        Err(FrameError::Direction(0xd6))
    );
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 1, 0xff, 0xd7, 0x29, 0]),
        Err(FrameError::PayloadTooShort)
    );
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 3, 0xfd, 0xd7, 0x2b, 0x00, 0xfe]),
        Err(FrameError::Length {
            expected: 10,
            actual: 9
        })
    );
    assert_eq!(wire::frame_length(&[0, 0, 0xff, 0xff, 0xff, 3]), Ok(None));
    assert_eq!(
        wire::frame_length(&[0, 0, 0xff, 0xff, 0xff, 0x17, 0x03, 0xe6]),
        Err(FrameError::PayloadTooLarge {
            length: MAX_LENGTH + 1
        })
    );
}
