//! Frame encoding and decoding against hand-computed vectors.

use rcs310::wire::{self, Frame, FrameError};

#[test]
fn encodes_commands_with_length_and_data_checksums() -> Result<(), FrameError> {
    assert_eq!(
        wire::encode(0x54, &[])?,
        [0x00, 0x00, 0xff, 0x01, 0xff, 0x54, 0xac, 0x00]
    );
    assert_eq!(
        wire::encode(0x62, &[0x01, 0x82])?,
        [0x00, 0x00, 0xff, 0x03, 0xfd, 0x62, 0x01, 0x82, 0x1b, 0x00]
    );
    assert_eq!(wire::encode(0x5c, &[0; 254])?.len(), 262);
    assert_eq!(
        wire::encode(0x5c, &[0; 255]),
        Err(FrameError::PayloadTooLarge { length: 256 })
    );
    Ok(())
}

#[test]
fn decodes_acknowledgements_error_frames_and_responses() -> Result<(), FrameError> {
    assert_eq!(wire::parse(&[0, 0, 0xff, 0, 0xff, 0])?, Frame::Ack);
    assert_eq!(wire::parse(&[0, 0, 0xff, 0xff, 0, 0])?, Frame::Nak);
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 1, 0xff, 0x7f, 0x81, 0])?,
        Frame::ReaderError
    );
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 2, 0xfe, 0x5b, 0x00, 0xa5, 0])?,
        Frame::Data {
            command: 0x5b,
            data: &[0]
        }
    );
    Ok(())
}

#[test]
fn rejects_damaged_frames() {
    assert_eq!(
        wire::parse(&[0, 1, 0xff, 2, 0xfe, 0x5b, 0, 0xa5, 0]),
        Err(FrameError::Preamble)
    );
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 2, 0xff, 0x5b, 0, 0xa5, 0]),
        Err(FrameError::LengthChecksum)
    );
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 2, 0xfe, 0x5b, 0, 0xa4, 0]),
        Err(FrameError::DataChecksum)
    );
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 2, 0xfe, 0x5b, 0, 0xa5, 1]),
        Err(FrameError::Postamble)
    );
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 0, 0, 0, 0]),
        Err(FrameError::PayloadTooShort)
    );
    assert_eq!(
        wire::parse(&[0, 0, 0xff, 2, 0xfe, 0x5b, 0, 0xa5]),
        Err(FrameError::Length {
            expected: 9,
            actual: 8
        })
    );
    assert_eq!(wire::frame_length(&[0, 0, 0xff, 2]), Ok(None));
}
