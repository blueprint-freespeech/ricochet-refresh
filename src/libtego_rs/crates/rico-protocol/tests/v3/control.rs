// extern
use anyhow::*;

// internal
use rico_protocol::v3::message::auth_hidden_service;
use rico_protocol::v3::message::contact_request_channel;
use rico_protocol::v3::message::contact_request_channel::{ContactRequest, MessageText, Nickname};
use rico_protocol::v3::message::control_channel::*;

#[test]
fn test_open_channel_serialization() -> Result<()> {
    // verify failure cases
    assert!(OpenChannel::new(0i32, ChannelType::Chat, None).is_err());
    assert!(OpenChannel::new(u16::MAX as i32 + 1i32, ChannelType::Chat, None).is_err());
    assert!(OpenChannel::new(-1i32, ChannelType::Chat, None).is_err());
    assert!(OpenChannel::new(1i32, ChannelType::ContactRequest, None).is_err());
    assert!(OpenChannel::new(1i32, ChannelType::AuthHiddenService, None).is_err());
    assert!(MessageText::try_from(String::from_utf8(vec!['A' as u8; 2001])?).is_err());
    assert!(Nickname::try_from(String::from_utf8(vec!['A' as u8; 31])?).is_err());
    // Unassigned code units
    for c in '\u{fdd0}'..='\u{fdef}' {
        assert!(Nickname::try_from(c.to_string()).is_err());
    }
    for upper in 0x0000u32..=0x0010u32 {
        let c = char::from_u32((upper << 16) | (0x0fffeu32)).unwrap();
        assert!(Nickname::try_from(c.to_string()).is_err());
        let c = char::from_u32((upper << 16) | (0x0ffffu32)).unwrap();
        assert!(Nickname::try_from(c.to_string()).is_err());
    }
    assert!(Nickname::try_from('\"'.to_string()).is_err());
    assert!(Nickname::try_from('<'.to_string()).is_err());
    assert!(Nickname::try_from('>'.to_string()).is_err());
    assert!(Nickname::try_from('&'.to_string()).is_err());
    // Cc code units
    for c in '\u{0000}'..='\u{001f}' {
        assert!(Nickname::try_from(c.to_string()).is_err());
    }
    for c in '\u{007f}'..='\u{009f}' {
        assert!(Nickname::try_from(c.to_string()).is_err());
    }
    // Cf code units
    let standalone_format_chars = [
        '\u{00ad}',
        '\u{061c}',
        '\u{06dd}',
        '\u{070f}',
        '\u{0890}',
        '\u{0891}',
        '\u{08e2}',
        '\u{180e}',
        '\u{feff}',
        '\u{110bd}',
        '\u{110cd}',
        '\u{e0001}',
    ];
    for c in standalone_format_chars.iter() {
        assert!(Nickname::try_from(c.to_string()).is_err());
    }
    for c in '\u{0600}'..='\u{0605}' {
        assert!(Nickname::try_from(c.to_string()).is_err());
    }
    for c in '\u{200b}'..='\u{200f}' {
        assert!(Nickname::try_from(c.to_string()).is_err());
    }
    for c in '\u{202a}'..='\u{202e}' {
        assert!(Nickname::try_from(c.to_string()).is_err());
    }
    for c in '\u{2060}'..='\u{2064}' {
        assert!(Nickname::try_from(c.to_string()).is_err());
    }
    for c in '\u{2066}'..='\u{206f}' {
        assert!(Nickname::try_from(c.to_string()).is_err());
    }
    for c in '\u{fff9}'..='\u{fffb}' {
        assert!(Nickname::try_from(c.to_string()).is_err());
    }
    for c in '\u{13430}'..='\u{13438}' {
        assert!(Nickname::try_from(c.to_string()).is_err());
    }
    for c in '\u{1bca0}'..='\u{1bca3}' {
        assert!(Nickname::try_from(c.to_string()).is_err());
    }
    for c in '\u{1d173}'..='\u{1d17a}' {
        assert!(Nickname::try_from(c.to_string()).is_err());
    }
    for c in '\u{e0020}'..='\u{e007f}' {
        assert!(Nickname::try_from(c.to_string()).is_err());
    }

    // ensure serialisation round trip
    let valid_packets: [(Vec<u8>, Packet); 4] = [
        (
            vec![
                10, 20, 8, 1, 18, 16, 105, 109, 46, 114, 105, 99, 111, 99, 104, 101, 116, 46, 99,
                104, 97, 116,
            ],
            Packet::OpenChannel(OpenChannel::new(1i32, ChannelType::Chat, None)?),
        ),
        (
            vec![
                10, 56, 8, 1, 18, 27, 105, 109, 46, 114, 105, 99, 111, 99, 104, 101, 116, 46, 99,
                111, 110, 116, 97, 99, 116, 46, 114, 101, 113, 117, 101, 115, 116, 194, 12, 22, 10,
                5, 97, 108, 105, 99, 101, 18, 13, 104, 101, 108, 108, 111, 32, 112, 97, 114, 116,
                110, 101, 114,
            ],
            Packet::OpenChannel(OpenChannel::new(
                1i32,
                ChannelType::ContactRequest,
                Some(OpenChannelExtension::ContactRequestChannel(
                    contact_request_channel::OpenChannel {
                        contact_request: ContactRequest {
                            nickname: "alice".to_string().try_into()?,
                            message_text: "hello partner".to_string().try_into()?,
                        },
                    },
                )),
            )?),
        ),
        (
            vec![
                10, 55, 8, 1, 18, 31, 105, 109, 46, 114, 105, 99, 111, 99, 104, 101, 116, 46, 97,
                117, 116, 104, 46, 104, 105, 100, 100, 101, 110, 45, 115, 101, 114, 118, 105, 99,
                101, 130, 194, 3, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            Packet::OpenChannel(OpenChannel::new(
                1i32,
                ChannelType::AuthHiddenService,
                Some(OpenChannelExtension::AuthHiddenService(
                    auth_hidden_service::OpenChannel {
                        client_cookie: Default::default(),
                    },
                )),
            )?),
        ),
        (
            vec![
                10, 29, 8, 1, 18, 25, 105, 109, 46, 114, 105, 99, 111, 99, 104, 101, 116, 46, 102,
                105, 108, 101, 45, 116, 114, 97, 110, 115, 102, 101, 114,
            ],
            Packet::OpenChannel(OpenChannel::new(1i32, ChannelType::FileTransfer, None)?),
        ),
    ];

    // ensure serialisation round trip
    for (bytes, expected_packet) in valid_packets.iter() {
        // verify raw bytes can be serialised to a packet
        let packet: Packet = bytes.as_slice().try_into()?;
        // verify the serialised packet equals our expected packet
        assert_eq!(packet, *expected_packet);
        // convert packet back into bytes
        let packet_bytes: Vec<u8> = (&packet).try_into()?;
        // verify the bytes -> packet -> bytes round-trips
        assert_eq!(packet_bytes.as_slice(), bytes);

        // ensure equivalent packets serialise to equivalent bytes
        let expected_packet_bytes: Vec<u8> = expected_packet.try_into()?;
        assert_eq!(packet_bytes, expected_packet_bytes);
    }
    Ok(())
}
