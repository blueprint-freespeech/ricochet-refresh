// extern
use anyhow::*;

// internal
use rico_protocol::v3::message::chat_channel::*;

#[test]
fn test_chat_message_serialization() -> anyhow::Result<()> {
    // verify failure cases
    assert!(ChatMessage::new(
        "message text".to_string().try_into()?,
        1u32,
        Some(std::time::Duration::from_secs(i64::MAX as u64 + 1u64))
    )
    .is_err());
    assert!(MessageText::try_from("".to_string()).is_err());
    assert!(MessageText::try_from(String::from_utf8(vec!['a' as u8; 2001])?).is_err());

    // ensure serialisation round trip
    let valid_packets: [(Vec<u8>, Packet); 3] = [
        (
            vec![10, 5, 10, 1, 32, 16, 0],
            Packet::ChatMessage(ChatMessage::new(" ".to_string().try_into()?, 0u32, None)?),
        ),
        (
            vec![10, 10, 10, 6, 104, 101, 108, 108, 111, 33, 16, 1],
            Packet::ChatMessage(ChatMessage::new(
                "hello!".to_string().try_into()?,
                1u32,
                None,
            )?),
        ),
        (
            vec![
                10, 22, 10, 7, 100, 101, 108, 97, 97, 97, 121, 16, 2, 24, 174, 246, 255, 255, 255,
                255, 255, 255, 255, 1,
            ],
            Packet::ChatMessage(ChatMessage::new(
                "delaaay".to_string().try_into()?,
                2u32,
                Some(std::time::Duration::from_secs(1234)),
            )?),
        ),
    ];

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
