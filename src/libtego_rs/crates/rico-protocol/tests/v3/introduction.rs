// extern
use anyhow::*;

// internal
use rico_protocol::v3::message::introduction::*;

#[test]
fn test_introduction_serialization() -> Result<()> {
    // verify failure cases
    assert!(IntroductionPacket::new(Default::default()).is_err());
    assert!(
        IntroductionPacket::new(vec![Version::RicochetRefresh3; u8::MAX as usize + 1]).is_err()
    );

    // ensure serialisation round trip
    let valid_packets: [(Vec<u8>, IntroductionPacket); 3] = [
        (
            vec![73, 77, 1, 3],
            IntroductionPacket::new(vec![Version::RicochetRefresh3])?,
        ),
        (
            vec![73, 77, 3, 0, 1, 3],
            IntroductionPacket::new(vec![
                Version::Ricochet1_0,
                Version::Ricochet1_1,
                Version::RicochetRefresh3,
            ])?,
        ),
        (
            vec![
                73, 77, 255, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3,
            ],
            IntroductionPacket::new(vec![Version::RicochetRefresh3; u8::MAX as usize])?,
        ),
    ];

    for (bytes, expected_packet) in valid_packets.iter() {
        // verify raw bytes can be serialised to a packet
        let packet: IntroductionPacket = bytes.as_slice().try_into()?;
        // verify the serialised packet equals our expected packet
        assert_eq!(packet, *expected_packet);
        // convert packet back into bytess
        let packet_bytes: Vec<u8> = (&packet).try_into()?;
        // verify the bytes -> packet -> bytes round-trips
        assert_eq!(packet_bytes.as_slice(), bytes);

        // ensure equivalent packets serialise to equivalent bytes
        let expected_packet_bytes: Vec<u8> = expected_packet.try_into()?;
        assert_eq!(packet_bytes, expected_packet_bytes);
    }
    Ok(())
}
