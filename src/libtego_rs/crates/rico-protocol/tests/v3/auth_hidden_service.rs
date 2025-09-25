// extern
use anyhow::*;
use tor_interface::tor_crypto::V3OnionServiceId;

// internal
use rico_protocol::v3::message::auth_hidden_service::Result;
use rico_protocol::v3::message::auth_hidden_service::*;

#[test]
fn test_proof_serialization() -> anyhow::Result<()> {
    // ensure serialisation round trip
    let valid_packets: [(Vec<u8>, Packet); 1] = [(
        vec![
            10, 124, 10, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 56, 54, 108, 54, 50, 102, 119, 55, 116, 113,
            99, 116, 108, 117, 53, 102, 101, 115, 100, 113, 117, 107, 118, 112, 111, 120, 101, 122,
            107, 97, 120, 98, 122, 108, 108, 114, 97, 102, 97, 50, 118, 101, 54, 101, 119, 117,
            104, 122, 112, 104, 120, 99, 122, 115, 106, 121, 100,
        ],
        Packet::Proof(Proof::new(
            [0u8; 64],
            V3OnionServiceId::from_string(
                "6l62fw7tqctlu5fesdqukvpoxezkaxbzllrafa2ve6ewuhzphxczsjyd",
            )?,
        )?),
    )];

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

#[test]
fn test_result_serialization() -> anyhow::Result<()> {
    // verify failure cases
    assert!(Result::new(true, None).is_err());

    // ensure serialisation round trip
    let valid_packets: [(Vec<u8>, Packet); 3] = [
        (
            vec![18, 4, 8, 1, 16, 1],
            Packet::Result(Result::new(true, Some(true))?),
        ),
        (
            vec![18, 4, 8, 1, 16, 0],
            Packet::Result(Result::new(true, Some(false))?),
        ),
        (vec![18, 2, 8, 0], Packet::Result(Result::new(false, None)?)),
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
