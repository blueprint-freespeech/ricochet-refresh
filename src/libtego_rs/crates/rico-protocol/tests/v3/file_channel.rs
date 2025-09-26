// extern
use anyhow::*;

// internal
use rico_protocol::v3::message::file_channel::*;

#[test]
fn test_file_header_serialization() -> Result<()> {
    // verify failure cases
    assert!(FileHeader::new(0u32, 128u64, "../relative-path.txt".to_string(), [0u8; 64]).is_err());
    assert!(FileHeader::new(0u32, 128u64, "/absolute-path.txt".to_string(), [0u8; 64]).is_err());

    // ensure serialisation round trip
    let valid_packets: [(Vec<u8>, Packet); 2] = [
        (
            vec![
                10, 72, 8, 0, 16, 0, 26, 0, 34, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            Packet::FileHeader(FileHeader::new(0u32, 0u64, "".to_string(), [0u8; 64])?),
        ),
        (
            vec![
                10, 78, 8, 1, 16, 128, 1, 26, 5, 115, 116, 117, 102, 102, 34, 64, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1,
            ],
            Packet::FileHeader(FileHeader::new(
                1u32,
                128u64,
                "stuff".to_string(),
                [1u8; 64],
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

#[test]
fn test_file_header_ack_serialization() -> Result<()> {
    // ensure serialisation round trip
    let valid_packets: [(Vec<u8>, Packet); 2] = [
        (
            vec![18, 4, 8, 0, 16, 1],
            Packet::FileHeaderAck(FileHeaderAck::new(0u32, true)?),
        ),
        (
            vec![18, 4, 8, 1, 16, 0],
            Packet::FileHeaderAck(FileHeaderAck::new(1u32, false)?),
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

#[test]
fn test_file_header_response_serialization() -> Result<()> {
    // ensure serialisation round trip
    let valid_packets: [(Vec<u8>, Packet); 2] = [
        (
            vec![26, 4, 8, 0, 16, 0],
            Packet::FileHeaderResponse(FileHeaderResponse::new(0u32, Response::Accept)?),
        ),
        (
            vec![26, 4, 8, 1, 16, 1],
            Packet::FileHeaderResponse(FileHeaderResponse::new(1u32, Response::Reject)?),
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

#[test]
fn test_file_chunk_serialization() -> Result<()> {
    // ensure serialisation round trip
    let valid_packets: [(Vec<u8>, Packet); 1] = [(
        vec![
            34, 133, 1, 8, 0, 18, 128, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        Packet::FileChunk(FileChunk::new(0u32, ChunkData::new(vec![0u8; 128])?)?),
    )];

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
fn test_file_chunk_ack_serialization() -> Result<()> {
    // ensure serialisation round trip
    let valid_packets: [(Vec<u8>, Packet); 2] = [
        (
            vec![42, 4, 8, 0, 16, 0],
            Packet::FileChunkAck(FileChunkAck::new(0u32, 0u64)?),
        ),
        (
            vec![42, 7, 8, 0, 16, 206, 194, 241, 5],
            Packet::FileChunkAck(FileChunkAck::new(0u32, 12345678u64)?),
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

#[test]
fn test_file_transfer_complete_notification_serialization() -> Result<()> {
    // ensure serialisation round trip
    let valid_packets: [(Vec<u8>, Packet); 3] = [
        (
            vec![50, 4, 8, 0, 16, 0],
            Packet::FileTransferCompleteNotification(FileTransferCompleteNotification::new(
                0u32,
                FileTransferResult::Success,
            )?),
        ),
        (
            vec![50, 4, 8, 1, 16, 1],
            Packet::FileTransferCompleteNotification(FileTransferCompleteNotification::new(
                1u32,
                FileTransferResult::Failure,
            )?),
        ),
        (
            vec![50, 4, 8, 2, 16, 2],
            Packet::FileTransferCompleteNotification(FileTransferCompleteNotification::new(
                2u32,
                FileTransferResult::Cancelled,
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
