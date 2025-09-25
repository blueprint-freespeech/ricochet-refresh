// extern
use anyhow::*;

// internal
use rico_protocol::v3::message::contact_request_channel::*;

#[test]
fn test_response_serialization() -> anyhow::Result<()> {
    // ensure serialisation round trip
    let valid_packets: [(Vec<u8>, Packet); 5] = [
        (
            vec![8, 0],
            Packet::Response(Response {
                status: Status::Undefined,
            }),
        ),
        (
            vec![8, 1],
            Packet::Response(Response {
                status: Status::Pending,
            }),
        ),
        (
            vec![8, 2],
            Packet::Response(Response {
                status: Status::Accepted,
            }),
        ),
        (
            vec![8, 3],
            Packet::Response(Response {
                status: Status::Rejected,
            }),
        ),
        (
            vec![8, 4],
            Packet::Response(Response {
                status: Status::Error,
            }),
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
