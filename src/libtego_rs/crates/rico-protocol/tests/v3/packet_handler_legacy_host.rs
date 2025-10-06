// extern
use anyhow::*;
use tor_interface::tor_crypto::{
    Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature, V3OnionServiceId,
};

// internal
use rico_protocol::v3::message::*;
use rico_protocol::v3::packet_handler::*;

// Test packet_handler using a (partial) replay of responses from a
// legacy host where:
// - new client connects to legacy host
// - authenticates
// - new client makes a contact request
// - legacy host accepts contact request
// - new client sends message
// - legacy host sends message
// - new  client sends file transfer request
// - legacy host accepts and completes request
#[test]
fn test_legacy_host_interop() -> Result<()> {
    let mut to_legacy: Vec<Packet> = Default::default();

    let legacy_private_key = Ed25519PrivateKey::generate();
    let legacy_service_id = V3OnionServiceId::from_private_key(&legacy_private_key);
    let server_service_id = &legacy_service_id;

    let new_private_key = Ed25519PrivateKey::generate();
    let new_public_key = Ed25519PublicKey::from_private_key(&new_private_key);
    let new_service_id = V3OnionServiceId::from_public_key(&new_public_key);
    let client_service_id = &new_service_id;

    let mut packet_handler = PacketHandler::new(new_private_key, Default::default(), Default::default());
    let connection_handle = packet_handler.new_outgoing_connection(
        legacy_service_id.clone(),
        Some(contact_request_channel::MessageText::try_from(
            "Hello!".to_string(),
        )?),
        &mut to_legacy,
    )?;

    // introduction handshake
    assert_eq!(to_legacy.len(), 1);
    let packet = to_legacy.remove(0);
    if let Packet::IntroductionPacket(introduction_packet) = packet {
        assert_eq!(
            introduction_packet.versions(),
            &vec![introduction::Version::RicochetRefresh3]
        )
    } else {
        bail!("unexpected packet: {packet:?}");
    }
    let packet = Packet::IntroductionResponsePacket(introduction::IntroductionResponsePacket {
        version: Some(introduction::Version::RicochetRefresh3),
    });
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    assert!(
        matches!(event, Event::IntroductionResponseReceived),
        "unexpected event: {event:?}"
    );

    // authorise new client with host: open channel, send cookie
    assert_eq!(to_legacy.len(), 1);
    let packet = to_legacy.remove(0);
    let client_cookie =
        if let Packet::ControlChannelPacket(control_channel::Packet::OpenChannel(open_channel)) =
            packet
        {
            assert_eq!(open_channel.channel_identifier(), 1u16);
            assert_eq!(
                open_channel.channel_type(),
                &control_channel::ChannelType::AuthHiddenService
            );
            if let Some(control_channel::OpenChannelExtension::AuthHiddenService(extension)) =
                open_channel.extension()
            {
                extension.client_cookie
            } else {
                bail!("unexpected extension: {:?}", open_channel.extension());
            }
        } else {
            bail!("unexpected packet: {packet:?}");
        };
    let server_cookie: [u8; 16] = Default::default();
    let packet = Packet::ControlChannelPacket(control_channel::Packet::ChannelResult(
        control_channel::ChannelResult::new(
            1i32,
            true,
            None,
            Some(control_channel::ChannelResultExtension::AuthHiddenService(
                auth_hidden_service::ChannelResult { server_cookie },
            )),
        )?,
    ));

    // send proof
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::OutgoingAuthHiddenServiceChannelOpened { service_id } = event {
        assert_eq!(&service_id, server_service_id);
    }
    assert_eq!(to_legacy.len(), 1);
    let packet = to_legacy.remove(0);
    if let Packet::AuthHiddenServicePacket {
        channel: 1u16,
        packet: auth_hidden_service::Packet::Proof(proof),
    } = packet
    {
        assert_eq!(proof.service_id(), client_service_id);
        let message = auth_hidden_service::Proof::message(
            &client_cookie,
            &server_cookie,
            &client_service_id,
            &server_service_id,
        );
        let signature = proof.signature();
        let signature = Ed25519Signature::from_raw(signature)?;
        assert!(signature.verify(&message, &new_public_key));
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    // legacy host approves of client, new client sends contact request
    let packet = Packet::AuthHiddenServicePacket {
        channel: 1u16,
        packet: auth_hidden_service::Packet::Result(auth_hidden_service::Result::new(
            true,
            Some(false),
        )?),
    };
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::HostAuthenticated {
        service_id,
        is_known_contact: false,
        duplicate_connection: None,
    } = event
    {
        assert_eq!(&service_id, server_service_id);
    } else {
        bail!("unexpected event: {event:?}");
    }
    assert_eq!(to_legacy.len(), 2);
    let packet = to_legacy.remove(0);
    assert!(matches!(
        packet,
        Packet::CloseChannelPacket { channel: 1u16 }
    ));
    let packet = to_legacy.remove(0);
    if let Packet::ControlChannelPacket(control_channel::Packet::OpenChannel(open_channel)) = packet
    {
        assert_eq!(open_channel.channel_identifier(), 3u16);
        assert_eq!(
            open_channel.channel_type(),
            &control_channel::ChannelType::ContactRequest
        );
        if let Some(control_channel::OpenChannelExtension::ContactRequestChannel(
            contact_request_channel::OpenChannel { contact_request },
        )) = open_channel.extension()
        {
            assert_eq!(String::from(&contact_request.nickname), "");
            assert_eq!(String::from(&contact_request.message_text), "Hello!");
        } else {
            bail!("unexpected extension: {:?}", open_channel.extension());
        }
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    // legacy host also closes the auth hidden service channel
    let packet = Packet::CloseChannelPacket { channel: 1u16 };
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    assert!(matches!(event, Event::ProtocolFailure { .. }));

    // legacy host acks contact request
    let packet = Packet::ControlChannelPacket(control_channel::Packet::ChannelResult(
        control_channel::ChannelResult::new(
            3i32,
            true,
            None,
            Some(
                control_channel::ChannelResultExtension::ContactRequestChannel(
                    contact_request_channel::ChannelResult {
                        response: contact_request_channel::Response {
                            status: contact_request_channel::Status::Pending,
                        },
                    },
                ),
            ),
        )?,
    ));
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::ContactRequestResultPending { service_id } = event {
        assert_eq!(&service_id, server_service_id);
    }
    assert!(to_legacy.is_empty());

    // legacy host accepts contact request
    let packet = Packet::ContactRequestChannelPacket {
        channel: 3u16,
        packet: contact_request_channel::Packet::Response(contact_request_channel::Response {
            status: contact_request_channel::Status::Accepted,
        }),
    };
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::ContactRequestResultAccepted { service_id } = event {
        assert_eq!(&service_id, server_service_id);
    }

    // new client sends open channel packets for chat and file transfer channels
    assert_eq!(to_legacy.len(), 2);
    let packet = to_legacy.remove(0);
    if let Packet::ControlChannelPacket(control_channel::Packet::OpenChannel(open_channel)) = packet
    {
        assert_eq!(open_channel.channel_identifier(), 5u16);
        assert_eq!(
            open_channel.channel_type(),
            &control_channel::ChannelType::Chat
        );
        assert!(open_channel.extension().is_none());
    } else {
        bail!("unexpected packet: {packet:?}");
    }
    let packet = to_legacy.remove(0);
    if let Packet::ControlChannelPacket(control_channel::Packet::OpenChannel(open_channel)) = packet
    {
        assert_eq!(open_channel.channel_identifier(), 7u16);
        assert_eq!(
            open_channel.channel_type(),
            &control_channel::ChannelType::FileTransfer
        );
        assert!(open_channel.extension().is_none());
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    // legacy host closes contact request channel
    let packet = Packet::CloseChannelPacket { channel: 3u16 };
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    assert!(matches!(event, Event::ChannelClosed { id: 3u16 }));

    // legacy host sends open channel packets for chat and file transfer channels
    let packet = Packet::ControlChannelPacket(control_channel::Packet::OpenChannel(
        control_channel::OpenChannel::new(2i32, control_channel::ChannelType::Chat, None)?,
    ));
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::IncomingChatChannelOpened { service_id } = event {
        assert_eq!(&service_id, server_service_id);
    } else {
        bail!("unexpected event: {event:?}");
    }
    assert_eq!(to_legacy.len(), 1);
    let packet = to_legacy.remove(0);
    if let Packet::ControlChannelPacket(control_channel::Packet::ChannelResult(channel_result)) =
        packet
    {
        assert_eq!(channel_result.channel_identifier(), 2u16);
        assert!(channel_result.opened());
        assert!(channel_result.common_error().is_none());
        assert!(channel_result.extension().is_none());
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    let packet = Packet::ControlChannelPacket(control_channel::Packet::OpenChannel(
        control_channel::OpenChannel::new(4i32, control_channel::ChannelType::FileTransfer, None)?,
    ));
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::IncomingFileTransferChannelOpened { service_id } = event {
        assert_eq!(&service_id, server_service_id);
    } else {
        bail!("unexpected event: {event:?}");
    }
    assert_eq!(to_legacy.len(), 1);
    let packet = to_legacy.remove(0);
    if let Packet::ControlChannelPacket(control_channel::Packet::ChannelResult(channel_result)) =
        packet
    {
        assert_eq!(channel_result.channel_identifier(), 4u16);
        assert!(channel_result.opened());
        assert!(channel_result.common_error().is_none());
        assert!(channel_result.extension().is_none());
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    // legacy host accepts opening chat and file transfer channels
    let packet = Packet::ControlChannelPacket(control_channel::Packet::ChannelResult(
        control_channel::ChannelResult::new(5i32, true, None, None)?,
    ));
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::OutgoingChatChannelOpened { service_id } = event {
        assert_eq!(&service_id, server_service_id);
    }
    assert!(to_legacy.is_empty());

    let packet = Packet::ControlChannelPacket(control_channel::Packet::ChannelResult(
        control_channel::ChannelResult::new(7i32, true, None, None)?,
    ));
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::OutgoingFileTransferChannelOpened { service_id } = event {
        assert_eq!(&service_id, server_service_id);
    }
    assert!(to_legacy.is_empty());

    // new client sends a chat message
    let (dest, message_handle) = packet_handler.send_message(
        legacy_service_id.clone(),
        chat_channel::MessageText::try_from("hello!".to_string())?,
        &mut to_legacy,
    )?;
    assert_eq!(dest, connection_handle);
    assert_eq!(message_handle.message_id(), 0);
    assert_eq!(to_legacy.len(), 1);
    let packet = to_legacy.remove(0);
    if let Packet::ChatChannelPacket {
        channel: 5u16,
        packet: chat_channel::Packet::ChatMessage(chat_message),
    } = packet
    {
        assert_eq!(String::from(chat_message.message_text()), "hello!");
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    // legacy would reply with an ack
    let packet = Packet::ChatChannelPacket {
        channel: 5u16,
        packet: chat_channel::Packet::ChatAcknowledge(chat_channel::ChatAcknowledge::new(0, true)?),
    };
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::ChatAcknowledgeReceived {
        service_id,
        message_handle,
        accepted,
    } = event
    {
        assert_eq!(&service_id, server_service_id);
        assert_eq!(message_handle.message_id(), 0);
        assert!(accepted);
    } else {
        bail!("unexpected event: {event:?}");
    }

    // legacy host sends a chat message
    let packet = Packet::ChatChannelPacket {
        channel: 2u16,
        packet: chat_channel::Packet::ChatMessage(chat_channel::ChatMessage::new(
            chat_channel::MessageText::try_from("hi there!".to_string())?,
            1873504473,
            None,
        )?),
    };
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::ChatMessageReceived {
        service_id,
        message_text,
        message_handle,
        time_delta,
    } = event
    {
        assert_eq!(&service_id, server_service_id);
        assert_eq!(message_text, "hi there!");
        assert_eq!(message_handle.message_id(), 1873504473);
        assert_eq!(time_delta, std::time::Duration::ZERO);
    } else {
        bail!("unexpected event: {event:?}");
    }
    // new client would reply with an ack
    assert_eq!(to_legacy.len(), 1);
    let packet = to_legacy.remove(0);
    if let Packet::ChatChannelPacket {
        channel: 2u16,
        packet: chat_channel::Packet::ChatAcknowledge(chat_acknowledge),
    } = packet
    {
        assert_eq!(chat_acknowledge.message_id(), 1873504473);
        assert!(chat_acknowledge.accepted());
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    // new client sends file transfer request
    let (dest, file_transfer_handle) = packet_handler.send_file_transfer_request(
        server_service_id.clone(),
        "small-file.bin".to_string(),
        128u64,
        [
            18, 122, 4, 8, 136, 86, 210, 183, 149, 112, 122, 154, 225, 69, 207, 170, 119, 140, 248,
            129, 203, 219, 196, 237, 94, 12, 206, 88, 64, 9, 89, 110, 158, 170, 232, 137, 216, 159,
            27, 136, 24, 227, 92, 60, 42, 252, 179, 83, 253, 175, 183, 148, 52, 216, 243, 123, 255,
            31, 194, 28, 93, 161, 50, 247,
        ],
        &mut to_legacy,
    )?;
    assert_eq!(dest, connection_handle);
    assert_eq!(file_transfer_handle.file_id(), 1u32);
    assert_eq!(to_legacy.len(), 1);
    let packet = to_legacy.remove(0);
    if let Packet::FileChannelPacket {
        channel: 7u16,
        packet: file_channel::Packet::FileHeader(file_header),
    } = packet
    {
        assert_eq!(file_header.file_id(), 1u32);
        assert_eq!(file_header.file_size(), 128u64);
        assert_eq!(file_header.name(), "small-file.bin");
        assert_eq!(
            file_header.file_hash(),
            &[
                18, 122, 4, 8, 136, 86, 210, 183, 149, 112, 122, 154, 225, 69, 207, 170, 119, 140,
                248, 129, 203, 219, 196, 237, 94, 12, 206, 88, 64, 9, 89, 110, 158, 170, 232, 137,
                216, 159, 27, 136, 24, 227, 92, 60, 42, 252, 179, 83, 253, 175, 183, 148, 52, 216,
                243, 123, 255, 31, 194, 28, 93, 161, 50, 247
            ]
        );
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    // legacy host acks request
    let packet = Packet::FileChannelPacket {
        channel: 7u16,
        packet: file_channel::Packet::FileHeaderAck(file_channel::FileHeaderAck::new(1u32, true)?),
    };
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::FileTransferRequestAcknowledgeReceived {
        service_id,
        file_transfer_handle,
        accepted,
    } = event
    {
        assert_eq!(&service_id, server_service_id);
        assert_eq!(file_transfer_handle.file_id(), 1u32);
        assert!(accepted);
    } else {
        bail!("unexpected event: {event:?}");
    }
    assert!(to_legacy.is_empty());

    // legacy host accepts request
    let packet = Packet::FileChannelPacket {
        channel: 7u16,
        packet: file_channel::Packet::FileHeaderResponse(file_channel::FileHeaderResponse::new(
            1u32,
            file_channel::Response::Accept,
        )?),
    };
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::FileTransferRequestAccepted {
        service_id,
        file_transfer_handle,
    } = event
    {
        assert_eq!(&service_id, server_service_id);
        assert_eq!(file_transfer_handle.file_id(), 1u32);
    } else {
        bail!("unexpected event: {event:?}");
    }
    assert!(to_legacy.is_empty());
    // new client sends chunk
    assert_eq!(
        packet_handler.send_file_chunk(
            server_service_id,
            file_transfer_handle,
            vec![
                8, 200, 16, 250, 52, 56, 251, 245, 252, 138, 248, 77, 200, 40, 233, 220, 92, 109,
                13, 53, 2, 82, 212, 192, 229, 113, 222, 173, 196, 48, 11, 246, 248, 176, 40, 197,
                253, 68, 62, 238, 151, 136, 110, 37, 192, 137, 167, 170, 135, 79, 153, 146, 107, 2,
                208, 27, 158, 130, 200, 37, 203, 16, 61, 104, 106, 108, 196, 137, 116, 70, 36, 66,
                21, 90, 117, 190, 187, 220, 187, 117, 135, 43, 219, 184, 185, 242, 71, 230, 193,
                37, 37, 183, 248, 219, 26, 201, 78, 156, 46, 138, 178, 235, 118, 183, 27, 57, 153,
                186, 236, 72, 165, 156, 0, 63, 239, 116, 39, 73, 203, 196, 169, 207, 106, 65, 120,
                201, 202, 78
            ],
            &mut to_legacy
        )?,
        connection_handle
    );
    assert_eq!(to_legacy.len(), 1);
    let packet = to_legacy.remove(0);
    if let Packet::FileChannelPacket {
        channel: 7u16,
        packet: file_channel::Packet::FileChunk(file_chunk),
    } = packet
    {
        assert_eq!(file_chunk.file_id(), 1u32);
        assert_eq!(
            file_chunk.chunk_data().data(),
            &[
                8, 200, 16, 250, 52, 56, 251, 245, 252, 138, 248, 77, 200, 40, 233, 220, 92, 109,
                13, 53, 2, 82, 212, 192, 229, 113, 222, 173, 196, 48, 11, 246, 248, 176, 40, 197,
                253, 68, 62, 238, 151, 136, 110, 37, 192, 137, 167, 170, 135, 79, 153, 146, 107, 2,
                208, 27, 158, 130, 200, 37, 203, 16, 61, 104, 106, 108, 196, 137, 116, 70, 36, 66,
                21, 90, 117, 190, 187, 220, 187, 117, 135, 43, 219, 184, 185, 242, 71, 230, 193,
                37, 37, 183, 248, 219, 26, 201, 78, 156, 46, 138, 178, 235, 118, 183, 27, 57, 153,
                186, 236, 72, 165, 156, 0, 63, 239, 116, 39, 73, 203, 196, 169, 207, 106, 65, 120,
                201, 202, 78
            ]
        );
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    // legacy replies with ack
    let packet = Packet::FileChannelPacket {
        channel: 7u16,
        packet: file_channel::Packet::FileChunkAck(file_channel::FileChunkAck::new(1u32, 128u64)?),
    };
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::FileChunkAckReceived {
        service_id,
        file_transfer_handle,
        offset,
    } = event
    {
        assert_eq!(&service_id, server_service_id);
        assert_eq!(file_transfer_handle.file_id(), 1u32);
        assert_eq!(offset, 128u64);
    } else {
        bail!("unexpected event: {event:?}");
    }
    assert!(to_legacy.is_empty());

    // legacy signals successful transfer
    let packet = Packet::FileChannelPacket {
        channel: 7u16,
        packet: file_channel::Packet::FileTransferCompleteNotification(
            file_channel::FileTransferCompleteNotification::new(
                1u32,
                file_channel::FileTransferResult::Success,
            )?,
        ),
    };
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::FileTransferSucceeded {
        service_id,
        file_transfer_handle,
    } = event
    {
        assert_eq!(&service_id, server_service_id);
        assert_eq!(file_transfer_handle.file_id(), 1u32);
    } else {
        bail!("unexpected event: {event:?}");
    }

    Ok(())
}
