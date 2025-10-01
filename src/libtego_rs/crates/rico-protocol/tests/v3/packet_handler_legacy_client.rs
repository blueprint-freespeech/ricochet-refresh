// extern
use anyhow::*;
use tor_interface::tor_crypto::{Ed25519PrivateKey, V3OnionServiceId};

// internal
use rico_protocol::v3::message::*;
use rico_protocol::v3::packet_handler::*;

// Test packet_handler using a (partial) replay of responses from a
// legacy client where:
// - legacy client connects to new host
// - authenticates
// - legacy client makes a contact request
// - new host accepts contact request
// - legacy client sends message
// - new host sends message
// - legacy client sends file transfer request
// - new host accepts and completes request
#[test]
fn test_legacy_client_interop() -> Result<()> {
    let mut to_legacy: Vec<Packet> = Default::default();

    let legacy_private_key = Ed25519PrivateKey::generate();
    let legacy_service_id = V3OnionServiceId::from_private_key(&legacy_private_key);
    let client_service_id = &legacy_service_id;

    let new_private_key = Ed25519PrivateKey::generate();
    let new_service_id = V3OnionServiceId::from_private_key(&new_private_key);
    let server_service_id = &new_service_id;

    let mut packet_handler = PacketHandler::new(new_private_key, Default::default());
    let connection_handle = packet_handler.new_incoming_connection()?;

    // introduction handshake
    let packet = Packet::IntroductionPacket(introduction::IntroductionPacket::new(vec![
        introduction::Version::RicochetRefresh3,
    ])?);
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    assert!(matches!(event, Event::IntroductionReceived));
    assert_eq!(to_legacy.len(), 1usize);
    let packet = to_legacy.remove(0);
    assert!(matches!(
        packet,
        Packet::IntroductionResponsePacket(introduction::IntroductionResponsePacket {
            version: Some(introduction::Version::RicochetRefresh3)
        })
    ));

    // authorize legacy client: open channel, send cookie
    let client_cookie: [u8; 16] = Default::default();
    let packet = Packet::ControlChannelPacket(control_channel::Packet::OpenChannel(
        control_channel::OpenChannel::new(
            1i32,
            control_channel::ChannelType::AuthHiddenService,
            Some(control_channel::OpenChannelExtension::AuthHiddenService(
                auth_hidden_service::OpenChannel { client_cookie },
            )),
        )?,
    ));
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    assert!(matches!(event, Event::OpenChannelAuthHiddenServiceReceived));
    assert_eq!(to_legacy.len(), 1usize);
    let packet = to_legacy.remove(0);
    let channel_result = if let Packet::ControlChannelPacket(
        control_channel::Packet::ChannelResult(channel_result),
    ) = packet
    {
        channel_result
    } else {
        bail!("unexpected packet: {packet:?}");
    };
    assert_eq!(channel_result.channel_identifier(), 1u16);
    assert_eq!(channel_result.opened(), true);
    assert_eq!(channel_result.common_error(), &None);
    let server_cookie =
        if let Some(control_channel::ChannelResultExtension::AuthHiddenService(channel_result)) =
            channel_result.extension()
        {
            channel_result.server_cookie
        } else {
            bail!(
                "unexpected channel_result: {:?}",
                channel_result.extension()
            );
        };
    // authorize client: send proof
    let message = auth_hidden_service::Proof::message(
        &client_cookie,
        &server_cookie,
        client_service_id,
        server_service_id,
    );
    let signature = legacy_private_key.sign_message(&message);
    let signature = signature.to_bytes();
    let packet = Packet::AuthHiddenServicePacket {
        channel: 1u16,
        packet: auth_hidden_service::Packet::Proof(auth_hidden_service::Proof::new(
            signature,
            client_service_id.clone(),
        )?),
    };
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    match event {
        Event::ClientAuthenticated {
            service_id,
            duplicate_connection,
        } => {
            assert_eq!(&service_id, client_service_id);
            assert!(duplicate_connection.is_none());
        }
        evt => bail!("unexpected event: {evt:?}"),
    }

    // close auth hidden service channel
    assert_eq!(to_legacy.len(), 2);
    let packet = to_legacy.remove(0);
    if let Packet::AuthHiddenServicePacket {
        channel: 1u16,
        packet: auth_hidden_service::Packet::Result(result),
    } = packet
    {
        assert!(result.accepted());
        assert!(matches!(result.is_known_contact(), Some(false)));
    } else {
        bail!("unexpected packet: {packet:?}");
    }
    let packet = to_legacy.remove(0);
    assert!(matches!(
        packet,
        Packet::CloseChannelPacket { channel: 1u16 }
    ));

    // legacy also closes hidden service channel
    let packet = Packet::CloseChannelPacket { channel: 1u16 };
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    assert!(matches!(event, Event::ProtocolFailure { .. }));

    // contact request: open channel
    let packet = Packet::ControlChannelPacket(control_channel::Packet::OpenChannel(
        control_channel::OpenChannel::new(
            3i32,
            control_channel::ChannelType::ContactRequest,
            Some(
                control_channel::OpenChannelExtension::ContactRequestChannel(
                    contact_request_channel::OpenChannel {
                        contact_request: contact_request_channel::ContactRequest {
                            nickname: contact_request_channel::Nickname::try_from(
                                "alice".to_string(),
                            )?,
                            message_text: contact_request_channel::MessageText::try_from(
                                "Hello!".to_string(),
                            )?,
                        },
                    },
                ),
            ),
        )?,
    ));
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::ContactRequestReceived {
        service_id,
        nickname,
        message_text,
    } = event
    {
        assert_eq!(&service_id, client_service_id);
        assert_eq!(nickname.as_str(), "alice");
        assert_eq!(message_text.as_str(), "Hello!");
    }

    // contact request: reply with confirmation channel is opened
    // and response is pending
    assert_eq!(to_legacy.len(), 1);
    let packet = to_legacy.remove(0);
    if let Packet::ControlChannelPacket(control_channel::Packet::ChannelResult(channel_result)) =
        packet
    {
        assert_eq!(channel_result.channel_identifier(), 3u16);
        assert!(channel_result.opened());
        assert!(channel_result.common_error().is_none());
        assert!(matches!(
            channel_result.extension(),
            Some(
                control_channel::ChannelResultExtension::ContactRequestChannel(
                    contact_request_channel::ChannelResult {
                        response: contact_request_channel::Response {
                            status: contact_request_channel::Status::Pending
                        }
                    }
                )
            )
        ));
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    // contact request: accept, close contact request channel
    // and open outgoing chat and file transfer channels
    assert_eq!(
        packet_handler.accept_contact_request(client_service_id.clone(), &mut to_legacy)?,
        connection_handle
    );
    assert_eq!(to_legacy.len(), 4);
    let packet = to_legacy.remove(0);
    assert!(matches!(
        packet,
        Packet::ContactRequestChannelPacket {
            channel: 3u16,
            packet: contact_request_channel::Packet::Response(contact_request_channel::Response {
                status: contact_request_channel::Status::Accepted,
            }),
        }
    ));
    let packet = to_legacy.remove(0);
    assert!(matches!(
        packet,
        Packet::CloseChannelPacket { channel: 3u16 }
    ));
    let packet = to_legacy.remove(0);
    if let Packet::ControlChannelPacket(control_channel::Packet::OpenChannel(open_channel)) = packet
    {
        assert_eq!(open_channel.channel_identifier(), 2u16);
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
        assert_eq!(open_channel.channel_identifier(), 4u16);
        assert_eq!(
            open_channel.channel_type(),
            &control_channel::ChannelType::FileTransfer
        );
        assert!(open_channel.extension().is_none());
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    // legacy opens new outgoing chat and file transfer channels, also closes
    // contact request channel, and accepts openning incomng chat and file
    // transfer channels

    // chat channel
    let packet = Packet::ControlChannelPacket(control_channel::Packet::OpenChannel(
        control_channel::OpenChannel::new(5i32, control_channel::ChannelType::Chat, None)?,
    ));
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::IncomingChatChannelOpened { service_id } = event {
        assert_eq!(&service_id, client_service_id);
    } else {
        bail!("unexpected event: {event:?}");
    }
    assert_eq!(to_legacy.len(), 1);
    let packet = to_legacy.remove(0);
    if let Packet::ControlChannelPacket(control_channel::Packet::ChannelResult(channel_result)) =
        packet
    {
        assert_eq!(channel_result.channel_identifier(), 5u16);
        assert!(channel_result.opened());
        assert!(channel_result.common_error().is_none());
        assert!(channel_result.extension().is_none());
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    // file transfer channel
    let packet = Packet::ControlChannelPacket(control_channel::Packet::OpenChannel(
        control_channel::OpenChannel::new(7i32, control_channel::ChannelType::FileTransfer, None)?,
    ));
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::IncomingFileTransferChannelOpened { service_id } = event {
        assert_eq!(&service_id, client_service_id);
    } else {
        bail!("unexpected event: {event:?}");
    }
    assert_eq!(to_legacy.len(), 1);
    let packet = to_legacy.remove(0);
    if let Packet::ControlChannelPacket(control_channel::Packet::ChannelResult(channel_result)) =
        packet
    {
        assert_eq!(channel_result.channel_identifier(), 7u16);
        assert!(channel_result.opened());
        assert!(channel_result.common_error().is_none());
        assert!(channel_result.extension().is_none());
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    // close client authentication channel
    let packet = Packet::CloseChannelPacket { channel: 3u16 };
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    assert!(matches!(event, Event::ProtocolFailure { .. }));
    assert!(to_legacy.is_empty());

    // legacy confirms opening of chat channel
    let packet = Packet::ControlChannelPacket(control_channel::Packet::ChannelResult(
        control_channel::ChannelResult::new(2i32, true, None, None)?,
    ));
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::OutgoingChatChannelOpened { service_id } = event {
        assert_eq!(&service_id, client_service_id)
    } else {
        bail!("unexpected event: {event:?}");
    }

    // legacy confirms opening of file transfer channel
    let packet = Packet::ControlChannelPacket(control_channel::Packet::ChannelResult(
        control_channel::ChannelResult::new(4i32, true, None, None)?,
    ));
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::OutgoingFileTransferChannelOpened { service_id } = event {
        assert_eq!(&service_id, client_service_id)
    } else {
        bail!("unexpected event: {event:?}");
    }

    // legacy client sends a chat message
    let packet = Packet::ChatChannelPacket {
        channel: 5u16,
        packet: chat_channel::Packet::ChatMessage(chat_channel::ChatMessage::new(
            chat_channel::MessageText::try_from("hello!".to_string())?,
            338555239,
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
        assert_eq!(&service_id, client_service_id);
        assert_eq!(message_text, "hello!");
        assert_eq!(message_handle.message_id(), 338555239);
        assert_eq!(time_delta, std::time::Duration::ZERO);
    } else {
        bail!("unexpected event: {event:?}");
    }
    // new host would reply with an ack
    assert_eq!(to_legacy.len(), 1);
    let packet = to_legacy.remove(0);
    if let Packet::ChatChannelPacket {
        channel: 5u16,
        packet: chat_channel::Packet::ChatAcknowledge(chat_acknowledge),
    } = packet
    {
        assert_eq!(chat_acknowledge.message_id(), 338555239);
        assert!(chat_acknowledge.accepted());
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    // host sends a reply chat message
    let (dest, message_handle) = packet_handler.send_message(
        legacy_service_id.clone(),
        chat_channel::MessageText::try_from("hi there!".to_string())?,
        &mut to_legacy,
    )?;
    assert_eq!(dest, connection_handle);
    assert_eq!(message_handle.message_id(), 0);
    assert_eq!(to_legacy.len(), 1);
    let packet = to_legacy.remove(0);
    if let Packet::ChatChannelPacket {
        channel: 2u16,
        packet: chat_channel::Packet::ChatMessage(chat_message),
    } = packet
    {
        assert_eq!(String::from(chat_message.message_text()), "hi there!");
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    // legacy would reply with an ack
    let packet = Packet::ChatChannelPacket {
        channel: 2u16,
        packet: chat_channel::Packet::ChatAcknowledge(chat_channel::ChatAcknowledge::new(0, true)?),
    };
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::ChatAcknowledgeReceived {
        service_id,
        message_handle,
        accepted,
    } = event
    {
        assert_eq!(&service_id, client_service_id);
        assert_eq!(message_handle.message_id(), 0);
        assert!(accepted);
    } else {
        bail!("unexpected event: {event:?}");
    }

    // legacy sends a file transfer request and host replies with an ack
    let packet = Packet::FileChannelPacket {
        channel: 7u16,
        packet: file_channel::Packet::FileHeader(file_channel::FileHeader::new(
            338555240,
            128u64,
            "small-file.bin".to_string(),
            [
                18, 122, 4, 8, 136, 86, 210, 183, 149, 112, 122, 154, 225, 69, 207, 170, 119, 140,
                248, 129, 203, 219, 196, 237, 94, 12, 206, 88, 64, 9, 89, 110, 158, 170, 232, 137,
                216, 159, 27, 136, 24, 227, 92, 60, 42, 252, 179, 83, 253, 175, 183, 148, 52, 216,
                243, 123, 255, 31, 194, 28, 93, 161, 50, 247,
            ],
        )?),
    };
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    let file_transfer_handle = if let Event::FileTransferRequestReceived {
        service_id,
        file_transfer_handle,
        file_name,
        file_size,
        file_hash,
    } = event
    {
        assert_eq!(&service_id, client_service_id);
        assert_eq!(file_transfer_handle.file_id(), 338555240u32);
        assert_eq!(file_size, 128u64);
        assert_eq!(file_name, "small-file.bin");
        assert_eq!(
            file_hash,
            [
                18, 122, 4, 8, 136, 86, 210, 183, 149, 112, 122, 154, 225, 69, 207, 170, 119, 140,
                248, 129, 203, 219, 196, 237, 94, 12, 206, 88, 64, 9, 89, 110, 158, 170, 232, 137,
                216, 159, 27, 136, 24, 227, 92, 60, 42, 252, 179, 83, 253, 175, 183, 148, 52, 216,
                243, 123, 255, 31, 194, 28, 93, 161, 50, 247,
            ]
        );
        file_transfer_handle
    } else {
        bail!("unexpected event: {event:?}");
    };

    assert_eq!(to_legacy.len(), 1);
    let packet = to_legacy.remove(0);
    if let Packet::FileChannelPacket {
        channel: 7u16,
        packet: file_channel::Packet::FileHeaderAck(file_header_ack),
    } = packet
    {
        assert_eq!(file_header_ack.file_id(), 338555240u32);
        assert!(file_header_ack.accepted());
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    // accept file transfer request
    assert_eq!(
        packet_handler.accept_file_transfer_request(
            &client_service_id,
            file_transfer_handle,
            &mut to_legacy
        )?,
        connection_handle
    );
    assert_eq!(to_legacy.len(), 1);
    let packet = to_legacy.remove(0);
    if let Packet::FileChannelPacket {
        channel: 7u16,
        packet: file_channel::Packet::FileHeaderResponse(file_header_response),
    } = packet
    {
        assert_eq!(file_header_response.file_id(), 338555240u32);
        assert_eq!(
            file_header_response.response(),
            &file_channel::Response::Accept
        );
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    // legacy sends file chunk
    let packet = Packet::FileChannelPacket {
        channel: 7u16,
        packet: file_channel::Packet::FileChunk(file_channel::FileChunk::new(
            338555240u32,
            file_channel::ChunkData::new(vec![
                8, 200, 16, 250, 52, 56, 251, 245, 252, 138, 248, 77, 200, 40, 233, 220, 92, 109,
                13, 53, 2, 82, 212, 192, 229, 113, 222, 173, 196, 48, 11, 246, 248, 176, 40, 197,
                253, 68, 62, 238, 151, 136, 110, 37, 192, 137, 167, 170, 135, 79, 153, 146, 107, 2,
                208, 27, 158, 130, 200, 37, 203, 16, 61, 104, 106, 108, 196, 137, 116, 70, 36, 66,
                21, 90, 117, 190, 187, 220, 187, 117, 135, 43, 219, 184, 185, 242, 71, 230, 193,
                37, 37, 183, 248, 219, 26, 201, 78, 156, 46, 138, 178, 235, 118, 183, 27, 57, 153,
                186, 236, 72, 165, 156, 0, 63, 239, 116, 39, 73, 203, 196, 169, 207, 106, 65, 120,
                201, 202, 78,
            ])?,
        )?),
    };
    let event = packet_handler.handle_packet(connection_handle, packet, &mut to_legacy)?;
    if let Event::FileChunkReceived {
        service_id,
        file_transfer_handle,
        data,
        last_chunk: true,
        hash_matches: Some(true),
    } = event
    {
        assert_eq!(&service_id, client_service_id);
        assert_eq!(file_transfer_handle.file_id(), 338555240u32);
        assert_eq!(
            data,
            vec![
                8, 200, 16, 250, 52, 56, 251, 245, 252, 138, 248, 77, 200, 40, 233, 220, 92, 109,
                13, 53, 2, 82, 212, 192, 229, 113, 222, 173, 196, 48, 11, 246, 248, 176, 40, 197,
                253, 68, 62, 238, 151, 136, 110, 37, 192, 137, 167, 170, 135, 79, 153, 146, 107, 2,
                208, 27, 158, 130, 200, 37, 203, 16, 61, 104, 106, 108, 196, 137, 116, 70, 36, 66,
                21, 90, 117, 190, 187, 220, 187, 117, 135, 43, 219, 184, 185, 242, 71, 230, 193,
                37, 37, 183, 248, 219, 26, 201, 78, 156, 46, 138, 178, 235, 118, 183, 27, 57, 153,
                186, 236, 72, 165, 156, 0, 63, 239, 116, 39, 73, 203, 196, 169, 207, 106, 65, 120,
                201, 202, 78,
            ]
        );
    } else {
        bail!("unexpected event: {event:?}");
    }
    assert_eq!(to_legacy.len(), 2);
    let packet = to_legacy.remove(0);
    if let Packet::FileChannelPacket {
        channel: 7u16,
        packet: file_channel::Packet::FileChunkAck(file_chunk_ack),
    } = packet
    {
        assert_eq!(file_chunk_ack.file_id(), 338555240u32);
        assert_eq!(file_chunk_ack.bytes_received(), 128u64);
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    let packet = to_legacy.remove(0);
    if let Packet::FileChannelPacket {
        channel: 7u16,
        packet:
            file_channel::Packet::FileTransferCompleteNotification(file_transfer_complete_notification),
    } = packet
    {
        assert_eq!(file_transfer_complete_notification.file_id(), 338555240u32);
        assert_eq!(
            file_transfer_complete_notification.result(),
            &file_channel::FileTransferResult::Success
        );
    } else {
        bail!("unexpected packet: {packet:?}");
    }

    Ok(())
}
