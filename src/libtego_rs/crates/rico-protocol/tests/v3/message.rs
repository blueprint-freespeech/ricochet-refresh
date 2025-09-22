use rico_protocol::v3::message::*;

#[test]
fn test_round_trip() -> anyhow::Result<()> {
    // OpenChannel ContactRequestChannel
    {
        println!("---");
        let nickname: contact_request_channel::Nickname = "alice".to_string().try_into()?;
        let message_text: contact_request_channel::MessageText =
            "hello world".to_string().try_into()?;

        println!("{nickname:?}: {message_text:?}");

        let contact_request = contact_request_channel::ContactRequest {
            nickname,
            message_text,
        };

        println!("{contact_request:?}");

        let open_channel = control_channel::OpenChannel::new(
            1,
            control_channel::ChannelType::ContactRequest,
            Some(
                control_channel::OpenChannelExtension::ContactRequestChannel(
                    contact_request_channel::OpenChannel { contact_request },
                ),
            ),
        )?;

        println!("{open_channel:?}");

        let packet_src = control_channel::Packet::OpenChannel(open_channel);

        println!("{packet_src:?}");

        let mut bytes: Vec<u8> = Vec::default();
        packet_src.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        let packet_dest: control_channel::Packet = bytes.as_slice().try_into()?;

        println!("{packet_dest:?}");
        let mut bytes: Vec<u8> = Vec::default();
        packet_dest.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        assert_eq!(packet_src, packet_dest);
    }

    // OpenChannel AuthHiddenService
    {
        println!("---");
        let client_cookie: [u8; 16] = Default::default();
        let open_channel = control_channel::OpenChannel::new(
            1i32,
            control_channel::ChannelType::AuthHiddenService,
            Some(control_channel::OpenChannelExtension::AuthHiddenService(
                auth_hidden_service::OpenChannel { client_cookie },
            )),
        )?;

        println!("{open_channel:?}");

        let packet_src = control_channel::Packet::OpenChannel(open_channel);

        println!("{packet_src:?}");

        let mut bytes: Vec<u8> = Vec::default();
        packet_src.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        let packet_dest: control_channel::Packet = bytes.as_slice().try_into()?;

        println!("{packet_dest:?}");
        let mut bytes: Vec<u8> = Vec::default();
        packet_dest.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        assert_eq!(packet_src, packet_dest);
    }
    // ChannelResult ContactRequestChanel
    {
        println!("---");

        let response = contact_request_channel::Response {
            status: contact_request_channel::Status::Pending,
        };

        let channel_result = control_channel::ChannelResult::new(
            1i32,
            false,
            Some(control_channel::CommonError::GenericError),
            Some(
                control_channel::ChannelResultExtension::ContactRequestChannel(
                    contact_request_channel::ChannelResult { response },
                ),
            ),
        )?;

        println!("{channel_result:?}");

        let packet_src = control_channel::Packet::ChannelResult(channel_result);

        println!("{packet_src:?}");

        let mut bytes: Vec<u8> = Vec::default();
        packet_src.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        let packet_dest: control_channel::Packet = bytes.as_slice().try_into()?;

        println!("{packet_dest:?}");
        let mut bytes: Vec<u8> = Vec::default();
        packet_dest.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        assert_eq!(packet_src, packet_dest);
    }

    // ChannelResult AuthHiddenService
    {
        println!("---");

        let server_cookie: [u8; 16] = Default::default();

        let channel_result = control_channel::ChannelResult::new(
            1i32,
            false,
            Some(control_channel::CommonError::GenericError),
            Some(control_channel::ChannelResultExtension::AuthHiddenService(
                auth_hidden_service::ChannelResult { server_cookie },
            )),
        )?;

        println!("{channel_result:?}");

        let packet_src = control_channel::Packet::ChannelResult(channel_result);

        println!("{packet_src:?}");

        let mut bytes: Vec<u8> = Vec::default();
        packet_src.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        let packet_dest: control_channel::Packet = bytes.as_slice().try_into()?;

        println!("{packet_dest:?}");
        let mut bytes: Vec<u8> = Vec::default();
        packet_dest.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        assert_eq!(packet_src, packet_dest);
    }

    // ChatChannel ChatMessage
    {
        println!("---");

        let message_text: chat_channel::MessageText = "hello world".to_string().try_into()?;
        let message_id = 12u32;
        let time_delta = Some(std::time::Duration::from_secs(2));

        let chat_message = chat_channel::ChatMessage::new(message_text, message_id, time_delta)?;

        println!("{chat_message:?}");

        let packet_src = chat_channel::Packet::ChatMessage(chat_message);

        println!("{packet_src:?}");

        let mut bytes: Vec<u8> = Vec::default();
        packet_src.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        let packet_dest: chat_channel::Packet = bytes.as_slice().try_into()?;

        println!("{packet_dest:?}");
        let mut bytes: Vec<u8> = Vec::default();
        packet_dest.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        assert_eq!(packet_src, packet_dest);
    }

    // ChatChannel ChatAcknowledge
    {
        println!("---");

        let message_id = 12u32;
        let accepted = true;

        let chat_acknowledge = chat_channel::ChatAcknowledge::new(message_id, accepted)?;

        println!("{chat_acknowledge:?}");

        let packet_src = chat_channel::Packet::ChatAcknowledge(chat_acknowledge);

        println!("{packet_src:?}");

        let mut bytes: Vec<u8> = Vec::default();
        packet_src.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        let packet_dest: chat_channel::Packet = bytes.as_slice().try_into()?;

        println!("{packet_dest:?}");
        let mut bytes: Vec<u8> = Vec::default();
        packet_dest.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        assert_eq!(packet_src, packet_dest);
    }

    // AuthHiddenService Proof
    {
        println!("---");

        let signature = [0u8; 64];
        let private_key = tor_interface::tor_crypto::Ed25519PrivateKey::generate();
        let service_id =
            tor_interface::tor_crypto::V3OnionServiceId::from_private_key(&private_key);

        let proof = auth_hidden_service::Proof::new(signature, service_id)?;

        println!("{proof:?}");

        let packet_src = auth_hidden_service::Packet::Proof(proof);

        println!("{packet_src:?}");

        let mut bytes: Vec<u8> = Vec::default();
        packet_src.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        let packet_dest: auth_hidden_service::Packet = bytes.as_slice().try_into()?;

        println!("{packet_dest:?}");
        let mut bytes: Vec<u8> = Vec::default();
        packet_dest.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        assert_eq!(packet_src, packet_dest);
    }

    // AuthHiddenService Result
    {
        println!("---");

        let accepted = false;
        let is_known_contact = Some(false);

        let result = auth_hidden_service::Result::new(accepted, is_known_contact)?;

        println!("{result:?}");

        let packet_src = auth_hidden_service::Packet::Result(result);

        println!("{packet_src:?}");

        let mut bytes: Vec<u8> = Vec::default();
        packet_src.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        let packet_dest: auth_hidden_service::Packet = bytes.as_slice().try_into()?;

        println!("{packet_dest:?}");
        let mut bytes: Vec<u8> = Vec::default();
        packet_dest.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        assert_eq!(packet_src, packet_dest);
    }

    // FileChannel FileHeader
    {
        println!("---");

        let file_id = 12u32;
        let file_size = 128u64;
        let name = "file.txt".to_string();
        let file_hash = [0u8; file_channel::FILE_HASH_SIZE];

        let file_header = file_channel::FileHeader::new(file_id, file_size, name, file_hash)?;

        println!("{file_header:?}");

        let packet_src = file_channel::Packet::FileHeader(file_header);

        println!("{packet_src:?}");

        let mut bytes: Vec<u8> = Vec::default();
        packet_src.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        let packet_dest: file_channel::Packet = bytes.as_slice().try_into()?;

        println!("{packet_dest:?}");
        let mut bytes: Vec<u8> = Vec::default();
        packet_dest.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        assert_eq!(packet_src, packet_dest);
    }

    // FileChannel FileHeaderAck
    {
        println!("---");

        let file_id = 12u32;
        let accepted = false;

        let file_header_ack = file_channel::FileHeaderAck::new(file_id, accepted)?;

        println!("{file_header_ack:?}");

        let packet_src = file_channel::Packet::FileHeaderAck(file_header_ack);

        println!("{packet_src:?}");

        let mut bytes: Vec<u8> = Vec::default();
        packet_src.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        let packet_dest: file_channel::Packet = bytes.as_slice().try_into()?;

        println!("{packet_dest:?}");
        let mut bytes: Vec<u8> = Vec::default();
        packet_dest.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        assert_eq!(packet_src, packet_dest);
    }

    // FileChannel FileHeaderResponse
    {
        println!("---");

        let file_id = 12u32;
        let response = file_channel::Response::Reject;

        let file_header_response = file_channel::FileHeaderResponse::new(file_id, response)?;

        println!("{file_header_response:?}");

        let packet_src = file_channel::Packet::FileHeaderResponse(file_header_response);

        println!("{packet_src:?}");

        let mut bytes: Vec<u8> = Vec::default();
        packet_src.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        let packet_dest: file_channel::Packet = bytes.as_slice().try_into()?;

        println!("{packet_dest:?}");
        let mut bytes: Vec<u8> = Vec::default();
        packet_dest.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        assert_eq!(packet_src, packet_dest);
    }

    // FileChannel FileChunk
    {
        println!("---");

        let file_id = 12u32;
        let chunk_data: file_channel::ChunkData = vec![0u8, 1u8, 2u8].try_into()?;

        let file_chunk = file_channel::FileChunk::new(file_id, chunk_data)?;

        println!("{file_chunk:?}");

        let packet_src = file_channel::Packet::FileChunk(file_chunk);

        println!("{packet_src:?}");

        let mut bytes: Vec<u8> = Vec::default();
        packet_src.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        let packet_dest: file_channel::Packet = bytes.as_slice().try_into()?;

        println!("{packet_dest:?}");
        let mut bytes: Vec<u8> = Vec::default();
        packet_dest.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        assert_eq!(packet_src, packet_dest);
    }

    // FileChannel FileChunAck
    {
        println!("---");

        let file_id = 12u32;
        let bytes_received = 48u64;

        let file_chunk_ack = file_channel::FileChunkAck::new(file_id, bytes_received)?;

        println!("{file_chunk_ack:?}");

        let packet_src = file_channel::Packet::FileChunkAck(file_chunk_ack);

        println!("{packet_src:?}");

        let mut bytes: Vec<u8> = Vec::default();
        packet_src.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        let packet_dest: file_channel::Packet = bytes.as_slice().try_into()?;

        println!("{packet_dest:?}");
        let mut bytes: Vec<u8> = Vec::default();
        packet_dest.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        assert_eq!(packet_src, packet_dest);
    }

    // FileChannel FileTransferCompleteNotification
    {
        println!("---");

        let file_id = 12u32;
        let result = file_channel::FileTransferResult::Failure;

        let file_transfer_complete_notification =
            file_channel::FileTransferCompleteNotification::new(file_id, result)?;

        println!("{file_transfer_complete_notification:?}");

        let packet_src = file_channel::Packet::FileTransferCompleteNotification(
            file_transfer_complete_notification,
        );

        println!("{packet_src:?}");

        let mut bytes: Vec<u8> = Vec::default();
        packet_src.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        let packet_dest: file_channel::Packet = bytes.as_slice().try_into()?;

        println!("{packet_dest:?}");
        let mut bytes: Vec<u8> = Vec::default();
        packet_dest.write_to_vec(&mut bytes)?;

        println!("{bytes:?}");

        assert_eq!(packet_src, packet_dest);
    }

    Ok(())
}
