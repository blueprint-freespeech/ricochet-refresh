// std
use std::collections::BTreeMap;

pub mod introduction;
pub mod control_channel;
pub mod chat_channel;
pub mod contact_request_channel;
pub mod auth_hidden_service;
pub mod file_channel;

/// The error type for the [`Message`] type.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid protocol version: {0:#04x}")]
    InvalidVersion(u8),
    #[error("invalid introduction packet")]
    InvalidIntroductionPacket,
    #[error("invalid channel type: \"{0}\"")]
    InvalidChannelType(String),
    #[error("chat message too long")]
    InvalidChatMessageTooLong,
    #[error("chat message empty")]
    InvalidChatMessageEmpty,
    #[error("nickname too long")]
    InvalidNicknameTooLong,
    #[error("nickname contains non-character: {0:#06x}")]
    InvalidNicknameContainsNonCharacter(u16),
    #[error("nickname contains html character: '{0}'")]
    InvalidNicknameContainsHtmlCharacter(char),
    #[error("nickname contains format code unit (Cf): {0:#06x}")]
    InvalidNicknameContainsFormatCodeUnit(u16),
    #[error("nickname contains control code unit (Cc): {0:#06x}")]
    InvalidNicknameContainsControlCodeUnit(u16),
    #[error("contact request message too long")]
    InvalidContactRequestMessageTooLong,
    #[error("chunk_data too large: {0} bytes")]
    InvalidFileChunkDataTooLarge(usize),
    #[error("not enough data")]
    NeedMoreBytes,
    #[error("target channel does not exist: {0}")]
    TargetChannelDoesNotExist(u16),
    // received bytes cannot be parsed or understood
    #[error("bad data stream")]
    BadDataStream,
    // an error when parsing a protobuf message
    #[error("protobuf error: {0}")]
    ProtobufError(#[source] protobuf::Error),
    // received message parses but contains incorrectly formatted data (e.g. byte arrays wrong size, wrong combinatins of optional params, etc)
    #[error("invalid protobuf message")]
    InvalidProtobufMessage,

    // failed to construct a packet type
    #[error("packet construction failed: {0}")]
    PacketConstructionFailed(String),

    // TODO: remove this error when no longer needed
    #[error("not implemented")]
    NotImplemented,
}

//
// Ricochet Protocol Packet
//
#[derive(Debug, PartialEq)]
pub enum Packet {
    // sent by client to begin Ricochet-Refresh handshake
    IntroductionPacket(introduction::IntroductionPacket),
    // server reply indicating introduction success or failure
    IntroductionResponsePacket(introduction::IntroductionResponsePacket),
    // used to open various channel types
    ControlChannelPacket(control_channel::Packet),
    // used to close a channel
    CloseChannelPacket{channel: u16},
    // used to send/ack messages
    ChatChannelPacket{
        channel: u16,
        packet: chat_channel::Packet,
    },
    // used to authorise connecting clients
    AuthHiddenServicePacket{
        channel: u16,
        packet: auth_hidden_service::Packet,
    },
    // used to send file attachments
    FileChannelPacket{
        channel: u16,
        packet: file_channel::Packet,
    },
}

impl Packet {
    pub fn write_to_vec(&self, v:& mut Vec<u8>) -> Result<(), crate::Error> {
        match self {
            Packet::IntroductionPacket(packet) => packet.write_to_vec(v)?,
            Packet::IntroductionResponsePacket(packet) => packet.write_to_vec(v)?,
            packet => {
                let packet_begin = v.len();

                let header_begin = packet_begin;
                let size_hi = header_begin + 0usize;
                let size_lo = header_begin + 1usize;
                let channel_hi = header_begin + 2usize;
                let channel_lo = header_begin + 3usize;

                let header_size = 4usize;

                v.resize(v.len() + header_size, 0xffu8);

                let data_begin = v.len();
                let channel = match packet {
                    Packet::ControlChannelPacket(packet) => {
                        packet.write_to_vec(v)?;
                        0u16
                    },
                    Packet::CloseChannelPacket{channel} => {
                        *channel
                    },
                    Packet::ChatChannelPacket{channel, packet} => {
                        packet.write_to_vec(v)?;
                        *channel
                    },
                    Packet::AuthHiddenServicePacket{channel, packet} => {
                        packet.write_to_vec(v)?;
                        *channel
                    },
                    Packet::FileChannelPacket{channel, packet} => {
                        packet.write_to_vec(v)?;
                        *channel
                    },
                    _ => unreachable!(),
                };
                let data_end = v.len();
                let data_size = data_end - data_begin;
                let packet_size = header_size + data_size;
                assert!(packet_size <= u16::MAX as usize);
                let size = (packet_size & 0xffffusize) as u16;

                v[size_hi] = ((size & 0xff00u16) >> 8) as u8;
                v[size_lo] = (size & 0xffu16) as u8;
                v[channel_hi] = ((channel & 0xff00u16) >> 8) as u8;
                v[channel_lo] = (channel & 0xffu16) as u8;
            }
        }
        Ok(())
    }
}

// on success returns a (packet, bytes read) tuple
// consumers should drop the returned number of bytes from their
// read buffer
// TODO: should return an Result<Option<(Packet, usize)>, Error> instead
// of using an Error for 'needs more bytes'
pub fn next_packet(bytes: &[u8], channel_map: BTreeMap<u16, control_channel::ChannelType>) -> Result<(Packet, usize), Error> {

    if channel_map.is_empty() {
        match TryInto::<introduction::IntroductionPacket>::try_into(bytes) {
            Ok(packet) => {
                let offset = 3 + packet.versions().len();
                return Ok((Packet::IntroductionPacket(packet), offset));
            },
            Err(Error::NeedMoreBytes) => return Err(Error::NeedMoreBytes),
            _ => (),
        }

        match TryInto::<introduction::IntroductionResponsePacket>::try_into(bytes) {
            Ok(packet) => {
                let offset = 1;
                return Ok((Packet::IntroductionResponsePacket(packet), offset));
            },
            Err(Error::NeedMoreBytes) => return Err(Error::NeedMoreBytes),
            _ => (),
        }

        return Err(Error::BadDataStream);
    } else {
        if bytes.len() >= 4 {
            // size is encoded as big-endian u16
            let size: u16 = (bytes[0] as u16) << 8 + bytes[1] as u16;
            let size = size as usize;
            // channel id is encoded as big-endian u16
            let channel: u16 = (bytes[2] as u16) << 8 + bytes[3] as u16;

            // size must be at least
            if size < 4 {
                Err(Error::BadDataStream)
            } else if bytes.len() < size {
                Err(Error::NeedMoreBytes)
            } else if size == 4 {
                Ok((Packet::CloseChannelPacket{channel}, 4))
            } else {
                let bytes = &bytes[4..];
                use control_channel::ChannelType;
                let packet = match channel_map.get(&channel) {
                    Some(ChannelType::Control) => {
                        let packet = control_channel::Packet::try_from(bytes)?;
                        Packet::ControlChannelPacket(packet)
                    },
                    Some(ChannelType::Chat) => {
                        let packet = chat_channel::Packet::try_from(bytes)?;
                        Packet::ChatChannelPacket{channel, packet}
                    },
                    Some(ChannelType::AuthHiddenService) => {
                        let packet = auth_hidden_service::Packet::try_from(bytes)?;
                        Packet::AuthHiddenServicePacket{channel, packet}
                    },
                    Some(ChannelType::FileTransfer) => {
                        let packet = file_channel::Packet::try_from(bytes)?;
                        Packet::FileChannelPacket{channel, packet}
                    },
                    Some(_) => return Err(Error::NotImplemented),
                    None => return Err(Error::TargetChannelDoesNotExist(channel)),
                };
                Ok((packet, size))
            }
        } else {
            Err(Error::NeedMoreBytes)
        }
    }
}

#[test]
fn test_round_trip() -> anyhow::Result<()> {

    // OpenChannel ContactRequestChannel
    {
        println!("---");
        let nickname: contact_request_channel::Nickname = "alice".to_string().try_into()?;
        let message_text: contact_request_channel::MessageText = "hello world".to_string().try_into()?;

        println!("{nickname:?}: {message_text:?}");

        let contact_request = contact_request_channel::ContactRequest{nickname, message_text};

        println!("{contact_request:?}");

        let open_channel = control_channel::OpenChannel::new(1, control_channel::ChannelType::ContactRequest, Some(control_channel::OpenChannelExtension::ContactRequestChannel(contact_request_channel::OpenChannel{contact_request})))?;

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
        let open_channel = control_channel::OpenChannel::new(1i32, control_channel::ChannelType::AuthHiddenService, Some(control_channel::OpenChannelExtension::AuthHiddenService(auth_hidden_service::OpenChannel{client_cookie})))?;

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

        let response = contact_request_channel::Response{status: contact_request_channel::Status::Pending};

        let channel_result = control_channel::ChannelResult::new(1i32, false, control_channel::CommonError::GenericError, Some(control_channel::ChannelResultExtension::ContactRequestChannel(contact_request_channel::ChannelResult{response})))?;

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

        let channel_result = control_channel::ChannelResult::new(1i32, false, control_channel::CommonError::GenericError, Some(control_channel::ChannelResultExtension::AuthHiddenService(auth_hidden_service::ChannelResult{server_cookie})))?;

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

        let signature = [0u8; auth_hidden_service::PROOF_SIGNATURE_SIZE];
        let private_key = tor_interface::tor_crypto::Ed25519PrivateKey::generate();
        let service_id = tor_interface::tor_crypto::V3OnionServiceId::from_private_key(&private_key);

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

        let file_transfer_complete_notification = file_channel::FileTransferCompleteNotification::new(file_id, result)?;

        println!("{file_transfer_complete_notification:?}");

        let packet_src = file_channel::Packet::FileTransferCompleteNotification(file_transfer_complete_notification);

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

    anyhow::bail!("test over");
}