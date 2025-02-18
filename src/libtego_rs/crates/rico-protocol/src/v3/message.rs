// std
use std::collections::BTreeMap;

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

    // TODO: remove this error when no longer needed
    #[error("not implemented")]
    NotImplemented,
}

//
// Introduction
//

pub mod introduction {

    pub struct IntroductionPacket {
        pub versions: Vec<Version>,
    }

    impl TryFrom<&[u8]> for IntroductionPacket {
        type Error = crate::Error;

        fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
            match bytes.len() {
                0 => Err(Self::Error::NeedMoreBytes),
                1 => if bytes[0] == 0x49 {
                    Err(Self::Error::NeedMoreBytes)
                } else {
                    Err(Self::Error::InvalidIntroductionPacket)
                },
                2 => if bytes[0] == 0x49 && bytes[1] == 0x4d {
                    Err(Self::Error::NeedMoreBytes)
                } else {
                    Err(Self::Error::InvalidIntroductionPacket)
                },
                3 => if bytes[0] == 0x49 && bytes[1] == 0x4d && bytes[3] >= 1 {
                    Err(Self::Error::NeedMoreBytes)
                } else {
                    Err(Self::Error::InvalidIntroductionPacket)
                }
                count => if bytes[0] == 0x49 && bytes[1] == 0x4d && bytes[3] >= 1 {
                    if count >= 3usize + bytes[3] as usize {
                        Err(Self::Error::NeedMoreBytes)
                    } else {
                        let version_count = bytes[3] as usize;
                        let mut versions: Vec<Version> = Vec::with_capacity(version_count);
                        for i in 0..version_count {
                            versions.push(bytes[3 + i].try_into()?);
                        }

                        Ok(IntroductionPacket{versions})
                    }
                } else {
                    Err(Self::Error::InvalidIntroductionPacket)
                }
            }
        }
    }

    pub struct IntroductionResponsePacket {
        pub version: Option<Version>,
    }

    impl TryFrom<&[u8]> for IntroductionResponsePacket {
        type Error = crate::Error;

        fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
            match bytes.len() {
                0 => Err(Self::Error::NeedMoreBytes),
                count => if bytes[0] == 0xff {
                    Ok(IntroductionResponsePacket{version: None})
                } else {
                    let version: Version = bytes[0].try_into()?;
                    Ok(IntroductionResponsePacket{version: Some(version)})
                }
            }
        }
    }

    pub enum Version {
        Ricochet1_0,
        Ricochet1_1,
        RicochetRefresh3,
    }

    impl From<Version> for u8 {
        fn from(version: Version) -> u8 {
            match version {
                Version::Ricochet1_0 => 0u8,
                Version::Ricochet1_1 => 1u8,
                Version::RicochetRefresh3 => 3u8,
            }
        }
    }

    impl TryFrom<u8> for Version {
        type Error = crate::Error;

        fn try_from(value: u8) -> Result<Self, Self::Error> {
            match value {
                0 => Ok(Version::Ricochet1_0),
                1 => Ok(Version::Ricochet1_1),
                3 => Ok(Version::RicochetRefresh3),
                _ => Err(Self::Error::InvalidVersion(value))
            }
        }
    }
}

//
// ControlChannel
//

pub mod control_channel {
    // this isn't actually used in the protocol but useful for debugging
    pub(crate) const CHANNEL_TYPE: &'static str = "im.ricochet.control";

    pub enum Packet {
        OpenChannel(OpenChannel),
        ChannelResult(ChannelResult),
        // TODO: Ricochet-Refresh v3 does not send:
        // - KeepAlive
        // - EnableFeatures
        // - FeaturesEnabled
        KeepAlive(KeepAlive),
        EnableFeatures(EnableFeatures),
        FeaturesEnabled(FeaturesEnabled),
    }

    impl TryFrom<&[u8]> for Packet {
        type Error = crate::Error;

        fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
            use protobuf::Message;
            use crate::v3::protos;

            // parse bytes into protobuf message
            let pb = protos::ControlChannel::Packet::parse_from_bytes(value).map_err(Self::Error::ProtobufError)?;

            // convert protobuf message to Packet

            // ensure the message has only 1 initialised member
            let mut count: usize = 0;
            count += pb.open_channel.is_some() as usize;
            count += pb.channel_result.is_some() as usize;
            count += pb.keep_alive.is_some() as usize;
            count += pb.enable_features.is_some() as usize;
            count += pb.features_enabled.is_some() as usize;

            if count != 1 {
                return Err(Self::Error::InvalidProtobufMessage);
            }

            if let Some(open_channel) = pb.open_channel.into_option() {
                // base fields
                let channel_identifier = open_channel.channel_identifier.ok_or(Self::Error::InvalidProtobufMessage)?;
                let channel_type = open_channel.channel_type.as_ref().ok_or(Self::Error::InvalidProtobufMessage)?;
                let channel_type: ChannelType = channel_type.as_str().try_into()?;

                // extension fields
                let contact_request = protos::ContactRequestChannel::exts::contact_request.get(&open_channel);
                let client_cookie = protos::AuthHiddenService::exts::client_cookie.get(&open_channel);

                let derived: Option<OpenChannelDerived> = match channel_type {
                    // contact request channel open channel
                    ChannelType::ContactRequest => {
                        let mut contact_request = contact_request.ok_or(Self::Error::InvalidProtobufMessage)?;
                        if client_cookie.is_some() {
                            return Err(Self::Error::InvalidProtobufMessage);
                        }

                        let nickname = contact_request.take_nickname();
                        let nickname: crate::contact_request_channel::Nickname = nickname.try_into()?;

                        let message_text = contact_request.take_message_text();
                        let message_text: crate::contact_request_channel::MessageText = message_text.try_into()?;

                        let contact_request = crate::contact_request_channel::ContactRequest{nickname, message_text};

                        Some(OpenChannelDerived::ContactRequestChannel(crate::contact_request_channel::OpenChannel{contact_request}))
                    },
                    // auth hidden service open channel
                    ChannelType::AuthHiddenService => {
                        if contact_request.is_some() {
                            return Err(Self::Error::InvalidProtobufMessage);
                        }
                        let mut client_cookie = client_cookie.ok_or(Self::Error::InvalidProtobufMessage)?;

                        let client_cookie: [u8; crate::auth_hidden_service::CLIENT_COOKIE_SIZE] = match client_cookie.try_into() {
                            Ok(client_cookie) => client_cookie,
                            Err(_) => return Err(Self::Error::InvalidProtobufMessage),
                        };

                        Some(OpenChannelDerived::AuthHiddenService(crate::auth_hidden_service::OpenChannel{client_cookie}))
                    },
                    _ => None,
                };

                let open_channel = OpenChannel{channel_identifier, channel_type, derived};
                Ok(Packet::OpenChannel(open_channel))
            } else if let Some(channel_result) = pb.channel_result.into_option() {
                // base fields
                let channel_identifier = channel_result.channel_identifier.ok_or(Self::Error::InvalidProtobufMessage)?;

                let opened = channel_result.opened.ok_or(Self::Error::InvalidProtobufMessage)?;

                let common_error = channel_result.common_error.ok_or(Self::Error::InvalidProtobufMessage)?;
                let common_error = match common_error.value() {
                    0 => CommonError::GenericError,
                    1 => CommonError::UnknownTypeError,
                    2 => CommonError::UnauthorizedError,
                    3 => CommonError::BadUsageError,
                    4 => CommonError::FailedError,
                    _ => return Err(Self::Error::InvalidProtobufMessage),
                };

                // extension fields
                let response = protos::ContactRequestChannel::exts::response.get(&channel_result);
                let server_cookie = protos::AuthHiddenService::exts::server_cookie.get(&channel_result);

                let derived: Option<ChannelResultDerived> = match (response, server_cookie) {
                    // contact request channel channel result
                    (Some(response), None) => {
                        let status = response.status.ok_or(Self::Error::InvalidProtobufMessage)?;
                        use crate::v3::message::contact_request_channel::Status;
                        let status = match status.value() {
                            0 => Status::Undefined,
                            1 => Status::Pending,
                            2 => Status::Accepted,
                            3 => Status::Rejected,
                            4 => Status::Error,
                            _ => return Err(Self::Error::InvalidProtobufMessage),
                        };

                        let response = crate::contact_request_channel::Response{status};
                        Some(ChannelResultDerived::ContactRequestChannel(crate::contact_request_channel::ChannelResult{response}))
                    },
                    // auth hidden service channel result
                    (None, Some(server_cookie)) => {
                        let server_cookie: [u8; crate::auth_hidden_service::SERVER_COOKIE_SIZE] = match server_cookie.try_into() {
                            Ok(server_cookie) => server_cookie,
                            Err(_) => return Err(Self::Error::InvalidProtobufMessage),
                        };

                        Some(ChannelResultDerived::AuthHiddenService(crate::auth_hidden_service::ChannelResult{server_cookie}))
                    },
                    _ => return Err(Self::Error::InvalidProtobufMessage),
                };

                let channel_result = ChannelResult{channel_identifier, opened, common_error, derived};
                Ok(Packet::ChannelResult(channel_result))
            } else {
                // TODO: skip unused packets for now
                Err(Self::Error::NotImplemented)
            }
        }
    }

    pub struct OpenChannel {
        pub channel_identifier: i32,
        pub channel_type: ChannelType,
        pub derived: Option<OpenChannelDerived>,
    }

    pub enum ChannelType {
        Control,
        Chat,
        ContactRequest,
        AuthHiddenService,
        FileTransfer,
    }

    impl TryFrom<&str> for ChannelType {
        type Error = crate::Error;

        fn try_from(value: &str) -> Result<Self, Self::Error> {
            let channel_type = match value {
                crate::control_channel::CHANNEL_TYPE => ChannelType::Control,
                crate::chat_channel::CHANNEL_TYPE => ChannelType::Chat,
                crate::contact_request_channel::CHANNEL_TYPE => ChannelType::ContactRequest,
                crate::auth_hidden_service::CHANNEL_TYPE => ChannelType::AuthHiddenService,
                crate::file_channel::CHANNEL_TYPE => ChannelType::FileTransfer,
                _ => return Err(Self::Error::InvalidChannelType(value.to_string())),
            };
            Ok(channel_type)
        }
    }


    impl From<ChannelType> for &'static str {
        fn from(value: ChannelType) -> &'static str {
            match value {
                ChannelType::Control => crate::control_channel::CHANNEL_TYPE,
                ChannelType::Chat => crate::chat_channel::CHANNEL_TYPE,
                ChannelType::ContactRequest => crate::contact_request_channel::CHANNEL_TYPE,
                ChannelType::AuthHiddenService => crate::auth_hidden_service::CHANNEL_TYPE,
                ChannelType::FileTransfer => crate::file_channel::CHANNEL_TYPE,
            }
        }
    }

    enum OpenChannelDerived {
        ContactRequestChannel(crate::contact_request_channel::OpenChannel),
        AuthHiddenService(crate::auth_hidden_service::OpenChannel),
    }

    pub struct ChannelResult {
        pub channel_identifier: i32,
        pub opened: bool,
        pub common_error: CommonError,
        pub derived: Option<ChannelResultDerived>,
    }

    enum ChannelResultDerived {
        ContactRequestChannel(crate::contact_request_channel::ChannelResult),
        AuthHiddenService(crate::auth_hidden_service::ChannelResult),
    }

    pub enum CommonError {
        GenericError,
        UnknownTypeError,
        UnauthorizedError,
        BadUsageError,
        FailedError,
    }

    pub struct KeepAlive {
        response_requested: bool,
    }

    pub struct EnableFeatures {
        feature: Vec<String>,
    }

    pub struct FeaturesEnabled {
        feature: Vec<String>,
    }
}

//
// ChatChannel
//

pub mod chat_channel {
    pub(crate) const CHANNEL_TYPE: &'static str = "im.ricochet.chat";

    pub enum Packet {
        ChatMessage(ChatMessage),
        ChatAcknowledge(ChatAcknowledge),
    }

    impl TryFrom<&[u8]> for Packet {
        type Error = crate::Error;

        fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
            use protobuf::Message;
            use crate::v3::protos;

            // parse bytes into protobuf message
            let pb = protos::ChatChannel::Packet::parse_from_bytes(value).map_err(Self::Error::ProtobufError)?;

            let chat_message = pb.chat_message.into_option();
            let chat_acknowledge = pb.chat_acknowledge.into_option();

            match (chat_message, chat_acknowledge) {
                (Some(chat_message), None) => {
                    let message_text = chat_message.message_text.ok_or(Self::Error::InvalidProtobufMessage)?;
                    let message_text: MessageText = message_text.try_into()?;

                    let message_id = chat_message.message_id.ok_or(Self::Error::InvalidProtobufMessage)?;

                    let time_delta: Option<std::time::Duration> = match chat_message.time_delta {
                        Some(time_delta) => match time_delta {
                            ..=0 => Some(std::time::Duration::from_secs(-time_delta as u64)),
                            _ => return Err(Self::Error::InvalidProtobufMessage),
                        },
                        None => None
                    };

                    let chat_message = ChatMessage{message_text, message_id, time_delta};
                    Ok(Packet::ChatMessage(chat_message))
                },
                (None, Some(chat_acknowledge)) => {
                    let message_id = chat_acknowledge.message_id.ok_or(Self::Error::InvalidProtobufMessage)?;
                    let accepted = chat_acknowledge.accepted.ok_or(Self::Error::InvalidProtobufMessage)?;

                    let chat_acknowledge = ChatAcknowledge{message_id, accepted};
                    Ok(Packet::ChatAcknowledge(chat_acknowledge))
                },
                _ => Err(Self::Error::InvalidProtobufMessage)
            }
        }
    }

    pub struct ChatMessage {
        message_text: MessageText,
        // TODO: in practice message id is always set
        message_id: u32,
        // TODO: time_delta is the number of second this message sat in the send queue
        // before it was sent. In practice this value must be:
        // - 0 or negative
        // - if not present, assumed to be 0
        time_delta: Option<std::time::Duration>,
    }

    pub struct MessageText {
        value: String
    }

    impl From<MessageText> for String {
        fn from(message_text: MessageText) -> String {
            message_text.value
        }
    }

    impl TryFrom<String> for MessageText {
        type Error = crate::Error;
        fn try_from(value: String) -> Result<Self, Self::Error> {
            // TODO: message_text requirements are NOT defined in the spec:
            // - must contain at least 1 utf16 code unit
            // - must contain no more than 2000 utf16 code units

            const MAX_MESSAGE_SIZE: usize = 2000;
            let mut count:usize = 0;
            for _code_unit in value.encode_utf16() {
                count += 1;
                if count > MAX_MESSAGE_SIZE {
                    return Err(Self::Error::InvalidChatMessageTooLong);
                }
            }
            if count == 0 {
                return Err(Self::Error::InvalidChatMessageEmpty);
            }

            Ok(MessageText{value})
        }
    }

    pub struct ChatAcknowledge {
        // TODO: behaviour undefined in spec
        // - acking without a message_id results in closing the associated channel
        // - in practice, it is always set
        pub message_id: u32,
        pub accepted: bool,
    }
}

//
// ContactRequestChannel
//

pub mod contact_request_channel {
    pub(crate) const CHANNEL_TYPE: &'static str = "im.ricochet.contact.request";

    pub struct OpenChannel {
        pub contact_request: ContactRequest,
    }

    pub struct ContactRequest {
        pub nickname: Nickname,
        pub message_text: MessageText,
    }

    pub struct MessageText {
        value: String
    }

    impl From<MessageText> for String {
        fn from(message_text: MessageText) -> String {
            message_text.value
        }
    }

    impl TryFrom<String> for MessageText {
        type Error = crate::Error;
        fn try_from(value: String) -> Result<Self, Self::Error> {
            // TODO: message_text requirements are NOT defined in the spec:
            // - must contain no more than 2000 utf16 code units

            const MAX_MESSAGE_SIZE: usize = 2000;
            let mut count:usize = 0;
            for _code_unit in value.encode_utf16() {
                count += 1;
                if count > MAX_MESSAGE_SIZE {
                    return Err(Self::Error::InvalidContactRequestMessageTooLong);
                }
            }

            Ok(MessageText{value})
        }
    }

    pub struct Nickname {
        value: String
    }

    impl From<Nickname> for String {
        fn from(nickname: Nickname) -> String {
            nickname.value
        }
    }

    impl TryFrom<String> for Nickname {
        type Error = crate::Error;
        fn try_from(value: String) -> Result<Self, Self::Error> {
            // TODO: nickname requirements are NOT defined in the spec
            // from Ricochet-Refresh's isAcceptableNickname() function:
            // - must contain no more than 30 utf16 code units
            // - must not contain "\"", "<", ">", "&"
            // - must not contain 'other, format' code units (Cf)
            // - must not contain 'other, control' code units (Cc)
            // - must not be non-characters (i.e.  0xFFFE, 0xFFFF, and 0xFDD0 through 0xFDEF)

            const MAX_NICKNAME_SIZE: usize = 30;
            let mut count:usize = 0;
            for code_unit in value.encode_utf16() {
                count += 1;
                if count > MAX_NICKNAME_SIZE {
                    return Err(Self::Error::InvalidNicknameTooLong);
                }

                // ensure not a non-character
                let is_non_character = match code_unit {
                    0xFFFEu16..=0xFFFFu16 => true,
                    0xFDD0u16..=0xFDEFu16 => true,
                    _ => false,
                };

                if is_non_character {
                    return Err(Self::Error::InvalidNicknameContainsNonCharacter(code_unit));
                }

                if let Some(character) = char::from_u32(code_unit as u32) {
                    // ensure not an html-character
                    let is_html_character = match character {
                        '\"' => true,
                        '<' => true,
                        '>' => true,
                        '&' => true,
                        _ => false,
                    };

                    if is_html_character {
                        return Err(Self::Error::InvalidNicknameContainsHtmlCharacter(character));
                    }

                    use unicode_general_category::*;
                    match get_general_category(character) {
                        // ensure not a format code unit (Cf)
                        GeneralCategory::Format => {
                            return Err(Self::Error::InvalidNicknameContainsFormatCodeUnit(code_unit));
                        },
                        // ensure not a control code unit (Cc)
                        GeneralCategory::Control => {
                            return Err(Self::Error::InvalidNicknameContainsControlCodeUnit(code_unit));
                        },
                        _ => ()
                    }
                }

            }

            Ok(Nickname{value})
        }
    }

    pub struct ChannelResult {
        pub response: Response,
    }

    pub struct Response {
        pub status: Status,
    }

    pub enum Status {
        Undefined,
        Pending,
        Accepted,
        Rejected,
        Error,
    }
}

//
// AuthHiddenService
//

pub mod auth_hidden_service {
    pub(crate) const CHANNEL_TYPE: &'static str = "im.ricochet.auth.hidden-service";
    pub(crate) const CLIENT_COOKIE_SIZE: usize = 16;
    pub(crate) const SERVER_COOKIE_SIZE: usize = 16;
    pub(crate) const PROOF_SIGNATURE_SIZE: usize = 64;

    pub enum Packet {
        Proof(Proof),
        Result(Result),
    }

    impl TryFrom<&[u8]> for Packet {
        type Error = crate::Error;

        fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
            use protobuf::Message;
            use crate::v3::protos;

            // parse bytes into protobuf message
            let pb = protos::AuthHiddenService::Packet::parse_from_bytes(value).map_err(Self::Error::ProtobufError)?;

            let proof = pb.proof.into_option();
            let result = pb.result.into_option();

            match (proof, result) {
                (Some(proof), None) => {
                    let signature = proof.signature.ok_or(Self::Error::InvalidProtobufMessage)?;
                    use crate::auth_hidden_service::PROOF_SIGNATURE_SIZE;
                    let signature: [u8; PROOF_SIGNATURE_SIZE] = match signature.try_into() {
                        Ok(signature) => signature,
                        Err(_) => return Err(Self::Error::InvalidProtobufMessage),
                    };

                    let service_id = proof.service_id.ok_or(Self::Error::InvalidProtobufMessage)?;
                    use tor_interface::tor_crypto::V3OnionServiceId;
                    let service_id = match V3OnionServiceId::from_string(service_id.as_str()) {
                        Ok(service_id) => service_id,
                        Err(_) => return Err(Self::Error::InvalidProtobufMessage),
                    };

                    let proof = Proof{signature, service_id};
                    Ok(Packet::Proof(proof))
                },
                (None, Some(result)) => {
                    let accepted = result.accepted.ok_or(Self::Error::InvalidProtobufMessage)?;

                    let is_known_contact = result.is_known_contact;
                    if accepted && is_known_contact.is_none() {
                        return Err(Self::Error::InvalidProtobufMessage);
                    }

                    let result = Result{accepted, is_known_contact};
                    Ok(Packet::Result(result))
                },
                _ => Err(Self::Error::InvalidProtobufMessage),
            }
        }
    }

    pub struct OpenChannel {
        pub client_cookie: [u8; CLIENT_COOKIE_SIZE],
    }

    pub struct ChannelResult {
        pub server_cookie: [u8; SERVER_COOKIE_SIZE],
    }

    pub struct Proof {
        // TODO: spec doesn't explicitly say how many bytes the proof's signature is
        pub signature: [u8; PROOF_SIGNATURE_SIZE],
        pub service_id: tor_interface::tor_crypto::V3OnionServiceId,
    }

    pub struct Result {
        pub accepted: bool,
        // TODO: is_known_contact must be present if accepted is true
        pub is_known_contact: Option<bool>,
    }
}

//
// FileChannel
//

pub mod file_channel {
    pub(crate) const CHANNEL_TYPE: &'static str = "im.ricochet.file-transfer";
    pub const FILE_HASH_SIZE: usize = 64;
    pub const MAX_FILE_CHUNK_SIZE: usize = 63*1024;

    pub enum Packet {
        FileHeader(FileHeader),
        FileHeaderAck(FileHeaderAck),
        FileHeaderResponse(FileHeaderResponse),
        FileChunk(FileChunk),
        FileChunkAck(FileChunkAck),
        FileTransferCompleteNotification(FileTransferCompleteNotification),
    }

    impl TryFrom<&[u8]> for Packet {
        type Error = crate::Error;

        fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
            use protobuf::Message;
            use crate::v3::protos;

            // parse bytes into protobuf message
            let pb = protos::FileChannel::Packet::parse_from_bytes(value).map_err(Self::Error::ProtobufError)?;

            let file_header = pb.file_header.into_option();
            let file_header_ack = pb.file_header_ack.into_option();
            let file_header_response = pb.file_header_response.into_option();
            let file_chunk = pb.file_chunk.into_option();
            let file_chunk_ack = pb.file_chunk_ack.into_option();
            let file_transfer_complete_notification = pb.file_transfer_complete_notification.into_option();

            match (
                file_header,
                file_header_ack,
                file_header_response,
                file_chunk,
                file_chunk_ack,
                file_transfer_complete_notification) {
                (Some(file_header), None, None, None, None, None) => {
                    let file_id = file_header.file_id.ok_or(Self::Error::InvalidProtobufMessage)?;

                    let file_size = file_header.file_size.ok_or(Self::Error::InvalidProtobufMessage)?;

                    let name = file_header.name.ok_or(Self::Error::InvalidProtobufMessage)?;

                    let mut file_hash = file_header.file_hash.ok_or(Self::Error::InvalidProtobufMessage)?;
                    let file_hash: [u8; FILE_HASH_SIZE] = match file_hash.try_into() {
                        Ok(bytes) => bytes,
                        Err(_) => return Err(Self::Error::InvalidProtobufMessage),
                    };

                    let file_header = FileHeader{file_id, file_size, name, file_hash};
                    Ok(Packet::FileHeader(file_header))
                },
                (None, Some(file_header_ack), None, None, None, None) => {
                    let file_id = file_header_ack.file_id.ok_or(Self::Error::InvalidProtobufMessage)?;

                    let accepted = file_header_ack.accepted.ok_or(Self::Error::InvalidProtobufMessage)?;

                    let file_header_ack = FileHeaderAck{file_id, accepted};
                    Ok(Packet::FileHeaderAck(file_header_ack))
                },
                (None, None, Some(file_header_response), None, None, None) => {
                    let file_id = file_header_response.file_id.ok_or(Self::Error::InvalidProtobufMessage)?;

                    let response = file_header_response.response.ok_or(Self::Error::InvalidProtobufMessage)?;
                    let response = match response {
                        0 => Response::Accept,
                        1 => Response::Reject,
                        _ => return Err(Self::Error::InvalidProtobufMessage),
                    };

                    let file_header_response = FileHeaderResponse{file_id, response};
                    Ok(Packet::FileHeaderResponse(file_header_response))
                },
                (None, None, None, Some(file_chunk), None, None) => {
                    let file_id = file_chunk.file_id.ok_or(Self::Error::InvalidProtobufMessage)?;

                    let chunk_data = file_chunk.chunk_data.ok_or(Self::Error::InvalidProtobufMessage)?;
                    let chunk_data: ChunkData = chunk_data.try_into()?;

                    let file_chunk = FileChunk{file_id, chunk_data};
                    Ok(Packet::FileChunk(file_chunk))
                },
                (None, None, None, None, Some(file_chunk_ack), None) => {
                    let file_id = file_chunk_ack.file_id.ok_or(Self::Error::InvalidProtobufMessage)?;

                    let bytes_received = file_chunk_ack.bytes_received.ok_or(Self::Error::InvalidProtobufMessage)?;

                    let file_chunk_ack = FileChunkAck{file_id, bytes_received};
                    Ok(Packet::FileChunkAck(file_chunk_ack))
                },
                (None, None, None, None, None, Some(file_transfer_complete_notification)) => {
                    let file_id = file_transfer_complete_notification.file_id.ok_or(Self::Error::InvalidProtobufMessage)?;

                    let result = file_transfer_complete_notification.result.ok_or(Self::Error::InvalidProtobufMessage)?;
                    let result = match result.value() {
                        0 => FileTransferResult::Success,
                        1 => FileTransferResult::Failure,
                        2 => FileTransferResult::Cancelled,
                        _ => return Err(Self::Error::InvalidProtobufMessage),
                    };

                    let file_transfer_complete_notification = FileTransferCompleteNotification{file_id, result};
                    Ok(Packet::FileTransferCompleteNotification(file_transfer_complete_notification))
                },
                _ => Err(Self::Error::InvalidProtobufMessage),
            }
        }
    }

    pub struct FileHeader {
        file_id: u32,
        // TODO: file_size requirements are not defined in spec
        // - must be theoretically writable to target disk
        file_size: u64,
        // TODO: name requirements are NOT defined in spec
        // - must not contain "..' substring
        // - must not contain '/' characters
        name: String,
        // TODO: file_hash requirements are NOT defined in spec
        // - file_hash algorithm is SHA3_512
        // - file_hash therefore must be 64 bytes
        file_hash: [u8; FILE_HASH_SIZE],
    }

    pub struct FileHeaderAck {
        file_id:  u32,
        accepted: bool,
    }

    pub struct FileHeaderResponse {
        file_id: u32,
        response: Response,
    }

    pub enum Response {
        Accept,
        Reject,
    }

    pub struct FileChunk {
        file_id: u32,
        chunk_data: ChunkData,
    }

    pub struct ChunkData {
        value: Vec<u8>,
    }

    impl From<ChunkData> for Vec<u8> {
        fn from(chunk_data: ChunkData) -> Vec<u8> {
            chunk_data.value
        }
    }

    impl TryFrom<Vec<u8>> for ChunkData {
        type Error = crate::Error;
        fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
            let value_len = value.len();
            if value_len > MAX_FILE_CHUNK_SIZE {
                Err(Self::Error::InvalidFileChunkDataTooLarge(value_len))
            } else {
                Ok(ChunkData{value})
            }
        }
    }

    pub struct FileChunkAck {
        file_id: u32,
        // TODO: bytes_received param is not defined in spec
        bytes_received: u64,
    }

    pub struct FileTransferCompleteNotification {
        file_id: u32,
        result: FileTransferResult,
    }

    pub enum FileTransferResult {
        Success,
        Failure,
        Cancelled,
    }
}

//
// Ricochet Protocol Packet
//
pub enum Packet {
    // sent by client to begin Ricochet-Refresh handshake
    IntroductionPacket(introduction::IntroductionPacket),
    // server reply indicating introduction success or failure
    IntroductionResponsePacket(introduction::IntroductionResponsePacket),
    // used to open various channel types
    ControlChannelPacket(control_channel::Packet),
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
    // used to close a channel
    CloseChannelPacket{channel: u16},
}

// on success returns a (packet, bytes read) tuple
// consumers should drop the returned number of bytes from their
// read buffer
pub fn next_packet(bytes: &[u8], channel_map: BTreeMap<u16, control_channel::ChannelType>) -> Result<(Packet, usize), Error> {

    if channel_map.is_empty() {
        match TryInto::<introduction::IntroductionPacket>::try_into(bytes) {
            Ok(packet) => {
                let offset = 3 + packet.versions.len();
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
