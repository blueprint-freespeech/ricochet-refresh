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

    // failed to construct a packet type
    #[error("packet construction failed: {0}")]
    PacketConstructionFailed(String),

    // TODO: remove this error when no longer needed
    #[error("not implemented")]
    NotImplemented,
}

//
// Introduction
//

pub mod introduction {

    #[derive(Debug, PartialEq)]
    pub struct IntroductionPacket {
        versions: Vec<Version>,
    }

    impl IntroductionPacket {
        pub fn new(versions: Vec<Version>) -> Result<Self, crate::Error> {
            if versions.is_empty() {
                Err(crate::Error::PacketConstructionFailed("introduction packet must have specify at least one supported version".to_string()))
            } else if versions.len() > u8::MAX as usize {
                Err(crate::Error::PacketConstructionFailed("introduction packet may have no more than 255 supported version".to_string()))
            } else {
                Ok(Self{versions})
            }
        }

        pub fn versions(&self) -> &Vec<Version> {
            &self.versions
        }

        pub fn write_to_vec(&self, v: &mut Vec<u8>) -> Result<(), crate::Error> {

            v.push(0x49u8);
            v.push(0x4du8);
            v.push(self.versions.len() as u8);
            for ver in &self.versions {
                v.push(ver.into());
            }

            Ok(())
        }
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

    #[derive(Debug, PartialEq)]
    pub struct IntroductionResponsePacket {
        pub version: Option<Version>,
    }

    impl IntroductionResponsePacket {
        pub fn write_to_vec(&self, v: &mut Vec<u8>) -> Result<(), crate::Error> {
            if let Some(version) = &self.version {
                v.push(version.into());
            } else {
                v.push(0xffu8);
            }
            Ok(())
        }
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

    #[derive(Debug, PartialEq)]
    pub enum Version {
        Ricochet1_0,
        Ricochet1_1,
        RicochetRefresh3,
    }

    impl From<&Version> for u8 {
        fn from(version: &Version) -> u8 {
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

    #[derive(Debug, PartialEq)]
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

    impl Packet {
        pub fn write_to_vec(&self, v: &mut Vec<u8>) -> Result<(), crate::Error> {
            use protobuf::Message;
            use crate::v3::protos;

            // construct our protobuf message
            let mut pb: protos::ControlChannel::Packet = Default::default();
            match self {
                Packet::OpenChannel(open_channel) => {
                    let channel_identifier = Some(open_channel.channel_identifier());
                    let channel_type = open_channel.channel_type();
                    let channel_type: &str = channel_type.into();
                    let channel_type = Some(channel_type.to_string());
                    let extension = open_channel.extension();

                    // construct OpenChannel packet
                    let mut open_channel = protos::ControlChannel::OpenChannel::default();
                    open_channel.channel_identifier = channel_identifier;
                    open_channel.channel_type = channel_type;

                    // set extensions
                    match extension {
                        Some(OpenChannelExtension::ContactRequestChannel(extension)) => {
                            let contact_request = &extension.contact_request;
                            let nickname = &contact_request.nickname;
                            let nickname: String = nickname.into();
                            let nickname = Some(nickname);
                            let message_text = &contact_request.message_text;
                            let message_text: String = message_text.into();
                            let message_text = Some(message_text);

                            let mut contact_request = protos::ContactRequestChannel::ContactRequest::default();
                            contact_request.nickname = nickname;
                            contact_request.message_text = message_text;

                            let field_number = crate::contact_request_channel::OpenChannel::CONTACT_REQUEST_FIELD_NUMBER;

                            open_channel.mut_unknown_fields().add_length_delimited(field_number, contact_request.write_to_bytes().unwrap());
                        },
                        Some(OpenChannelExtension::AuthHiddenService(extension)) => {
                            let client_cookie = &extension.client_cookie;

                            let field_number = crate::auth_hidden_service::OpenChannel::CLIENT_COOKIE_FIELD_NUMBER;

                            open_channel.mut_unknown_fields().add_length_delimited(field_number, client_cookie.into());
                        },
                        None => (),
                    }
                    pb.open_channel = Some(open_channel).into();
                },
                Packet::ChannelResult(channel_result) => {
                    let channel_identifier = Some(channel_result.channel_identifier);
                    let opened = Some(channel_result.opened);
                    let common_error = &channel_result.common_error;
                    let common_error = match common_error {
                        CommonError::GenericError => protos::ControlChannel::channel_result::CommonError::GenericError,
                        CommonError::UnknownTypeError => protos::ControlChannel::channel_result::CommonError::UnknownTypeError,
                        CommonError::UnauthorizedError => protos::ControlChannel::channel_result::CommonError::UnauthorizedError,
                        CommonError::BadUsageError => protos::ControlChannel::channel_result::CommonError::BadUsageError,
                        CommonError::FailedError => protos::ControlChannel::channel_result::CommonError::FailedError,
                    };
                    let common_error = Some(protobuf::EnumOrUnknown::new(common_error));
                    let extension = channel_result.extension();

                    // construct ChannelResult packet
                    let mut channel_result = protos::ControlChannel::ChannelResult::default();
                    channel_result.channel_identifier = channel_identifier;
                    channel_result.opened = opened;
                    channel_result.common_error = common_error;

                    match extension {
                        Some(ChannelResultExtension::ContactRequestChannel(extension)) => {
                            let status = &extension.response.status;
                            let status = match status {
                                crate::contact_request_channel::Status::Undefined => protos::ContactRequestChannel::response::Status::Undefined,
                                crate::contact_request_channel::Status::Pending => protos::ContactRequestChannel::response::Status::Pending,
                                crate::contact_request_channel::Status::Accepted => protos::ContactRequestChannel::response::Status::Accepted,
                                crate::contact_request_channel::Status::Rejected => protos::ContactRequestChannel::response::Status::Rejected,
                                crate::contact_request_channel::Status::Error => protos::ContactRequestChannel::response::Status::Error,
                            };

                            let mut response = protos::ContactRequestChannel::Response::default();
                            response.status = Some(protobuf::EnumOrUnknown::new(status));

                            let field_number = crate::contact_request_channel::ChannelResult::RESPONSE_FIELD_NUMBER;

                            channel_result.mut_unknown_fields().add_length_delimited(field_number, response.write_to_bytes().unwrap());
                        },
                        Some(ChannelResultExtension::AuthHiddenService(extension)) => {
                            let server_cookie = &extension.server_cookie;

                            let field_number = crate::auth_hidden_service::ChannelResult::SERVER_COOKIE_FIELD_NUMBER;

                            channel_result.mut_unknown_fields().add_length_delimited(field_number, server_cookie.into());
                        },
                        None => (),
                    }
                    pb.channel_result = Some(channel_result).into();
                },
                // TODO: we don't care about KeepAlive, EnableFeatures, or FeaturesEnabled
                _ => return Err(crate::Error::NotImplemented),
            }

            // serialise
            pb.write_to_vec(v).map_err(crate::Error::ProtobufError)?;
            Ok(())
        }
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

                let extension: Option<OpenChannelExtension> = match channel_type {
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

                        Some(OpenChannelExtension::ContactRequestChannel(crate::contact_request_channel::OpenChannel{contact_request}))
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

                        Some(OpenChannelExtension::AuthHiddenService(crate::auth_hidden_service::OpenChannel{client_cookie}))
                    },
                    _ => None,
                };

                let open_channel = OpenChannel::new(channel_identifier, channel_type, extension)?;
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

                let extension: Option<ChannelResultExtension> = match (response, server_cookie) {
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
                        Some(ChannelResultExtension::ContactRequestChannel(crate::contact_request_channel::ChannelResult{response}))
                    },
                    // auth hidden service channel result
                    (None, Some(server_cookie)) => {
                        let server_cookie: [u8; crate::auth_hidden_service::SERVER_COOKIE_SIZE] = match server_cookie.try_into() {
                            Ok(server_cookie) => server_cookie,
                            Err(_) => return Err(Self::Error::InvalidProtobufMessage),
                        };

                        Some(ChannelResultExtension::AuthHiddenService(crate::auth_hidden_service::ChannelResult{server_cookie}))
                    },
                    _ => return Err(Self::Error::InvalidProtobufMessage),
                };

                let channel_result = ChannelResult::new(channel_identifier, opened, common_error, extension)?;
                Ok(Packet::ChannelResult(channel_result))
            } else {
                // TODO: skip unused packets for now
                Err(Self::Error::NotImplemented)
            }
        }
    }

    #[derive(Debug, PartialEq)]
    pub struct OpenChannel {
        // TODO: spec needs updating, channel_identifier must be positive and non-zero, and less than u16::MAX
        channel_identifier: i32,
        channel_type: ChannelType,
        extension: Option<OpenChannelExtension>,
    }

    impl OpenChannel {
        pub fn new(
            channel_identifier: i32,
            channel_type: ChannelType,
            extension: Option<OpenChannelExtension>) -> Result<Self, crate::Error> {
            if channel_identifier < 1 ||
               channel_identifier > u16::MAX as i32 {
                Err(crate::Error::PacketConstructionFailed("channel_identifier must be postive, non-zero, and less than u16::MAX".to_string()))
            } else if channel_type == ChannelType::Control {
                Err(crate::Error::PacketConstructionFailed("channel_type may not be ChannelType::Control".to_string()))
            } else {
                Ok(Self{channel_identifier, channel_type, extension})
            }
        }

        pub fn channel_identifier(&self) -> i32 {
            self.channel_identifier
        }

        pub fn channel_type(&self) -> &ChannelType {
            &self.channel_type
        }

        pub fn extension(&self) -> &Option<OpenChannelExtension> {
            &self.extension
        }
    }


    #[derive(Debug, PartialEq)]
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


    impl From<&ChannelType> for &'static str {
        fn from(value: &ChannelType) -> &'static str {
            match value {
                ChannelType::Control => crate::control_channel::CHANNEL_TYPE,
                ChannelType::Chat => crate::chat_channel::CHANNEL_TYPE,
                ChannelType::ContactRequest => crate::contact_request_channel::CHANNEL_TYPE,
                ChannelType::AuthHiddenService => crate::auth_hidden_service::CHANNEL_TYPE,
                ChannelType::FileTransfer => crate::file_channel::CHANNEL_TYPE,
            }
        }
    }

    #[derive(Debug, PartialEq)]
    pub enum OpenChannelExtension {
        ContactRequestChannel(crate::contact_request_channel::OpenChannel),
        AuthHiddenService(crate::auth_hidden_service::OpenChannel),
    }

    #[derive(Debug, PartialEq)]
    pub struct ChannelResult {
        // TODO: spec needs updating, channel_identifier must be positive and non-zero, and less than u16::MAX
        channel_identifier: i32,
        opened: bool,
        common_error: CommonError,
        extension: Option<ChannelResultExtension>,
    }

    impl ChannelResult {
        pub fn new(
            channel_identifier: i32,
            opened: bool,
            common_error: CommonError,
            extension: Option<ChannelResultExtension>) -> Result<Self, crate::Error> {
            if channel_identifier < 1 ||
               channel_identifier > u16::MAX as i32 {
                Err(crate::Error::PacketConstructionFailed("channel_identifier must be postive, non-zero, and less than u16::MAX".to_string()))
            } else {
                Ok(Self{channel_identifier, opened, common_error, extension})
            }
        }

        pub fn channel_identifier(&self) -> i32 {
            self.channel_identifier
        }

        pub fn opened(&self) -> bool {
            self.opened
        }

        pub fn common_error(&self) -> &CommonError {
            &self.common_error
        }

        pub fn extension(&self) -> &Option<ChannelResultExtension> {
            &self.extension
        }
    }

    #[derive(Debug, PartialEq)]
    pub enum ChannelResultExtension {
        ContactRequestChannel(crate::contact_request_channel::ChannelResult),
        AuthHiddenService(crate::auth_hidden_service::ChannelResult),
    }

    #[derive(Debug, PartialEq)]
    pub enum CommonError {
        GenericError,
        UnknownTypeError,
        UnauthorizedError,
        BadUsageError,
        FailedError,
    }

    #[derive(Debug, PartialEq)]
    pub struct KeepAlive {
        response_requested: bool,
    }

    #[derive(Debug, PartialEq)]
    pub struct EnableFeatures {
        feature: Vec<String>,
    }

    #[derive(Debug, PartialEq)]
    pub struct FeaturesEnabled {
        feature: Vec<String>,
    }
}

//
// ChatChannel
//

pub mod chat_channel {
    pub(crate) const CHANNEL_TYPE: &'static str = "im.ricochet.chat";

    #[derive(Debug, PartialEq)]
    pub enum Packet {
        ChatMessage(ChatMessage),
        ChatAcknowledge(ChatAcknowledge),
    }

    impl Packet {
        pub fn write_to_vec(&self, v: &mut Vec<u8>) -> Result<(), crate::Error> {
            use protobuf::Message;
            use crate::v3::protos;

            let mut pb: protos::ChatChannel::Packet = Default::default();

            match self {
                Packet::ChatMessage(chat_message) => {
                    let message_text: String = chat_message.message_text().into();
                    let message_text = Some(message_text);
                    let message_id = Some(chat_message.message_id());
                    let time_delta: Option<i64> = match chat_message.time_delta() {
                        Some(time_delta) => Some(-(time_delta.as_secs() as i64)),
                        None => None
                    };

                    let mut chat_message = protos::ChatChannel::ChatMessage::default();
                    chat_message.message_text = message_text;
                    chat_message.message_id = message_id;
                    chat_message.time_delta = time_delta;

                    pb.chat_message = Some(chat_message).into();
                }
                Packet::ChatAcknowledge(chat_acknowledge) => {
                    let message_id = Some(chat_acknowledge.message_id());
                    let accepted = Some(chat_acknowledge.accepted());

                    let mut chat_acknowledge = protos::ChatChannel::ChatAcknowledge::default();
                    chat_acknowledge.message_id = message_id;
                    chat_acknowledge.accepted = accepted;

                    pb.chat_acknowledge = Some(chat_acknowledge).into();
                }
            }
            pb.write_to_vec(v).map_err(crate::Error::ProtobufError)?;
            Ok(())
        }
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

                    let chat_message = ChatMessage::new(message_text, message_id, time_delta)?;
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

    #[derive(Debug, PartialEq)]
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

    impl ChatMessage {
        pub fn new(
            message_text: MessageText,
            message_id: u32,
            time_delta: Option<std::time::Duration>) -> Result<Self, crate::Error> {

            if let Some(time_delta) = time_delta {
                if time_delta.as_secs() > i64::MAX as u64 {
                    return Err(crate::Error::PacketConstructionFailed("time_delta in seconds must be less than or equal to i64::MAX".to_string()));
                }
            }

            Ok(Self{message_text, message_id, time_delta})
        }

        pub fn message_text(&self) -> &MessageText {
            &self.message_text
        }

        pub fn message_id(&self) -> u32 {
            self.message_id
        }

        pub fn time_delta(&self) -> &Option<std::time::Duration> {
            &self.time_delta
        }
    }

    #[derive(Debug, PartialEq)]
    pub struct MessageText {
        value: String
    }

    impl From<&MessageText> for String {
        fn from(message_text: &MessageText) -> String {
            message_text.value.clone()
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

    #[derive(Debug, PartialEq)]
    pub struct ChatAcknowledge {
        // TODO: behaviour undefined in spec
        // - acking without a message_id results in closing the associated channel
        // - in practice, it is always set
        message_id: u32,
        accepted: bool,
    }

    impl ChatAcknowledge {
        pub fn new(
            message_id: u32,
            accepted: bool) -> Result<Self, crate::Error> {
            Ok(Self{message_id, accepted})
        }

        pub fn message_id(&self) -> u32 {
            self.message_id
        }

        pub fn accepted(&self) -> bool {
            self.accepted
        }
    }
}

//
// ContactRequestChannel
//

pub mod contact_request_channel {
    pub(crate) const CHANNEL_TYPE: &'static str = "im.ricochet.contact.request";

    #[derive(Debug, PartialEq)]
    pub struct OpenChannel {
        pub contact_request: ContactRequest,
    }

    impl OpenChannel {
        pub(crate) const CONTACT_REQUEST_FIELD_NUMBER: u32 = 200u32;
    }

    #[derive(Debug, PartialEq)]
    pub struct ContactRequest {
        pub nickname: Nickname,
        pub message_text: MessageText,
    }

    #[derive(Debug, PartialEq)]
    pub struct MessageText {
        value: String
    }

    impl From<&MessageText> for String {
        fn from(message_text: &MessageText) -> String {
            message_text.value.clone()
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

    #[derive(Debug, PartialEq)]
    pub struct Nickname {
        value: String
    }

    impl From<&Nickname> for String {
        fn from(nickname: &Nickname) -> String {
            nickname.value.clone()
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

    #[derive(Debug, PartialEq)]
    pub struct ChannelResult {
        pub response: Response,
    }

    impl ChannelResult {
        pub(crate) const RESPONSE_FIELD_NUMBER: u32 = 201u32;
    }

    #[derive(Debug, PartialEq)]
    pub struct Response {
        pub status: Status,
    }

    #[derive(Debug, PartialEq)]
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

    #[derive(Debug, PartialEq)]
    pub enum Packet {
        Proof(Proof),
        Result(Result),
    }

    impl Packet {
        pub fn write_to_vec(&self, v:& mut Vec<u8>) -> std::result::Result<(), crate::Error> {
            use protobuf::Message;
            use crate::v3::protos;

            let mut pb: protos::AuthHiddenService::Packet = Default::default();

            match self {
                Packet::Proof(proof) => {
                    let signature = proof.signature();
                    let service_id = proof.service_id();

                    let mut proof = protos::AuthHiddenService::Proof::default();
                    proof.signature = Some(signature.into());
                    proof.service_id = Some(service_id.to_string());

                    pb.proof = Some(proof).into();
                },
                Packet::Result(result) => {
                    let accepted = result.accepted();
                    let is_known_contact = result.is_known_contact().clone();

                    let mut result = protos::AuthHiddenService::Result::default();
                    result.accepted = Some(accepted);
                    result.is_known_contact = is_known_contact;

                    pb.result = Some(result).into();
                }
            }

            // serialise
            pb.write_to_vec(v).map_err(crate::Error::ProtobufError)?;
            Ok(())
        }
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

                    let proof = Proof::new(signature, service_id)?;
                    Ok(Packet::Proof(proof))
                },
                (None, Some(result)) => {
                    let accepted = result.accepted.ok_or(Self::Error::InvalidProtobufMessage)?;

                    let is_known_contact = result.is_known_contact;

                    let result = Result::new(accepted, is_known_contact)?;
                    Ok(Packet::Result(result))
                },
                _ => Err(Self::Error::InvalidProtobufMessage),
            }
        }
    }

    #[derive(Debug, PartialEq)]
    pub struct OpenChannel {
        pub client_cookie: [u8; CLIENT_COOKIE_SIZE],
    }

    impl OpenChannel {
        pub(crate) const CLIENT_COOKIE_FIELD_NUMBER: u32 = 7200;
    }

    #[derive(Debug, PartialEq)]
    pub struct ChannelResult {
        pub server_cookie: [u8; SERVER_COOKIE_SIZE],
    }

    impl ChannelResult {
        pub(crate) const SERVER_COOKIE_FIELD_NUMBER: u32 = 7200;
    }

    #[derive(Debug, PartialEq)]
    pub struct Proof {
        // TODO: spec doesn't explicitly say how many bytes the proof's signature is
        signature: [u8; PROOF_SIGNATURE_SIZE],
        service_id: tor_interface::tor_crypto::V3OnionServiceId,
    }

    impl Proof {
        pub fn new(signature: [u8; PROOF_SIGNATURE_SIZE], service_id: tor_interface::tor_crypto::V3OnionServiceId) -> std::result::Result<Self, crate::Error> {
            Ok(Self{signature, service_id})
        }

        pub fn signature(&self) -> &[u8; PROOF_SIGNATURE_SIZE] {
            &self.signature
        }

        pub fn service_id(&self) -> &tor_interface::tor_crypto::V3OnionServiceId {
            &self.service_id
        }
    }

    #[derive(Debug, PartialEq)]
    pub struct Result {
        accepted: bool,
        // TODO: is_known_contact must be present if accepted is true
        is_known_contact: Option<bool>,
    }

    impl Result {
        pub fn new(accepted: bool, is_known_contact: Option<bool>) -> std::result::Result<Self, crate::Error> {
            if accepted && is_known_contact.is_none() {
                return Err(crate::Error::PacketConstructionFailed("is_known_contact must be present if accepted is true".to_string()));
            }
            Ok(Self{accepted, is_known_contact})
        }

        pub fn accepted(&self) -> bool {
            self.accepted
        }

        pub fn is_known_contact(&self) -> &Option<bool> {
            &self.is_known_contact
        }
    }
}

//
// FileChannel
//

pub mod file_channel {
    pub(crate) const CHANNEL_TYPE: &'static str = "im.ricochet.file-transfer";
    pub const FILE_HASH_SIZE: usize = 64;
    pub const MAX_FILE_CHUNK_SIZE: usize = 63*1024;

    #[derive(Debug, PartialEq)]
    pub enum Packet {
        FileHeader(FileHeader),
        FileHeaderAck(FileHeaderAck),
        FileHeaderResponse(FileHeaderResponse),
        FileChunk(FileChunk),
        FileChunkAck(FileChunkAck),
        FileTransferCompleteNotification(FileTransferCompleteNotification),
    }

    impl Packet {
        pub fn write_to_vec(&self, v:& mut Vec<u8>) -> Result<(), crate::Error> {
            use protobuf::Message;
            use crate::v3::protos;

            let mut pb: protos::FileChannel::Packet = Default::default();

            match self {
                Packet::FileHeader(file_header) => {
                    let file_id = file_header.file_id();
                    let file_size = file_header.file_size();
                    let name = file_header.name().to_string();
                    let file_hash = file_header.file_hash().clone();

                    let mut file_header = protos::FileChannel::FileHeader::default();
                    file_header.file_id = Some(file_id);
                    file_header.file_size = Some(file_size);
                    file_header.name = Some(name);
                    file_header.file_hash = Some(file_hash.into());

                    pb.file_header = Some(file_header).into();
                },
                Packet::FileHeaderAck(file_header_ack) => {
                    let file_id = file_header_ack.file_id();
                    let accepted = file_header_ack.accepted();

                    let mut file_header_ack = protos::FileChannel::FileHeaderAck::default();
                    file_header_ack.file_id = Some(file_id);
                    file_header_ack.accepted = Some(accepted);

                    pb.file_header_ack = Some(file_header_ack).into();
                },
                Packet::FileHeaderResponse(file_header_response) => {
                    let file_id = file_header_response.file_id();
                    let response: i32 = file_header_response.response().into();

                    let mut file_header_response = protos::FileChannel::FileHeaderResponse::default();
                    file_header_response.file_id = Some(file_id);
                    file_header_response.response = Some(response);

                    pb.file_header_response = Some(file_header_response).into();
                },
                Packet::FileChunk(file_chunk) => {
                    let file_id = file_chunk.file_id();
                    let chunk_data = file_chunk.chunk_data();

                    let mut file_chunk = protos::FileChannel::FileChunk::default();
                    file_chunk.file_id = Some(file_id);
                    file_chunk.chunk_data = Some(chunk_data.into());

                    pb.file_chunk = Some(file_chunk).into();
                },
                Packet::FileChunkAck(file_chunk_ack) => {
                    let file_id = file_chunk_ack.file_id();
                    let bytes_received = file_chunk_ack.bytes_received();

                    let mut file_chunk_ack = protos::FileChannel::FileChunkAck::default();
                    file_chunk_ack.file_id = Some(file_id);
                    file_chunk_ack.bytes_received = Some(bytes_received);

                    pb.file_chunk_ack = Some(file_chunk_ack).into();
                },
                Packet::FileTransferCompleteNotification(file_transfer_complete_notification) => {
                    let file_id = file_transfer_complete_notification.file_id();
                    let result = file_transfer_complete_notification.result();
                    let result = match result {
                        FileTransferResult::Success => protos::FileChannel::FileTransferResult::Success,
                        FileTransferResult::Failure => protos::FileChannel::FileTransferResult::Failure,
                        FileTransferResult::Cancelled => protos::FileChannel::FileTransferResult::Cancelled,
                    };
                    let result = protobuf::EnumOrUnknown::new(result);

                    let mut file_transfer_complete_notification = protos::FileChannel::FileTransferCompleteNotification::default();
                    file_transfer_complete_notification.file_id = Some(file_id);
                    file_transfer_complete_notification.result = Some(result);

                    pb.file_transfer_complete_notification = Some(file_transfer_complete_notification).into();
                },
            }

            // serialise
            pb.write_to_vec(v).map_err(crate::Error::ProtobufError)?;
            Ok(())
        }
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

    #[derive(Debug, PartialEq)]
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

    impl FileHeader {
        pub fn new(
            file_id: u32,
            file_size: u64,
            name: String,
            file_hash: [u8; FILE_HASH_SIZE]) -> Result<Self, crate::Error> {
            if name.contains("..") || name.contains("/") {
                Err(crate::Error::PacketConstructionFailed("name contains forbidden substring".to_string()))
            } else {
                Ok(Self{file_id, file_size, name, file_hash})
            }
        }

        pub fn file_id(&self) -> u32 {
            self.file_id
        }

        pub fn file_size(&self) -> u64 {
            self.file_size
        }

        pub fn name(&self) -> &str {
            self.name.as_str()
        }

        pub fn file_hash(&self) -> &[u8; FILE_HASH_SIZE] {
            &self.file_hash
        }
    }

    #[derive(Debug, PartialEq)]
    pub struct FileHeaderAck {
        file_id:  u32,
        accepted: bool,
    }

    impl FileHeaderAck {
        pub fn new(file_id: u32, accepted: bool) -> Result<Self, crate::Error> {
            Ok(Self{file_id, accepted})
        }

        pub fn file_id(&self) -> u32 {
            self.file_id
        }

        pub fn accepted(&self) -> bool {
            self.accepted
        }
    }

    #[derive(Debug, PartialEq)]
    pub struct FileHeaderResponse {
        file_id: u32,
        response: Response,
    }

    impl FileHeaderResponse {
        pub fn new(file_id: u32, response: Response) -> Result<Self, crate::Error> {
            Ok(Self{file_id, response})
        }

        pub fn file_id(&self) -> u32 {
            self.file_id
        }

        pub fn response(&self) -> &Response {
            &self.response
        }
    }

    #[derive(Debug, PartialEq)]
    pub enum Response {
        Accept,
        Reject,
    }

    impl From<&Response> for i32 {
        fn from(response: &Response) -> i32 {
            match response {
                Response::Accept => 0i32,
                Response::Reject => 1i32,
            }
        }
    }

    impl TryFrom<i32> for Response {
        type Error = crate::Error;
        fn try_from(value: i32) -> Result<Response, Self::Error> {
            match value {
                0i32 => Ok(Response::Accept),
                1i32 => Ok(Response::Reject),
                _ => Err(Self::Error::PacketConstructionFailed("response must be 0 or 1".to_string())),
            }
        }
    }

    #[derive(Debug, PartialEq)]
    pub struct FileChunk {
        file_id: u32,
        chunk_data: ChunkData,
    }

    impl FileChunk {
        pub fn new(file_id: u32, chunk_data: ChunkData) -> Result<Self, crate::Error> {
            Ok(Self{file_id, chunk_data})
        }

        pub fn file_id(&self) -> u32 {
            self.file_id
        }

        pub fn chunk_data(&self) -> &ChunkData {
            &self.chunk_data
        }
    }

    #[derive(Debug, PartialEq)]
    pub struct ChunkData {
        data: Vec<u8>,
    }

    impl ChunkData {
        pub fn new(data: Vec<u8>) -> Result<ChunkData, crate::Error> {
            let data_len = data.len();
            if data_len > MAX_FILE_CHUNK_SIZE {
                Err(crate::Error::PacketConstructionFailed(format!("chunk data must be less than {MAX_FILE_CHUNK_SIZE} bytes")))
            } else {
                Ok(Self{data})
            }
        }

        fn data(&self) -> &[u8] {
            self.data.as_slice()
        }
    }

    impl From<&ChunkData> for Vec<u8> {
        fn from(chunk_data: &ChunkData) -> Vec<u8> {
            chunk_data.data.clone()
        }
    }

    impl TryFrom<Vec<u8>> for ChunkData {
        type Error = crate::Error;
        fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
            ChunkData::new(value)
        }
    }

    #[derive(Debug, PartialEq)]
    pub struct FileChunkAck {
        file_id: u32,
        // TODO: bytes_received param is not defined in spec
        bytes_received: u64,
    }

    impl FileChunkAck {
        pub fn new(file_id: u32, bytes_received: u64) -> Result<Self, crate::Error> {
            Ok(Self{file_id, bytes_received})
        }

        pub fn file_id(&self) -> u32 {
            self.file_id
        }

        pub fn bytes_received(&self) -> u64 {
            self.bytes_received
        }
    }

    #[derive(Debug, PartialEq)]
    pub struct FileTransferCompleteNotification {
        file_id: u32,
        result: FileTransferResult,
    }

    impl FileTransferCompleteNotification {
        pub fn new(file_id: u32, result: FileTransferResult) -> Result<Self, crate::Error> {
            Ok(Self{file_id, result})
        }

        pub fn file_id(&self) -> u32 {
            self.file_id
        }

        pub fn result(&self) -> &FileTransferResult {
            &self.result
        }
    }

    #[derive(Debug, PartialEq)]
    pub enum FileTransferResult {
        Success,
        Failure,
        Cancelled,
    }
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