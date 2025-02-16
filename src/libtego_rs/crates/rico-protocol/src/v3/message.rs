// std
use std::collections::BTreeMap;

/// The error type for the [`Message`] type.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid version: {0:#04x}")]
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
    #[error("bad data stream")]
    BadDataStream,
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
    pub enum Packet {
        OpenChannel(OpenChannel),
        ChannelResult(ChannelResult),
        // TODO: Ricochet-Refresh v3 does not send
        // - KeepAlive
        // - EnableFeatures
        // - FeaturesEnabled
        KeepAlive(KeepAlive),
        EnableFeatures(EnableFeatures),
        FeaturesEnabled(FeaturesEnabled),
    }

    pub struct OpenChannel {
        pub channel_identifier: i32,
        pub channel_type: ChannelType,
        pub derived: Option<OpenChannelDerived>,
    }

    pub enum ChannelType {
        Chat,
        ContactRequest,
        AuthHiddenService,
        FileTransfer,
    }

    impl TryFrom<String> for ChannelType {
        type Error = crate::Error;

        fn try_from(value: String) -> Result<Self, Self::Error> {
            let channel_type = match value.as_str() {
                crate::chat_channel::CHANNEL_TYPE => ChannelType::Chat,
                crate::contact_request_channel::CHANNEL_TYPE => ChannelType::ContactRequest,
                crate::auth_hidden_service::CHANNEL_TYPE => ChannelType::AuthHiddenService,
                crate::file_channel::CHANNEL_TYPE => ChannelType::FileTransfer,
                _ => return Err(Self::Error::InvalidChannelType(value)),
            };
            Ok(channel_type)
        }
    }


    impl From<ChannelType> for &'static str {
        fn from(value: ChannelType) -> &'static str {
            match value {
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

    pub enum Packet {
        ChatMessage(ChatMessage),
        ChatAcknowledge(ChatAcknowledge),
    }

    pub struct ChatMessage {
        message: MessageText,
        message_id: Option<u32>,
        time_delta: Option<std::time::Duration>,
    }

    pub struct ChatAcknowledge {
        pub message_id: Option<u32>,
        pub accepted: bool,
    }
}

//
// ContactRequestChannel
//

pub mod contact_request_channel {
    pub(crate) const CHANNEL_TYPE: &'static str = "im.ricochet.contact.request";

    pub struct OpenChannel {
        contact_request: ContactRequest,
    }

    pub struct ContactRequest {
        nickname: Nickname,
        message_text: MessageText,
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
        response: Response,
    }

    pub struct Response {
        status: Status,
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
    const CLIENT_COOKIE_SIZE: usize = 16;
    const SERVER_COOKIE_SIZE: usize = 16;
    const PROOF_SIGNATURE_SIZE: usize = 64;

    pub enum Packet {
        Proof(Proof),
        Result(Result),
    }

    pub struct OpenChannel {
        client_cookie: [u8; CLIENT_COOKIE_SIZE],
    }

    pub struct ChannelResult {
        server_cookie: [u8; SERVER_COOKIE_SIZE],
    }

    pub struct Proof {
        // TODO: spec doesn't explicitly say how many bytes the proof's signature is
        signature: [u8; PROOF_SIGNATURE_SIZE],
        service_id: tor_interface::tor_crypto::V3OnionServiceId,
    }

    pub struct Result {
        accepted: bool,
        is_known_contract: bool,
    }
}

//
// FileChannel
//

pub mod file_channel {
    pub(crate) const CHANNEL_TYPE: &'static str = "im.ricochet.file-transfer";
    const FILE_HASH_SIZE: usize = 64;
    const MAX_FILE_CHUNK_SIZE: usize = 63*1024;

    pub enum Packet {
        FileHeader(FileHeader),
        FileHeaderAck(FileHeaderAck),
        FileHeaderResponse(FileHeaderResponse),
        FileChunk(FileChunk),
        FileChunkAck(FileChunkAck),
        FileTransferCompleteNotification(FileTransferCompleteNotification),
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
        response: i32,
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
    // server reply indicating success or faillure
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
            let size: u16 = (bytes[0] as u16) << 8 + bytes[1] as u16;
            let size = size as usize;
            let channel: u16 = (bytes[2] as u16) << 8 + bytes[3] as u16;

            if size < 4 {
                return Err(Error::BadDataStream);
            } else if bytes.len() < size {
                return Err(Error::NeedMoreBytes);
            }

            match channel_map.get(&channel) {
                Some(channel_type) => {
                    return Err(Error::NotImplemented)
                },
                None => return Err(Error::TargetChannelDoesNotExist(channel)),
            }
        } else {
            return Err(Error::NeedMoreBytes);
        }
    }

}
