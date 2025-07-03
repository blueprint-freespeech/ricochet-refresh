pub(crate) mod channel_map;
pub mod message;
pub mod packet_handler;
pub(crate) mod protos;

/// The error type for the [`Message`] type.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    //
    // somehow badly formatted packets errors
    //
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

    //
    // user errors
    //
    #[error("no ConnectionHandle associated with V3OnionServiceId: {0}")]
    ServiceIdToConnectionHandleMappingFailure(tor_interface::tor_crypto::V3OnionServiceId),
    #[error("no Connection associated with ConnectionHandle: {0}")]
    ConnectionHandleToConnectionMappingFailure(u32),
    #[error("channel already open: {0}")]
    ChannelAlreadyOpen(u16),
    #[error("channel type already open: {0:?}")]
    ChannelTypeAlreadyOpen(crate::v3::channel_map::ChannelDataType),
    #[error("peer is already an accepted contact: {0}")]
    PeerAlreadyAcceptedContact(tor_interface::tor_crypto::V3OnionServiceId),
    #[error("peer may not be accepted as it is blocked: {0}")]
    PeerIsBlocked(tor_interface::tor_crypto::V3OnionServiceId),

    // rand_core failure
    #[error("rand error: {0}")]
    RandOsError(#[source] rand_core::OsError),

    #[error("not implemented")]
    NotImplemented,
}