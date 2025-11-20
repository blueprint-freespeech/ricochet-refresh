pub(crate) mod channel_map;
pub mod file_hasher;
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
    #[error("nickname contains non-character: {0:x}")]
    InvalidNicknameContainsNonCharacter(u32),
    #[error("nickname contains html character: '{0}'")]
    InvalidNicknameContainsHtmlCharacter(char),
    #[error("nickname contains format code unit (Cf): {0:x}")]
    InvalidNicknameContainsFormatCodeUnit(u32),
    #[error("nickname contains control code unit (Cc): {0:x}")]
    InvalidNicknameContainsControlCodeUnit(u32),
    #[error("contact request message too long")]
    InvalidContactRequestMessageTooLong,
    #[error("chunk_data too large: {0} bytes")]
    InvalidFileChunkDataTooLarge(usize),
    #[error("not enough data")]
    NeedMoreBytes,
    // bad internal state errors
    #[error("target channel does not exist: {0}")]
    TargetChannelDoesNotExist(u16),
    #[error("target channel type is not open: {0:?}")]
    TargetChannelTypeNotOpen(channel_map::ChannelType),
    #[error("no more MessageHandles available")]
    MessageHandlesExhausted,
    #[error("no more FileTransferHandles available")]
    FileTransferHandlesExhausted,

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
    #[error("outgoing connection to blocked peer attempted: {0}")]
    OutgoingConnectionToBlockedPeerRejected(tor_interface::tor_crypto::V3OnionServiceId),
    #[error("no ConnectionHandle associated with V3OnionServiceId: {0}")]
    ServiceIdToConnectionHandleMappingFailure(tor_interface::tor_crypto::V3OnionServiceId),
    #[error("no V3OnionServiceId associated with ConnectionHandle: {0}")]
    ConnectionHandleToServiceIdMappingFailure(u32),
    #[error("no Connection associated with ConnectionHandle: {0}")]
    ConnectionHandleToConnectionMappingFailure(u32),
    #[error("channel already open: {0}")]
    ChannelAlreadyOpen(u16),
    #[error("channel type already open: {0:?}")]
    ChannelTypeAlreadyOpen(crate::v3::channel_map::ChannelType),
    #[error("peer is already a known contact: {0}")]
    PeerAlreadyKnownContact(tor_interface::tor_crypto::V3OnionServiceId),
    #[error("no FileTransfer associated with FileTransferHandle: {0:?}")]
    FileTransferHandleToFileTransferMappingFailure(crate::v3::packet_handler::FileTransferHandle),
    #[error("no FileDownload associated with FileTransferHandle: {0:?}")]
    FileTransferHandleToFileDownloadMappingFailure(crate::v3::packet_handler::FileTransferHandle),
    #[error("no FileUpload associated with FileTransferHandle: {0:?}")]
    FileTransferHandleToFileUploadMappingFailure(crate::v3::packet_handler::FileTransferHandle),
    #[error("FileUploads cannot be rejected: {0:?}")]
    FileUploadCannotBeRejected(crate::v3::packet_handler::FileTransferHandle),

    // rand_core failure
    #[error("rand error: {0}")]
    RandOsError(#[source] rand_core::OsError),

    #[error("not implemented")]
    NotImplemented,
}

pub const MAX_FILE_CHUNK_SIZE: usize = message::file_channel::MAX_FILE_CHUNK_SIZE;
