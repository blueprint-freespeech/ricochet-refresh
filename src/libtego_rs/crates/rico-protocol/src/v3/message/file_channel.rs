use crate::v3::Error;

pub(crate) const CHANNEL_TYPE: &str = "im.ricochet.file-transfer";
// TODO: protocol specificaiton does not define what hash is used to verify transferred file contents

// TODO: make FILE_HASH_SIZE also pub(crate)
pub const FILE_HASH_SIZE: usize = 64;
pub(crate) const MAX_FILE_CHUNK_SIZE: usize = 63*1024;

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
    pub fn write_to_vec(&self, v:& mut Vec<u8>) -> Result<(), Error> {
        use protobuf::Message;
        use crate::v3::protos;

        let mut pb: protos::FileChannel::Packet = Default::default();

        match self {
            Packet::FileHeader(file_header) => {
                let file_id = Some(file_header.file_id());
                let file_size = Some(file_header.file_size());
                let name = Some(file_header.name().to_string());
                let file_hash: Option<Vec<u8>> = Some(file_header.file_hash().into());

                let file_header = protos::FileChannel::FileHeader{file_id, file_size, name, file_hash, ..Default::default()};

                pb.file_header = Some(file_header).into();
            },
            Packet::FileHeaderAck(file_header_ack) => {
                let file_id = Some(file_header_ack.file_id());
                let accepted = Some(file_header_ack.accepted());

                let file_header_ack = protos::FileChannel::FileHeaderAck{file_id, accepted, ..Default::default()};

                pb.file_header_ack = Some(file_header_ack).into();
            },
            Packet::FileHeaderResponse(file_header_response) => {
                let file_id = Some(file_header_response.file_id());
                let response: Option<i32> = Some(file_header_response.response().into());

                let file_header_response = protos::FileChannel::FileHeaderResponse{file_id, response, ..Default::default()};

                pb.file_header_response = Some(file_header_response).into();
            },
            Packet::FileChunk(file_chunk) => {
                let file_id = Some(file_chunk.file_id());
                let chunk_data: Option<Vec<u8>> = Some(file_chunk.chunk_data().into());

                let file_chunk = protos::FileChannel::FileChunk{file_id, chunk_data, ..Default::default()};

                pb.file_chunk = Some(file_chunk).into();
            },
            Packet::FileChunkAck(file_chunk_ack) => {
                let file_id = Some(file_chunk_ack.file_id());
                let bytes_received = Some(file_chunk_ack.bytes_received());

                let file_chunk_ack = protos::FileChannel::FileChunkAck{file_id, bytes_received, ..Default::default()};

                pb.file_chunk_ack = Some(file_chunk_ack).into();
            },
            Packet::FileTransferCompleteNotification(file_transfer_complete_notification) => {
                let file_id = Some(file_transfer_complete_notification.file_id());
                let result = file_transfer_complete_notification.result();
                let result = match result {
                    FileTransferResult::Success => protos::FileChannel::FileTransferResult::Success,
                    FileTransferResult::Failure => protos::FileChannel::FileTransferResult::Failure,
                    FileTransferResult::Cancelled => protos::FileChannel::FileTransferResult::Cancelled,
                };
                let result = Some(protobuf::EnumOrUnknown::new(result));

                let file_transfer_complete_notification = protos::FileChannel::FileTransferCompleteNotification{file_id, result, ..Default::default()};

                pb.file_transfer_complete_notification = Some(file_transfer_complete_notification).into();
            },
        }

        // serialise
        pb.write_to_vec(v).map_err(Error::ProtobufError)?;
        Ok(())
    }
}

impl TryFrom<&[u8]> for Packet {
    type Error = Error;

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

                let file_hash = file_header.file_hash.ok_or(Self::Error::InvalidProtobufMessage)?;
                let file_hash: [u8; FILE_HASH_SIZE] = match file_hash.try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return Err(Self::Error::InvalidProtobufMessage),
                };

                let file_header = FileHeader::new(file_id, file_size, name, file_hash)?;
                Ok(Packet::FileHeader(file_header))
            },
            (None, Some(file_header_ack), None, None, None, None) => {
                let file_id = file_header_ack.file_id.ok_or(Self::Error::InvalidProtobufMessage)?;

                let accepted = file_header_ack.accepted.ok_or(Self::Error::InvalidProtobufMessage)?;

                let file_header_ack = FileHeaderAck::new(file_id, accepted)?;
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

                let file_header_response = FileHeaderResponse::new(file_id, response)?;
                Ok(Packet::FileHeaderResponse(file_header_response))
            },
            (None, None, None, Some(file_chunk), None, None) => {
                let file_id = file_chunk.file_id.ok_or(Self::Error::InvalidProtobufMessage)?;

                let chunk_data = file_chunk.chunk_data.ok_or(Self::Error::InvalidProtobufMessage)?;
                let chunk_data: ChunkData = chunk_data.try_into()?;

                let file_chunk = FileChunk::new(file_id, chunk_data)?;
                Ok(Packet::FileChunk(file_chunk))
            },
            (None, None, None, None, Some(file_chunk_ack), None) => {
                let file_id = file_chunk_ack.file_id.ok_or(Self::Error::InvalidProtobufMessage)?;

                let bytes_received = file_chunk_ack.bytes_received.ok_or(Self::Error::InvalidProtobufMessage)?;

                let file_chunk_ack = FileChunkAck::new(file_id, bytes_received)?;
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

                let file_transfer_complete_notification = FileTransferCompleteNotification::new(file_id, result)?;
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
        file_hash: [u8; FILE_HASH_SIZE]) -> Result<Self, Error> {
        if name.contains("..") || name.contains("/") {
            Err(Error::PacketConstructionFailed("name contains forbidden substring".to_string()))
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
    pub fn new(file_id: u32, accepted: bool) -> Result<Self, Error> {
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
    pub fn new(file_id: u32, response: Response) -> Result<Self, Error> {
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
    type Error = Error;
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
    pub fn new(file_id: u32, chunk_data: ChunkData) -> Result<Self, Error> {
        Ok(Self{file_id, chunk_data})
    }

    pub fn file_id(&self) -> u32 {
        self.file_id
    }

    pub fn chunk_data(&self) -> &ChunkData {
        &self.chunk_data
    }

    pub fn take_chunk_data(self) -> ChunkData {
        self.chunk_data
    }
}

#[derive(Debug, PartialEq)]
pub struct ChunkData {
    data: Vec<u8>,
}

impl ChunkData {
    pub fn new(data: Vec<u8>) -> Result<ChunkData, Error> {
        let data_len = data.len();
        if data_len > MAX_FILE_CHUNK_SIZE {
            Err(Error::PacketConstructionFailed(format!("chunk data must be less than {MAX_FILE_CHUNK_SIZE} bytes")))
        } else {
            Ok(Self{data})
        }
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }
}

impl From<&ChunkData> for Vec<u8> {
    fn from(chunk_data: &ChunkData) -> Vec<u8> {
        chunk_data.data.clone()
    }
}

impl From<ChunkData> for Vec<u8> {
    fn from(chunk_data: ChunkData) -> Vec<u8> {
        chunk_data.data
    }
}

impl TryFrom<Vec<u8>> for ChunkData {
    type Error = Error;
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
    pub fn new(file_id: u32, bytes_received: u64) -> Result<Self, Error> {
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
    pub fn new(file_id: u32, result: FileTransferResult) -> Result<Self, Error> {
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
