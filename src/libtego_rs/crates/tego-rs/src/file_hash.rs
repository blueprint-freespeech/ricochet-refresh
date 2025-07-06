// TODO: remove this type from FFI

// extgern crates
use data_encoding::HEXLOWER;

pub(crate) const FILE_HASH_SIZE: usize = rico_protocol::v3::message::file_channel::FILE_HASH_SIZE;
// two chars per byte plus null terminator
pub(crate) const FILE_HASH_STRING_LENGTH: usize = FILE_HASH_SIZE * 2;
pub(crate) const FILE_HASH_STRING_SIZE: usize = FILE_HASH_STRING_LENGTH + 1;

pub(crate) struct FileHash {
    pub data: [u8; FILE_HASH_SIZE],
}

impl FileHash {

    pub fn to_string(&self) -> String {
        HEXLOWER.encode(&self.data)
    }
}
