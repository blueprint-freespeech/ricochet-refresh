// extgern crates
use data_encoding::HEXLOWER;

// 512 bits, 8 bits per byte
const SHA3_512_DIGEST_SIZE: usize = 512 / 8;
const DIGEST_SIZE: usize = SHA3_512_DIGEST_SIZE;
// two chars per byte plus null terminator
pub(crate) const FILE_HASH_STRING_LENGTH: usize = DIGEST_SIZE * 2;
pub(crate) const FILE_HASH_STRING_SIZE: usize = FILE_HASH_STRING_LENGTH + 1;

pub(crate) struct FileHash {
    data: [u8; DIGEST_SIZE],
}

impl FileHash {
    pub fn to_string(&self) -> String {
        HEXLOWER.encode(&self.data)
    }
}
