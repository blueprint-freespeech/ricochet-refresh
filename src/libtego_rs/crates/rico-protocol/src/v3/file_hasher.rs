// std
use std::io::Read;
use std::path::PathBuf;

// extern
use sha3::{Digest, Sha3_512};

// internal
use crate::v3::message::file_channel::FILE_HASH_SIZE;

pub type FileHash = [u8; FILE_HASH_SIZE];

#[derive(Default)]
pub struct FileHasher {
    hasher: Sha3_512,
}

impl FileHasher {
    pub fn update(&mut self, input: &[u8]) -> () {
        self.hasher.update(input);
    }

    pub fn finalize(mut self) -> FileHash {
        assert!(Sha3_512::output_size() == FILE_HASH_SIZE);
        self.hasher.finalize().try_into().unwrap()
    }
}
