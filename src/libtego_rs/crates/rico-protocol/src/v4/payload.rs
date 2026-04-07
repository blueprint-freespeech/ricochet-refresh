// std
use std::collections::BTreeSet;
use std::io::Read;

// extern
use sha3::{Digest, Sha3_256};
use tor_interface::tor_crypto::{Ed25519PublicKey, Ed25519Signature, ED25519_SIGNATURE_SIZE};

// internal
use crate::v4::{
    self, ConversationType, FileSize, MessageContentData, MessageSequence, RecordSequence, Salt,
    Sha256Sum, Timestamp, TombstoneData,
};

// sha2
pub fn conversation_key(
    conversation_type: ConversationType,
    conversation_member_public_keys: &BTreeSet<Ed25519PublicKey>,
) -> Sha256Sum {
    const NULL_BYTE: &[u8; 1] = &[0x00u8];

    let mut hasher = Sha3_256::new();

    // domain seperator
    hasher.update(b"ricochet-refresh-conversation");

    // conversation type
    let conversation_type: i64 = conversation_type.into();
    hasher.update(NULL_BYTE);
    hasher.update(&conversation_type.to_be_bytes());

    //  number of members
    let conversation_member_count: i64 = conversation_member_public_keys.len() as i64;
    hasher.update(NULL_BYTE);
    hasher.update(&conversation_member_count.to_be_bytes());
    // keys in order
    for public_key in conversation_member_public_keys {
        hasher.update(NULL_BYTE);
        hasher.update(public_key.as_bytes());
    }

    Sha256Sum(hasher.finalize().into())
}

pub fn message_record_payload(
    previous_signature: Option<&Ed25519Signature>,
    conversation_key: &Sha256Sum,
    user_identity_ed25519_public_key: &Ed25519PublicKey,
    record_sequence: RecordSequence,
    message_sequence: MessageSequence,
    create_timestamp: Timestamp,
    message_content_hash: &Sha256Sum,
) -> Vec<u8> {
    const NULL_BYTE: &[u8; 1] = &[0x00u8];
    let mut payload: Vec<u8> = Default::default();

    if let Some(previous_signature) = previous_signature {
        payload.extend_from_slice(&previous_signature.to_bytes());
    } else {
        payload.extend_from_slice(&[0u8; ED25519_SIGNATURE_SIZE]);
    }

    payload.extend_from_slice(NULL_BYTE);
    payload.extend_from_slice(b"ricochet-refresh-message-record");
    payload.extend_from_slice(NULL_BYTE);
    payload.extend_from_slice(&conversation_key.0);
    payload.extend_from_slice(NULL_BYTE);
    payload.extend_from_slice(user_identity_ed25519_public_key.as_bytes());
    payload.extend_from_slice(NULL_BYTE);
    payload.extend_from_slice(&record_sequence.0.to_be_bytes());
    payload.extend_from_slice(NULL_BYTE);
    payload.extend_from_slice(&message_sequence.0.to_be_bytes());
    payload.extend_from_slice(NULL_BYTE);
    payload.extend_from_slice(&create_timestamp.millis_since_unix_epoch.to_be_bytes());
    payload.extend_from_slice(NULL_BYTE);
    payload.extend_from_slice(&message_content_hash.0);

    payload
}

pub fn message_content_hash(
    message_content_salt: &Salt,
    message_content_data: &MessageContentData,
) -> Sha256Sum {
    const NULL_BYTE: &[u8; 1] = &[0x00u8];
    let mut hasher = Sha3_256::new();

    match message_content_data {
        MessageContentData::Tombstone(TombstoneData {
            original_message_content_hash,
            original_message_record_signature,
        }) => {
            hasher.update(b"ricochet-refresh-tombstone-message");
            hasher.update(NULL_BYTE);
            hasher.update(&message_content_salt.0);
            hasher.update(NULL_BYTE);
            hasher.update(&original_message_content_hash.0);
            hasher.update(NULL_BYTE);
            hasher.update(&original_message_record_signature.to_bytes());
        }
        MessageContentData::Text { text } => {
            hasher.update(b"ricochet-refresh-text-message");
            hasher.update(NULL_BYTE);
            hasher.update(&message_content_salt.0);
            hasher.update(NULL_BYTE);
            hasher.update(text.as_bytes());
        }
        MessageContentData::FileShare {
            file_data_salt: _,
            file_size: _,
            file_data_hash,
            file_path: _,
        } => {
            hasher.update(b"ricochet-refresh-file-share-message");
            hasher.update(NULL_BYTE);
            hasher.update(&message_content_salt.0);
            hasher.update(NULL_BYTE);
            hasher.update(&file_data_hash.0);
        }
    }

    Sha256Sum(hasher.finalize().into())
}

pub fn file_data_hash(
    file_data_salt: &Salt,
    file_size: FileSize,
    file_contents: &mut impl Read,
) -> Result<Sha256Sum, v4::Error> {
    const NULL_BYTE: &[u8; 1] = &[0x00u8];
    let mut hasher = Sha3_256::new();

    hasher.update("ricochet-refresh-file-data".as_bytes());
    hasher.update(NULL_BYTE);
    hasher.update(file_data_salt.0);
    hasher.update(NULL_BYTE);
    hasher.update(&file_size.0.to_be_bytes());
    hasher.update(NULL_BYTE);

    // hash file contents
    let mut buffer = [0u8; 8192];
    loop {
        let n = file_contents.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(Sha256Sum(hasher.finalize().into()))
}
