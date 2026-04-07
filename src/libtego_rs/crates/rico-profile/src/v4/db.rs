// std
use std::collections::BTreeSet;

// extern
use rusqlite::{params, Connection, Transaction};
use time::UtcDateTime;
use tor_interface::tor_crypto::{
    Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature, X25519PrivateKey, X25519PublicKey,
    ED25519_PRIVATE_KEY_SIZE, ED25519_PUBLIC_KEY_SIZE, ED25519_SIGNATURE_SIZE,
    X25519_PRIVATE_KEY_SIZE, X25519_PUBLIC_KEY_SIZE,
};

// internal
use crate::v4::error::Error;
use crate::v4::profile;

/// Implements ToSql, FromSql for a wrapper struct around a single value.
macro_rules! impl_sql_wrapper_type {
    // struct case
    ($vis:vis struct $wrapper_type:ident($inner_vis:vis $inner_type:ty)) => {
        #[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
        $vis struct $wrapper_type($inner_vis $inner_type);

        impl rusqlite::ToSql for $wrapper_type {
            fn to_sql(&self) -> Result<rusqlite::types::ToSqlOutput<'_>, rusqlite::Error> {
                self.0.to_sql()
            }
        }

        impl rusqlite::types::FromSql for $wrapper_type {
            fn column_result(
                value: rusqlite::types::ValueRef<'_>,
            ) -> Result<Self, rusqlite::types::FromSqlError> {
                <$inner_type>::column_result(value).map(|v| $wrapper_type(v))
            }
        }
    };
}

//
// RowID types
//

impl_sql_wrapper_type!(pub(crate) struct DBVersionRowID(pub i64));
impl_sql_wrapper_type!(pub struct UserProfileRowID(pub i64));
impl_sql_wrapper_type!(pub(crate) struct AvatarRowID(pub i64));
impl_sql_wrapper_type!(pub struct UserRowID(pub i64));
impl_sql_wrapper_type!(pub struct ConversationRowID(pub i64));
impl_sql_wrapper_type!(pub struct MessageRecordRowID(pub i64));
impl_sql_wrapper_type!(pub(crate) struct MessageContentRowID(pub i64));
impl_sql_wrapper_type!(pub(crate) struct TombstoneMessageRowID(pub i64));
impl_sql_wrapper_type!(pub(crate) struct TextMessageRowID(pub i64));
impl_sql_wrapper_type!(pub(crate) struct FileShareMessageRowID(pub i64));
impl_sql_wrapper_type!(pub(crate) struct SaltRowID(pub i64));
impl_sql_wrapper_type!(pub(crate) struct Sha256HashRowID(pub i64));
impl_sql_wrapper_type!(pub(crate) struct Ed25519PrivateKeyRowID(pub i64));
impl_sql_wrapper_type!(pub(crate) struct Ed25519PublicKeyRowID(pub i64));
impl_sql_wrapper_type!(pub(crate) struct Ed25519SignatureRowID(pub i64));
impl_sql_wrapper_type!(pub(crate) struct X25519PrivateKeyRowID(pub i64));
impl_sql_wrapper_type!(pub(crate) struct X25519PublicKeyRowID(pub i64));
type Timestamp = rico_protocol::v4::Timestamp;

type MessageType = rico_protocol::v4::MessageType;

//
// Set the table's password for decryption key
//

pub(super) fn set_password(conn: &Connection, password: &str) -> Result<(), Error> {
    conn.pragma_update(None, "key", password)
        .map_err(Error::PragmaUpdateFailure)?;
    Ok(())
}

//
// Create database tables and indexes
//

pub(super) fn create_tables(conn: &Connection) -> Result<(), Error> {
    // build our tables
    conn.execute_batch(
        "BEGIN;

        -- db_versions
        CREATE TABLE db_versions (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          major INTEGER NOT NULL CHECK(major >= 0),
          minor INTEGER NOT NULL CHECK(minor >= 0),
          patch INTEGER NOT NULL CHECK(patch >= 0)
        );

        -- user_profiles
        CREATE TABLE user_profiles (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          nickname TEXT NOT NULL,
          pet_name TEXT,
          pronouns TEXT CHECK(LENGTH(pronouns) <= 64),
          avatar_rowid INTEGER UNIQUE REFERENCES avatars(rowid),
          status TEXT CHECK(LENGTH(status) <= 256),
          description TEXT CHECK(LENGTH(description) <= 2048)
        );

        -- avatars
        CREATE TABLE avatars (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          value BLOB CHECK(LENGTH(value) = 262144)
        );

        -- users
        CREATE TABLE users (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          user_type INTEGER NOT NULL CHECK(user_type >= 0 AND user_type <= 4),
          user_profile_rowid INTEGER UNIQUE REFERENCES user_profiles(rowid),
          identity_ed25519_public_key_rowid INTEGER NOT NULL UNIQUE REFERENCES ed25519_public_keys(rowid),
          identity_ed25519_private_key_rowid INTEGER UNIQUE REFERENCES ed25519_private_keys(rowid),
          remote_endpoint_ed25519_public_key_rowid INTEGER UNIQUE REFERENCES ed25519_public_keys(rowid),
          remote_endpoint_x25519_private_key_rowid INTEGER UNIQUE REFERENCES x25519_private_keys(rowid),
          local_endpoint_ed25519_private_key_rowid INTEGER UNIQUE REFERENCES ed25519_private_keys(rowid),
          local_endpoint_x25519_public_key_rowid INTEGER UNIQUE REFERENCES x25519_public_keys(rowid),
          CHECK((user_type == 0) == (identity_ed25519_private_key_rowid IS NOT NULL)),
          CHECK((remote_endpoint_ed25519_public_key_rowid IS NULL AND remote_endpoint_x25519_private_key_rowid IS NULL) OR (remote_endpoint_ed25519_public_key_rowid IS NOT NULL AND remote_endpoint_x25519_private_key_rowid IS NOT NULL)),
          CHECK((local_endpoint_ed25519_private_key_rowid IS NULL AND local_endpoint_x25519_public_key_rowid IS NULL) OR (local_endpoint_ed25519_private_key_rowid IS NOT NULL AND local_endpoint_x25519_public_key_rowid IS NOT NULL))
        );

        -- conversations
        CREATE TABLE conversations (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          conversation_type INTEGER NOT NULL CHECK(conversation_type >= 1 AND conversation_type <= 2),
          conversation_key_rowid INTEGER NOT NULL UNIQUE REFERENCES sha256_hashes(rowid)
        );

        -- conversation_members
        CREATE TABLE conversation_members (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          conversation_rowid INTEGER NOT NULL REFERENCES conversations(rowid),
          user_rowid INTEGER NOT NULL REFERENCES users(rowid),
          UNIQUE(conversation_rowid, user_rowid)
        );

        -- message_records
        CREATE TABLE message_records (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          conversation_rowid INTEGER NOT NULL REFERENCES conversations(rowid),
          user_rowid INTEGER NOT NULL REFERENCES users(rowid),
          record_sequence INTEGER NOT NULL CHECK(record_sequence >= 0),
          message_sequence INTEGER NOT NULL CHECK(message_sequence >= 0),
          create_timestamp INTEGER NOT NULL,
          message_content_rowid INTEGER NOT NULL UNIQUE REFERENCES message_contents(rowid),
          signature_rowid INTEGER NOT NULL UNIQUE REFERENCES ed25519_signatures(rowid),
          UNIQUE(conversation_rowid, user_rowid, record_sequence)
        );

        -- message_records_view
        CREATE VIEW message_records_view AS
        SELECT
          mr.rowid AS mr_rowid,
          mr.conversation_rowid AS mr_conversation_rowid,
          mr.user_rowid AS mr_user_rowid,
          mr.record_sequence AS mr_record_sequence,
          mr.message_sequence AS mr_message_sequence,
          mr.create_timestamp AS mr_create_timestamp,
          mc_salt.value AS mc_salt,
          mc.message_type AS mc_message_type,
          tsm_hash.value AS tsm_original_message_content_hash,
          tsm_sig.value AS tsm_original_message_record_signature,
          tm.text AS tm_text,
          fsm_salt.value AS fsm_file_data_salt,
          fsm.file_size AS fsm_file_size,
          fsm_hash.value AS fsm_file_data_hash,
          fsm.file_path AS fsm_file_path,
          es.value AS mr_signature
        FROM message_records mr
        JOIN conversations c ON mr.conversation_rowid = c.rowid
        JOIN message_contents mc ON mr.message_content_rowid = mc.rowid
        JOIN salts mc_salt ON mc.salt_rowid = mc_salt.rowid
        JOIN ed25519_signatures es ON mr.signature_rowid = es.rowid
        LEFT JOIN tombstone_messages tsm ON mc.tombstone_message_rowid = tsm.rowid
        LEFT JOIN sha256_hashes tsm_hash ON tsm.original_message_content_hash_rowid = tsm_hash.rowid
        LEFT JOIN ed25519_signatures tsm_sig ON tsm.original_message_record_signature_rowid = tsm_sig.rowid
        LEFT JOIN text_messages tm ON mc.text_message_rowid = tm.rowid
        LEFT JOIN file_share_messages fsm ON mc.file_share_message_rowid = fsm.rowid
        LEFT JOIN salts fsm_salt ON fsm.file_data_salt_rowid = fsm_salt.rowid
        LEFT JOIN sha256_hashes fsm_hash ON fsm.file_data_hash_rowid = fsm_hash.rowid;

        -- message_records_tombstone_view
        CREATE VIEW message_records_tombstone_view AS
        SELECT
          mr.rowid AS mr_rowid,
          mr.message_content_rowid as mr_message_content_rowid,
          mr.signature_rowid as mr_signature_rowid,
          mc.message_type as mc_message_type
        FROM message_records mr
        JOIN message_contents mc ON mr.message_content_rowid = mc.rowid;

        -- message_contents
        CREATE TABLE message_contents (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          salt_rowid INTEGER NOT NULL REFERENCES salts(rowid),
          message_type INTEGER NOT NULL CHECK(message_type >= 0 AND message_type <= 2),
          tombstone_message_rowid INTEGER REFERENCES tombstone_messages(rowid),
          text_message_rowid INTEGER REFERENCES text_messages(rowid),
          file_share_message_rowid INTEGER UNIQUE REFERENCES file_share_messages(rowid),
          CHECK((message_type = 0) = (tombstone_message_rowid IS NOT NULL)),
          CHECK((message_type = 1) = (text_message_rowid IS NOT NULL)),
          CHECK((message_type = 2) = (file_share_message_rowid IS NOT NULL))
        );

        -- tombstone_messages
        CREATE TABLE tombstone_messages (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          original_message_content_hash_rowid INTEGER NOT NULL REFERENCES sha256_hashes(rowid),
          original_message_record_signature_rowid INTEGER NOT NULL REFERENCES ed25519_signatures(rowid)
        );

        -- text_messages
        CREATE TABLE text_messages (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          text TEXT NOT NULL
        );

        -- file_share_messages
        CREATE TABLE file_share_messages (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          file_data_salt_rowid INTEGER NOT NULL REFERENCES salts(rowid),
          file_size INTEGER NOT NULL CHECK(file_size >= 0),
          file_data_hash_rowid INTEGER NOT NULL REFERENCES sha256_hashes(rowid),
          file_path TEXT
        );

        -- salts
        CREATE TABLE salts (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          value BLOB NOT NULL UNIQUE CHECK(LENGTH(value) = 32)
        );

        -- sha256_hashes
        CREATE TABLE sha256_hashes (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          value BLOB NOT NULL UNIQUE CHECK(LENGTH(value) = 32)
        );

        -- ed25519_private_keys
        CREATE TABLE ed25519_private_keys (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          value BLOB NOT NULL UNIQUE CHECK(LENGTH(value) = 64)
        );

        -- ed25519_public_keys
        CREATE TABLE ed25519_public_keys (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          value BLOB NOT NULL UNIQUE CHECK(LENGTH(value) = 32)
        );

        -- ed25519_signatures
        CREATE TABLE ed25519_signatures (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          value BLOB NOT NULL UNIQUE CHECK(LENGTH(value) = 64)
        );

        -- x25519_private_keys
        CREATE TABLE x25519_private_keys (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          value BLOB NOT NULL UNIQUE CHECK(LENGTH(value) = 32)
        );

        -- x25519_public_keys
        CREATE TABLE x25519_public_keys (
          rowid INTEGER PRIMARY KEY AUTOINCREMENT,
          value BLOB NOT NULL UNIQUE CHECK(LENGTH(value) = 32)
        );

        COMMIT;"
    ).map_err(Error::StatementExecuteFailure)?;
    Ok(())
}

//
// Row insert methods
//

pub(crate) fn insert_db_version(
    conn: &Connection,
    major: i64,
    minor: i64,
    patch: i64,
) -> Result<DBVersionRowID, Error> {
    conn.execute(
        "INSERT INTO db_versions (
            major,
            minor,
            patch
        ) VALUES (?1, ?2, ?3)",
        params![major, minor, patch],
    )
    .map_err(Error::StatementExecuteFailure)?;
    let rowid = conn.last_insert_rowid();
    Ok(DBVersionRowID(rowid))
}

pub fn insert_user_profile(
    tx: &Transaction<'_>,
    user_profile: &profile::UserProfile,
) -> Result<UserProfileRowID, Error> {
    let nickname = &user_profile.nickname;
    let pet_name = &user_profile.pet_name;
    let pronouns = &user_profile.pronouns;
    let avatar_rowid = if let Some(avatar) = &user_profile.avatar {
        Some(insert_avatar(tx, avatar)?)
    } else {
        None
    };
    let status = &user_profile.status;
    let description = &user_profile.description;

    tx.execute(
        "INSERT INTO user_profiles (
              nickname,
              pet_name,
              pronouns,
              avatar_rowid,
              status,
              description
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            nickname,
            pet_name,
            pronouns,
            avatar_rowid,
            status,
            description
        ],
    )
    .map_err(Error::StatementExecuteFailure)?;
    let rowid = tx.last_insert_rowid();
    Ok(UserProfileRowID(rowid))
}

pub fn insert_avatar(tx: &Transaction<'_>, avatar: &profile::Avatar) -> Result<AvatarRowID, Error> {
    tx.execute(
        "INSERT INTO avatars (value) VALUES (?1)",
        params![avatar.rgba_data],
    )
    .map_err(Error::StatementExecuteFailure)?;
    let rowid = tx.last_insert_rowid();
    Ok(AvatarRowID(rowid))
}

pub fn insert_user(tx: &Transaction<'_>, user: &profile::User) -> Result<UserRowID, Error> {
    let user_type = user.user_type;
    let user_profile_rowid = insert_user_profile(tx, &user.user_profile)?;
    let identity_ed25519_public_key_rowid =
        insert_ed25519_public_key(tx, &user.identity_ed25519_public_key)?;
    let identity_ed25519_private_key_rowid =
        if let Some(identity_ed25519_private_key) = &user.identity_ed25519_private_key {
            Some(insert_ed25519_private_key(
                tx,
                &identity_ed25519_private_key,
            )?)
        } else {
            None
        };
    let remote_endpoint_ed25519_public_key_rowid = if let Some(remote_endpoint_ed25519_public_key) =
        &user.remote_endpoint_ed25519_public_key
    {
        Some(insert_ed25519_public_key(
            tx,
            &remote_endpoint_ed25519_public_key,
        )?)
    } else {
        None
    };
    let remote_endpoint_x25519_private_key_rowid = if let Some(remote_endpoint_x25519_private_key) =
        &user.remote_endpoint_x25519_private_key
    {
        Some(insert_x25519_private_key(
            tx,
            &remote_endpoint_x25519_private_key,
        )?)
    } else {
        None
    };
    let local_endpoint_ed25519_private_key_rowid = if let Some(local_endpoint_ed25519_private_key) =
        &user.local_endpoint_ed25519_private_key
    {
        Some(insert_ed25519_private_key(
            tx,
            &local_endpoint_ed25519_private_key,
        )?)
    } else {
        None
    };
    let local_endpoint_x25519_public_key_rowid =
        if let Some(local_endpoint_x25519_public_key) = &user.local_endpoint_x25519_public_key {
            Some(insert_x25519_public_key(
                tx,
                &local_endpoint_x25519_public_key,
            )?)
        } else {
            None
        };

    tx.execute(
        "INSERT INTO users (
              user_type,
              user_profile_rowid,
              identity_ed25519_public_key_rowid,
              identity_ed25519_private_key_rowid,
              remote_endpoint_ed25519_public_key_rowid,
              remote_endpoint_x25519_private_key_rowid,
              local_endpoint_ed25519_private_key_rowid,
              local_endpoint_x25519_public_key_rowid
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            user_type,
            user_profile_rowid,
            identity_ed25519_public_key_rowid,
            identity_ed25519_private_key_rowid,
            remote_endpoint_ed25519_public_key_rowid,
            remote_endpoint_x25519_private_key_rowid,
            local_endpoint_ed25519_private_key_rowid,
            local_endpoint_x25519_public_key_rowid,
        ],
    )?;
    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);
    Ok(UserRowID(rowid))
}

pub fn insert_conversation(
    tx: &Transaction<'_>,
    conversation: &profile::Conversation,
) -> Result<ConversationRowID, Error> {
    let conversation_type: i64 = conversation.conversation_type.into();
    let conversation_members = &conversation.conversation_members;
    let conversation_key = &conversation.conversation_key;
    let conversation_key_rowid = insert_sha256_hash(tx, &conversation_key)?;

    tx.execute(
        "INSERT INTO conversations (conversation_type, conversation_key_rowid) VALUES (?1, ?2)",
        params![conversation_type, conversation_key_rowid],
    )
    .map_err(Error::StatementExecuteFailure)?;
    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);
    let conversation_rowid = ConversationRowID(rowid);

    for conversation_member in conversation_members {
        let user_rowid = UserRowID(conversation_member.0);
        let _ = insert_conversation_member(tx, conversation_rowid, user_rowid)?;
    }
    Ok(conversation_rowid)
}

pub fn insert_conversation_member(
    tx: &Transaction<'_>,
    conversation_rowid: ConversationRowID,
    user_rowid: UserRowID,
) -> Result<ConversationRowID, Error> {
    tx.execute(
        "INSERT INTO conversation_members (
              conversation_rowid,
              user_rowid
            ) VALUES (?1, ?2)",
        params![conversation_rowid, user_rowid],
    )
    .map_err(Error::StatementExecuteFailure)?;
    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);
    Ok(ConversationRowID(rowid))
}

pub fn insert_message_record(
    tx: &Transaction<'_>,
    message_record: &profile::MessageRecord,
) -> Result<MessageRecordRowID, Error> {
    let conversation_rowid = message_record.conversation_handle;
    let user_rowid = message_record.user_handle;
    let record_sequence = message_record.record_sequence;
    let message_sequence = message_record.message_sequence;
    let create_timestamp = message_record.create_timestamp;
    let message_content_salt = &message_record.message_content.salt;
    let message_content_salt_rowid = insert_salt(tx, message_content_salt)?;
    let message_content_data = &message_record.message_content.data;
    let message_content_rowid =
        insert_message_content(tx, message_content_salt_rowid, message_content_data)?;
    let signature = &message_record.signature;
    let signature_rowid = insert_ed25519_signature(tx, signature)?;

    tx.execute(
        "INSERT INTO message_records (
            conversation_rowid,
            user_rowid,
            record_sequence,
            message_sequence,
            create_timestamp,
            message_content_rowid,
            signature_rowid
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            conversation_rowid,
            user_rowid,
            record_sequence,
            message_sequence,
            create_timestamp,
            message_content_rowid,
            signature_rowid
        ],
    )?;
    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);

    Ok(MessageRecordRowID(rowid))
}

fn insert_message_content(
    tx: &Transaction<'_>,
    salt_rowid: SaltRowID,
    message_content_data: &profile::MessageContentData,
) -> Result<MessageContentRowID, Error> {
    use profile::{MessageContentData, TombstoneData};
    let (message_type, tombstone_message_rowid, text_message_rowid, file_share_message_rowid) =
        match message_content_data {
            MessageContentData::Tombstone(TombstoneData {
                original_message_content_hash,
                original_message_record_signature,
            }) => {
                let rowid = insert_tombstone_message(
                    tx,
                    original_message_content_hash,
                    original_message_record_signature,
                )?;
                (MessageType::Tombstone, Some(rowid), None, None)
            }
            MessageContentData::Text { text } => {
                let rowid = insert_text_message(tx, text.as_str())?;
                (MessageType::Text, None, Some(rowid), None)
            }
            MessageContentData::FileShare {
                file_data_salt,
                file_size,
                file_data_hash,
                file_path,
            } => {
                let rowid = insert_file_share_message(
                    tx,
                    file_data_salt,
                    file_size,
                    file_data_hash,
                    file_path,
                )?;
                (MessageType::FileShare, None, None, Some(rowid))
            }
        };

    tx.execute("INSERT INTO message_contents (salt_rowid, message_type, tombstone_message_rowid, text_message_rowid, file_share_message_rowid) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![salt_rowid, message_type, tombstone_message_rowid, text_message_rowid, file_share_message_rowid])?;

    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);
    Ok(MessageContentRowID(rowid))
}

fn insert_tombstone_message(
    tx: &Transaction<'_>,
    original_message_content_hash: &profile::Sha256Sum,
    original_message_record_signature: &Ed25519Signature,
) -> Result<TombstoneMessageRowID, Error> {
    let original_message_content_hash_rowid =
        insert_sha256_hash(tx, original_message_content_hash)?;
    let original_message_record_signature_rowid =
        insert_ed25519_signature(tx, original_message_record_signature)?;

    tx.execute("INSERT INTO tombstone_messages (original_message_content_hash_rowid, original_message_record_signature_rowid) VALUES (?1, ?2)",
        params![original_message_content_hash_rowid, original_message_record_signature_rowid])?;

    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);
    Ok(TombstoneMessageRowID(rowid))
}

fn insert_text_message(tx: &Transaction<'_>, text: &str) -> Result<TextMessageRowID, Error> {
    tx.execute(
        "INSERT INTO text_messages (text) VALUES (?1)",
        params![text],
    )?;

    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);
    Ok(TextMessageRowID(rowid))
}

fn insert_file_share_message(
    tx: &Transaction<'_>,
    file_data_salt: &profile::Salt,
    file_size: &profile::FileSize,
    file_data_hash: &profile::Sha256Sum,
    file_path: &Option<std::path::PathBuf>,
) -> Result<FileShareMessageRowID, Error> {
    let file_data_salt_rowid = insert_salt(tx, file_data_salt)?;
    let file_data_hash_rowid = insert_sha256_hash(tx, file_data_hash)?;
    let file_path = match file_path {
        Some(file_path) => file_path.to_str(),
        None => None,
    };

    tx.execute("INSERT INTO file_share_messages (file_data_salt_rowid, file_size, file_data_hash_rowid, file_path) VALUES (?1, ?2, ?3, ?4)",
        params![file_data_salt_rowid, file_size, file_data_hash_rowid, file_path])?;

    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);
    Ok(FileShareMessageRowID(rowid))
}

fn insert_salt(tx: &Transaction<'_>, value: &profile::Salt) -> Result<SaltRowID, Error> {
    tx.execute(
        "INSERT INTO salts (
                value
            ) VALUES (?1)",
        params![value.0],
    )?;
    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);
    Ok(SaltRowID(rowid))
}

fn insert_sha256_hash(
    tx: &Transaction<'_>,
    value: &profile::Sha256Sum,
) -> Result<Sha256HashRowID, Error> {
    tx.execute(
        "INSERT INTO sha256_hashes (
                value
            ) VALUES (?1)",
        params![value.0],
    )
    .map_err(Error::StatementExecuteFailure)?;
    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);
    Ok(Sha256HashRowID(rowid))
}

fn insert_ed25519_private_key(
    tx: &Transaction<'_>,
    value: &Ed25519PrivateKey,
) -> Result<Ed25519PrivateKeyRowID, Error> {
    let value = value.to_bytes();
    tx.execute(
        "INSERT INTO ed25519_private_keys (
                value
            ) VALUES (?1)",
        params![value],
    )
    .map_err(Error::StatementExecuteFailure)?;
    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);
    Ok(Ed25519PrivateKeyRowID(rowid))
}

fn insert_ed25519_public_key(
    tx: &Transaction<'_>,
    value: &Ed25519PublicKey,
) -> Result<Ed25519PublicKeyRowID, Error> {
    let value = value.as_bytes();
    tx.execute(
        "INSERT INTO ed25519_public_keys (
                value
            ) VALUES (?1)",
        params![value],
    )
    .map_err(Error::StatementExecuteFailure)?;
    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);
    Ok(Ed25519PublicKeyRowID(rowid))
}

fn insert_ed25519_signature(
    tx: &Transaction<'_>,
    value: &Ed25519Signature,
) -> Result<Ed25519SignatureRowID, Error> {
    let value = value.to_bytes();
    tx.execute(
        "INSERT INTO ed25519_signatures (
                value
            ) VALUES (?1)",
        params![value],
    )
    .map_err(Error::StatementExecuteFailure)?;
    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);
    Ok(Ed25519SignatureRowID(rowid))
}

fn insert_x25519_private_key(
    tx: &Transaction<'_>,
    value: &X25519PrivateKey,
) -> Result<X25519PrivateKeyRowID, Error> {
    let value = value.to_bytes();
    tx.execute(
        "INSERT INTO x25519_private_keys (
                value
            ) VALUES (?1)",
        params![value],
    )
    .map_err(Error::StatementExecuteFailure)?;
    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);
    Ok(X25519PrivateKeyRowID(rowid))
}

fn insert_x25519_public_key(
    tx: &Transaction<'_>,
    value: &X25519PublicKey,
) -> Result<X25519PublicKeyRowID, Error> {
    let value = value.as_bytes();
    tx.execute(
        "INSERT INTO x25519_public_keys (
                value
            ) VALUES (?1)",
        params![value],
    )
    .map_err(Error::StatementExecuteFailure)?;
    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);
    Ok(X25519PublicKeyRowID(rowid))
}

//
// Row Update Methods
//

pub(crate) fn update_user_profile(
    tx: &Transaction<'_>,
    user_handle: profile::UserHandle,
    user_profile: &profile::UserProfile,
) -> Result<(), Error> {
    let user_rowid = user_handle;
    let user_profile_rowid = select_user_profile_rowid_by_user_rowid(tx, user_rowid)?;

    let old_avatar_rowid = tx.query_one(
        "SELECT avatar_rowid FROM user_profiles WHERE rowid = ?1",
        params![user_profile_rowid],
        |row| row.get::<_, Option<AvatarRowID>>(0),
    )?;

    let nickname = &user_profile.nickname;
    let pet_name = &user_profile.pet_name;
    let pronouns = &user_profile.pronouns;
    let avatar_rowid = match &user_profile.avatar {
        Some(avatar) => Some(insert_avatar(tx, avatar)?),
        None => None,
    };
    let status = &user_profile.status;
    let description = &user_profile.description;
    tx.execute("UPDATE user_profiles SET nickname = ?2, pet_name = ?3, pronouns = ?4, avatar_rowid = ?5, status = ?6, description = ?7 WHERE rowid = ?1",
        params![user_profile_rowid, nickname, pet_name, pronouns, avatar_rowid, status, description])?;

    if let Some(avatar_rowid) = old_avatar_rowid {
        delete_avatar(tx, avatar_rowid)?;
    }

    Ok(())
}

pub(crate) fn update_remote_endpoint_keys(
    tx: &Transaction<'_>,
    user_handle: profile::UserHandle,
    remote_endpoint_ed25519_public_key: &Ed25519PublicKey,
    remote_endpoint_x25519_private_key: &X25519PrivateKey,
) -> Result<(), Error> {
    let user_rowid = user_handle;
    let remote_endpoint_ed25519_public_key_rowid =
        insert_ed25519_public_key(tx, remote_endpoint_ed25519_public_key)?;
    let remote_endpoint_x25519_private_key_rowid =
        insert_x25519_private_key(tx, remote_endpoint_x25519_private_key)?;

    tx.execute("UPDATE users SET remote_endpoint_ed25519_public_key_rowid = ?1, remote_endpoint_x25519_private_key_rowid = ?2 WHERE rowid = ?3",
        params![remote_endpoint_ed25519_public_key_rowid, remote_endpoint_x25519_private_key_rowid, user_rowid])?;

    Ok(())
}

pub(crate) fn update_local_endpoint_keys(
    tx: &Transaction<'_>,
    user_handle: profile::UserHandle,
    local_endpoint_ed25519_private_key: &Ed25519PrivateKey,
    local_endpoint_x25519_public_key: &X25519PublicKey,
) -> Result<(), Error> {
    let user_rowid = user_handle;
    let local_endpoint_ed25519_private_key_rowid =
        insert_ed25519_private_key(tx, local_endpoint_ed25519_private_key)?;
    let local_endpoint_x25519_public_key_rowid =
        insert_x25519_public_key(tx, local_endpoint_x25519_public_key)?;
    tx.execute("UPDATE users SET local_endpoint_ed25519_private_key_rowid = ?1, local_endpoint_x25519_public_key_rowid = ?2 WHERE rowid = ?3",
        params![local_endpoint_ed25519_private_key_rowid, local_endpoint_x25519_public_key_rowid, user_rowid])?;

    Ok(())
}

pub(crate) fn tombstone_message_record(
    tx: &Transaction<'_>,
    message_record_handle: profile::MessageRecordHandle,
    tombstone_message_content_salt: &profile::Salt,
    original_message_content_hash: &profile::Sha256Sum,
    new_message_record_signature: &Ed25519Signature,
) -> Result<(), Error> {
    // first we need the old message_content_rowid and the old signature_rowid for the message_record
    let (original_message_content_rowid, original_message_record_signature_rowid) = tx.query_one(
        "SELECT mr_message_content_rowid, mr_signature_rowid
        FROM message_records_tombstone_view
        WHERE mr_rowid = ?1 AND mc_message_type != ?2",
        params![message_record_handle, MessageType::Tombstone],
        |row| {
            Ok((
                row.get::<_, MessageContentRowID>(0)?,
                row.get::<_, Ed25519SignatureRowID>(1)?,
            ))
        },
    )?;

    // insert new tombstone_message
    let original_message_content_hash_rowid =
        insert_sha256_hash(tx, original_message_content_hash)?;
    tx.execute("INSERT INTO tombstone_messages (original_message_content_hash_rowid, original_message_record_signature_rowid) VALUES (?1, ?2)",
        params![original_message_content_hash_rowid, original_message_record_signature_rowid])?;
    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);
    let tombstone_message_rowid = TombstoneMessageRowID(rowid);

    // then we need to build a new message_contents with the tombstone contents
    let salt_rowid = insert_salt(tx, tombstone_message_content_salt)?;
    tx.execute("INSERT INTO message_contents (salt_rowid, message_type, tombstone_message_rowid) VALUES (?1, ?2, ?3)",
        params![salt_rowid, MessageType::Tombstone, tombstone_message_rowid])?;
    let rowid = tx.last_insert_rowid();
    assert!(rowid > 0);
    let message_content_rowid = MessageContentRowID(rowid);

    // then we need to add the new signature to the db
    let signature_rowid = insert_ed25519_signature(tx, new_message_record_signature)?;

    // then we need to update the message_record with the new message_contents and the new signature
    tx.execute("UPDATE message_records SET message_content_rowid = ?1, signature_rowid = ?2 WHERE rowid = ?3",
        params![message_content_rowid, signature_rowid, message_record_handle])?;

    // finally we can delete the old message_content
    delete_message_content(tx, original_message_content_rowid)?;

    Ok(())
}

//
// Row Select Methods
//

pub(crate) fn select_newest_db_version(conn: &Connection) -> Result<profile::Version, Error> {
    let (major, minor, patch) = conn.query_one(
        "SELECT major, minor, patch FROM db_versions ORDER BY rowid DESC LIMIT 1;",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    )?;

    profile::Version::new(major, minor, patch)
}

pub(crate) fn select_user_profile_by_user_handle(
    conn: &Connection,
    user_handle: profile::UserHandle,
) -> Result<profile::UserProfile, Error> {
    let user_rowid = user_handle;
    let user_profile_rowid = select_user_profile_rowid_by_user_rowid(conn, user_rowid)?;

    select_user_profile(conn, user_profile_rowid)
}

pub(crate) fn select_all_conversations(
    conn: &Connection,
) -> Result<Vec<(profile::Conversation, ConversationRowID)>, Error> {
    let mut result: Vec<(profile::Conversation, ConversationRowID)> = Default::default();

    // create our prepared statements
    let mut select_conversations_stmt =
        conn.prepare("SELECT rowid, conversation_type, conversation_key_rowid FROM conversations")?;

    let mut select_conversation_members_stmt =
        conn.prepare("SELECT user_rowid FROM conversation_members WHERE conversation_rowid = ?1")?;

    let mut select_conversation_key_stmt =
        conn.prepare("SELECT value FROM sha256_hashes WHERE rowid = ?1")?;

    // get all our conversaiton rows
    let conversation_rows = select_conversations_stmt.query_map(params![], |row| {
        Ok((
            row.get::<_, ConversationRowID>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Sha256HashRowID>(2)?,
        ))
    })?;

    // build conversation objects from rows
    for conversation in conversation_rows {
        let (rowid, conversation_type, conversation_key_rowid) = conversation?;
        let conversation_type = profile::ConversationType::try_from(conversation_type)?;

        // get conversation members
        let mut conversation_members: BTreeSet<UserRowID> = Default::default();
        let conversation_member_rows = select_conversation_members_stmt
            .query_map(params![rowid], |row| row.get::<_, UserRowID>(0))?;
        for conversation_member in conversation_member_rows {
            conversation_members.insert(conversation_member?);
        }

        // get our conversation key
        let conversation_key = select_conversation_key_stmt
            .query_one(params![conversation_key_rowid], |row| {
                row.get::<_, [u8; 32]>(0)
            })?;
        let conversation_key = profile::Sha256Sum(conversation_key);

        // append result
        result.push((
            profile::Conversation {
                conversation_type,
                conversation_members,
                conversation_key,
            },
            rowid,
        ));
    }
    Ok(result)
}

pub(crate) fn select_all_users(
    conn: &Connection,
) -> Result<Vec<(profile::User, UserRowID)>, Error> {
    // create our prepared statement
    let mut select_users_stmt = conn.prepare(
        "SELECT
          rowid,
          user_type,
          user_profile_rowid,
          identity_ed25519_public_key_rowid,
          identity_ed25519_private_key_rowid,
          remote_endpoint_ed25519_public_key_rowid,
          remote_endpoint_x25519_private_key_rowid,
          local_endpoint_ed25519_private_key_rowid,
          local_endpoint_x25519_public_key_rowid
        FROM users",
    )?;

    let mut select_user_profile_stmt = conn.prepare("SELECT nickname, pet_name, pronouns, avatar_rowid, status, description FROM user_profiles WHERE rowid = ?1")?;

    let mut select_avatar_stmt = conn.prepare("SELECT value FROM avatars WHERE rowid = ?1")?;

    let mut select_ed25519_private_key_stmt =
        conn.prepare("SELECT value FROM ed25519_private_keys WHERE rowid = ?1")?;

    let mut select_ed25519_public_key_stmt =
        conn.prepare("SELECT value FROM ed25519_public_keys WHERE rowid = ?1")?;

    let mut select_x25519_private_key_stmt =
        conn.prepare("SELECT value FROM x25519_private_keys WHERE rowid = ?1")?;

    let mut select_x25519_public_key_stmt =
        conn.prepare("SELECT value FROM x25519_public_keys WHERE rowid = ?1")?;

    let user_rows = select_users_stmt.query_map(params![], |row| {
        Ok((
            row.get::<_, UserRowID>(0)?,
            row.get::<_, profile::UserType>(1)?,
            row.get::<_, UserProfileRowID>(2)?,
            // identity
            row.get::<_, Ed25519PublicKeyRowID>(3)?,
            row.get::<_, Option<Ed25519PrivateKeyRowID>>(4)?,
            // remote endpoint
            row.get::<_, Option<Ed25519PublicKeyRowID>>(5)?,
            row.get::<_, Option<X25519PrivateKeyRowID>>(6)?,
            // local endpoint
            row.get::<_, Option<Ed25519PrivateKeyRowID>>(7)?,
            row.get::<_, Option<X25519PublicKeyRowID>>(8)?,
        ))
    })?;

    // construct list of users
    let mut result: Vec<(profile::User, UserRowID)> = Default::default();
    for user in user_rows {
        let (
            user_rowid,
            user_type,
            user_profile_rowid,
            identity_ed25519_public_key_rowid,
            identity_ed25519_private_key_rowid,
            remote_endpoint_ed25519_public_key_rowid,
            remote_endpoint_x25519_private_key_rowid,
            local_endpoint_ed25519_private_key_rowid,
            local_endpoint_x25519_public_key_rowid,
        ) = user?;

        // construct user's profile
        let (nickname, pet_name, pronouns, avatar_rowid, status, description) =
            select_user_profile_stmt.query_one(params![user_profile_rowid], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<AvatarRowID>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })?;

        let avatar = match avatar_rowid {
            Some(avatar_rowid) => {
                let rgba_data =
                    Box::new(select_avatar_stmt.query_one(params![avatar_rowid], |row| {
                        row.get::<_, [u8; profile::Avatar::BYTES]>(0)
                    })?);
                let avatar = profile::Avatar { rgba_data };
                Some(avatar)
            }
            None => None,
        };

        let user_profile = profile::UserProfile {
            nickname,
            pet_name,
            pronouns,
            avatar,
            status,
            description,
        };

        // get user's keys

        // identity keys
        let identity_ed25519_public_key = {
            let raw = select_ed25519_public_key_stmt
                .query_one(params![identity_ed25519_public_key_rowid], |row| {
                    row.get::<_, [u8; ED25519_PUBLIC_KEY_SIZE]>(0)
                })?;
            Ed25519PublicKey::from_raw(&raw)?
        };
        let identity_ed25519_private_key = match identity_ed25519_private_key_rowid {
            Some(identity_ed25519_private_key_rowid) => {
                let raw = select_ed25519_private_key_stmt
                    .query_one(params![identity_ed25519_private_key_rowid], |row| {
                        row.get::<_, [u8; ED25519_PRIVATE_KEY_SIZE]>(0)
                    })?;
                Some(Ed25519PrivateKey::from_raw(&raw)?)
            }
            None => None,
        };
        // remote endpoint keys
        let remote_endpoint_ed25519_public_key = match remote_endpoint_ed25519_public_key_rowid {
            Some(remote_endpoint_ed25519_public_key_rowid) => {
                let raw = select_ed25519_public_key_stmt
                    .query_one(params![remote_endpoint_ed25519_public_key_rowid], |row| {
                        row.get::<_, [u8; ED25519_PUBLIC_KEY_SIZE]>(0)
                    })?;
                Some(Ed25519PublicKey::from_raw(&raw)?)
            }
            None => None,
        };
        let remote_endpoint_x25519_private_key = match remote_endpoint_x25519_private_key_rowid {
            Some(remote_endpoint_x25519_private_key_rowid) => {
                let raw = select_x25519_private_key_stmt
                    .query_one(params![remote_endpoint_x25519_private_key_rowid], |row| {
                        row.get::<_, [u8; X25519_PRIVATE_KEY_SIZE]>(0)
                    })?;
                Some(X25519PrivateKey::from_raw(&raw)?)
            }
            None => None,
        };

        // local endpoint keys
        let local_endpoint_ed25519_private_key = match local_endpoint_ed25519_private_key_rowid {
            Some(local_endpoint_ed25519_private_key_rowid) => {
                let raw = select_ed25519_private_key_stmt
                    .query_one(params![local_endpoint_ed25519_private_key_rowid], |row| {
                        row.get::<_, [u8; ED25519_PRIVATE_KEY_SIZE]>(0)
                    })?;
                Some(Ed25519PrivateKey::from_raw(&raw)?)
            }
            None => None,
        };
        let local_endpoint_x25519_public_key = match local_endpoint_x25519_public_key_rowid {
            Some(local_endpoint_x25519_public_key_rowid) => {
                let raw = select_x25519_public_key_stmt
                    .query_one(params![local_endpoint_x25519_public_key_rowid], |row| {
                        row.get::<_, [u8; X25519_PUBLIC_KEY_SIZE]>(0)
                    })?;
                Some(X25519PublicKey::from_raw(&raw))
            }
            None => None,
        };

        let user = profile::User {
            user_type,
            user_profile,
            identity_ed25519_public_key,
            identity_ed25519_private_key,
            remote_endpoint_ed25519_public_key,
            remote_endpoint_x25519_private_key,
            local_endpoint_ed25519_private_key,
            local_endpoint_x25519_public_key,
        };

        result.push((user, user_rowid));
    }

    Ok(result)
}

fn select_user_profile(
    conn: &Connection,
    user_profile_rowid: UserProfileRowID,
) -> Result<profile::UserProfile, Error> {
    let mut select_user_profile_stmt = conn.prepare("SELECT nickname, pet_name, pronouns, avatar_rowid, status, description FROM user_profiles WHERE rowid = ?1")?;

    let mut select_avatar_stmt = conn.prepare("SELECT value FROM avatars WHERE rowid = ?1")?;

    // construct user's profile
    let (nickname, pet_name, pronouns, avatar_rowid, status, description) =
        select_user_profile_stmt.query_one(params![user_profile_rowid], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<AvatarRowID>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?;

    let avatar = match avatar_rowid {
        Some(avatar_rowid) => {
            let rgba_data =
                Box::new(select_avatar_stmt.query_one(params![avatar_rowid], |row| {
                    row.get::<_, [u8; profile::Avatar::BYTES]>(0)
                })?);
            let avatar = profile::Avatar { rgba_data };
            Some(avatar)
        }
        None => None,
    };

    let user_profile = profile::UserProfile {
        nickname,
        pet_name,
        pronouns,
        avatar,
        status,
        description,
    };

    Ok(user_profile)
}

fn select_user_profile_rowid_by_user_rowid(
    conn: &Connection,
    user_rowid: UserRowID,
) -> Result<UserProfileRowID, Error> {
    let user_profile_rowid = conn.query_one(
        "SELECT user_profile_rowid FROM users WHERE rowid = ?1",
        params![user_rowid],
        |row| row.get::<_, UserProfileRowID>(0),
    )?;

    Ok(user_profile_rowid)
}

pub(crate) fn select_message_record(
    conn: &Connection,
    message_record_rowid: MessageRecordRowID,
) -> Result<profile::MessageRecord, Error> {
    let mut stmt = conn.prepare(
        "SELECT *
        FROM message_records_view WHERE mr_rowid = ?1",
    )?;
    let mut rows = stmt.query(params![message_record_rowid])?;
    if let Some(row) = rows.next()? {
        let message_record = message_record_from_row(row)?;
        Ok(message_record)
    } else {
        Err(rusqlite::Error::QueryReturnedNoRows)?
    }
}

pub(crate) fn select_message_record_rowid(
    conn: &Connection,
    conversation_rowid: ConversationRowID,
    user_rowid: UserRowID,
    record_sequence: profile::RecordSequence,
) -> Result<MessageRecordRowID, Error> {
    let rowid = conn.query_one(
        "SELECT rowid
        FROM message_records
        WHERE conversation_rowid = ?1 AND user_rowid = ?2 AND record_sequence = ?3",
        params![conversation_rowid, user_rowid, record_sequence],
        |row| row.get::<_, MessageRecordRowID>(0),
    )?;
    Ok(rowid)
}

pub(crate) fn select_message_records_from_conversation(
    conn: &Connection,
    conversation_rowid: ConversationRowID,
    older_than_creation_timestamp: Option<UtcDateTime>,
    limit: Option<u32>,
) -> Result<Vec<profile::MessageRecord>, Error> {
    let mut query = String::from(
        "SELECT *
        FROM message_records_view WHERE mr_conversation_rowid = ?",
    );

    if older_than_creation_timestamp.is_some() {
        query.push_str(" AND mr_create_timestamp < ?");
    }

    query.push_str(" ORDER BY mr_create_timestamp ASC, mr_record_sequence ASC");

    if limit.is_some() {
        query.push_str(" LIMIT ?");
    }

    let mut stmt = conn.prepare(&query)?;
    let mut param_index = 1;
    stmt.raw_bind_parameter(param_index, conversation_rowid.0)?;

    if let Some(older_than_creation_timestamp) = older_than_creation_timestamp {
        param_index += 1;
        let older_than_creation_timestamp = Timestamp::try_from(older_than_creation_timestamp)?;
        stmt.raw_bind_parameter(param_index, older_than_creation_timestamp)?;
    }

    if let Some(limit) = limit {
        param_index += 1;
        stmt.raw_bind_parameter(param_index, limit as i64)?;
    }

    let mut rows = stmt.raw_query();
    let mut result: Vec<profile::MessageRecord> = Default::default();
    while let Some(row) = rows.next()? {
        result.push(message_record_from_row(row)?);
    }
    Ok(result)
}

pub(crate) fn select_message_records_from_conversation_by_user(
    conn: &Connection,
    conversation_rowid: ConversationRowID,
    user_rowid: UserRowID,
    older_than_record_sequence: Option<profile::RecordSequence>,
    limit: Option<u32>,
) -> Result<Vec<profile::MessageRecord>, Error> {
    let mut query = String::from(
        "SELECT *
        FROM message_records_view WHERE mr_conversation_rowid = ? AND mr_user_rowid = ?",
    );

    if older_than_record_sequence.is_some() {
        query.push_str(" AND mr_record_sequence < ?");
    }

    query.push_str(" ORDER BY mr_record_sequence ASC");

    if limit.is_some() {
        query.push_str(" LIMIT ?");
    }

    let mut stmt = conn.prepare(&query)?;
    let mut param_index = 1;
    stmt.raw_bind_parameter(param_index, conversation_rowid)?;

    param_index += 1;
    stmt.raw_bind_parameter(param_index, user_rowid)?;

    if let Some(older_than_record_sequence) = older_than_record_sequence {
        param_index += 1;
        stmt.raw_bind_parameter(param_index, older_than_record_sequence)?;
    }

    if let Some(limit) = limit {
        param_index += 1;
        stmt.raw_bind_parameter(param_index, limit as i64)?;
    }

    let mut rows = stmt.raw_query();
    let mut result: Vec<profile::MessageRecord> = Default::default();
    while let Some(row) = rows.next()? {
        result.push(message_record_from_row(row)?);
    }
    Ok(result)
}

pub(crate) fn select_newest_record_sequence_in_conversation_by_user(
    conn: &Connection,
    conversation_rowid: ConversationRowID,
    user_rowid: UserRowID,
) -> Result<profile::RecordSequence, Error> {
    let record_sequence = conn.query_one(
        "SELECT record_sequence
        FROM message_records
        WHERE conversation_rowid = ?1 AND user_rowid = ?2
        ORDER BY record_sequence DESC
        LIMIT 1",
        params![conversation_rowid, user_rowid],
        |row| row.get::<_, profile::RecordSequence>(0),
    )?;

    Ok(record_sequence)
}

/// Convert Row from a SELECT * query from message_records_view table
/// to Vec<MessageRecord>
fn message_record_from_row(row: &rusqlite::Row<'_>) -> Result<profile::MessageRecord, Error> {
    let (
        _rowid,
        conversation_handle,
        user_handle,
        record_sequence,
        message_sequence,
        create_timestamp,
        message_content_salt,
        message_type,
        original_message_content_hash,
        original_message_record_signature,
        text,
        file_data_salt,
        file_size,
        file_data_hash,
        file_path,
        signature,
    ) = (
        row.get::<_, MessageRecordRowID>(0)?,
        row.get::<_, ConversationRowID>(1)?,
        row.get::<_, UserRowID>(2)?,
        row.get::<_, profile::RecordSequence>(3)?,
        row.get::<_, profile::MessageSequence>(4)?,
        row.get::<_, Timestamp>(5)?,
        row.get::<_, [u8; profile::Salt::BYTES]>(6)?,
        row.get::<_, MessageType>(7)?,
        row.get::<_, Option<[u8; profile::Sha256Sum::BYTES]>>(8)?,
        row.get::<_, Option<[u8; ED25519_SIGNATURE_SIZE]>>(9)?,
        row.get::<_, Option<String>>(10)?,
        row.get::<_, Option<[u8; profile::Salt::BYTES]>>(11)?,
        row.get::<_, Option<profile::FileSize>>(12)?,
        row.get::<_, Option<[u8; profile::Sha256Sum::BYTES]>>(13)?,
        row.get::<_, Option<String>>(14)?,
        row.get::<_, [u8; ED25519_SIGNATURE_SIZE]>(15)?,
    );

    let create_timestamp = create_timestamp.into();
    let message_content_salt = profile::Salt(message_content_salt);
    let message_content_data = match (
        message_type,
        original_message_content_hash,
        original_message_record_signature,
        text,
        file_data_salt,
        file_size,
        file_data_hash,
        file_path,
    ) {
        (
            MessageType::Tombstone,
            Some(original_message_content_hash),
            Some(original_message_record_signature),
            None,
            None,
            None,
            None,
            None,
        ) => {
            let original_message_content_hash = profile::Sha256Sum(original_message_content_hash);
            let original_message_record_signature =
                Ed25519Signature::from_raw(&original_message_record_signature)?;
            profile::MessageContentData::Tombstone(profile::TombstoneData {
                original_message_content_hash,
                original_message_record_signature,
            })
        }
        (MessageType::Text, None, None, Some(text), None, None, None, None) => {
            profile::MessageContentData::Text { text }
        }
        (
            MessageType::FileShare,
            None,
            None,
            None,
            Some(file_data_salt),
            Some(file_size),
            Some(file_data_hash),
            file_path,
        ) => {
            let file_data_salt = profile::Salt(file_data_salt);
            let file_data_hash = profile::Sha256Sum(file_data_hash);
            let file_path = match file_path {
                Some(file_path) => Some(file_path.into()),
                None => None,
            };
            profile::MessageContentData::FileShare {
                file_data_salt,
                file_size,
                file_data_hash,
                file_path,
            }
        }
        _ => unreachable!("unexpected message_content_data"),
    };
    let message_content = profile::MessageContent {
        salt: message_content_salt,
        data: message_content_data,
    };
    let signature = Ed25519Signature::from_raw(&signature)?;

    Ok(profile::MessageRecord {
        conversation_handle,
        user_handle,
        record_sequence,
        message_sequence,
        create_timestamp,
        message_content,
        signature,
    })
}

//
// Row delete methods
//

fn delete_avatar(tx: &Transaction, avatar_rowid: AvatarRowID) -> Result<(), Error> {
    let _count = tx.execute(
        "DELETE FROM avatars WHERE rowid = ?1",
        params![avatar_rowid],
    )?;
    Ok(())
}

fn delete_user_profile(
    tx: &Transaction<'_>,
    user_profile_rowid: UserProfileRowID,
) -> Result<(), Error> {
    let avatar_rowid = tx.query_one(
        "DELETE FROM user_profiles WHERE rowid = ?1 RETURNING avatar_rowid",
        params![user_profile_rowid],
        |row| row.get::<_, Option<AvatarRowID>>(0),
    )?;
    if let Some(avatar_rowid) = avatar_rowid {
        delete_avatar(tx, avatar_rowid)?;
    }

    Ok(())
}

pub(crate) fn delete_user(tx: &Transaction<'_>, user_handle: UserRowID) -> Result<(), Error> {
    let user_rowid = user_handle;

    // delete all of the user's conversations
    let mut select_conversations_stmt = tx.prepare(
        "SELECT DISTINCT conversation_rowid FROM conversation_members WHERE user_rowid = ?1",
    )?;
    let conversation_rowids = select_conversations_stmt.query_map(params![user_rowid], |row| {
        row.get::<_, ConversationRowID>(0)
    })?;

    for conversation_rowid in conversation_rowids {
        let conversation_rowid = conversation_rowid?;
        delete_conversation(tx, conversation_rowid)?;
    }

    let (user_profile_rowid, identity_ed25519_public_key_rowid, identity_ed25519_private_key_rowid, remote_endpoint_ed25519_public_key_rowid, remote_endpoint_x25519_private_key_rowid, local_endpoint_ed25519_private_key_rowid, local_endpoint_x25519_public_key_rowid) = tx.query_one("DELETE FROM users WHERE rowid = ?1 RETURNING user_profile_rowid, identity_ed25519_public_key_rowid, identity_ed25519_private_key_rowid, remote_endpoint_ed25519_public_key_rowid, remote_endpoint_x25519_private_key_rowid, local_endpoint_ed25519_private_key_rowid, local_endpoint_x25519_public_key_rowid", params![user_rowid], |row| Ok((
                row.get::<_, UserProfileRowID>(0)?,
                row.get::<_, Ed25519PublicKeyRowID>(1)?,
                row.get::<_, Option<Ed25519PrivateKeyRowID>>(2)?,
                row.get::<_, Option<Ed25519PublicKeyRowID>>(3)?,
                row.get::<_, Option<X25519PrivateKeyRowID>>(4)?,
                row.get::<_, Option<Ed25519PrivateKeyRowID>>(5)?,
                row.get::<_, Option<X25519PublicKeyRowID>>(6)?,
            )))?;

    delete_user_profile(tx, user_profile_rowid)?;
    delete_ed25519_public_key(tx, identity_ed25519_public_key_rowid)?;
    if let Some(identity_ed25519_private_key_rowid) = identity_ed25519_private_key_rowid {
        delete_ed25519_private_key(tx, identity_ed25519_private_key_rowid)?;
    }
    if let Some(remote_endpoint_ed25519_public_key_rowid) = remote_endpoint_ed25519_public_key_rowid
    {
        delete_ed25519_public_key(tx, remote_endpoint_ed25519_public_key_rowid)?;
    }
    if let Some(remote_endpoint_x25519_private_key_rowid) = remote_endpoint_x25519_private_key_rowid
    {
        delete_x25519_private_key(tx, remote_endpoint_x25519_private_key_rowid)?;
    }
    if let Some(local_endpoint_ed25519_private_key_rowid) = local_endpoint_ed25519_private_key_rowid
    {
        delete_ed25519_private_key(tx, local_endpoint_ed25519_private_key_rowid)?;
    }
    if let Some(local_endpoint_x25519_public_key_rowid) = local_endpoint_x25519_public_key_rowid {
        delete_x25519_public_key(tx, local_endpoint_x25519_public_key_rowid)?;
    }
    Ok(())
}

pub(crate) fn delete_conversation(
    tx: &Transaction<'_>,
    conversation_handle: ConversationRowID,
) -> Result<(), Error> {
    let conversation_rowid = conversation_handle;

    // get and delete this conversation's conversation_key and delete the conversation
    let conversation_key_rowid = tx.query_one(
        "SELECT conversation_key_rowid FROM conversations WHERE rowid = ?1",
        params![conversation_rowid],
        |row| row.get::<_, Sha256HashRowID>(0),
    )?;

    // and delete all of the conversation members
    let _count = tx.execute(
        "DELETE FROM conversation_members WHERE conversation_rowid = ?1",
        params![conversation_rowid],
    )?;

    // delete all of the conversation's messages and return foreign keys
    let mut delete_messages_stmt = tx.prepare(
        "DELETE FROM message_records WHERE conversation_rowid = ?1 RETURNING message_content_rowid, signature_rowid")?;
    let message_record_foreign_keys_it =
        delete_messages_stmt.query_map(params![conversation_key_rowid], |row| {
            Ok((
                row.get::<_, MessageContentRowID>(0)?,
                row.get::<_, Ed25519SignatureRowID>(1)?,
            ))
        })?;

    // delete referenced message_contents and ed25519_signature
    for message_record_foreign_keys in message_record_foreign_keys_it {
        let (message_content_rowid, signature_rowid) = message_record_foreign_keys?;
        delete_message_content(tx, message_content_rowid)?;
        delete_ed25519_signature(tx, signature_rowid)?;
    }

    tx.execute(
        "DELETE FROM conversations WHERE rowid = ?1",
        params![conversation_rowid],
    )?;
    delete_sha256_hash(tx, conversation_key_rowid)?;

    Ok(())
}

fn delete_message_content(
    tx: &Transaction<'_>,
    message_content_rowid: MessageContentRowID,
) -> Result<(), Error> {
    let (salt_rowid, tombstone_message_rowid, text_message_rowid, file_share_message_rowid) = tx.query_one("DELETE FROM message_contents WHERE rowid = ?1 RETURNING salt_rowid, tombstone_message_rowid, text_message_rowid, file_share_message_rowid", params![message_content_rowid], |row| Ok((
            row.get::<_, SaltRowID>(0)?,
            row.get::<_, Option<TombstoneMessageRowID>>(1)?,
            row.get::<_, Option<TextMessageRowID>>(2)?,
            row.get::<_, Option<FileShareMessageRowID>>(3)?,
        )))?;

    delete_salt(tx, salt_rowid)?;
    if let Some(tombstone_message_rowid) = tombstone_message_rowid {
        delete_tombstone_message(tx, tombstone_message_rowid)?;
    }

    if let Some(text_message_rowid) = text_message_rowid {
        delete_text_message(tx, text_message_rowid)?;
    }

    if let Some(file_share_message_rowid) = file_share_message_rowid {
        delete_file_share_message(tx, file_share_message_rowid)?;
    }

    Ok(())
}

fn delete_tombstone_message(
    tx: &Transaction<'_>,
    tombstone_message_rowid: TombstoneMessageRowID,
) -> Result<(), Error> {
    let (original_message_content_hash_rowid, original_message_record_signature_rowid) = tx.query_one("DELETE FROM tombstone_messages WHERE rowid = ?1 RETURNING original_message_content_hash_rowid, original_message_record_signature_rowid", params![tombstone_message_rowid], |row| Ok((
            row.get::<_, Sha256HashRowID>(0)?,
            row.get::<_, Ed25519SignatureRowID>(1)?,
        )))?;

    delete_sha256_hash(tx, original_message_content_hash_rowid)?;
    delete_ed25519_signature(tx, original_message_record_signature_rowid)?;

    Ok(())
}

fn delete_text_message(
    tx: &Transaction<'_>,
    text_message_rowid: TextMessageRowID,
) -> Result<(), Error> {
    let _count = tx.execute(
        "DELETE FROM text_messages WHERE rowid = ?1",
        params![text_message_rowid],
    )?;

    Ok(())
}

fn delete_file_share_message(
    tx: &Transaction<'_>,
    file_share_message_rowid: FileShareMessageRowID,
) -> Result<(), Error> {
    let (file_data_salt_rowid, file_data_hash_rowid) = tx.query_one("DELETE FROM file_share_messages WHERE rowid = ?1 RETURNING file_data_salt_rowid, file_data_hash_rowid", params![file_share_message_rowid], |row| Ok((
            row.get::<_, SaltRowID>(0)?,
            row.get::<_, Sha256HashRowID>(1)?,
        )))?;

    delete_salt(tx, file_data_salt_rowid)?;
    delete_sha256_hash(tx, file_data_hash_rowid)?;

    Ok(())
}

fn delete_salt(tx: &Transaction<'_>, salt_rowid: SaltRowID) -> Result<(), Error> {
    let _count = tx.execute("DELETE FROM salts WHERE rowid = ?1", params![salt_rowid])?;
    Ok(())
}

fn delete_sha256_hash(
    tx: &Transaction<'_>,
    sha256_hash_rowid: Sha256HashRowID,
) -> Result<(), Error> {
    let _count = tx.execute(
        "DELETE FROM sha256_hashes WHERE rowid = ?1",
        params![sha256_hash_rowid],
    )?;
    Ok(())
}

fn delete_ed25519_private_key(
    tx: &Transaction<'_>,
    ed25519_private_key_rowid: Ed25519PrivateKeyRowID,
) -> Result<(), Error> {
    let _count = tx.execute(
        "DELETE FROM ed25519_private_keys WHERE rowid = ?1",
        params![ed25519_private_key_rowid],
    )?;
    Ok(())
}

fn delete_ed25519_public_key(
    tx: &Transaction<'_>,
    ed25519_public_key_rowid: Ed25519PublicKeyRowID,
) -> Result<(), Error> {
    let _count = tx.execute(
        "DELETE FROM ed25519_public_keys WHERE rowid = ?1",
        params![ed25519_public_key_rowid],
    )?;
    Ok(())
}

fn delete_ed25519_signature(
    tx: &Transaction<'_>,
    ed25519_signature_rowid: Ed25519SignatureRowID,
) -> Result<(), Error> {
    let _count = tx.execute(
        "DELETE FROM ed25519_signatures WHERE rowid = ?1",
        params![ed25519_signature_rowid],
    )?;
    Ok(())
}

fn delete_x25519_private_key(
    tx: &Transaction<'_>,
    x25519_private_key_rowid: X25519PrivateKeyRowID,
) -> Result<(), Error> {
    let _count = tx.execute(
        "DELETE FROM x25519_private_keys WHERE rowid = ?1",
        params![x25519_private_key_rowid],
    )?;
    Ok(())
}

fn delete_x25519_public_key(
    tx: &Transaction<'_>,
    x25519_public_key_rowid: X25519PublicKeyRowID,
) -> Result<(), Error> {
    let _count = tx.execute(
        "DELETE FROM x25519_public_keys WHERE rowid = ?1",
        params![x25519_public_key_rowid],
    )?;
    Ok(())
}
