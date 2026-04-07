pub mod payload;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("could not convert '{0}' to type {1}")]
    TypeConversionFailed(String, &'static str),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    // rand_core failure
    #[error(transparent)]
    RandOsError(#[from] rand_core::OsError),

    #[error(transparent)]
    TryFromIntError(#[from] std::num::TryFromIntError),

    #[error("not implemented")]
    NotImplemented,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConversationType {
    EphemeralDirectMessage,
    PersistentDirectMessage,
}

impl From<ConversationType> for i64 {
    fn from(value: ConversationType) -> i64 {
        match value {
            ConversationType::EphemeralDirectMessage => 1i64,
            ConversationType::PersistentDirectMessage => 2i64,
        }
    }
}

impl TryFrom<i64> for ConversationType {
    type Error = Error;
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            1i64 => Ok(ConversationType::EphemeralDirectMessage),
            2i64 => Ok(ConversationType::PersistentDirectMessage),
            _ => Err(Error::TypeConversionFailed(
                format!("{value}"),
                "ConversationType",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MessageType {
    Tombstone,
    Text,
    FileShare,
    Unknown(i64),
}

impl From<MessageType> for i64 {
    fn from(value: MessageType) -> i64 {
        match value {
            MessageType::Tombstone => 0i64,
            MessageType::Text => 1i64,
            MessageType::FileShare => 2i64,
            MessageType::Unknown(val) => val,
        }
    }
}

impl From<i64> for MessageType {
    fn from(value: i64) -> Self {
        match value {
            0i64 => MessageType::Tombstone,
            1i64 => MessageType::Text,
            2i64 => MessageType::FileShare,
            val => MessageType::Unknown(val),
        }
    }
}

#[cfg(feature = "rusqlite-traits")]
impl rusqlite::types::ToSql for MessageType {
    fn to_sql(&self) -> Result<rusqlite::types::ToSqlOutput<'_>, rusqlite::Error> {
        let val = i64::from(*self);
        Ok(val.into())
    }
}

#[cfg(feature = "rusqlite-traits")]
impl rusqlite::types::FromSql for MessageType {
    fn column_result(
        value: rusqlite::types::ValueRef<'_>,
    ) -> Result<Self, rusqlite::types::FromSqlError> {
        let value = i64::column_result(value)?;
        Ok(MessageType::from(value))
    }
}

//
// RecordSequence
//

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RecordSequence(pub i64);
#[cfg(feature = "rusqlite-traits")]
impl rusqlite::types::ToSql for RecordSequence {
    fn to_sql(&self) -> Result<rusqlite::types::ToSqlOutput<'_>, rusqlite::Error> {
        let val = self.0;
        Ok(val.into())
    }
}

#[cfg(feature = "rusqlite-traits")]
impl rusqlite::types::FromSql for RecordSequence {
    fn column_result(
        value: rusqlite::types::ValueRef<'_>,
    ) -> Result<Self, rusqlite::types::FromSqlError> {
        let value = i64::column_result(value)?;
        Ok(RecordSequence(value))
    }
}

//
// MessageSequence
//

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MessageSequence(pub i64);
#[cfg(feature = "rusqlite-traits")]
impl rusqlite::types::ToSql for MessageSequence {
    fn to_sql(&self) -> Result<rusqlite::types::ToSqlOutput<'_>, rusqlite::Error> {
        let val = self.0;
        Ok(val.into())
    }
}

#[cfg(feature = "rusqlite-traits")]
impl rusqlite::types::FromSql for MessageSequence {
    fn column_result(
        value: rusqlite::types::ValueRef<'_>,
    ) -> Result<Self, rusqlite::types::FromSqlError> {
        let value = i64::column_result(value)?;
        Ok(MessageSequence(value))
    }
}

//
// FileSize
//

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FileSize(pub i64);
#[cfg(feature = "rusqlite-traits")]
impl rusqlite::types::ToSql for FileSize {
    fn to_sql(&self) -> Result<rusqlite::types::ToSqlOutput<'_>, rusqlite::Error> {
        let val = self.0;
        Ok(val.into())
    }
}

#[cfg(feature = "rusqlite-traits")]
impl rusqlite::types::FromSql for FileSize {
    fn column_result(
        value: rusqlite::types::ValueRef<'_>,
    ) -> Result<Self, rusqlite::types::FromSqlError> {
        let value = i64::column_result(value)?;
        Ok(FileSize(value))
    }
}

//
// Timestamp
//

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Timestamp {
    pub(crate) millis_since_unix_epoch: i64,
}

impl From<Timestamp> for time::UtcDateTime {
    fn from(timestamp: Timestamp) -> Self {
        use time::ext::NumericalDuration;
        time::UtcDateTime::UNIX_EPOCH + timestamp.millis_since_unix_epoch.milliseconds()
    }
}
impl TryFrom<time::UtcDateTime> for Timestamp {
    type Error = Error;
    fn try_from(utc_datetime: time::UtcDateTime) -> Result<Self, Error> {
        let duration_since_unix_epoch = utc_datetime - time::UtcDateTime::UNIX_EPOCH;
        let millis_since_unix_epoch = duration_since_unix_epoch.whole_milliseconds();
        let millis_since_unix_epoch = i64::try_from(millis_since_unix_epoch)?;
        Ok(Timestamp {
            millis_since_unix_epoch,
        })
    }
}

#[cfg(feature = "rusqlite-traits")]
impl rusqlite::types::ToSql for Timestamp {
    fn to_sql(&self) -> Result<rusqlite::types::ToSqlOutput<'_>, rusqlite::Error> {
        let val = self.millis_since_unix_epoch;
        Ok(val.into())
    }
}

#[cfg(feature = "rusqlite-traits")]
impl rusqlite::types::FromSql for Timestamp {
    fn column_result(
        value: rusqlite::types::ValueRef<'_>,
    ) -> Result<Self, rusqlite::types::FromSqlError> {
        let millis_since_unix_epoch = i64::column_result(value)?;
        Ok(Self {
            millis_since_unix_epoch,
        })
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let utc_datetime = time::UtcDateTime::from(*self);
        utc_datetime.fmt(f)
    }
}

//
// MessageContent
//

#[derive(Debug, PartialEq)]
pub enum MessageContentData {
    Tombstone(TombstoneData),
    Text {
        text: String,
    },
    FileShare {
        file_data_salt: Salt,
        file_size: FileSize,
        file_data_hash: Sha256Sum,
        file_path: Option<std::path::PathBuf>,
    },
}

#[derive(Debug, PartialEq)]
pub struct TombstoneData {
    pub original_message_content_hash: Sha256Sum,
    pub original_message_record_signature: tor_interface::tor_crypto::Ed25519Signature,
}

//
// Salt
//
#[derive(Clone, Debug, PartialEq)]
pub struct Salt(pub [u8; Self::BYTES]);
impl Salt {
    pub const BYTES: usize = 32;

    pub fn generate() -> Result<Self, Error> {
        use rand::{rngs::OsRng, TryRngCore};

        let mut salt: [u8; Self::BYTES] = Default::default();
        OsRng.try_fill_bytes(&mut salt)?;
        Ok(Self(salt))
    }
}

//
// Sha256Sum
//

#[derive(Clone, Debug, PartialEq)]
pub struct Sha256Sum(pub [u8; Self::BYTES]);
impl Sha256Sum {
    pub const BYTES: usize = 32;
}
