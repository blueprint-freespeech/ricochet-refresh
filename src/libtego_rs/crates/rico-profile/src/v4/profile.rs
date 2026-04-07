// std
use std::boxed::Box;
use std::collections::BTreeSet;

// extern
use rusqlite::{Connection, OpenFlags};
use time::UtcDateTime;
use tor_interface::tor_crypto::{
    Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature, X25519PrivateKey, X25519PublicKey,
};

// internal
#[cfg(feature = "v3-profile")]
use crate::v3;
use crate::v4::db;
use crate::v4::error::Error;

//
// Profile: semantic version of the schema of the databases
//

#[derive(Debug, PartialEq)]
pub struct Version {
    major: i64,
    minor: i64,
    patch: i64,
}

impl Version {
    pub const LATEST: Version = Version {
        major: 0i64,
        minor: 1i64,
        patch: 0i64,
    };
}

impl Version {
    pub(crate) const fn new(major: i64, minor: i64, patch: i64) -> Result<Self, Error> {
        if major < 0 || minor < 0 || patch < 0 {
            Err(Error::InvalidSemanticVersion(major, minor, patch))
        } else {
            Ok(Self {
                major,
                minor,
                patch,
            })
        }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{0}.{1}.{2}", self.major, self.minor, self.patch)
    }
}

//
// Profile and associated types
//

pub struct Profile {
    pub(crate) conn: Connection,
}

impl Profile {
    pub fn new(path: &std::path::Path, password: &str) -> Result<Profile, Error> {
        let open_flags: OpenFlags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;

        let conn =
            Connection::open_with_flags(path, open_flags).map_err(Error::DatabaseOpenFailure)?;

        // set the our password
        db::set_password(&conn, password)?;

        // create tabless
        db::create_tables(&conn)?;

        // insert the version row
        let version = Version::LATEST;
        db::insert_db_version(&conn, version.major, version.minor, version.patch)?;
        std::mem::drop(conn);

        Self::open(path, password)
    }

    #[cfg(feature = "v3-profile")]
    pub fn new_from_v3_profile(
        v3_profile: v3::profile::Profile,
        nickname: &str,
        path: &std::path::Path,
        password: &str,
    ) -> Result<Profile, Error> {
        // todo, write profile to a temp file and move after successful creation
        let mut profile = Profile::new(path, password)?;
        let tx = profile
            .conn
            .transaction()
            .map_err(Error::TransactionCreateFailure)?;
        //
        // Add our host user
        //

        let host_identity_ed25519_private_key = v3_profile.private_key;
        let nickname = nickname.to_string();

        let host_identity_ed25519_public_key =
            Ed25519PublicKey::from_private_key(&host_identity_ed25519_private_key);
        let host_identity_ed25519_private_key = Some(host_identity_ed25519_private_key);

        let host_user = User {
            user_type: UserType::Owner,
            user_profile: UserProfile {
                nickname,
                pet_name: None,
                pronouns: None,
                avatar: None,
                status: None,
                description: None,
            },
            identity_ed25519_public_key: host_identity_ed25519_public_key.clone(),
            identity_ed25519_private_key: host_identity_ed25519_private_key,
            remote_endpoint_ed25519_public_key: None,
            remote_endpoint_x25519_private_key: None,
            local_endpoint_ed25519_private_key: None,
            local_endpoint_x25519_public_key: None,
        };

        let host_user_handle = db::insert_user(&tx, &host_user)?;

        for (service_id, user) in v3_profile.users {
            // map legacy UserType to v4 UserType
            let user_type = user.user_type;
            let user_type = match user_type {
                v3::profile::UserType::Allowed => UserType::Allowed,
                v3::profile::UserType::Requesting | v3::profile::UserType::Pending => {
                    UserType::Requesting
                }
                v3::profile::UserType::Rejected => UserType::Rejected,
                v3::profile::UserType::Blocked => UserType::Blocked,
            };
            let nickname = service_id.to_string();
            let pet_name = Some(user.nickname);

            // map legacy user types to new user types
            let identity_ed25519_public_key =
                Ed25519PublicKey::from_service_id(&service_id).unwrap();

            let user = User {
                user_type,
                user_profile: UserProfile {
                    nickname,
                    pet_name,
                    pronouns: None,
                    avatar: None,
                    status: None,
                    description: None,
                },
                identity_ed25519_public_key: identity_ed25519_public_key.clone(),
                identity_ed25519_private_key: None,
                remote_endpoint_ed25519_public_key: None,
                remote_endpoint_x25519_private_key: None,
                local_endpoint_ed25519_private_key: None,
                local_endpoint_x25519_public_key: None,
            };

            // insert user
            let user_handle = db::insert_user(&tx, &user)?;

            //
            // insert default conversations
            //
            let conversation_members_public_keys: BTreeSet<Ed25519PublicKey> = [
                host_identity_ed25519_public_key.clone(),
                identity_ed25519_public_key,
            ]
            .into();

            // ephemeral conversation
            let ephemeral_conversation_key = rico_protocol::v4::payload::conversation_key(
                ConversationType::EphemeralDirectMessage,
                &conversation_members_public_keys,
            );
            let ephemeral_conversation = Conversation {
                conversation_type: ConversationType::EphemeralDirectMessage,
                conversation_members: [host_user_handle, user_handle].into(),
                conversation_key: ephemeral_conversation_key,
            };
            db::insert_conversation(&tx, &ephemeral_conversation)?;

            // persistent conversation
            let persistent_conversation_key = rico_protocol::v4::payload::conversation_key(
                ConversationType::PersistentDirectMessage,
                &conversation_members_public_keys,
            );
            let persistent_conversation = Conversation {
                conversation_type: ConversationType::PersistentDirectMessage,
                conversation_members: [host_user_handle, user_handle].into(),
                conversation_key: persistent_conversation_key,
            };
            db::insert_conversation(&tx, &persistent_conversation)?;
        }
        tx.commit().map_err(Error::TransactionCommitFailure)?;

        Ok(profile)
    }

    pub fn open(path: &std::path::Path, password: &str) -> Result<Profile, Error> {
        let open_flags: OpenFlags =
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;

        let conn =
            Connection::open_with_flags(path, open_flags).map_err(Error::DatabaseOpenFailure)?;

        // set password
        db::set_password(&conn, password)?;

        let profile = Profile { conn };

        match profile.get_version()? {
            Version::LATEST => Ok(profile),
            // todo: we can add migration functions here when the version number needs to be bumped
            version => Err(Error::UnknownProfileVersion(version)),
        }
    }

    //
    // Public read/write methods
    //

    //
    // Version
    //
    pub fn get_version(&self) -> Result<Version, Error> {
        db::select_newest_db_version(&self.conn)
    }

    //
    // Conversation
    //

    pub fn add_conversation(
        &mut self,
        conversation: &Conversation,
    ) -> Result<ConversationHandle, Error> {
        let tx = self.conn.transaction()?;
        let conversation_handle = db::insert_conversation(&tx, conversation)?;
        tx.commit()?;
        Ok(conversation_handle)
    }

    pub fn get_conversations(&self) -> Result<Vec<(Conversation, ConversationHandle)>, Error> {
        db::select_all_conversations(&self.conn)
    }

    pub fn remove_conversation(
        &mut self,
        conversation_handle: ConversationHandle,
    ) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        db::delete_conversation(&tx, conversation_handle)?;
        tx.commit()?;
        Ok(())
    }

    //
    // Profile
    //

    pub fn get_user_profile(&self, user_handle: UserHandle) -> Result<UserProfile, Error> {
        db::select_user_profile_by_user_handle(&self.conn, user_handle)
    }

    pub fn set_user_profile(
        &mut self,
        user_handle: UserHandle,
        user_profile: &UserProfile,
    ) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        db::update_user_profile(&tx, user_handle, user_profile)?;
        tx.commit()?;
        Ok(())
    }

    //
    // User
    //

    pub fn add_user(&mut self, user: &User) -> Result<UserHandle, Error> {
        let tx = self.conn.transaction()?;
        let user_handle = db::insert_user(&tx, user)?;
        tx.commit()?;
        Ok(user_handle)
    }

    pub fn get_users(&self) -> Result<Vec<(User, UserHandle)>, Error> {
        db::select_all_users(&self.conn)
    }

    pub fn remove_user(&mut self, user_handle: UserHandle) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        db::delete_user(&tx, user_handle)?;
        tx.commit()?;
        Ok(())
    }

    pub fn set_user_remote_endpoint_keys(
        &mut self,
        user_handle: UserHandle,
        remote_endpoint_ed25519_public_key: &Ed25519PublicKey,
        remote_endpoint_x25519_private_key: &X25519PrivateKey,
    ) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        db::update_remote_endpoint_keys(
            &tx,
            user_handle,
            remote_endpoint_ed25519_public_key,
            remote_endpoint_x25519_private_key,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn set_user_local_endpoint_keys(
        &mut self,
        user_handle: UserHandle,
        local_endpoint_ed25519_private_key: &Ed25519PrivateKey,
        local_endpoint_x25519_public_key: &X25519PublicKey,
    ) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        db::update_local_endpoint_keys(
            &tx,
            user_handle,
            local_endpoint_ed25519_private_key,
            local_endpoint_x25519_public_key,
        )?;
        tx.commit()?;
        Ok(())
    }

    //
    // Messages
    //

    /// Add a single message record
    pub fn add_message_record(
        &mut self,
        message_record: &MessageRecord,
    ) -> Result<MessageRecordHandle, Error> {
        let tx = self.conn.transaction()?;
        let message_record_handle = db::insert_message_record(&tx, message_record)?;
        tx.commit()?;
        Ok(message_record_handle)
    }

    /// Retrieve a single message record
    pub fn get_message_record(
        &self,
        message_record_handle: MessageRecordHandle,
    ) -> Result<MessageRecord, Error> {
        db::select_message_record(&self.conn, message_record_handle)
    }

    /// Find the `MessageRecordHandle` of an entry with a particular `(Conversationhandle, UserHandle, RecordSequence)` tuple
    pub fn get_message_record_handle(
        &self,
        conversation_handle: ConversationHandle,
        user_handle: UserHandle,
        record_sequence: RecordSequence,
    ) -> Result<MessageRecordHandle, Error> {
        db::select_message_record_rowid(
            &self.conn,
            conversation_handle,
            user_handle,
            record_sequence,
        )
    }

    /// Replace a `MessageRecord` (e.g. for tombstoning)
    pub fn tombstone_message_record(
        &mut self,
        message_record_handle: MessageRecordHandle,
        tombstone_message_content_salt: &Salt,
        original_message_content_hash: &Sha256Sum,
        new_message_record_signature: &Ed25519Signature,
    ) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        db::tombstone_message_record(
            &tx,
            message_record_handle,
            tombstone_message_content_salt,
            original_message_content_hash,
            new_message_record_signature,
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Get `MessageRecord`s older than a particular time from a conversation
    pub fn get_message_records_from_conversation(
        &self,
        conversation: ConversationHandle,
        older_than_creation_timestamp: Option<UtcDateTime>,
        limit: Option<u32>,
    ) -> Result<Vec<MessageRecord>, Error> {
        db::select_message_records_from_conversation(
            &self.conn,
            conversation,
            older_than_creation_timestamp,
            limit,
        )
    }

    /// Get a particular user's messages from a conversation
    pub fn get_message_records_from_conversation_by_user(
        &self,
        conversation: ConversationHandle,
        author: UserHandle,
        older_than_record_sequence: Option<RecordSequence>,
        limit: Option<u32>,
    ) -> Result<Vec<MessageRecord>, Error> {
        db::select_message_records_from_conversation_by_user(
            &self.conn,
            conversation,
            author,
            older_than_record_sequence,
            limit,
        )
    }

    /// Get the most recent `RecordSequence` for a given user in a given conversation
    pub fn get_newest_record_sequence_in_converation(
        &self,
        conversation: ConversationHandle,
        author: UserHandle,
    ) -> Result<RecordSequence, Error> {
        db::select_newest_record_sequence_in_conversation_by_user(&self.conn, conversation, author)
    }
}

//
// UserProfile
//
pub type UserProfileHandle = db::UserProfileRowID;
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub struct UserProfile {
    pub nickname: String,
    pub pet_name: Option<String>,
    pub pronouns: Option<String>,
    pub avatar: Option<Avatar>,
    pub status: Option<String>,
    pub description: Option<String>,
}

// Avatar
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub struct Avatar {
    // 256x256 8-bit channel RGBA image in row-major order
    pub rgba_data: Box<[u8; Self::BYTES]>,
}

impl Avatar {
    pub const WIDTH: usize = 256;
    pub const HEIGHT: usize = 256;
    pub const CHANNELS: usize = 4;
    pub const BYTES: usize = Self::WIDTH * Self::HEIGHT * Self::CHANNELS;
}

//
// User
//
pub type UserHandle = db::UserRowID;
#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
pub struct User {
    pub user_type: UserType,
    pub user_profile: UserProfile,
    pub identity_ed25519_public_key: Ed25519PublicKey,
    pub identity_ed25519_private_key: Option<Ed25519PrivateKey>,
    pub remote_endpoint_ed25519_public_key: Option<Ed25519PublicKey>,
    pub remote_endpoint_x25519_private_key: Option<X25519PrivateKey>,
    pub local_endpoint_ed25519_private_key: Option<Ed25519PrivateKey>,
    pub local_endpoint_x25519_public_key: Option<X25519PublicKey>,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(Clone, Copy, Debug)]
pub enum UserType {
    Owner,
    Allowed,
    Requesting,
    Rejected,
    Blocked,
}

impl From<UserType> for i64 {
    fn from(value: UserType) -> i64 {
        match value {
            UserType::Owner => 0i64,
            UserType::Allowed => 1i64,
            UserType::Requesting => 2i64,
            UserType::Rejected => 3i64,
            UserType::Blocked => 4i64,
        }
    }
}

impl TryFrom<i64> for UserType {
    type Error = Error;
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0i64 => Ok(UserType::Owner),
            1i64 => Ok(UserType::Allowed),
            2i64 => Ok(UserType::Requesting),
            3i64 => Ok(UserType::Rejected),
            4i64 => Ok(UserType::Blocked),
            _ => Err(Error::TypeConversionFailed(format!("{value}"), "UserType")),
        }
    }
}

impl rusqlite::ToSql for UserType {
    fn to_sql(&self) -> Result<rusqlite::types::ToSqlOutput<'_>, rusqlite::Error> {
        let value: i64 = (*self).into();
        Ok(value.into())
    }
}

impl rusqlite::types::FromSql for UserType {
    fn column_result(
        value: rusqlite::types::ValueRef<'_>,
    ) -> Result<Self, rusqlite::types::FromSqlError> {
        let value = i64::column_result(value)?;
        match UserType::try_from(value) {
            Ok(value) => Ok(value),
            Err(_) => Err(rusqlite::types::FromSqlError::OutOfRange(value)),
        }
    }
}

//
// Conversation
//
pub type ConversationHandle = db::ConversationRowID;
pub struct Conversation {
    pub conversation_type: ConversationType,
    pub conversation_members: BTreeSet<UserHandle>,
    pub conversation_key: Sha256Sum,
}

pub use rico_protocol::v4::ConversationType;

// Messages

pub type MessageRecordHandle = db::MessageRecordRowID;
pub use rico_protocol::v4::MessageSequence;
pub use rico_protocol::v4::RecordSequence;
pub use rico_protocol::v4::Timestamp;
#[derive(Debug, PartialEq)]
pub struct MessageRecord {
    pub conversation_handle: ConversationHandle,
    pub user_handle: UserHandle,
    pub record_sequence: RecordSequence,
    pub message_sequence: MessageSequence,
    pub create_timestamp: Timestamp,
    pub message_content: MessageContent,
    pub signature: Ed25519Signature,
}

#[derive(Debug, PartialEq)]
pub struct MessageContent {
    pub salt: Salt,
    pub data: MessageContentData,
}

pub use rico_protocol::v4::FileSize;
pub use rico_protocol::v4::MessageContentData;
pub use rico_protocol::v4::TombstoneData;

//
// Salt
//

pub use rico_protocol::v4::Salt;
pub use rico_protocol::v4::Sha256Sum;

#[cfg(feature = "test-features")]
pub mod test {
    use super::*;

    pub fn create_test_profile(name: &str) -> anyhow::Result<Profile> {
        let mut path = std::env::temp_dir();
        path.push(name);
        if std::path::Path::exists(&path) {
            std::fs::remove_file(&path)?;
        }
        let profile = Profile::new(&path, "hunter42")?;
        println!("created profile: {path:?}");
        Ok(profile)
    }

    pub fn generate_test_keys() -> (
        Ed25519PublicKey,
        Ed25519PrivateKey,
        Ed25519PublicKey,
        X25519PrivateKey,
        Ed25519PrivateKey,
        X25519PublicKey,
    ) {
        let identity_ed25519_private_key = Ed25519PrivateKey::generate();
        let identity_ed25519_public_key =
            Ed25519PublicKey::from_private_key(&identity_ed25519_private_key);

        let remote_endpoint_ed25519_public_key =
            Ed25519PublicKey::from_private_key(&Ed25519PrivateKey::generate());
        let remote_endpoint_x25519_private_key = X25519PrivateKey::generate();

        let local_endpoint_ed25519_private_key = Ed25519PrivateKey::generate();
        let local_endpoint_x25519_public_key =
            X25519PublicKey::from_private_key(&X25519PrivateKey::generate());

        (
            identity_ed25519_public_key,
            identity_ed25519_private_key,
            remote_endpoint_ed25519_public_key,
            remote_endpoint_x25519_private_key,
            local_endpoint_ed25519_private_key,
            local_endpoint_x25519_public_key,
        )
    }

    #[test]
    fn test_add_get_remove_user() -> anyhow::Result<()> {
        let mut profile = create_test_profile("test_add_get_remove_user.ricochet-profile")?;

        // Test: add_user() - Add Owner user (must have identity_ed25519_private_key)
        let (
            identity_ed25519_pub1,
            identity_ed25519_priv1,
            _remote_endpoint_ed25519_pub1,
            _remote_endpoint_x25519_priv1,
            _local_endpoint_ed25519_priv1,
            _local_endpoint_x25519_pub1,
        ) = generate_test_keys();

        let user1 = User {
            user_type: UserType::Owner,
            user_profile: UserProfile {
                nickname: "alice".to_string(),
                pet_name: Some("Alice Wonder".to_string()),
                pronouns: Some("she/her".to_string()),
                avatar: None,
                status: Some("Online".to_string()),
                description: Some("A test user".to_string()),
            },
            identity_ed25519_public_key: identity_ed25519_pub1.clone(),
            identity_ed25519_private_key: Some(identity_ed25519_priv1.clone()),
            remote_endpoint_ed25519_public_key: None,
            remote_endpoint_x25519_private_key: None,
            local_endpoint_ed25519_private_key: None,
            local_endpoint_x25519_public_key: None,
        };

        let user1_handle = profile.add_user(&user1)?;

        // Test: get_users() - Verify the user was added
        let users = profile.get_users()?;
        assert_eq!(users.len(), 1);
        let (retrieved_user, retrieved_handle) = &users[0];
        assert_eq!(*retrieved_handle, user1_handle, "Handle should match");
        assert_eq!(retrieved_user.user_type, user1.user_type,);
        assert_eq!(
            retrieved_user.user_profile.nickname,
            user1.user_profile.nickname,
        );
        assert_eq!(
            retrieved_user.user_profile.pet_name,
            user1.user_profile.pet_name,
        );
        assert_eq!(
            retrieved_user.user_profile.pronouns,
            user1.user_profile.pronouns,
        );
        assert_eq!(
            retrieved_user.user_profile.status,
            user1.user_profile.status,
        );
        assert_eq!(
            retrieved_user.user_profile.description,
            user1.user_profile.description,
        );

        // Test: add_user() - Add Allowed user (non-Owner: no identity_ed25519_private_key)
        let (
            identity_ed25519_pub2,
            _identity_ed25519_priv2,
            remote_endpoint_ed25519_pub2,
            remote_endpoint_x25519_priv2,
            _local_endpoint_ed25519_priv2,
            _local_endpoint_x25519_pub2,
        ) = generate_test_keys();

        let user2 = User {
            user_type: UserType::Allowed,
            user_profile: UserProfile {
                nickname: "bob".to_string(),
                pet_name: None,
                pronouns: None,
                avatar: None,
                status: None,
                description: None,
            },
            identity_ed25519_public_key: identity_ed25519_pub2.clone(),
            identity_ed25519_private_key: None,
            remote_endpoint_ed25519_public_key: Some(remote_endpoint_ed25519_pub2.clone()),
            remote_endpoint_x25519_private_key: Some(remote_endpoint_x25519_priv2.clone()),
            local_endpoint_ed25519_private_key: None,
            local_endpoint_x25519_public_key: None,
        };

        let user2_handle = profile.add_user(&user2)?;
        assert_ne!(user1_handle, user2_handle);

        // Test: get_users() - Verify both users are present
        let users = profile.get_users()?;
        assert_eq!(users.len(), 2);

        // Test: remove_user() - Remove the first user
        profile.remove_user(user1_handle)?;
        let users = profile.get_users()?;
        assert_eq!(users.len(), 1);
        let (remaining_user, remaining_handle) = &users[0];
        assert_eq!(*remaining_handle, user2_handle,);
        assert_eq!(remaining_user.user_profile.nickname, "bob",);

        // Test: remove_user() - Remove the second user
        profile.remove_user(user2_handle)?;
        let users = profile.get_users()?;
        assert_eq!(users.len(), 0);

        Ok(())
    }

    #[test]
    fn test_user_profile_management() -> anyhow::Result<()> {
        let mut profile = create_test_profile("test_user_profile_management.ricochet-profile")?;

        // Generate keys for the test user
        let (identity_ed25519_public_key, identity_ed25519_private_key, _, _, _, _) =
            generate_test_keys();

        // Create and add a user
        let user = User {
            user_type: UserType::Owner,
            user_profile: UserProfile {
                nickname: "alice".to_string(),
                pet_name: None,
                pronouns: None,
                avatar: None,
                status: None,
                description: None,
            },
            identity_ed25519_public_key: identity_ed25519_public_key.clone(),
            identity_ed25519_private_key: Some(identity_ed25519_private_key),
            remote_endpoint_ed25519_public_key: None,
            remote_endpoint_x25519_private_key: None,
            local_endpoint_ed25519_private_key: None,
            local_endpoint_x25519_public_key: None,
        };

        let user_handle = profile.add_user(&user)?;

        // Test: Retrieve user profile and verify initial state
        let retrieved_profile = profile.get_user_profile(user_handle)?;
        assert_eq!(retrieved_profile.nickname, "alice");
        assert_eq!(retrieved_profile.pet_name, None);
        assert_eq!(retrieved_profile.pronouns, None);
        assert_eq!(retrieved_profile.avatar, None);
        assert_eq!(retrieved_profile.status, None);
        assert_eq!(retrieved_profile.description, None);

        // Test: Update profile with all fields populated
        let updated_profile = UserProfile {
            nickname: "alice".to_string(),
            pet_name: Some("Ally".to_string()),
            pronouns: Some("she/her".to_string()),
            avatar: None, // Avatar creation is complex; test separately if needed
            status: Some("Available".to_string()),
            description: Some("Alice is a developer".to_string()),
        };

        profile.set_user_profile(user_handle, &updated_profile)?;

        // Verify the update persisted
        let retrieved_profile = profile.get_user_profile(user_handle)?;
        assert_eq!(retrieved_profile.nickname, "alice");
        assert_eq!(retrieved_profile.pet_name, Some("Ally".to_string()));
        assert_eq!(retrieved_profile.pronouns, Some("she/her".to_string()));
        assert_eq!(retrieved_profile.status, Some("Available".to_string()));
        assert_eq!(
            retrieved_profile.description,
            Some("Alice is a developer".to_string())
        );

        // Test: Update profile with cleared optional fields
        let cleared_profile = UserProfile {
            nickname: "alice".to_string(),
            pet_name: None,
            pronouns: None,
            avatar: None,
            status: None,
            description: None,
        };

        profile.set_user_profile(user_handle, &cleared_profile)?;

        // Verify optional fields were cleared
        let retrieved_profile = profile.get_user_profile(user_handle)?;
        assert_eq!(retrieved_profile.pet_name, None);
        assert_eq!(retrieved_profile.pronouns, None);
        assert_eq!(retrieved_profile.status, None);
        assert_eq!(retrieved_profile.description, None);

        // Test: Update only the nickname
        let nickname_only = UserProfile {
            nickname: "alice_v2".to_string(),
            pet_name: None,
            pronouns: None,
            avatar: None,
            status: None,
            description: None,
        };

        profile.set_user_profile(user_handle, &nickname_only)?;

        let retrieved_profile = profile.get_user_profile(user_handle)?;
        assert_eq!(retrieved_profile.nickname, "alice_v2");
        assert_eq!(retrieved_profile.pet_name, None);
        assert_eq!(retrieved_profile.pronouns, None);
        assert_eq!(retrieved_profile.status, None);
        assert_eq!(retrieved_profile.description, None);

        Ok(())
    }

    #[test]
    fn test_user_endpoint_keys() -> anyhow::Result<()> {
        let mut profile = create_test_profile("test_user_endpoint_keys.ricochet-profile")?;

        // Generate keys for the test user
        let (identity_ed25519_public_key, _, _, _, _, _) = generate_test_keys();

        // Create and add a user with no endpoint keys
        let user = User {
            user_type: UserType::Allowed,
            user_profile: UserProfile {
                nickname: "bob".to_string(),
                pet_name: None,
                pronouns: None,
                avatar: None,
                status: None,
                description: None,
            },
            identity_ed25519_public_key: identity_ed25519_public_key.clone(),
            identity_ed25519_private_key: None,
            remote_endpoint_ed25519_public_key: None,
            remote_endpoint_x25519_private_key: None,
            local_endpoint_ed25519_private_key: None,
            local_endpoint_x25519_public_key: None,
        };

        let user_handle = profile.add_user(&user)?;

        // Verify initial state: no endpoint keys
        let users = profile.get_users()?;
        let found_user = users
            .iter()
            .find(|(_, handle)| *handle == user_handle)
            .expect("User not found");

        assert!(found_user.0.remote_endpoint_ed25519_public_key.is_none());
        assert!(found_user.0.remote_endpoint_x25519_private_key.is_none());
        assert!(found_user.0.local_endpoint_ed25519_private_key.is_none());
        assert!(found_user.0.local_endpoint_x25519_public_key.is_none());

        // Test: Set remote endpoint keys
        let (_, _, remote_ed25519_public_key, remote_x25519_private_key, _, _) =
            generate_test_keys();

        profile.set_user_remote_endpoint_keys(
            user_handle,
            &remote_ed25519_public_key,
            &remote_x25519_private_key,
        )?;

        // Verify remote endpoint keys were persisted
        let users = profile.get_users()?;
        let found_user = users
            .iter()
            .find(|(_, handle)| *handle == user_handle)
            .expect("User not found");

        assert_eq!(
            found_user.0.remote_endpoint_ed25519_public_key,
            Some(remote_ed25519_public_key.clone())
        );
        assert_eq!(
            found_user.0.remote_endpoint_x25519_private_key,
            Some(remote_x25519_private_key.clone())
        );
        // Local endpoint keys should still be None
        assert!(found_user.0.local_endpoint_ed25519_private_key.is_none());
        assert!(found_user.0.local_endpoint_x25519_public_key.is_none());

        // Test: Set local endpoint keys
        let (_, _, _, _, local_ed25519_private_key, local_x25519_public_key) = generate_test_keys();

        profile.set_user_local_endpoint_keys(
            user_handle,
            &local_ed25519_private_key,
            &local_x25519_public_key,
        )?;

        // Verify local endpoint keys were persisted
        let users = profile.get_users()?;
        let found_user = users
            .iter()
            .find(|(_, handle)| *handle == user_handle)
            .expect("User not found");
        assert_eq!(
            found_user.0.local_endpoint_ed25519_private_key,
            Some(local_ed25519_private_key.clone())
        );
        assert_eq!(
            found_user.0.local_endpoint_x25519_public_key,
            Some(local_x25519_public_key.clone())
        );
        // Remote endpoint keys should still be set
        assert_eq!(
            found_user.0.remote_endpoint_ed25519_public_key,
            Some(remote_ed25519_public_key.clone())
        );
        assert_eq!(
            found_user.0.remote_endpoint_x25519_private_key,
            Some(remote_x25519_private_key.clone())
        );

        // Test: Update remote endpoint keys to new values
        let (_, _, remote_ed25519_public_key_v2, remote_x25519_private_key_v2, _, _) =
            generate_test_keys();

        profile.set_user_remote_endpoint_keys(
            user_handle,
            &remote_ed25519_public_key_v2,
            &remote_x25519_private_key_v2,
        )?;

        // Verify remote keys were updated
        let users = profile.get_users()?;
        let found_user = users
            .iter()
            .find(|(_, handle)| *handle == user_handle)
            .expect("User not found");

        assert_eq!(
            found_user.0.remote_endpoint_ed25519_public_key,
            Some(remote_ed25519_public_key_v2.clone())
        );
        assert_eq!(
            found_user.0.remote_endpoint_x25519_private_key,
            Some(remote_x25519_private_key_v2.clone())
        );
        // Local keys should remain unchanged
        assert_eq!(
            found_user.0.local_endpoint_ed25519_private_key,
            Some(local_ed25519_private_key.clone())
        );
        assert_eq!(
            found_user.0.local_endpoint_x25519_public_key,
            Some(local_x25519_public_key.clone())
        );

        // Test: Update local endpoint keys to new values
        let (_, _, _, _, local_ed25519_private_key_v2, local_x25519_public_key_v2) =
            generate_test_keys();

        profile.set_user_local_endpoint_keys(
            user_handle,
            &local_ed25519_private_key_v2,
            &local_x25519_public_key_v2,
        )?;

        // Verify local keys were updated
        let users = profile.get_users()?;
        let found_user = users
            .iter()
            .find(|(_, handle)| *handle == user_handle)
            .expect("User not found");

        assert_eq!(
            found_user.0.local_endpoint_ed25519_private_key,
            Some(local_ed25519_private_key_v2.clone())
        );
        assert_eq!(
            found_user.0.local_endpoint_x25519_public_key,
            Some(local_x25519_public_key_v2.clone())
        );
        // Remote keys should remain updated to v2
        assert_eq!(
            found_user.0.remote_endpoint_ed25519_public_key,
            Some(remote_ed25519_public_key_v2.clone())
        );
        assert_eq!(
            found_user.0.remote_endpoint_x25519_private_key,
            Some(remote_x25519_private_key_v2.clone())
        );
        Ok(())
    }

    #[test]
    fn test_conversation_lifecycle() -> anyhow::Result<()> {
        let mut profile = create_test_profile("test_conversation_lifecycle.ricochet-profile")?;

        // Generate keys for two test users
        let (identity_ed25519_public_key_alice, identity_ed25519_private_key_alice, _, _, _, _) =
            generate_test_keys();
        let (identity_ed25519_public_key_bob, _, _, _, _, _) = generate_test_keys();

        // Create and add two users
        let user_alice = User {
            user_type: UserType::Owner,
            user_profile: UserProfile {
                nickname: "alice".to_string(),
                pet_name: None,
                pronouns: None,
                avatar: None,
                status: None,
                description: None,
            },
            identity_ed25519_public_key: identity_ed25519_public_key_alice.clone(),
            identity_ed25519_private_key: Some(identity_ed25519_private_key_alice),
            remote_endpoint_ed25519_public_key: None,
            remote_endpoint_x25519_private_key: None,
            local_endpoint_ed25519_private_key: None,
            local_endpoint_x25519_public_key: None,
        };

        let user_bob = User {
            user_type: UserType::Allowed,
            user_profile: UserProfile {
                nickname: "bob".to_string(),
                pet_name: None,
                pronouns: None,
                avatar: None,
                status: None,
                description: None,
            },
            identity_ed25519_public_key: identity_ed25519_public_key_bob.clone(),
            identity_ed25519_private_key: None,
            remote_endpoint_ed25519_public_key: None,
            remote_endpoint_x25519_private_key: None,
            local_endpoint_ed25519_private_key: None,
            local_endpoint_x25519_public_key: None,
        };

        let alice_handle = profile.add_user(&user_alice)?;
        let bob_handle = profile.add_user(&user_bob)?;

        // Test: Retrieve conversations when empty
        let conversations = profile.get_conversations()?;
        assert!(conversations.is_empty());

        // Test: Create an ephemeral direct message conversation
        let conversation_members_ephemeral: BTreeSet<UserHandle> =
            [alice_handle, bob_handle].into();
        let conversation_members_public_keys: BTreeSet<Ed25519PublicKey> = [
            identity_ed25519_public_key_alice.clone(),
            identity_ed25519_public_key_bob.clone(),
        ]
        .into();

        let ephemeral_conversation_key = rico_protocol::v4::payload::conversation_key(
            ConversationType::EphemeralDirectMessage,
            &conversation_members_public_keys,
        );

        let ephemeral_conversation = Conversation {
            conversation_type: ConversationType::EphemeralDirectMessage,
            conversation_members: conversation_members_ephemeral.clone(),
            conversation_key: ephemeral_conversation_key.clone(),
        };

        let ephemeral_conversation_handle = profile.add_conversation(&ephemeral_conversation)?;

        // Verify ephemeral conversation was created
        let conversations = profile.get_conversations()?;
        assert_eq!(conversations.len(), 1);
        let (retrieved_conv, handle) = &conversations[0];
        assert_eq!(*handle, ephemeral_conversation_handle);
        assert_eq!(
            retrieved_conv.conversation_type,
            ConversationType::EphemeralDirectMessage
        );
        assert_eq!(
            retrieved_conv.conversation_members,
            conversation_members_ephemeral
        );
        assert_eq!(retrieved_conv.conversation_key, ephemeral_conversation_key);

        // Test: Create a persistent direct message conversation
        let persistent_conversation_key = rico_protocol::v4::payload::conversation_key(
            ConversationType::PersistentDirectMessage,
            &conversation_members_public_keys,
        );

        let persistent_conversation = Conversation {
            conversation_type: ConversationType::PersistentDirectMessage,
            conversation_members: conversation_members_ephemeral.clone(),
            conversation_key: persistent_conversation_key.clone(),
        };

        let persistent_conversation_handle = profile.add_conversation(&persistent_conversation)?;

        // Verify both conversations exist
        let conversations = profile.get_conversations()?;
        assert_eq!(conversations.len(), 2);

        let ephemeral_found = conversations
            .iter()
            .find(|(_, handle)| *handle == ephemeral_conversation_handle)
            .expect("Ephemeral conversation not found");
        assert_eq!(
            ephemeral_found.0.conversation_type,
            ConversationType::EphemeralDirectMessage
        );

        let persistent_found = conversations
            .iter()
            .find(|(_, handle)| *handle == persistent_conversation_handle)
            .expect("Persistent conversation not found");
        assert_eq!(
            persistent_found.0.conversation_type,
            ConversationType::PersistentDirectMessage
        );

        // Test: Remove ephemeral conversation
        profile.remove_conversation(ephemeral_conversation_handle)?;

        // Verify only persistent conversation remains
        let conversations = profile.get_conversations()?;
        assert_eq!(conversations.len(), 1);
        let (remaining_conv, handle) = &conversations[0];
        assert_eq!(*handle, persistent_conversation_handle);
        assert_eq!(
            remaining_conv.conversation_type,
            ConversationType::PersistentDirectMessage
        );

        // Test: Remove persistent conversation
        profile.remove_conversation(persistent_conversation_handle)?;

        // Verify all conversations are gone
        let conversations = profile.get_conversations()?;
        assert!(conversations.is_empty());

        // Test: Create multiple conversations with different member sets
        let (identity_ed25519_public_key_charlie, _, _, _, _, _) = generate_test_keys();

        let user_charlie = User {
            user_type: UserType::Allowed,
            user_profile: UserProfile {
                nickname: "charlie".to_string(),
                pet_name: None,
                pronouns: None,
                avatar: None,
                status: None,
                description: None,
            },
            identity_ed25519_public_key: identity_ed25519_public_key_charlie.clone(),
            identity_ed25519_private_key: None,
            remote_endpoint_ed25519_public_key: None,
            remote_endpoint_x25519_private_key: None,
            local_endpoint_ed25519_private_key: None,
            local_endpoint_x25519_public_key: None,
        };

        let charlie_handle = profile.add_user(&user_charlie)?;

        // Alice-Bob conversation
        let alice_bob_key = rico_protocol::v4::payload::conversation_key(
            ConversationType::PersistentDirectMessage,
            &BTreeSet::from([
                identity_ed25519_public_key_alice.clone(),
                identity_ed25519_public_key_bob.clone(),
            ]),
        );

        let alice_bob_conv = Conversation {
            conversation_type: ConversationType::PersistentDirectMessage,
            conversation_members: [alice_handle, bob_handle].into(),
            conversation_key: alice_bob_key.clone(),
        };

        // Alice-Charlie conversation
        let alice_charlie_key = rico_protocol::v4::payload::conversation_key(
            ConversationType::PersistentDirectMessage,
            &BTreeSet::from([
                identity_ed25519_public_key_alice.clone(),
                identity_ed25519_public_key_charlie.clone(),
            ]),
        );

        let alice_charlie_conv = Conversation {
            conversation_type: ConversationType::PersistentDirectMessage,
            conversation_members: [alice_handle, charlie_handle].into(),
            conversation_key: alice_charlie_key.clone(),
        };

        let alice_bob_handle = profile.add_conversation(&alice_bob_conv)?;
        let alice_charlie_handle = profile.add_conversation(&alice_charlie_conv)?;

        // Verify all conversations exist with correct member sets
        let conversations = profile.get_conversations()?;
        assert_eq!(conversations.len(), 2);

        let alice_bob_retrieved = conversations
            .iter()
            .find(|(_, handle)| *handle == alice_bob_handle)
            .expect("Alice-Bob conversation not found");
        assert_eq!(
            alice_bob_retrieved.0.conversation_members,
            [alice_handle, bob_handle].into()
        );

        let alice_charlie_retrieved = conversations
            .iter()
            .find(|(_, handle)| *handle == alice_charlie_handle)
            .expect("Alice-Charlie conversation not found");
        assert_eq!(
            alice_charlie_retrieved.0.conversation_members,
            [alice_handle, charlie_handle].into()
        );

        Ok(())
    }

    #[test]
    fn test_message_record_functions() -> anyhow::Result<()> {
        // Create profile
        let mut profile = create_test_profile("test_message_records.ricochet-profile")?;

        // Generate keys for two users
        let (
            user1_id_pub,
            user1_id_priv,
            user1_remote_ed_pub,
            user1_remote_x_priv,
            user1_local_ed_priv,
            user1_local_x_pub,
        ) = generate_test_keys();
        let (
            user2_id_pub,
            _user2_id_priv,
            user2_remote_ed_pub,
            user2_remote_x_priv,
            user2_local_ed_priv,
            user2_local_x_pub,
        ) = generate_test_keys();

        // Create users
        let user1 = User {
            user_type: UserType::Owner,
            user_profile: UserProfile {
                nickname: "user1".to_string(),
                pet_name: None,
                pronouns: None,
                avatar: None,
                status: None,
                description: None,
            },
            identity_ed25519_public_key: user1_id_pub.clone(),
            identity_ed25519_private_key: Some(user1_id_priv.clone()),
            remote_endpoint_ed25519_public_key: Some(user1_remote_ed_pub),
            remote_endpoint_x25519_private_key: Some(user1_remote_x_priv),
            local_endpoint_ed25519_private_key: Some(user1_local_ed_priv),
            local_endpoint_x25519_public_key: Some(user1_local_x_pub),
        };

        let user2 = User {
            user_type: UserType::Allowed,
            user_profile: UserProfile {
                nickname: "user2".to_string(),
                pet_name: None,
                pronouns: None,
                avatar: None,
                status: None,
                description: None,
            },
            identity_ed25519_public_key: user2_id_pub.clone(),
            identity_ed25519_private_key: None,
            remote_endpoint_ed25519_public_key: Some(user2_remote_ed_pub),
            remote_endpoint_x25519_private_key: Some(user2_remote_x_priv),
            local_endpoint_ed25519_private_key: Some(user2_local_ed_priv),
            local_endpoint_x25519_public_key: Some(user2_local_x_pub),
        };

        let user1_handle = profile.add_user(&user1)?;
        let user2_handle = profile.add_user(&user2)?;
        // Create conversation
        let mut conversation_members = BTreeSet::new();
        conversation_members.insert(user1_handle);
        conversation_members.insert(user2_handle);

        let conversation_member_public_keys: BTreeSet<Ed25519PublicKey> =
            [user1_id_pub.clone(), user2_id_pub.clone()].into();

        let conversation_key = rico_protocol::v4::payload::conversation_key(
            ConversationType::PersistentDirectMessage,
            &conversation_member_public_keys,
        );

        let conversation = Conversation {
            conversation_type: ConversationType::PersistentDirectMessage,
            conversation_members,
            conversation_key: conversation_key.clone(),
        };

        let conversation_handle = profile.add_conversation(&conversation)?;

        // Track sequence numbers independently per user
        let mut user1_record_seq: i64 = -1;
        let mut user1_message_seq: i64 = -1;

        let now: Timestamp = Timestamp::try_from(UtcDateTime::now())?;

        //
        // User 1 - Send an embarassing text message
        //
        let user1_message_record1 = {
            let user_handle = user1_handle;

            user1_record_seq += 1;
            user1_message_seq += 1;

            let record_sequence = RecordSequence(user1_record_seq);
            let message_sequence = MessageSequence(user1_message_seq);

            let message_content_salt = Salt::generate()?;
            let message_content_data = MessageContentData::Text {
                text: "A truly embarassing message!".to_string(),
            };

            let content_hash = rico_protocol::v4::payload::message_content_hash(
                &message_content_salt,
                &message_content_data,
            );

            let message_record_payload = rico_protocol::v4::payload::message_record_payload(
                None,
                &conversation_key,
                &user1_id_pub,
                record_sequence,
                message_sequence,
                now,
                &content_hash,
            );
            let message_content = MessageContent {
                salt: message_content_salt,
                data: message_content_data,
            };
            let signature = user1_id_priv.sign_message(message_record_payload.as_slice());

            let message_record = MessageRecord {
                conversation_handle,
                user_handle,
                record_sequence,
                message_sequence,
                create_timestamp: now,
                message_content,
                signature: signature.clone(),
            };

            let handle = profile.add_message_record(&message_record)?;
            assert_eq!(
                handle,
                profile.get_message_record_handle(
                    conversation_handle,
                    user_handle,
                    record_sequence
                )?
            );
            assert_eq!(message_record, profile.get_message_record(handle)?);
            message_record
        };
        //
        // User 1 - Edit the first message first by tombstoning and adding an updated message_record
        // with new text
        //
        let _user1_message_record1_tombstone = {
            // first we tombstone the message record
            let user_handle = user1_handle;
            let record_sequence = RecordSequence(user1_record_seq);
            let message_sequence = MessageSequence(user1_message_seq);
            let message_record_handle = profile.get_message_record_handle(
                conversation_handle,
                user_handle,
                record_sequence,
            )?;
            let tombstone_message_content_salt = Salt::generate()?;
            let original_message_content = &user1_message_record1.message_content;
            let original_message_content_hash = rico_protocol::v4::payload::message_content_hash(
                &original_message_content.salt,
                &original_message_content.data,
            );
            let original_message_record_signature = user1_message_record1.signature.clone();
            // create our new tombstne message content which replaces the original content
            let tombstone_message_content = MessageContent {
                salt: tombstone_message_content_salt,
                data: MessageContentData::Tombstone(TombstoneData {
                    original_message_content_hash: original_message_content_hash.clone(),
                    original_message_record_signature,
                }),
            };
            let tombstone_message_content_hash = rico_protocol::v4::payload::message_content_hash(
                &tombstone_message_content.salt,
                &tombstone_message_content.data,
            );

            let tombstone_message_record_payload =
                rico_protocol::v4::payload::message_record_payload(
                    None,
                    &conversation_key,
                    &user1_id_pub,
                    record_sequence,
                    message_sequence,
                    now,
                    &tombstone_message_content_hash,
                );

            let tombstone_message_record_signature =
                user1_id_priv.sign_message(tombstone_message_record_payload.as_slice());

            // tombstone the record
            profile.tombstone_message_record(
                message_record_handle,
                &tombstone_message_content.salt,
                &original_message_content_hash,
                &tombstone_message_record_signature,
            )?;

            // verify correctness
            let tombstone_message_record = MessageRecord {
                conversation_handle,
                user_handle,
                record_sequence,
                message_sequence,
                create_timestamp: now,
                message_content: tombstone_message_content,
                signature: tombstone_message_record_signature,
            };
            assert_eq!(
                tombstone_message_record,
                profile.get_message_record(message_record_handle)?
            );
        };
        //
        // User 1 - Send a better text message instead
        //
        let user1_message_record2 = {
            let user_handle = user1_handle;

            user1_record_seq += 1;

            let record_sequence = RecordSequence(user1_record_seq);
            let message_sequence = MessageSequence(user1_message_seq);

            let message_content_salt = Salt::generate()?;
            let message_content_data = MessageContentData::Text {
                text: "Hello World!".to_string(),
            };

            let content_hash = rico_protocol::v4::payload::message_content_hash(
                &message_content_salt,
                &message_content_data,
            );

            let message_record_payload = rico_protocol::v4::payload::message_record_payload(
                Some(&user1_message_record1.signature),
                &conversation_key,
                &user1_id_pub,
                record_sequence,
                message_sequence,
                now,
                &content_hash,
            );
            let message_content = MessageContent {
                salt: message_content_salt,
                data: message_content_data,
            };
            let signature = user1_id_priv.sign_message(message_record_payload.as_slice());

            let message_record = MessageRecord {
                conversation_handle,
                user_handle,
                record_sequence,
                message_sequence,
                create_timestamp: now,
                message_content,
                signature: signature.clone(),
            };

            let handle = profile.add_message_record(&message_record)?;
            assert_eq!(
                handle,
                profile.get_message_record_handle(
                    conversation_handle,
                    user_handle,
                    record_sequence
                )?
            );
            assert_eq!(message_record, profile.get_message_record(handle)?);
            message_record
        };

        //
        // User 1 - Share a file
        //
        let _user1_message_record2 = {
            let user_handle = user1_handle;

            user1_record_seq += 1;
            user1_message_seq += 1;

            let record_sequence = RecordSequence(user1_record_seq);
            let message_sequence = MessageSequence(user1_message_seq);

            let file_data_salt = Salt::generate()?;
            let file_contents = b"This is test file data";
            let file_size = FileSize(file_contents.len() as i64);

            let file_data_hash = rico_protocol::v4::payload::file_data_hash(
                &file_data_salt,
                file_size,
                &mut std::io::Cursor::new(file_contents),
            )?;

            let message_content_salt = Salt::generate()?;
            let message_content_data = MessageContentData::FileShare {
                file_data_salt,
                file_size,
                file_data_hash,
                file_path: Some("test_file.txt".into()),
            };

            let content_hash = rico_protocol::v4::payload::message_content_hash(
                &message_content_salt,
                &message_content_data,
            );

            let message_record_payload = rico_protocol::v4::payload::message_record_payload(
                Some(&user1_message_record2.signature),
                &conversation_key,
                &user1_id_pub,
                record_sequence,
                message_sequence,
                now,
                &content_hash,
            );
            let message_content = MessageContent {
                salt: message_content_salt,
                data: message_content_data,
            };

            let signature = user1_id_priv.sign_message(message_record_payload.as_slice());

            let message_record = MessageRecord {
                conversation_handle,
                user_handle,
                record_sequence,
                message_sequence,
                create_timestamp: now,
                message_content,
                signature: signature.clone(),
            };

            let handle = profile.add_message_record(&message_record)?;
            assert_eq!(
                handle,
                profile.get_message_record_handle(
                    conversation_handle,
                    user_handle,
                    record_sequence
                )?
            );
            assert_eq!(message_record, profile.get_message_record(handle)?);
            message_record
        };

        // Verify we can retrieve all messages
        let messages =
            profile.get_message_records_from_conversation(conversation_handle, None, None)?;
        assert_eq!(messages.len(), 3);
        for message in &messages {
            println!("{message:?}");
        }

        // verify we get the same list of messages when filtering by the author
        let user1_messages = profile.get_message_records_from_conversation_by_user(
            conversation_handle,
            user1_handle,
            None,
            None,
        )?;
        assert_eq!(messages, user1_messages);

        // verify user2 has no messages
        let user2_messages = profile.get_message_records_from_conversation_by_user(
            conversation_handle,
            user2_handle,
            None,
            None,
        )?;
        assert!(user2_messages.is_empty());

        // verify the newest known record seq is correctly determined
        assert_eq!(
            profile.get_newest_record_sequence_in_converation(conversation_handle, user1_handle)?,
            RecordSequence(user1_record_seq)
        );

        // verify user2 has no messages in thsi conversation
        assert!(profile
            .get_newest_record_sequence_in_converation(conversation_handle, user2_handle)
            .is_err(),);

        Ok(())
    }
}
