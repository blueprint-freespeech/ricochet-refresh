// std
use std::path::Path;

// extern
use tor_interface::tor_crypto::*;

// internal
#[cfg(feature = "v3-profile")]
use rico_profile::v3;
use rico_profile::v4;

#[test]
fn test_construction() -> anyhow::Result<()> {
    let profile = v4::profile::test::create_test_profile("test_construction.ricochet-profile")?;

    assert_eq!(profile.get_version()?, v4::profile::Version::LATEST);

    Ok(())
}

#[test]
#[cfg(feature = "v3-profile")]
fn test_legacy_import() -> anyhow::Result<()> {
    use std::collections::BTreeMap;

    let v3_profile = v3::profile::Profile{
        private_key: Ed25519PrivateKey::from_key_blob_legacy("ED25519-V3:YLj7W9DouVzO4a1yPY1a3yIT7Hv3FYVwg/d3sE/h0F9oFE0vGhXtE61kFNjq6MhstvxaNGCRXmVm+mta2nwfgg==")?,
        users: BTreeMap::from([
            (V3OnionServiceId::from_string("um7kahbtdqiijlohv3cfsbi7iqo4bvidngshr6zshi6rxseu3bbiriid")?,
                v3::profile::User{
                    nickname: "alice".to_string(),
                    user_type: v3::profile::UserType::Allowed}),
            (V3OnionServiceId::from_string("kndfzlfstthybcnf62brkk5dn2ypqlzyra5srheqenpvmesoizodihad")?,
                v3::profile::User{
                    nickname: "bridgette".to_string(),
                    user_type: v3::profile::UserType::Requesting}),
            (V3OnionServiceId::from_string("mj4kpnujlesrslrmtqqbyu3yntr7macr6sbtmime5mktl272mdcn36yd")?,
                v3::profile::User{
                    nickname: "claire".to_string(),
                    user_type: v3::profile::UserType::Blocked}),
            (V3OnionServiceId::from_string("arn2oq6qp2gvcicolecju5x44x74zv56llno6cujvnxvtlcxyjhwlvid")?,
                v3::profile::User{
                    nickname: "danielle".to_string(),
                    user_type: v3::profile::UserType::Pending}),
            (V3OnionServiceId::from_string("zdqen2zfqcx25fcf4youogtlfjodwq6vx2u44pfr2vtjpktwbirm44yd")?,
                v3::profile::User{
                    nickname: "evelyn".to_string(),
                    user_type: v3::profile::UserType::Rejected}),
        ]),
    };
    let mut path = std::env::temp_dir();
    path.push("test_legacy_import.ricochet-profile");
    if Path::exists(&path) {
        std::fs::remove_file(&path)?;
    }

    let mut v4_profile =
        v4::profile::Profile::new_from_v3_profile(v3_profile, "morgan", &path, "hunter42")?;

    println!("created profile: {path:?}");

    let conversations = v4_profile.get_conversations()?;
    // All of our conversations must be empty
    // We start initially with 2 conversations per user
    assert_eq!(conversations.len(), 5 * 2);
    for (_conversation, conversation_handle) in conversations {
        let message_records =
            v4_profile.get_message_records_from_conversation(conversation_handle, None, None)?;
        assert_eq!(message_records.len(), 0);
    }

    // Verify each of users are imported correctly
    let users = v4_profile.get_users()?;
    for (user, user_handle) in users {
        use v4::profile::UserType;

        let user_type = user.user_type;
        let nickname = user.user_profile.nickname;
        let pet_name = user.user_profile.pet_name;
        let pronouns = user.user_profile.pronouns;
        let avatar = user.user_profile.avatar;
        let status = user.user_profile.status;
        let description = user.user_profile.description;
        let identity_ed25519_public_key = user.identity_ed25519_public_key;
        let identity_ed25519_private_key = user.identity_ed25519_private_key;
        let remote_endpoint_ed25519_public_key = user.remote_endpoint_ed25519_public_key;
        let remote_endpoint_x25519_private_key = user.remote_endpoint_x25519_private_key;
        let local_endpoint_ed25519_private_key = user.local_endpoint_ed25519_private_key;
        let local_endpoint_x25519_public_key = user.local_endpoint_x25519_public_key;

        match (user_type, nickname.as_str(), pet_name.as_deref()) {
            (UserType::Owner, "morgan", None) => {
                assert_eq!(
                    Ed25519PublicKey::from_private_key(
                        identity_ed25519_private_key.as_ref().unwrap()
                    ),
                    identity_ed25519_public_key
                );
                let service_id = V3OnionServiceId::from_public_key(&identity_ed25519_public_key);
                assert_eq!(
                    V3OnionServiceId::from_string(
                        "yl3jqul6g3x5t7fiy7bhjctqdluqczyksdwjf7yvpw6q4xzxlzqky7yd"
                    )?,
                    service_id
                );
            }
            (user_type, nickname, pet_name) => {
                let service_id = V3OnionServiceId::from_string(nickname)?;
                assert_eq!(
                    identity_ed25519_public_key,
                    Ed25519PublicKey::from_service_id(&service_id)?
                );
                assert!(identity_ed25519_private_key.is_none());
                match (user_type, nickname, pet_name) {
                    (
                        UserType::Allowed,
                        "um7kahbtdqiijlohv3cfsbi7iqo4bvidngshr6zshi6rxseu3bbiriid",
                        Some("alice"),
                    ) => (),
                    (
                        UserType::Requesting,
                        "kndfzlfstthybcnf62brkk5dn2ypqlzyra5srheqenpvmesoizodihad",
                        Some("bridgette"),
                    ) => (),
                    (
                        UserType::Blocked,
                        "mj4kpnujlesrslrmtqqbyu3yntr7macr6sbtmime5mktl272mdcn36yd",
                        Some("claire"),
                    ) => (),
                    (
                        UserType::Requesting,
                        "arn2oq6qp2gvcicolecju5x44x74zv56llno6cujvnxvtlcxyjhwlvid",
                        Some("danielle"),
                    ) => (),
                    (
                        UserType::Rejected,
                        "zdqen2zfqcx25fcf4youogtlfjodwq6vx2u44pfr2vtjpktwbirm44yd",
                        Some("evelyn"),
                    ) => (),
                    (user_type, nickname, pet_name) => {
                        panic!("user_type: {user_type:?}, nickname: {nickname}, pet_name: {pet_name:?}");
                    }
                }
            }
        }
        assert!(pronouns.is_none());
        assert!(avatar.is_none());
        assert!(status.is_none());
        assert!(description.is_none());
        assert!(remote_endpoint_ed25519_public_key.is_none());
        assert!(remote_endpoint_x25519_private_key.is_none());
        assert!(local_endpoint_ed25519_private_key.is_none());
        assert!(local_endpoint_x25519_public_key.is_none());

        v4_profile.remove_user(user_handle)?;
    }

    assert_eq!(v4_profile.get_users()?.len(), 0);

    Ok(())
}
