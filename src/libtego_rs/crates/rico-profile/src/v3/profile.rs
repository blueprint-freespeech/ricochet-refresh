// std
use std::collections::BTreeMap;
use std::str::FromStr;

// extern
use serde::{Deserialize, Deserializer};
use tor_interface::tor_crypto::{Ed25519PrivateKey, V3OnionServiceId};

//
// Profile Raw
//

#[derive(Deserialize)]
struct ProfileRaw {
    identity: IdentityRaw,
    users: Option<BTreeMap<String, UserRaw>>,
}

#[derive(Deserialize)]
struct IdentityRaw {
    #[serde(rename = "privateKey")]
    private_key: String,
}

#[derive(Deserialize)]
struct UserRaw {
    nickname: String,
    #[serde(rename = "type")]
    user_type: UserType,
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
pub enum UserType {
    #[serde(rename = "allowed")]
    Allowed,
    #[serde(rename = "requesting")]
    Requesting,
    #[serde(rename = "blocked")]
    Blocked,
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "rejected")]
    Rejected,
}

//
// Profile
//

#[derive(Debug, PartialEq)]
pub struct Profile {
    pub private_key: Ed25519PrivateKey,
    pub users: BTreeMap<V3OnionServiceId, User>,
}

#[derive(Debug, PartialEq)]
pub struct User {
    pub nickname: String,
    pub user_type: UserType,
}

impl TryFrom<ProfileRaw> for Profile {
    type Error = String;

    fn try_from(value: ProfileRaw) -> Result<Self, Self::Error> {
        let private_key =
            Ed25519PrivateKey::from_key_blob_legacy(value.identity.private_key.as_str())
                .map_err(|err| err.to_string())?;
        let mut users: BTreeMap<V3OnionServiceId, User> = BTreeMap::new();
        if let Some(raw_users) = value.users {
            for (service_id, user) in raw_users.into_iter() {
                let service_id = V3OnionServiceId::from_string(service_id.as_str())
                    .map_err(|err| err.to_string())?;
                let nickname = user.nickname;
                let user_type = user.user_type;
                users.insert(
                    service_id,
                    User {
                        nickname,
                        user_type,
                    },
                );
            }
        }

        Ok(Self { private_key, users })
    }
}

impl<'de> Deserialize<'de> for Profile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let profile_raw =
            ProfileRaw::deserialize(deserializer).map_err(serde::de::Error::custom)?;

        Profile::try_from(profile_raw).map_err(serde::de::Error::custom)
    }
}

impl FromStr for Profile {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let result: Profile = serde_json::from_str(s).map_err(|err| err.to_string())?;
        Ok(result)
    }
}
