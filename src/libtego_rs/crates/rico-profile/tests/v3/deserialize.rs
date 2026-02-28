// extern
use anyhow::bail;
use serde_json::{json, Value};
use tor_interface::tor_crypto::{Ed25519PrivateKey, V3OnionServiceId};

// internal
use rico_profile::v3::profile::*;

#[test]
fn test_deserialize_profile() -> anyhow::Result<()> {
    let valid_json: Vec<(Value, Profile)> = vec![
        // missing users map
        (json!({
            "identity" : {
                "privateKey" : "ED25519-V3:YLj7W9DouVzO4a1yPY1a3yIT7Hv3FYVwg/d3sE/h0F9oFE0vGhXtE61kFNjq6MhstvxaNGCRXmVm+mta2nwfgg=="
            }
        }),
        Profile{
            private_key: Ed25519PrivateKey::from_key_blob_legacy("ED25519-V3:YLj7W9DouVzO4a1yPY1a3yIT7Hv3FYVwg/d3sE/h0F9oFE0vGhXtE61kFNjq6MhstvxaNGCRXmVm+mta2nwfgg==").unwrap(),
            users: Default::default()
        }),
        // empty users map
        (json!({
            "identity" : {
                "privateKey" : "ED25519-V3:YLj7W9DouVzO4a1yPY1a3yIT7Hv3FYVwg/d3sE/h0F9oFE0vGhXtE61kFNjq6MhstvxaNGCRXmVm+mta2nwfgg=="
            },
            "users" : {},
        }),
        Profile{
            private_key: Ed25519PrivateKey::from_key_blob_legacy("ED25519-V3:YLj7W9DouVzO4a1yPY1a3yIT7Hv3FYVwg/d3sE/h0F9oFE0vGhXtE61kFNjq6MhstvxaNGCRXmVm+mta2nwfgg==").unwrap(),
            users: Default::default()
        }),
        // populated users map
        (json!({
            "identity" : {
                "privateKey" : "ED25519-V3:YLj7W9DouVzO4a1yPY1a3yIT7Hv3FYVwg/d3sE/h0F9oFE0vGhXtE61kFNjq6MhstvxaNGCRXmVm+mta2nwfgg=="
            },
            "users" : {
                "um7kahbtdqiijlohv3cfsbi7iqo4bvidngshr6zshi6rxseu3bbiriid" : {"nickname" : "alice", "type" : "allowed"},
                "kndfzlfstthybcnf62brkk5dn2ypqlzyra5srheqenpvmesoizodihad" : {"nickname" : "bridgette", "type" : "requesting"},
                "mj4kpnujlesrslrmtqqbyu3yntr7macr6sbtmime5mktl272mdcn36yd" : {"nickname" : "claire", "type" : "blocked"},
                "arn2oq6qp2gvcicolecju5x44x74zv56llno6cujvnxvtlcxyjhwlvid" : {"nickname" : "danielle", "type" : "pending"},
                "zdqen2zfqcx25fcf4youogtlfjodwq6vx2u44pfr2vtjpktwbirm44yd" : {"nickname" : "evelyn", "type" : "rejected"},
            },
        }),
        Profile{
            private_key: Ed25519PrivateKey::from_key_blob_legacy("ED25519-V3:YLj7W9DouVzO4a1yPY1a3yIT7Hv3FYVwg/d3sE/h0F9oFE0vGhXtE61kFNjq6MhstvxaNGCRXmVm+mta2nwfgg==").unwrap(),
            users: [
                (V3OnionServiceId::from_string("um7kahbtdqiijlohv3cfsbi7iqo4bvidngshr6zshi6rxseu3bbiriid").unwrap(), User{nickname: "alice".to_string(), user_type: UserType::Allowed}),
                (V3OnionServiceId::from_string("kndfzlfstthybcnf62brkk5dn2ypqlzyra5srheqenpvmesoizodihad").unwrap(), User{nickname: "bridgette".to_string(), user_type: UserType::Requesting}),
                (V3OnionServiceId::from_string("mj4kpnujlesrslrmtqqbyu3yntr7macr6sbtmime5mktl272mdcn36yd").unwrap(), User{nickname: "claire".to_string(), user_type: UserType::Blocked}),
                (V3OnionServiceId::from_string("arn2oq6qp2gvcicolecju5x44x74zv56llno6cujvnxvtlcxyjhwlvid").unwrap(), User{nickname: "danielle".to_string(), user_type: UserType::Pending}),
                (V3OnionServiceId::from_string("zdqen2zfqcx25fcf4youogtlfjodwq6vx2u44pfr2vtjpktwbirm44yd").unwrap(), User{nickname: "evelyn".to_string(), user_type: UserType::Rejected}),
            ].into(),
        }),
    ];

    for (json, expected) in valid_json {
        match serde_json::from_value::<Profile>(json.clone()) {
            Ok(parsed) => assert_eq!(parsed, expected),
            Err(err) => bail!("Failed to deserialize valid json:\n{json}\n  Err: {err}"),
        }
    }

    let invalid_json: Vec<Value> = vec![
        json!({}),
        json!({"identity" : {}}),
        json!({"identity" : {"privateKey" : "invalid-key"}}),
        json!({
            "identity" : {
                "privateKey" : "ED25519-V3:YLj7W9DouVzO4a1yPY1a3yIT7Hv3FYVwg/d3sE/h0F9oFE0vGhXtE61kFNjq6MhstvxaNGCRXmVm+mta2nwfgg=="
            },
            "users" : {
                "invalid-service-id" : {"nickname" : "alice", "type" : "allowed"},
            },
        }),
        json!({
            "identity" : {
                "privateKey" : "ED25519-V3:YLj7W9DouVzO4a1yPY1a3yIT7Hv3FYVwg/d3sE/h0F9oFE0vGhXtE61kFNjq6MhstvxaNGCRXmVm+mta2nwfgg=="
            },
            "users" : {
                "um7kahbtdqiijlohv3cfsbi7iqo4bvidngshr6zshi6rxseu3bbiriid" : {},
            },
        }),
        json!({
            "identity" : {
                "privateKey" : "ED25519-V3:YLj7W9DouVzO4a1yPY1a3yIT7Hv3FYVwg/d3sE/h0F9oFE0vGhXtE61kFNjq6MhstvxaNGCRXmVm+mta2nwfgg=="
            },
            "users" : {
                "um7kahbtdqiijlohv3cfsbi7iqo4bvidngshr6zshi6rxseu3bbiriid" : {"nickname" : "alice"},
            },
        }),
        json!({
            "identity" : {
                "privateKey" : "ED25519-V3:YLj7W9DouVzO4a1yPY1a3yIT7Hv3FYVwg/d3sE/h0F9oFE0vGhXtE61kFNjq6MhstvxaNGCRXmVm+mta2nwfgg=="
            },
            "users" : {
                "um7kahbtdqiijlohv3cfsbi7iqo4bvidngshr6zshi6rxseu3bbiriid" : {"type" : "allowed"},
            },
        }),
        json!({
            "identity" : {
                "privateKey" : "ED25519-V3:YLj7W9DouVzO4a1yPY1a3yIT7Hv3FYVwg/d3sE/h0F9oFE0vGhXtE61kFNjq6MhstvxaNGCRXmVm+mta2nwfgg=="
            },
            "users" : {
                "um7kahbtdqiijlohv3cfsbi7iqo4bvidngshr6zshi6rxseu3bbiriid" : {"nickname": "alice", "type" : "integer"},
            },
        }),
    ];

    for json in invalid_json {
        match serde_json::from_value::<Profile>(json.clone()) {
            Ok(_) => bail!("Successfully deserialized invalid Profile json:\n{json}"),
            Err(_) => (),
        }
    }

    Ok(())
}
