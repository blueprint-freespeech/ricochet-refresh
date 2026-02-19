// extern
use anyhow::bail;
use serde_json::{json, Value};

// internal
use rico_settings::v3::settings::*;

#[test]
fn test_deserialize_tor() -> anyhow::Result<()> {

    let valid_json: Vec<Value> = vec![
        json!({}),
        // bootstrapped successfully
        json!({"bootstrappedSuccessfully" : true}),
        json!({"bootstrappedSuccessfully" : false}),
        // bridges
        json!({"bridgeType" : "none"}),
        json!({"bridgeType" : "custom", "bridgeStrings" : ["meek_lite 192.0.2.20:80 url=https://1603026938.rsc.cdn77.org front=www.phpmyadmin.net utls=HelloRandomizedALPN"]}),
        json!({"bridgeType" : "obfs4"}),
        json!({"bridgeType" : "meek"}),
        json!({"bridgeType" : "meek-azure"}),
        json!({"bridgeType" : "snowflake"}),
        // socks4 proxy
        json!({"proxy" : {"type" : "socks4", "address" : "127.0.0.1", "port" : 4}}),
        json!({"proxy" : {"type" : "socks4", "address" : "example.com", "port" : 4}}),
        // socks5 proxy
        json!({"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 5}}),
        json!({"proxy" : {"type" : "socks5", "address" : "example.com", "port" : 5}}),
        json!({"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 5, "username" : "alice"}}),
        json!({"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 5, "password" : "123456"}}),
        json!({"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 5, "username" : "alice", "password" : "123456"}}),
        // https proxy
        json!({"proxy" : {"type" : "https", "address" : "127.0.0.1", "port" : 443}}),
        json!({"proxy" : {"type" : "https", "address" : "example.com", "port" : 443}}),
        json!({"proxy" : {"type" : "https", "address" : "127.0.0.1", "port" : 443, "username" : "alice", "password" : "123456"}}),
        // firewall
        json!({"allowedPorts" : [80, 443, 8080]}),
    ];

    for json_tor in valid_json {
        match serde_json::from_value::<Tor>(json_tor.clone()) {
            Ok(_) => (),
            Err(err) => bail!("Failed to deserialize valid tor json:\n{json_tor}\n  Err: {err}"),
        }
    }

    let invalid_json: Vec<Value> = vec![
        // bootstrapped successfully
        json!({"bootstrappedSuccessfully" : 42}),
        // bridges
        json!({"bridgeType" : "london",}),
        json!({"bridgeType" : "custom"}),
        json!({"bridgeType" : "custom", "bridgeStrings" : []}),
        json!({"bridgeType" : "custom", "bridgeStrings" : ["invalid-bridge-string"]}),
        json!({"bridgeType" : "meek", "bridgeStrings" : ["meek_lite 192.0.2.20:80 url=https://1603026938.rsc.cdn77.org front=www.phpmyadmin.net utls=HelloRandomizedALPN"]}),
        // socks4 proxy
        json!({"proxy" : {"type" : "socks4", "address" : "127.0.0.1", "port" : 0}}),
        json!({"proxy" : {"type" : "socks4", "address" : "127.0.0.1", "port" : 65536}}),
        json!({"proxy" : {"type" : "socks4", "address" : "127.0.0.1", "port" : 4, "username" : "alice"}}),
        json!({"proxy" : {"type" : "socks4", "address" : "127.0.0.1", "port" : 4, "password" : "123456"}}),
        json!({"proxy" : {"type" : "socks4", "address" : "127.0.0.1", "port" : 4, "username" : "alice", "password" : "123456"}}),
        json!({"proxy" : {"type" : "socks4", "address" : "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion", "port" : 1234}}),
        // socks5 proxy
        json!({"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 0}}),
        json!({"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 65536}}),
        json!({"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 4, "username" : "0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef"}}),
        json!({"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 4, "password" : "0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef"}}),
        json!({"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 4, "username" : "0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef", "password" : "0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef"}}),
        json!({"proxy" : {"type" : "socks5", "address" : "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion", "port" : 1234}}),
        // https proxy
        json!({"proxy" : {"type" : "https", "address" : "127.0.0.1", "port" : 0}}),
        json!({"proxy" : {"type" : "https", "address" : "127.0.0.1", "port" : 65536}}),
        json!({"proxy" : {"type" : "https", "address" : "127.0.0.1", "port" : 443, "username" : ":colon:"}}),
        json!({"proxy" : {"type" : "https", "address" : "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion", "port" : 443}}),
        // firewall
        json!({"allowedPorts" : []}),
        json!({"allowedPorts" : [0]}),
        json!({"allowedPorts" : [443,443]}),
    ];

    for json_tor in invalid_json {
        match serde_json::from_value::<Tor>(json_tor.clone()) {
            Ok(_) => bail!("Successfully deserialized invalid tor json:\n{json_tor}"),
            Err(_) => (),
        }
    }

    Ok(())
}

#[test]
fn test_deserialize_ui() -> anyhow::Result<()> {
    let valid_json: Vec<Value> = vec![
        json!({}),
        // combined chat window
        json!({"combinedChatWindow" : true}),
        json!({"combinedChatWindow" : false}),
        // language
        json!({"language" : ""}),
        json!({"language" : "bg"}),
        json!({"language" : "cs"}),
        json!({"language" : "da"}),
        json!({"language" : "de"}),
        json!({"language" : "en"}),
        json!({"language" : "es"}),
        json!({"language" : "et_EE"}),
        json!({"language" : "fi"}),
        json!({"language" : "fr"}),
        json!({"language" : "he"}),
        json!({"language" : "it"}),
        json!({"language" : "it_IT"}),
        json!({"language" : "ja"}),
        json!({"language" : "nb"}),
        json!({"language" : "nl_NL"}),
        json!({"language" : "pl"}),
        json!({"language" : "pt_BR"}),
        json!({"language" : "pt_PT"}),
        json!({"language" : "ru"}),
        json!({"language" : "sl"}),
        json!({"language" : "sq"}),
        json!({"language" : "sv"}),
        json!({"language" : "tr"}),
        json!({"language" : "uk"}),
        json!({"language" : "zh"}),
        json!({"language" : "zh_HK"}),
        // default notificaiton volume
        json!({"notificationVolume" : 0.0}),
        json!({"notificationVolume" : 1.0}),
        // play audio notification
        json!({"playAudioNotification" : true}),
        json!({"playAudioNotification" : false}),
    ];

    for json_ui in valid_json {
        match serde_json::from_value::<UI>(json_ui.clone()) {
            Ok(_) => (),
            Err(err) => bail!("Failed to deserialize valid ui json:\n{json_ui}\n  Err: {err}"),
        }
    }

    let invalid_json: Vec<Value> = vec![
        // combined chat window
        json!({"combinedChatWindow" : 42}),
        // language
        json!({"language" : "ar"}),
        json!({"language" : "English"}),
        // defaultNotificationVolume
        json!({"notificationVolume" : "loud"}),
        json!({"notificationVolume" : -1.0}),
        json!({"notificationVolume" : 2.0}),
        // playAudioNotification
        json!({"playAudioNotification" : 42}),
    ];

    for json_ui in invalid_json {
        match serde_json::from_value::<UI>(json_ui.clone()) {
            Ok(_) => bail!("Successfully deserialized invalid ui json:\n{json_ui}"),
            Err(_) => (),
        }
    }

    Ok(())
}

#[test]
fn test_deserialize_settings() -> anyhow::Result<()> {
    let valid_json_strings: Vec<&'static str> = vec![
        "{}",
        "{\"tor\" : {}, \"ui\" : {}}",
        r#"{
            "tor" : {
                "bootstrappedSuccessfully" : true,
                "bridgeType" : "custom",
                "bridgeStrings" : [
                    "meek_lite 192.0.2.20:80 url=https://1603026938.rsc.cdn77.org front=www.phpmyadmin.net utls=HelloRandomizedALPN"
                ],
                "proxy" : {
                    "type" : "socks5",
                    "address": "127.0.0.1",
                    "port": 5,
                    "username" : "alice",
                    "password" : "123456"
                }
            },
            "ui" : {
                "combinedChatWindow" : false,
                "language" : "nl_NL",
                "notificationVolume" : 0.5,
                "playAudioNotification" : true
            }
        }"#,
    ];

    for json_settings_string in valid_json_strings {
        match Settings::try_from(json_settings_string) {
            Ok(_) => (),
            Err(err) => bail!("Failed to deserialize valid settings json:\n{json_settings_string}\n  Err: {err}"),
        }
    }

    Ok(())
}
