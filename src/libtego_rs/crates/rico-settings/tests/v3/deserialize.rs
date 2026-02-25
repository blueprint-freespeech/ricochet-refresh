// std
use std::str::FromStr;

// extern
use anyhow::bail;
use serde_json::{json, Value};
use tor_interface::censorship_circumvention::BridgeLine;
use tor_interface::proxy::*;
use tor_interface::tor_provider::TargetAddr;

// internal
use rico_settings::common::*;
use rico_settings::v3::settings::*;

#[test]
fn test_deserialize_settings() -> anyhow::Result<()> {
    let valid_json: Vec<(Value, Settings)> = vec![
        // empty object
        (json!({}), Settings::default()),
        // combined chat window
        (json!({"ui": {"combinedChatWindow" : true}}), Settings{combined_chat_window: true, ..Settings::default()}),
        (json!({"ui": {"combinedChatWindow" : false}}), Settings{combined_chat_window: false, ..Settings::default()}),
        // language
        (json!({"ui": {"language" : ""}}), Settings{language: Language::SystemDefault, ..Settings::default()}),
        (json!({"ui": {"language" : "bg"}}), Settings{language: Language::Bulgarian, ..Settings::default()}),
        (json!({"ui": {"language" : "cs"}}), Settings{language: Language::Czech, ..Settings::default()}),
        (json!({"ui": {"language" : "da"}}), Settings{language: Language::Danish, ..Settings::default()}),
        (json!({"ui": {"language" : "de"}}), Settings{language: Language::German, ..Settings::default()}),
        (json!({"ui": {"language" : "en"}}), Settings{language: Language::English, ..Settings::default()}),
        (json!({"ui": {"language" : "es"}}), Settings{language: Language::Spanish, ..Settings::default()}),
        (json!({"ui": {"language" : "et_EE"}}), Settings{language: Language::Estonian, ..Settings::default()}),
        (json!({"ui": {"language" : "fi"}}), Settings{language: Language::Finnish, ..Settings::default()}),
        (json!({"ui": {"language" : "fil_PH"}}), Settings{language: Language::Filipino, ..Settings::default()}),
        (json!({"ui": {"language" : "fr"}}), Settings{language: Language::French, ..Settings::default()}),
        (json!({"ui": {"language" : "he"}}), Settings{language: Language::Hebrew, ..Settings::default()}),
        (json!({"ui": {"language" : "it"}}), Settings{language: Language::Italian, ..Settings::default()}),
        (json!({"ui": {"language" : "it_IT"}}), Settings{language: Language::Italian, ..Settings::default()}),
        (json!({"ui": {"language" : "ja"}}), Settings{language: Language::Japanese, ..Settings::default()}),
        (json!({"ui": {"language" : "nb"}}), Settings{language: Language::NorwegianBokmål, ..Settings::default()}),
        (json!({"ui": {"language" : "nl_NL"}}), Settings{language: Language::Dutch, ..Settings::default()}),
        (json!({"ui": {"language" : "pl"}}), Settings{language: Language::Polish, ..Settings::default()}),
        (json!({"ui": {"language" : "pt_BR"}}), Settings{language: Language::BrazilianPortuguese, ..Settings::default()}),
        (json!({"ui": {"language" : "pt_PT"}}), Settings{language: Language::Portuguese, ..Settings::default()}),
        (json!({"ui": {"language" : "ru"}}), Settings{language: Language::Russian, ..Settings::default()}),
        (json!({"ui": {"language" : "sl"}}), Settings{language: Language::Slovenian, ..Settings::default()}),
        (json!({"ui": {"language" : "sq"}}), Settings{language: Language::Albanian, ..Settings::default()}),
        (json!({"ui": {"language" : "sv"}}), Settings{language: Language::Swedish, ..Settings::default()}),
        (json!({"ui": {"language" : "tr"}}), Settings{language: Language::Turkish, ..Settings::default()}),
        (json!({"ui": {"language" : "uk"}}), Settings{language: Language::Ukranian, ..Settings::default()}),
        (json!({"ui": {"language" : "zh"}}), Settings{language: Language::Chinese, ..Settings::default()}),
        (json!({"ui": {"language" : "zh_HK"}}), Settings{language: Language::HongKongChinese, ..Settings::default()}),
        // default notificaiton volume
        (json!({"ui": {"notificationVolume" : 0.0}}), Settings{notification_volume: 0.0f32, ..Settings::default()}),
        (json!({"ui": {"notificationVolume" : 1.0}}), Settings{notification_volume: 1.0f32, ..Settings::default()}),
        // play audio notification
        (json!({"ui": {"playAudioNotification" : true}}), Settings{play_audio_notification: true, ..Settings::default()}),
        (json!({"ui": {"playAudioNotification" : false}}), Settings{play_audio_notification: false, ..Settings::default()}),

        // bootstrapped successfully
        (json!({"tor" : {"bootstrappedSuccessfully" : true}}), Settings{bootstrapped_successfully: true, ..Settings::default()}),
        (json!({"tor" : {"bootstrappedSuccessfully" : false}}), Settings{bootstrapped_successfully: false, ..Default::default()}),
        // bridges
        (json!({"tor" : {"bridgeType" : "none"}}), Settings{bridge_config: None, ..Settings::default()}),
        (json!({"tor" : {"bridgeType" : "custom", "bridgeStrings" : ["meek_lite 192.0.2.20:80 url=https://1603026938.rsc.cdn77.org front=www.phpmyadmin.net utls=HelloRandomizedALPN"]}}), Settings{bridge_config: Some(BridgeConfig::Custom(BridgeLine::from_str("meek_lite 192.0.2.20:80 url=https://1603026938.rsc.cdn77.org front=www.phpmyadmin.net utls=HelloRandomizedALPN")?, vec![])), ..Settings::default()}),
        (json!({"tor" : {"bridgeType" : "obfs4"}}), Settings{bridge_config: Some(BridgeConfig::BuiltIn(BuiltInBridge::Obfs4)), ..Settings::default()}),
        (json!({"tor" : {"bridgeType" : "meek"}}), Settings{bridge_config: Some(BridgeConfig::BuiltIn(BuiltInBridge::Meek)), ..Settings::default()}),
        (json!({"tor" : {"bridgeType" : "meek-azure"}}), Settings{bridge_config: Some(BridgeConfig::BuiltIn(BuiltInBridge::Meek)), ..Settings::default()}),
        (json!({"tor" : {"bridgeType" : "snowflake"}}), Settings{bridge_config: Some(BridgeConfig::BuiltIn(BuiltInBridge::Snowflake)), ..Settings::default()}),

        // socks4 proxy
        (json!({"tor" : {"proxy" : {"type" : "socks4", "address" : "127.0.0.1", "port" : 4}}}), Settings{proxy_config: Some(Socks4ProxyConfig::new(TargetAddr::from_str("127.0.0.1:4")?)?.into()), ..Settings::default()}),
        (json!({"tor" : {"proxy" : {"type" : "socks4", "address" : "example.com", "port" : 4}}}), Settings{proxy_config: Some(Socks4ProxyConfig::new(TargetAddr::from_str("example.com:4")?)?.into()), ..Settings::default()}),
        // socks5 proxy

        (json!({"tor" : {"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 5}}}), Settings{proxy_config: Some(Socks5ProxyConfig::new(TargetAddr::from_str("127.0.0.1:5")?, None, None)?.into()), ..Settings::default()}),
        (json!({"tor" : {"proxy" : {"type" : "socks5", "address" : "example.com", "port" : 5}}}), Settings{proxy_config: Some(Socks5ProxyConfig::new(TargetAddr::from_str("example.com:5")?, None, None)?.into()), ..Settings::default()}),
        (json!({"tor" : {"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 5, "username": "alice"}}}), Settings{proxy_config: Some(Socks5ProxyConfig::new(TargetAddr::from_str("127.0.0.1:5")?, Some("alice".to_string()), None)?.into()), ..Settings::default()}),
        (json!({"tor" : {"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 5, "password": "123456"}}}), Settings{proxy_config: Some(Socks5ProxyConfig::new(TargetAddr::from_str("127.0.0.1:5")?, None, Some("123456".to_string()))?.into()), ..Settings::default()}),
        (json!({"tor" : {"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 5, "username": "alice", "password": "123456"}}}), Settings{proxy_config: Some(Socks5ProxyConfig::new(TargetAddr::from_str("127.0.0.1:5")?, Some("alice".to_string()), Some("123456".to_string()))?.into()), ..Settings::default()}),

        // https proxy
        (json!({"tor" : {"proxy" : {"type" : "https", "address" : "127.0.0.1", "port" : 443}}}), Settings{proxy_config: Some(HttpsProxyConfig::new(TargetAddr::from_str("127.0.0.1:443")?, None, None)?.into()), ..Settings::default()}),
        (json!({"tor" : {"proxy" : {"type" : "https", "address" : "example.com", "port" : 443}}}), Settings{proxy_config: Some(HttpsProxyConfig::new(TargetAddr::from_str("example.com:443")?, None, None)?.into()), ..Settings::default()}),
        (json!({"tor" : {"proxy" : {"type" : "https", "address" : "127.0.0.1", "port" : 443, "username": "alice"}}}), Settings{proxy_config: Some(HttpsProxyConfig::new(TargetAddr::from_str("127.0.0.1:443")?, Some("alice".to_string()), None)?.into()), ..Settings::default()}),
        (json!({"tor" : {"proxy" : {"type" : "https", "address" : "127.0.0.1", "port" : 443, "password": "123456"}}}), Settings{proxy_config: Some(HttpsProxyConfig::new(TargetAddr::from_str("127.0.0.1:443")?, None, Some("123456".to_string()))?.into()), ..Settings::default()}),
        (json!({"tor" : {"proxy" : {"type" : "https", "address" : "127.0.0.1", "port" : 443, "username": "alice", "password": "123456"}}}), Settings{proxy_config: Some(HttpsProxyConfig::new(TargetAddr::from_str("127.0.0.1:443")?, Some("alice".to_string()), Some("123456".to_string()))?.into()), ..Settings::default()}),
        // firewall
        (json!({"tor" : {"allowedPorts" : [80, 443, 8080]}}), Settings{firewall_config: Some(FirewallConfig::try_from(vec![80, 443, 8080]).unwrap()), ..Settings::default()}),
    ];

    for (json, expected) in valid_json {
        match serde_json::from_value::<Settings>(json.clone()) {
            Ok(parsed) => assert_eq!(parsed, expected),
            Err(err) => bail!("Failed to deserialize valid json:\n{json}\n  Err: {err}"),
        }
    }

    let invalid_json: Vec<Value> = vec![
        // combined chat window
        json!({"ui": {"combinedChatWindow" : 42}}),
        // language
        json!({"ui": {"language" : "ar"}}),
        json!({"ui": {"language" : "English"}}),
        // defaultNotificationVolume
        json!({"ui": {"notificationVolume" : "loud"}}),
        json!({"ui": {"notificationVolume" : -1.0}}),
        json!({"ui": {"notificationVolume" : 2.0}}),
        // playAudioNotification
        json!({"ui": {"playAudioNotification" : 42}}),
        // bootstrapped successfully
        json!({"tor": {"bootstrappedSuccessfully" : 42}}),
        // bridges
        json!({"tor": {"bridgeType" : "london",}}),
        json!({"tor": {"bridgeType" : "custom"}}),
        json!({"tor": {"bridgeType" : "custom", "bridgeStrings" : []}}),
        json!({"tor": {"bridgeType" : "custom", "bridgeStrings" : ["invalid-bridge-string"]}}),
        json!({"tor": {"bridgeType" : "meek", "bridgeStrings" : ["meek_lite 192.0.2.20:80 url=https://1603026938.rsc.cdn77.org front=www.phpmyadmin.net utls=HelloRandomizedALPN"]}}),
        // socks4 proxy
        json!({"tor": {"proxy" : {"type" : "socks4", "address" : "127.0.0.1", "port" : 0}}}),
        json!({"tor": {"proxy" : {"type" : "socks4", "address" : "127.0.0.1", "port" : 65536}}}),
        json!({"tor": {"proxy" : {"type" : "socks4", "address" : "127.0.0.1", "port" : 4, "username" : "alice"}}}),
        json!({"tor": {"proxy" : {"type" : "socks4", "address" : "127.0.0.1", "port" : 4, "password" : "123456"}}}),
        json!({"tor": {"proxy" : {"type" : "socks4", "address" : "127.0.0.1", "port" : 4, "username" : "alice", "password" : "123456"}}}),
        json!({"tor": {"proxy" : {"type" : "socks4", "address" : "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion", "port" : 1234}}}),
        // socks5 proxy
        json!({"tor": {"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 0}}}),
        json!({"tor": {"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 65536}}}),
        json!({"tor": {"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 4, "username" : "0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef"}}}),
        json!({"tor": {"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 4, "password" : "0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef"}}}),
        json!({"tor": {"proxy" : {"type" : "socks5", "address" : "127.0.0.1", "port" : 4, "username" : "0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef", "password" : "0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef0123456790abcdef"}}}),
        json!({"tor": {"proxy" : {"type" : "socks5", "address" : "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion", "port" : 1234}}}),
        // https proxy
        json!({"tor": {"proxy" : {"type" : "https", "address" : "127.0.0.1", "port" : 0}}}),
        json!({"tor": {"proxy" : {"type" : "https", "address" : "127.0.0.1", "port" : 65536}}}),
        json!({"tor": {"proxy" : {"type" : "https", "address" : "127.0.0.1", "port" : 443, "username" : ":colon:"}}}),
        json!({"tor": {"proxy" : {"type" : "https", "address" : "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion", "port" : 443}}}),
        // firewall
        json!({"tor": {"allowedPorts" : []}}),
        json!({"tor": {"allowedPorts" : [0]}}),
        json!({"tor": {"allowedPorts" : [443,443]}}),
    ];

    for json in invalid_json {
        match serde_json::from_value::<Settings>(json.clone()) {
            Ok(_) => bail!("Successfully deserialized invalid Settings json:\n{json}"),
            Err(_) => (),
        }
    }

    Ok(())
}
