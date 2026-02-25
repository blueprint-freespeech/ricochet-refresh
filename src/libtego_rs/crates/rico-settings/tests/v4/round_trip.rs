// std
use std::str::FromStr;

// extern
use tor_interface::censorship_circumvention::BridgeLine;
use tor_interface::proxy::*;
use tor_interface::tor_provider::TargetAddr;

// internal
use rico_settings::common::*;
use rico_settings::v4::settings::*;

#[test]
fn test_round_trip() -> anyhow::Result<()> {
    let settings_vec: Vec<Settings> = vec![
        Settings::default(),
        Settings{start_only_single_instance: true, ..Settings::default()},
        Settings{start_only_single_instance: false, ..Settings::default()},
        Settings{check_for_updates_automatically: true, ..Settings::default()},
        Settings{check_for_updates_automatically: false, ..Settings::default()},
        Settings{language: Language::System, ..Settings::default()},
        Settings{language: Language::Arabic, ..Settings::default()},
        Settings{language: Language::German, ..Settings::default()},
        Settings{language: Language::English, ..Settings::default()},
        Settings{language: Language::Spanish, ..Settings::default()},
        Settings{language: Language::Dutch, ..Settings::default()},
        Settings{show_toolbar: true, ..Settings::default()},
        Settings{show_toolbar: false, ..Settings::default()},
        Settings{blink_taskbar_icon: true, ..Settings::default()},
        Settings{blink_taskbar_icon: false, ..Settings::default()},
        Settings{play_audio_notifications: true, ..Settings::default()},
        Settings{play_audio_notifications: false, ..Settings::default()},
        Settings{minimize_instead_of_exit: true, ..Settings::default()},
        Settings{minimize_instead_of_exit: false, ..Settings::default()},
        Settings{show_system_tray_icon: true, ..Settings::default()},
        Settings{show_system_tray_icon: false, ..Settings::default()},
        Settings{minimize_to_system_tray: true, ..Settings::default()},
        Settings{minimize_to_system_tray: false, ..Settings::default()},
        Settings{tor_backend: TorBackend::BundledTor, ..Settings::default()},
        Settings{tor_backend: TorBackend::SystemTor, ..Settings::default()},
        Settings{tor_backend: TorBackend::ArtiClient, ..Settings::default()},
        Settings{connect_automatically: true, ..Settings::default()},
        Settings{connect_automatically: false, ..Settings::default()},
        Settings{bridge_config: Some(BuiltInBridge::Obfs4.into()), ..Settings::default()},
        Settings{bridge_config: Some(BuiltInBridge::Meek.into()), ..Settings::default()},
        Settings{bridge_config: Some(BuiltInBridge::Snowflake.into()), ..Settings::default()},
        Settings{bridge_config: Some(vec![BridgeLine::from_str("meek_lite 192.0.2.20:80 url=https://1603026938.rsc.cdn77.org front=www.phpmyadmin.net utls=HelloRandomizedALPN")?].try_into().unwrap()), ..Settings::default()},
        Settings{bridge_config: None, ..Settings::default()},
        Settings{proxy_config: Some(Socks4ProxyConfig::new(TargetAddr::from_str("127.0.0.1:4")?)?.into()),..Settings::default()},
        Settings{proxy_config: Some(Socks4ProxyConfig::new(TargetAddr::from_str("example.com:4")?)?.into()),..Settings::default()},
        Settings{proxy_config: Some(Socks5ProxyConfig::new(TargetAddr::from_str("127.0.0.1:5")?, None, None)?.into()),..Settings::default()},
        Settings{proxy_config: Some(Socks5ProxyConfig::new(TargetAddr::from_str("example.com:5")?, None, None)?.into()),..Settings::default()},
        Settings{proxy_config: Some(Socks5ProxyConfig::new(TargetAddr::from_str("127.0.0.1:5")?, Some("alice".to_string()), None)?.into()),..Settings::default()},
        Settings{proxy_config: Some(Socks5ProxyConfig::new(TargetAddr::from_str("127.0.0.1:5")?, None, Some("123456".to_string()))?.into()),..Settings::default()},
        Settings{proxy_config: Some(Socks5ProxyConfig::new(TargetAddr::from_str("127.0.0.1:5")?, Some("alice".to_string()), None)?.into()),..Settings::default()},
        Settings{proxy_config: Some(Socks5ProxyConfig::new(TargetAddr::from_str("127.0.0.1:5")?, Some("alice".to_string()), Some("123456".to_string()))?.into()),..Settings::default()},
        Settings{proxy_config: Some(HttpsProxyConfig::new(TargetAddr::from_str("127.0.0.1:443")?, None, None)?.into()),..Settings::default()},
        Settings{proxy_config: Some(HttpsProxyConfig::new(TargetAddr::from_str("example.com:443")?, None, None)?.into()),..Settings::default()},
        Settings{proxy_config: Some(HttpsProxyConfig::new(TargetAddr::from_str("127.0.0.1:443")?, Some("alice".to_string()), None)?.into()),..Settings::default()},
        Settings{proxy_config: Some(HttpsProxyConfig::new(TargetAddr::from_str("127.0.0.1:443")?, None, Some("123456".to_string()))?.into()),..Settings::default()},
        Settings{proxy_config: Some(HttpsProxyConfig::new(TargetAddr::from_str("127.0.0.1:443")?, Some("alice".to_string()), None)?.into()),..Settings::default()},
        Settings{proxy_config: Some(HttpsProxyConfig::new(TargetAddr::from_str("127.0.0.1:443")?, Some("alice".to_string()), Some("123456".to_string()))?.into()),..Settings::default()},
        Settings{firewall_config: Some(FirewallConfig::try_from(vec![80, 443, 8080]).unwrap()), ..Settings::default()},
        Settings{firewall_config: None, ..Settings::default()},
    ];

    // verify settings objects can round-trip successfully
    for settings in settings_vec {
        let json = settings.to_string();
        assert_eq!(settings, Settings::from_str(json.as_ref()).unwrap());
    }

    Ok(())
}
