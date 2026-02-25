// std
use std::str::FromStr;

// extern
use serde::{Deserialize, Deserializer};
use tor_interface::censorship_circumvention::BridgeLine;
use tor_interface::proxy::*;
use tor_interface::tor_provider::TargetAddr;

// internal
use crate::common;

//
// Settings Raw
//

#[derive(Deserialize)]
pub struct SettingsRaw {
    #[serde(default)]
    tor: TorRaw,
    #[serde(default)]
    ui: UIRaw,
}

//
// Tor
//

#[derive(Deserialize)]
struct TorRaw {
    #[serde(rename = "bootstrappedSuccessfully")]
    #[serde(default = "TorRaw::default_bootstrapped_successfully")]
    bootstrapped_successfully: bool,
    #[serde(rename = "bridgeType")]
    #[serde(default = "TorRaw::default_bridge_type")]
    bridge_type: BridgeTypeRaw,
    #[serde(rename = "bridgeStrings")]
    bridge_strings: Option<Vec<String>>,
    proxy: Option<ProxyRaw>,
    #[serde(rename = "allowedPorts")]
    allowed_ports: Option<Vec<u16>>,
}

impl TorRaw {
    const fn default_bootstrapped_successfully() -> bool {
        false
    }

    const fn default_bridge_type() -> BridgeTypeRaw {
        BridgeTypeRaw::None
    }
}

impl Default for TorRaw {
    fn default() -> Self {
        Self {
            bootstrapped_successfully: Self::default_bootstrapped_successfully(),
            bridge_type: Self::default_bridge_type(),
            bridge_strings: None,
            proxy: None,
            allowed_ports: None,
        }
    }
}

//
// BridgeConfig
//

#[derive(Deserialize)]
pub enum BridgeTypeRaw {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "custom")]
    Custom,
    #[serde(rename = "meek")]
    #[serde(alias = "meek-azure")]
    Meek,
    #[serde(rename = "obfs4")]
    Obfs4,
    #[serde(rename = "snowflake")]
    Snowflake,
}

//
// Proxy
//

#[derive(Deserialize)]
struct ProxyRaw {
    #[serde(rename = "type")]
    proxy_type: ProxyTypeRaw,
    address: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize)]
enum ProxyTypeRaw {
    #[serde(rename = "socks4")]
    Socks4,
    #[serde(rename = "socks5")]
    Socks5,
    #[serde(rename = "https")]
    Https,
}

//
// UI
//

#[derive(Deserialize)]
struct UIRaw {
    #[serde(rename = "combinedChatWindow")]
    #[serde(default = "UIRaw::default_combined_chat_window")]
    combined_chat_window: bool,
    #[serde(default = "UIRaw::default_language")]
    language: Language,
    #[serde(rename = "notificationVolume")]
    #[serde(default = "UIRaw::default_notification_volume")]
    notification_volume: f32,
    #[serde(default = "UIRaw::default_play_audio_notification")]
    #[serde(rename = "playAudioNotification")]
    play_audio_notification: bool,
}

impl UIRaw {
    const fn default_combined_chat_window() -> bool {
        true
    }

    const fn default_language() -> Language {
        Language::SystemDefault
    }

    const fn default_notification_volume() -> f32 {
        0.75f32
    }

    const fn default_play_audio_notification() -> bool {
        false
    }
}

impl Default for UIRaw {
    fn default() -> Self {
        Self {
            combined_chat_window: Self::default_combined_chat_window(),
            language: Self::default_language(),
            notification_volume: Self::default_notification_volume(),
            play_audio_notification: Self::default_play_audio_notification(),
        }
    }
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
pub enum Language {
    #[serde(rename = "")]
    SystemDefault,
    #[serde(rename = "bg")]
    Bulgarian,
    #[serde(rename = "cs")]
    Czech,
    #[serde(rename = "da")]
    Danish,
    #[serde(rename = "de")]
    German,
    #[serde(rename = "en")]
    English,
    #[serde(rename = "es")]
    Spanish,
    #[serde(rename = "et_EE")]
    Estonian,
    #[serde(rename = "fi")]
    Finnish,
    #[serde(rename = "fil_PH")]
    Filipino,
    #[serde(rename = "fr")]
    French,
    #[serde(rename = "he")]
    Hebrew,
    #[serde(rename = "it")]
    #[serde(alias = "it_IT")]
    Italian,
    #[serde(rename = "ja")]
    Japanese,
    #[serde(rename = "nb")]
    NorwegianBokmål,
    #[serde(rename = "nl_NL")]
    Dutch,
    #[serde(rename = "pl")]
    Polish,
    #[serde(rename = "pt_BR")]
    BrazilianPortuguese,
    #[serde(rename = "pt_PT")]
    Portuguese,
    #[serde(rename = "ru")]
    Russian,
    #[serde(rename = "sl")]
    Slovenian,
    #[serde(rename = "sq")]
    Albanian,
    #[serde(rename = "sv")]
    Swedish,
    #[serde(rename = "tr")]
    Turkish,
    #[serde(rename = "uk")]
    Ukranian,
    #[serde(rename = "zh")]
    Chinese,
    #[serde(rename = "zh_HK")]
    HongKongChinese,
}

//
// Settings
//

#[derive(Debug, PartialEq)]
pub struct Settings {
    // ui settings
    pub combined_chat_window: bool,
    pub language: Language,
    pub notification_volume: f32,
    pub play_audio_notification: bool,

    // tor settings
    pub bootstrapped_successfully: bool,
    pub bridge_config: Option<common::BridgeConfig>,
    pub proxy_config: Option<ProxyConfig>,
    pub firewall_config: Option<common::FirewallConfig>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            combined_chat_window: true,
            language: Language::SystemDefault,
            notification_volume: 0.75f32,
            play_audio_notification: false,
            bootstrapped_successfully: false,
            bridge_config: None,
            proxy_config: None,
            firewall_config: None,
        }
    }
}

impl FromStr for Settings {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let result: Settings = serde_json::from_str(s).map_err(|err| err.to_string())?;
        Ok(result)
    }
}

impl TryFrom<SettingsRaw> for Settings {
    type Error = String;

    fn try_from(value: SettingsRaw) -> Result<Self, Self::Error> {
        // ui
        let ui = value.ui;
        let combined_chat_window = ui.combined_chat_window;
        let language = ui.language;
        let notification_volume = if ui.notification_volume < 0.0f32
            || ui.notification_volume > 1.0f32
        {
            return Err(
                "field 'ui.notificationVolume' must be a value from 0.0 through 1.0".to_string(),
            );
        } else {
            ui.notification_volume
        };
        let play_audio_notification = ui.play_audio_notification;

        // tor
        let tor = value.tor;
        let bootstrapped_successfully = tor.bootstrapped_successfully;
        let bridge_config = match (tor.bridge_type, tor.bridge_strings) {
            (BridgeTypeRaw::Custom, None) => {
                return Err(
                    "field 'tor.bridgeStrings' is required when field 'tor.bridgeType' is 'custom'"
                        .to_string(),
                );
            }
            (BridgeTypeRaw::Custom, Some(bridge_strings)) => {
                if bridge_strings.is_empty() {
                    return Err("field 'tor.bridgeStrings' must not be empty when field 'tor.bridgeType' is 'custom'".to_string());
                } else {
                    let mut bridge_lines: Vec<BridgeLine> = Default::default();
                    for bridge_string in bridge_strings {
                        match BridgeLine::from_str(bridge_string.as_ref()) {
                            Ok(bridge_line) => bridge_lines.push(bridge_line),
                            Err(err) => {
                                return Err(format!(
                                    "failed to parse \"{bridge_string}\" as BridgeLine; {err}"
                                ))
                            }
                        }
                    }
                    let first = bridge_lines.remove(0);
                    Some(common::BridgeConfig::Custom(first, bridge_lines))
                }
            }
            (_, Some(_bridge_strings)) => {
                return Err("field 'tor.bridgeStrings' may only be present when field 'tor.bridgeType' is 'custom'".to_string());
            }
            (BridgeTypeRaw::Obfs4, None) => {
                Some(common::BridgeConfig::BuiltIn(common::BuiltInBridge::Obfs4))
            }
            (BridgeTypeRaw::Meek, None) => {
                Some(common::BridgeConfig::BuiltIn(common::BuiltInBridge::Meek))
            }
            (BridgeTypeRaw::Snowflake, None) => Some(common::BridgeConfig::BuiltIn(
                common::BuiltInBridge::Snowflake,
            )),
            (BridgeTypeRaw::None, None) => None,
        };

        let proxy_config = if let Some(proxy_raw) = tor.proxy {
            let host = proxy_raw.address;
            let port = proxy_raw.port;
            let address = TargetAddr::try_from((host, port)).map_err(|err| err.to_string())?;
            match (proxy_raw.proxy_type, proxy_raw.username, proxy_raw.password) {
                (ProxyTypeRaw::Socks4, None, None) => {
                    let config = Socks4ProxyConfig::new(address).map_err(|err| err.to_string())?;
                    Some(ProxyConfig::from(config))
                }
                (ProxyTypeRaw::Socks4, Some(_username), _) => {
                    return Err("field 'tor.proxy.username' may only be present when field 'tor.proxy.type' is 'socks5' or 'https'".to_string());
                }
                (ProxyTypeRaw::Socks4, None, Some(_password)) => {
                    return Err("field 'tor.proxy.password' may only be present when field 'tor.proxy.type' is 'socks5' or 'https'".to_string());
                }
                (ProxyTypeRaw::Socks5, username, password) => {
                    let config = Socks5ProxyConfig::new(address, username, password)
                        .map_err(|err| err.to_string())?;
                    Some(ProxyConfig::from(config))
                }
                (ProxyTypeRaw::Https, username, password) => {
                    let config = HttpsProxyConfig::new(address, username, password)
                        .map_err(|err| err.to_string())?;
                    Some(ProxyConfig::from(config))
                }
            }
        } else {
            None
        };
        let firewall_config = if let Some(allowed_ports_raw) = tor.allowed_ports {
            Some(common::FirewallConfig::try_from(allowed_ports_raw)?)
        } else {
            None
        };

        Ok(Settings {
            combined_chat_window,
            language,
            notification_volume,
            play_audio_notification,
            bootstrapped_successfully,
            bridge_config,
            proxy_config,
            firewall_config,
        })
    }
}

impl<'de> Deserialize<'de> for Settings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let settings_raw =
            SettingsRaw::deserialize(deserializer).map_err(serde::de::Error::custom)?;

        Settings::try_from(settings_raw).map_err(serde::de::Error::custom)
    }
}
