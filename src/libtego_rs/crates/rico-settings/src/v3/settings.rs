// std
use std::str::FromStr;
use std::collections::BTreeSet;

// extern
use serde::{Deserialize, Deserializer};
use tor_interface::censorship_circumvention::BridgeLine;
use tor_interface::proxy::*;
use tor_interface::tor_provider::TargetAddr;


#[derive(Deserialize)]
pub struct Settings {
    #[serde(default = "Settings::default_tor")]
    pub tor: Tor,
    #[serde(default = "Settings::default_ui")]
    pub ui: UI,
}

impl Settings {
    fn default_tor() -> Tor {
        Default::default()
    }

    fn default_ui() -> UI {
        Default::default()
    }
}

impl TryFrom<&str> for Settings {
    type Error = String;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let result: Settings = serde_json::from_str(value).map_err(|err| err.to_string())?;
        Ok(result)
    }
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
    allowed_ports: Option<Vec<u16>>
}

impl TorRaw {
    const fn default_bootstrapped_successfully() -> bool {
        false
    }

    const fn default_bridge_type() -> BridgeTypeRaw {
        BridgeTypeRaw::None
    }
}

#[derive(Default)]
pub struct Tor {
    pub bootstrapped_successfully: bool,
    pub bridge_config: Option<BridgeConfig>,
    pub proxy_config: Option<ProxyConfig>,
    pub firewall_config: Option<FirewallConfig>,
}

impl TryFrom<TorRaw> for Tor {
    type Error = String;

    fn try_from(value: TorRaw) -> Result<Self, Self::Error> {

        // validate custom bridge strings
        let bridge_config= match (value.bridge_type, value.bridge_strings) {
            (BridgeTypeRaw::Custom, None) => {
                return Err("field 'bridgeStrings' is required when field 'bridgeType' is 'custom'".to_string());
            },
            (BridgeTypeRaw::Custom, Some(bridge_strings)) => {
                if bridge_strings.is_empty() {
                    return Err("field 'bridgeStrings' must not be empty when field 'bridgeType' is 'custom'".to_string());
                } else {
                    let mut bridge_lines: Vec<BridgeLine> = Default::default();
                    for bridge_string in bridge_strings {
                        match BridgeLine::from_str(bridge_string.as_ref()) {
                            Ok(bridge_line) => bridge_lines.push(bridge_line),
                            Err(err) => return Err(format!("failed to parse \"{bridge_string}\" as BridgeLine; {err}")),
                        }
                    }
                    Some(BridgeConfig::Custom(bridge_lines))
                }
            },
            (_, Some(_bridge_strings)) => {
                return Err("field 'bridgeStrings' may only be present when field 'bridgeType' is 'custom'".to_string());
            }
            (BridgeTypeRaw::Obfs4, None) => Some(BridgeConfig::BuiltInObfs4),
            (BridgeTypeRaw::Meek, None) => Some(BridgeConfig::BuiltInMeek),
            (BridgeTypeRaw::Snowflake, None) => Some(BridgeConfig::BuiltInSnowflake),
            (BridgeTypeRaw::None, None) => None,
        };

        let proxy_config = if let Some(proxy_raw) = value.proxy {
            let host = proxy_raw.address;
            let port = proxy_raw.port;
            let address = TargetAddr::try_from((host, port)).map_err(|err| err.to_string())?;
            match (proxy_raw.proxy_type, proxy_raw.username, proxy_raw.password) {
                (ProxyType::Socks4, None, None) => {
                    let config = Socks4ProxyConfig::new(address).map_err(|err| err.to_string())?;
                    Some(ProxyConfig::from(config))
                },
                (ProxyType::Socks4, Some(_username), _) => {
                    return Err("field 'username' may only be present when field 'type' is 'socks5' or 'https'".to_string());
                },
                (ProxyType::Socks4, None, Some(_password)) => {
                    return Err("field 'password' may only be present when field 'type' is 'socks5' or 'https'".to_string());
                },
                (ProxyType::Socks5, username, password) => {
                    let config = Socks5ProxyConfig::new(address, username, password).map_err(|err| err.to_string())?;
                    Some(ProxyConfig::from(config))
                },
                (ProxyType::Https, username, password) => {
                    let config = HttpsProxyConfig::new(address, username, password).map_err(|err| err.to_string())?;
                    Some(ProxyConfig::from(config))
                },
            }
        } else {
            None
        };

        let firewall_config = if let Some(allowed_ports_raw) = value.allowed_ports {
            let mut allowed_ports: BTreeSet<u16> = Default::default();
            if allowed_ports_raw.is_empty() {
                return Err("field 'allowedPorts' must not be empty".to_string());
            }
            for port in allowed_ports_raw {
                if port == 0u16 {
                    return Err("field 'allowedPorts' must not contain 0".to_string());

                } else if !allowed_ports.insert(port) {
                    return Err("field 'allowedPorts' must not contain duplicate entries".to_string());
                }
            }
            Some(FirewallConfig{allowed_ports})
        } else {
            None
        };

        Ok(Tor {
            bootstrapped_successfully: value.bootstrapped_successfully,
            bridge_config,
            proxy_config,
            firewall_config,
        })
    }
}

impl<'de> Deserialize<'de> for Tor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {
        let tor_raw = TorRaw::deserialize(deserializer)
            .map_err(serde::de::Error::custom)?;

        Tor::try_from(tor_raw).map_err(serde::de::Error::custom)
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

pub enum BridgeConfig {
    Custom(Vec<BridgeLine>),
    BuiltInObfs4,
    BuiltInMeek,
    BuiltInSnowflake,
}

//
// Proxy
//

#[derive(Deserialize)]
struct ProxyRaw {
    #[serde(rename = "type")]
    proxy_type: ProxyType,
    address: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize)]
enum ProxyType {
    #[serde(rename = "socks4")]
    Socks4,
    #[serde(rename = "socks5")]
    Socks5,
    #[serde(rename = "https")]
    Https,
}

//
// Firewall
//

pub struct FirewallConfig {
    pub allowed_ports: BTreeSet<u16>,
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
    play_audio_notification: bool
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

pub struct UI {
    pub combined_chat_window: bool,
    pub language: Language,
    pub notification_volume: f32,
    pub play_audio_notification: bool,
}

impl Default for UI {
    fn default() -> UI {
        UI{
            combined_chat_window: UIRaw::default_combined_chat_window(),
            language: UIRaw::default_language(),
            notification_volume: UIRaw::default_notification_volume(),
            play_audio_notification: UIRaw::default_play_audio_notification(),
        }
    }
}

impl TryFrom<UIRaw> for UI {
    type Error = String;

    fn try_from(value: UIRaw) -> Result<Self, Self::Error> {
        let combined_chat_window = value.combined_chat_window;
        let language = value.language;
        let notification_volume = if value.notification_volume < 0.0f32 || value.notification_volume > 1.0f32 {
            return Err("field 'notificationVolume' must be a value from 0.0 through 1.0".to_string());
        } else {
            value.notification_volume
        };
        let play_audio_notification = value.play_audio_notification;

        Ok(UI{combined_chat_window, language, notification_volume, play_audio_notification})
    }
}

impl<'de> Deserialize<'de> for UI {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {
        let ui_raw = UIRaw::deserialize(deserializer)
            .map_err(serde::de::Error::custom)?;

        UI::try_from(ui_raw).map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
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
