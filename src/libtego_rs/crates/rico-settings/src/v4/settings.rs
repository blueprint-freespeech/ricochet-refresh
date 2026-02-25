// std
use std::fmt::{Display, Formatter};
use std::str::FromStr;

// extern
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tor_interface::censorship_circumvention::BridgeLine;
use tor_interface::proxy::*;
use tor_interface::tor_provider::TargetAddr;

// crate
use crate::common::{BridgeConfig, BuiltInBridge, FirewallConfig};
use crate::v3;

//
// Settings Raw
//

#[derive(Deserialize, Serialize)]
pub struct SettingsRaw {
    version: Version,
    // general settings
    start_only_single_instance: bool,
    check_for_updates_automatically: bool,
    // interface settings
    language: Language,
    show_toolbar: bool,
    show_desktop_notifications: bool,
    blink_taskbar_icon: bool,
    play_audio_notifications: bool,
    minimize_instead_of_exit: bool,
    show_system_tray_icon: bool,
    minimize_to_system_tray: bool,
    // connection settings
    tor_backend: TorBackend,
    connect_automatically: bool,
    bridge_config: BridgeConfigRaw,
    proxy_config: ProxyConfigRaw,
    firewall_config: FirewallConfigRaw,
}

impl From<&Settings> for SettingsRaw {
    fn from(value: &Settings) -> SettingsRaw {
        let version = Version::V4_0_0;
        let start_only_single_instance = value.start_only_single_instance;
        let check_for_updates_automatically = value.check_for_updates_automatically;
        let language = value.language;
        let show_toolbar = value.show_toolbar;
        let show_desktop_notifications = value.show_desktop_notifications;
        let blink_taskbar_icon = value.blink_taskbar_icon;
        let play_audio_notifications = value.play_audio_notifications;
        let minimize_instead_of_exit = value.minimize_instead_of_exit;
        let show_system_tray_icon = value.show_system_tray_icon;
        let minimize_to_system_tray = value.minimize_to_system_tray;
        let tor_backend = value.tor_backend;
        let connect_automatically = value.connect_automatically;
        let bridge_config = match &value.bridge_config {
            None => BridgeConfigRaw::None,
            Some(BridgeConfig::Custom(first, bridge_lines)) => {
                let first = first.as_legacy_tor_setconf_value();
                let mut bridge_strings: Vec<String> = bridge_lines
                    .iter()
                    .map(|bridge_line| bridge_line.as_legacy_tor_setconf_value())
                    .collect();
                bridge_strings.insert(0, first);
                BridgeConfigRaw::Custom(bridge_strings)
            }
            Some(BridgeConfig::BuiltIn(BuiltInBridge::Obfs4)) => BridgeConfigRaw::BuiltInObfs4,
            Some(BridgeConfig::BuiltIn(BuiltInBridge::Meek)) => BridgeConfigRaw::BuiltInMeek,
            Some(BridgeConfig::BuiltIn(BuiltInBridge::Snowflake)) => {
                BridgeConfigRaw::BuiltInSnowflake
            }
        };
        let proxy_config = match &value.proxy_config {
            None => ProxyConfigRaw::None,
            Some(ProxyConfig::Socks4(config)) => {
                let address = config.address();
                let host = address.host();
                let port = address.port();
                ProxyConfigRaw::Socks4 { host, port }
            }
            Some(ProxyConfig::Socks5(config)) => {
                let address = config.address();
                let host = address.host();
                let port = address.port();
                let username = config.username().clone();
                let password = config.password().clone();
                ProxyConfigRaw::Socks5 {
                    host,
                    port,
                    username,
                    password,
                }
            }
            Some(ProxyConfig::Https(config)) => {
                let address = config.address();
                let host = address.host();
                let port = address.port();
                let username = config.username().clone();
                let password = config.password().clone();
                ProxyConfigRaw::Https {
                    host,
                    port,
                    username,
                    password,
                }
            }
        };
        let firewall_config = match &value.firewall_config {
            None => FirewallConfigRaw::None,
            Some(firewall_config) => {
                FirewallConfigRaw::AllowedPorts(firewall_config.allowed_ports().clone())
            }
        };

        SettingsRaw {
            version,
            start_only_single_instance,
            check_for_updates_automatically,
            language,
            show_toolbar,
            show_desktop_notifications,
            blink_taskbar_icon,
            play_audio_notifications,
            minimize_instead_of_exit,
            show_system_tray_icon,
            minimize_to_system_tray,
            tor_backend,
            connect_automatically,
            bridge_config,
            proxy_config,
            firewall_config,
        }
    }
}

//
// Settings
//
#[derive(Debug, PartialEq)]
pub struct Settings {
    // general settings
    pub start_only_single_instance: bool,
    pub check_for_updates_automatically: bool,
    // interface settings
    pub language: Language,
    pub show_toolbar: bool,
    pub show_desktop_notifications: bool,
    pub blink_taskbar_icon: bool,
    pub play_audio_notifications: bool,
    pub minimize_instead_of_exit: bool,
    pub show_system_tray_icon: bool,
    pub minimize_to_system_tray: bool,
    // connection settings
    pub tor_backend: TorBackend,
    pub connect_automatically: bool,
    pub bridge_config: Option<BridgeConfig>,
    pub proxy_config: Option<ProxyConfig>,
    pub firewall_config: Option<FirewallConfig>,
}

impl FromStr for Settings {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let result: Settings = serde_json::from_str(s).map_err(|err| err.to_string())?;
        Ok(result)
    }
}

impl Display for Settings {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let json: String = serde_json::to_string_pretty(self)
            .expect("Settins should always be Serializable to JSON");
        write!(f, "{json}")
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            start_only_single_instance: true,
            check_for_updates_automatically: true,
            language: Language::System,
            show_toolbar: true,
            show_desktop_notifications: false,
            blink_taskbar_icon: false,
            play_audio_notifications: false,
            minimize_instead_of_exit: false,
            show_system_tray_icon: false,
            minimize_to_system_tray: false,
            tor_backend: TorBackend::BundledTor,
            connect_automatically: false,
            bridge_config: None,
            proxy_config: None,
            firewall_config: None,
        }
    }
}

impl TryFrom<SettingsRaw> for Settings {
    type Error = String;

    fn try_from(value: SettingsRaw) -> Result<Self, Self::Error> {
        let start_only_single_instance = value.start_only_single_instance;
        let check_for_updates_automatically = value.check_for_updates_automatically;
        let language = value.language;
        let show_toolbar = value.show_toolbar;
        let show_desktop_notifications = value.show_desktop_notifications;
        let blink_taskbar_icon = value.blink_taskbar_icon;
        let play_audio_notifications = value.play_audio_notifications;
        let minimize_instead_of_exit = value.minimize_instead_of_exit;
        let show_system_tray_icon = value.show_system_tray_icon;
        let minimize_to_system_tray = value.minimize_to_system_tray;
        let tor_backend = value.tor_backend;
        let connect_automatically = value.connect_automatically;
        let bridge_config = match value.bridge_config {
            BridgeConfigRaw::None => None,
            BridgeConfigRaw::Custom(bridge_strings) => {
                if bridge_strings.is_empty() {
                    return Err(
                        "custom bridge_config must contain at least one bridge line".to_string()
                    );
                } else {
                    let mut bridge_lines: Vec<BridgeLine> =
                        Vec::with_capacity(bridge_strings.len());
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
                    Some(BridgeConfig::Custom(first, bridge_lines))
                }
            }
            BridgeConfigRaw::BuiltInObfs4 => Some(BridgeConfig::BuiltIn(BuiltInBridge::Obfs4)),
            BridgeConfigRaw::BuiltInMeek => Some(BridgeConfig::BuiltIn(BuiltInBridge::Meek)),
            BridgeConfigRaw::BuiltInSnowflake => {
                Some(BridgeConfig::BuiltIn(BuiltInBridge::Snowflake))
            }
        };
        let proxy_config = match value.proxy_config {
            ProxyConfigRaw::None => None,
            ProxyConfigRaw::Socks4 { host, port } => {
                let address = TargetAddr::try_from((host, port)).map_err(|err| err.to_string())?;
                let config = Socks4ProxyConfig::new(address).map_err(|err| err.to_string())?;
                Some(ProxyConfig::from(config))
            }
            ProxyConfigRaw::Socks5 {
                host,
                port,
                username,
                password,
            } => {
                let address = TargetAddr::try_from((host, port)).map_err(|err| err.to_string())?;
                let config = Socks5ProxyConfig::new(address, username, password)
                    .map_err(|err| err.to_string())?;
                Some(ProxyConfig::from(config))
            }
            ProxyConfigRaw::Https {
                host,
                port,
                username,
                password,
            } => {
                let address = TargetAddr::try_from((host, port)).map_err(|err| err.to_string())?;
                let config = HttpsProxyConfig::new(address, username, password)
                    .map_err(|err| err.to_string())?;
                Some(ProxyConfig::from(config))
            }
        };
        let firewall_config = match value.firewall_config {
            FirewallConfigRaw::None => None,
            FirewallConfigRaw::AllowedPorts(allowed_ports_list) => {
                Some(FirewallConfig::try_from(allowed_ports_list)?)
            }
        };

        Ok(Self {
            start_only_single_instance,
            check_for_updates_automatically,
            language,
            show_toolbar,
            show_desktop_notifications,
            blink_taskbar_icon,
            play_audio_notifications,
            minimize_instead_of_exit,
            show_system_tray_icon,
            minimize_to_system_tray,
            tor_backend,
            connect_automatically,
            bridge_config,
            proxy_config,
            firewall_config,
        })
    }
}

impl From<v3::settings::Settings> for Settings {
    fn from(value: v3::settings::Settings) -> Self {
        Self {
            language: match value.language {
                v3::settings::Language::SystemDefault => Language::System,
                v3::settings::Language::German => Language::German,
                v3::settings::Language::English => Language::English,
                v3::settings::Language::Spanish => Language::Spanish,
                v3::settings::Language::Dutch => Language::Dutch,
                _ => Language::System,
            },
            play_audio_notifications: value.play_audio_notification,
            bridge_config: value.bridge_config.clone(),
            proxy_config: value.proxy_config.clone(),
            firewall_config: value.firewall_config.clone(),
            ..Self::default()
        }
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

impl Serialize for Settings {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let settings_raw = SettingsRaw::from(self);
        settings_raw.serialize(serializer)
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub enum Version {
    #[default]
    #[serde(rename = "4.0.0")]
    V4_0_0,
}

#[derive(Copy, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub enum Language {
    #[default]
    #[serde(rename = "system")]
    System,
    #[serde(rename = "ar")]
    Arabic,
    #[serde(rename = "de")]
    German,
    #[serde(rename = "en")]
    English,
    #[serde(rename = "es")]
    Spanish,
    #[serde(rename = "nl")]
    Dutch,
}

#[derive(Copy, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub enum TorBackend {
    #[default]
    #[serde(rename = "bundled-tor")]
    BundledTor,
    #[serde(rename = "system-tor")]
    SystemTor,
    #[serde(rename = "arti-client")]
    ArtiClient,
}

#[derive(Default, Deserialize, Serialize)]
pub enum BridgeConfigRaw {
    #[default]
    #[serde(rename = "none")]
    None,
    #[serde(rename = "built-in-obfs4")]
    BuiltInObfs4,
    #[serde(rename = "built-in-meek")]
    BuiltInMeek,
    #[serde(rename = "built-in-snowflake")]
    BuiltInSnowflake,
    #[serde(rename = "custom")]
    Custom(Vec<String>),
}

#[derive(Default, Deserialize, Serialize)]
enum ProxyConfigRaw {
    #[default]
    #[serde(rename = "none")]
    None,
    #[serde(rename = "socks4")]
    Socks4 { host: String, port: u16 },
    #[serde(rename = "socks5")]
    Socks5 {
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
    #[serde(rename = "https")]
    Https {
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
}

#[derive(Default, Deserialize, Serialize)]
enum FirewallConfigRaw {
    #[default]
    #[serde(rename = "none")]
    None,
    #[serde(rename = "allowed_ports")]
    AllowedPorts(Vec<u16>),
}
