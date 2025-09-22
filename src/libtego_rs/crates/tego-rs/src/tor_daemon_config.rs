// extern
use tor_interface::censorship_circumvention::BridgeLine;
use tor_interface::proxy::ProxyConfig;

#[derive(Default)]
pub(crate) struct TorDaemonConfig {
    pub proxy_settings: Option<ProxyConfig>,
    pub allowed_ports: Option<Vec<u16>>,
    pub bridge_lines: Option<Vec<BridgeLine>>,
}
