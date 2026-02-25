// std
use std::collections::BTreeSet;

// extern
use tor_interface::censorship_circumvention::BridgeLine;

//
// Bridges
//

#[derive(Clone, Debug, PartialEq)]
pub enum BridgeConfig {
    BuiltIn(BuiltInBridge),
    Custom(BridgeLine, Vec<BridgeLine>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum BuiltInBridge {
    Obfs4,
    Meek,
    Snowflake,
}

impl From<BuiltInBridge> for BridgeConfig {
    fn from(value: BuiltInBridge) -> BridgeConfig {
        BridgeConfig::BuiltIn(value)
    }
}

impl TryFrom<Vec<BridgeLine>> for BridgeConfig {
    type Error = &'static str;

    fn try_from(mut value: Vec<BridgeLine>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err("must have at least one BridgeLine")
        } else {
            let first = value.remove(0);
            Ok(BridgeConfig::Custom(first, value))
        }
    }
}

//
// Firewall
//
#[derive(Clone, Debug, PartialEq)]
pub struct FirewallConfig {
    allowed_ports: Vec<u16>,
}

impl FirewallConfig {
    pub fn allowed_ports(&self) -> &Vec<u16> {
        &self.allowed_ports
    }
}

impl TryFrom<Vec<u16>> for FirewallConfig {
    type Error = String;

    fn try_from(value: Vec<u16>) -> Result<Self, Self::Error> {
        let mut allowed_ports: BTreeSet<u16> = Default::default();
        if value.is_empty() {
            return Err("must be a non-empty set of valid port values".to_string());
        }
        for port in value {
            if port == 0u16 {
                return Err("must not contain 0".to_string());
            } else if !allowed_ports.insert(port) {
                return Err("must not contain duplicate entries".to_string());
            }
        }
        let allowed_ports = allowed_ports.into_iter().collect();
        Ok(FirewallConfig { allowed_ports })
    }
}
