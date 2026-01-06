#pragma once

enum class ConnectionStatus {
    Offline,
    Connecting,
    Online,
};

// todo: gate InProcessArti on feature gate

enum class TorBackend {
    BundledLegacyTor,
    ExternalLegacyTor,
    InProcessArti,
};

enum class BridgeType {
    Builtin,
    Custom,
};

enum class BuiltinBridge {
    Obfs4,
    Snowflake,
    Meek
};

enum class ProxyType {
    SOCKS4 = 0,
    SOCKS5,
    HTTPS,
};
