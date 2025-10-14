#pragma once
// bridge lines
const QMap<QString, std::vector<std::string>> defaultBridges = {};
const QString recommendedBridgeType = "";
// pt_config
struct pt_config {
    std::string binary_name;
    std::vector<std::string> transports;
    std::vector<std::string> options;
};
const std::vector<pt_config> pluggableTransportConfigs = {};
