#include "TorControl.h"
#include "TorManager.h"
#include "UserIdentity.h"

#include "utils/Settings.h"

#include "pluggables.hpp"

#include <iostream>

namespace shims
{
    TorControl* TorControl::torControl = nullptr;

    TorControl::TorControl(tego_context* context_)
    : context(context_)
    { }

    // callable from QML
    // see TorConfigurationPage.qml
    void TorControl::setConfiguration(const QVariantMap &options)
    {
        QJsonObject json = QJsonObject::fromVariantMap(options);
        this->setConfiguration(json);
    }

    void TorControl::setConfiguration(const QJsonObject &config) try
    {
        settings_to_tor_config(config, nullptr);
        QJsonObject tor(config);
        SettingsObject settings;
        settings.write("tor", tor);
    } catch (std::exception& ex) {
        LOG_ERROR(ex.what());
    }

    void TorControl::settings_to_tor_config(const QJsonObject &config, tego_tor_daemon_config** out_config) {

        auto rawFilePath = (QFileInfo(SettingsObject::defaultFile()->filePath()).path() + QStringLiteral("/tor/")).toUtf8();

        std::unique_ptr<tego_tor_daemon_config> daemonConfig;
        tego_tor_daemon_config_initialize(
            tego::out(daemonConfig),
            rawFilePath.data(),
            static_cast<size_t>(rawFilePath.size()),
            tego::throw_on_error());

        // generate own json to save to settings
        QJsonObject tor;

        // proxy
        if (auto proxyIt = config.find("proxy"); proxyIt != config.end())
        {
            auto proxyObj = proxyIt->toObject();
            auto typeIt = proxyObj.find("type");
            TEGO_THROW_IF_EQUAL(typeIt, proxyObj.end());

            auto typeString = typeIt->toString().toStdString();
            if (typeString != "none")
            {
                TEGO_THROW_IF_FALSE(
                    typeString == "socks4" ||
                    typeString == "socks5" ||
                    typeString == "https");

                auto addressIt = proxyObj.find("address");
                TEGO_THROW_IF_EQUAL(addressIt, proxyObj.end());
                auto addressQString = addressIt->toString();
                auto address = addressQString.toStdString();
                TEGO_THROW_IF(address.size() == 0);

                auto portIt = proxyObj.find("port");
                TEGO_THROW_IF_EQUAL(portIt, proxyObj.end());
                auto port = portIt->toInt();
                TEGO_THROW_IF_FALSE(port > 0 && port < 65536);

                QJsonObject proxy;
                proxy["address"] = addressQString;
                proxy["port"] = port;

                if (typeString == "socks4")
                {
                    tego_tor_daemon_config_set_proxy_socks4(
                        daemonConfig.get(),
                        address.data(),
                        address.size(),
                        static_cast<uint16_t>(port),
                        tego::throw_on_error());

                    proxy["type"] = "socks4";
                }
                else
                {
                    auto usernameIt = proxyObj.find("username");
                    auto passwordIt = proxyObj.find("password");

                    auto usernameQString = (usernameIt == proxyObj.end()) ? QString() : usernameIt->toString();
                    auto passwordQString = (passwordIt == proxyObj.end()) ? QString() : passwordIt->toString();
                    auto username = usernameQString.toStdString();
                    auto password = passwordQString.toStdString();

                    proxy["username"] = usernameQString;
                    proxy["password"] = passwordQString;

                    if (typeString == "socks5")
                    {
                        tego_tor_daemon_config_set_proxy_socks5(
                            daemonConfig.get(),
                            address.data(),
                            address.size(),
                            static_cast<uint16_t>(port),
                            username.data(),
                            username.size(),
                            password.data(),
                            password.size(),
                            tego::throw_on_error());

                        proxy["type"] = "socks5";

                    }
                    else
                    {
                        TEGO_THROW_IF_FALSE(typeString == "https");
                        tego_tor_daemon_config_set_proxy_https(
                            daemonConfig.get(),
                            address.data(),
                            address.size(),
                            static_cast<uint16_t>(port),
                            username.data(),
                            username.size(),
                            password.data(),
                            password.size(),
                            tego::throw_on_error());

                        proxy["type"] = "https";
                    }
                }
                tor["proxy"] = proxy;
            }
        }
        // firewall
        if (auto allowedPortsIt = config.find("allowedPorts"); allowedPortsIt != config.end())
        {
            auto allowedPortsArray = allowedPortsIt->toArray();

            std::vector<uint16_t> allowedPorts;
            for(auto value : allowedPortsArray) {
                auto port = value.toInt();
                TEGO_THROW_IF_FALSE(port > 0 && port < 65536);

                // don't add duplicates
                if (std::find(allowedPorts.begin(), allowedPorts.end(), port) == allowedPorts.end())
                {
                    allowedPorts.push_back(static_cast<uint16_t>(port));
                }
            }
            std::sort(allowedPorts.begin(), allowedPorts.end());

            if (allowedPorts.size() > 0)
            {
                tego_tor_daemon_config_set_allowed_ports(
                    daemonConfig.get(),
                    allowedPorts.data(),
                    allowedPorts.size(),
                    tego::throw_on_error());

                tor["allowedPorts"] = ([&]() -> QJsonArray {
                    QJsonArray retval;
                    for(auto port : allowedPorts) {
                        retval.push_back(port);
                    }
                    return retval;
                })();
            }
        }
        // bridges
        if (auto bridgeTypeIt = config.find("bridgeType"); bridgeTypeIt != config.end() && *bridgeTypeIt != "none")
        {
            auto bridgeType = bridgeTypeIt->toString();

            // sets list of bridge strings
            const auto tegoTorDaemonConfigSetBridges = [&](const std::vector<std::string>& bridgeStrings) -> void {

                // convert strings to std::string
                const auto bridgeCount = static_cast<size_t>(bridgeStrings.size());

                // allocate buffers to pass to tego
                auto rawBridges = std::make_unique<const char* []>(bridgeCount);
                auto rawBridgeLengths = std::make_unique<size_t[]>(bridgeCount);

                for(size_t i = 0; i < bridgeCount; ++i) {
                    const auto& bridgeString = bridgeStrings[i];
                    rawBridges[i] = bridgeString.c_str();
                    rawBridgeLengths[i] = bridgeString.size();
                }

                tego_tor_daemon_config_set_bridges(
                    daemonConfig.get(),
                    const_cast<const char**>(rawBridges.get()),
                    rawBridgeLengths.get(),
                    bridgeCount,
                    tego::throw_on_error());
            };

            if (bridgeType == "custom")
            {
                auto bridgeStringsIt = config.find("bridgeStrings");
                TEGO_THROW_IF_EQUAL(bridgeStringsIt, config.end());

                std::vector<std::string> bridgeStrings;
                QJsonArray bridgeStringsArray;
                for(auto entry : bridgeStringsIt->toArray()) {
                    auto bridgeString = entry.toString();
                    bridgeStrings.push_back(bridgeString.toStdString());
                    bridgeStringsArray.push_back(bridgeString);
                }
                tegoTorDaemonConfigSetBridges(bridgeStrings);

                tor["bridgeType"] = "custom";
                tor["bridgeStrings"] = bridgeStringsArray;
            }
            else if (auto bridgeStrings = this->getBridgeStringsForType(bridgeType);
                     bridgeStrings.size() > 0)
            {
                // ensure the bridges are ordered randomly per user to distribute to all users evenly
                // but keep the seed per user consistent so their individual experience is consistent
                auto seedJson = SettingsObject().read("tor.seed");
                uint32_t seed = 0;

                // ensure the signed -> unsigned conversion does as we expect
                typedef decltype(seedJson.toInt()) json_int_t;
                static_assert(std::numeric_limits<json_int_t>::max() <= std::numeric_limits<uint32_t>::max());

                if (auto val = seedJson.toInt(-1); val >= 0)
                {
                    seed = static_cast<uint32_t>(val);
                }
                else
                {
                    // get a random quint32
                    seed = QRandomGenerator::global()->generate();
                    // now ensure we can save this value as an json_int_t
                    seed = seed % static_cast<uint32_t>(std::numeric_limits<json_int_t>::max());
                }

                // save seed to settings
                tor["seed"] = static_cast<json_int_t>(seed);

                // shuffle the bridge list so that users don't all select the first one
                std::minstd_rand rand;
                rand.seed(seed);
                std::shuffle(bridgeStrings.begin(), bridgeStrings.end(), rand);

                tegoTorDaemonConfigSetBridges(bridgeStrings);
                tor["bridgeType"] = bridgeType;
            }
        }
        // pluggable transports
        if (!pluggableTransportConfigs.empty()) {
            std::vector<tego_pluggable_transport_config*> pt_configs;
            for(auto it = pluggableTransportConfigs.begin(); it != pluggableTransportConfigs.end(); ++it) {
                // marshall binary_name
                // Use toUtf8() instead of toStdString() to ensure proper UTF-8 encoding
                // on non-UTF-8 locale systems (e.g., Chinese Windows uses GBK by default)
                const auto binaryPathUtf8 = (qApp->applicationDirPath() + QStringLiteral("/pluggable_transports/") + QString::fromStdString(it->binary_name)).toUtf8();
                const auto binaryPathLen = static_cast<size_t>(binaryPathUtf8.size());
                const auto rawBinaryPath = binaryPathUtf8.constData();

                // marshall transports
                const auto transportCount = it->transports.size();
                auto rawTransports = std::make_unique<const char* []>(transportCount);
                auto rawTransportLengths = std::make_unique<size_t[]>(transportCount);
                size_t transportIndex = 0;
                for (auto tit = it->transports.begin(); tit != it->transports.end(); ++tit) {
                    rawTransports[transportIndex] = tit->c_str();
                    rawTransportLengths[transportIndex] = tit->size();
                    ++transportIndex;
                }

                // marshall options
                const auto optionCount = it->options.size();
                auto rawOptions = std::make_unique<const char* []>(optionCount);
                auto rawOptionLengths = std::make_unique<size_t[]>(optionCount);
                size_t optionIndex = 0;
                for (auto oit = it->options.begin(); oit != it->options.end(); ++oit) {
                    rawOptions[optionIndex] = oit->c_str();
                    rawOptionLengths[optionIndex] = oit->size();
                    ++optionIndex;
                }

                std::unique_ptr<tego_pluggable_transport_config> pt_config;
                tego_pluggable_transport_config_initialize(
                    tego::out(pt_config),
                    rawBinaryPath,
                    binaryPathLen,
                    rawTransports.get(),
                    rawTransportLengths.get(),
                    transportCount,
                    rawOptions.get(),
                    rawOptionLengths.get(),
                    optionCount,
                    tego::throw_on_error());
                pt_configs.push_back(pt_config.release());
            }
            tego_tor_daemon_config_set_pluggable_transport_configs(daemonConfig.get(),
                pt_configs.data(),
                pt_configs.size(),
                tego::throw_on_error());
            for (auto pt_config: pt_configs) {
                tego_pluggable_transport_config_delete(pt_config);
            }
        }

        if (out_config != nullptr) {
            *out_config = daemonConfig.release();
        }
    }

    QJsonObject TorControl::getConfiguration()
    {
        return SettingsObject().read("tor").toObject();
    }


    void TorControl::beginBootstrap() try
    {
        // reset bootstrap progress
        setBootstrapStatus(0, tego_tor_bootstrap_tag_starting, "");

        //
        // Create Tor Config
        //

        auto networkSettings = SettingsObject().read("tor").toObject();
        std::unique_ptr<tego_tor_daemon_config> daemonConfig;
        this->settings_to_tor_config(networkSettings, tego::out(daemonConfig));


        //
        // Load/Generate Host Identity Key
        //

        auto privateKeyString = SettingsObject("identity").read<QString>("privateKey");

        std::unique_ptr<tego_ed25519_private_key> privateKey;
        if (privateKeyString.isEmpty()) {
            // generate a new one
            tego_ed25519_private_key_generate(tego::out(privateKey), tego::throw_on_error());

            char rawKeyBlob[TEGO_ED25519_KEYBLOB_SIZE] = {0};
            tego_ed25519_keyblob_from_ed25519_private_key(
                rawKeyBlob,
                sizeof(rawKeyBlob),
                privateKey.get(),
                tego::throw_on_error());

            QString keyBlob(rawKeyBlob);
            SettingsObject so(QStringLiteral("identity"));
            so.write("privateKey", keyBlob);
        } else {
            // construct privatekey from privateKey keyblob
            auto keyBlob = privateKeyString.toUtf8();
            tego_ed25519_private_key_from_ed25519_keyblob(
                tego::out(privateKey),
                keyBlob.data(),
                static_cast<size_t>(keyBlob.size()),
                tego::throw_on_error());
        }

        //
        // Load Contacts
        //

        auto contactsManager = shims::UserIdentity::userIdentity->getContacts();

        // load all of our user objects
        std::vector<tego_user_id*> userIds;
        std::vector<tego_user_type> userTypes;
        auto userIdCleanup = tego::make_scope_exit([&]() -> void
        {
            std::for_each(userIds.begin(), userIds.end(), &tego_user_id_delete);
        });

        for(auto user : contactsManager->contacts()) {
            const auto status = user->getStatus();
            auto user_id = user->toTegoUserId();
            userIds.push_back(user_id.release());
            auto user_type = [=]() {
                switch (status) {
                    case shims::ContactUser::Offline: return tego_user_type_allowed;
                    case shims::ContactUser::RequestPending: return tego_user_type_pending;
                    case shims::ContactUser::RequestRejected: return tego_user_type_rejected;
                }
            }();
            userTypes.push_back(user_type);
        }

        Q_ASSERT(userIds.size() == userTypes.size());
        const size_t userCount = userIds.size();

        tego_context_begin(
            context,
            daemonConfig.get(),
            privateKey.get(),
            userIds.data(),
            userTypes.data(),
            userCount,
            tego::throw_on_error());

        shims::TorManager::torManager->setRunning("Yes");

    } catch (std::exception& ex) {
        LOG_ERROR(ex.what());
    }

    void TorControl::cancelBootstrap() try
    {
        tego_context_end(context, tego::throw_on_error());
    } catch (std::exception& ex) {
        LOG_ERROR(ex.what());
    }

    QList<QString> TorControl::getBridgeTypes()
    {
        auto types = defaultBridges.keys();
        if (auto it = std::find(types.begin(), types.end(), recommendedBridgeType); it != types.end()) {
            std::iter_swap(it, types.begin());
        }

        // swap out legacy meek-azure name with meek
        // TODO: we can remove this once upstream's pt_config.json has migrated from meek-azure
        // to meek. See upstream issue:
        // - https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/issues/41532
        if (auto it = std::find(types.begin(), types.end(), "meek-azure"); it != types.end()) {
            *it = "meek";
        }

        return types;
    }

    std::vector<std::string> TorControl::getBridgeStringsForType(const QString &bridgeType)
    {
        // check if we need to use the legacy name
        // TODO: we can remove this once upstream's pt_config.json has migrated from meek-azure
        // to meek. See upstream issue:
        // - https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/issues/41532
        QString bridgeType2 = bridgeType != "meek" ? bridgeType : "meek-azure";

        if (auto it = defaultBridges.find(bridgeType2); it != defaultBridges.end()) {
            return *it;
        }
        return {};
    }

    // for now we just assume we always have ownership,
    // as we have no way in config to setup usage of
    // an existing tor process
    bool TorControl::hasOwnership() const
    {
        return true;
    }

    QString TorControl::torVersion() const
    {
        return tego_context_get_tor_version_string(
            context,
            tego::throw_on_error());
    }

    TorControl::TorStatus TorControl::torStatus() const
    {
        tego_tor_network_status status;
        tego_context_get_tor_network_status(
            context,
            &status,
            tego::throw_on_error());

        switch(status)
        {
            case tego_tor_network_status_unknown:
                return TorControl::TorUnknown;
            case tego_tor_network_status_ready:
                return TorControl::TorReady;
            case tego_tor_network_status_offline:
                return TorControl::TorOffline;
            default:
                return TorControl::TorError;
        }
    }

    QVariantMap TorControl::bootstrapStatus() const
    {
        QVariantMap retval;
        retval["progress"] = this->m_bootstrapProgress;
        retval["done"] = (this->m_bootstrapTag == tego_tor_bootstrap_tag_done);
        retval["summary"] = this->m_bootstrapSummary;
        return retval;
    }

    void TorControl::setTorStatus(TorStatus status)
    {
        auto oldStatus = m_torStatus;
        if (oldStatus == status) return;

        m_torStatus = status;
        emit this->torStatusChanged(
            static_cast<int>(status),
            static_cast<int>(oldStatus));
    }

    void TorControl::setBootstrapStatus(int32_t progress, tego_tor_bootstrap_tag tag, QString&& summary)
    {
        TEGO_THROW_IF_FALSE(progress >= 0 && progress <= 100);
        this->m_bootstrapProgress = static_cast<int>(progress);
        this->m_bootstrapTag = tag;
        this->m_bootstrapSummary = std::move(summary);

        emit torControl->bootstrapStatusChanged();
    }
}
