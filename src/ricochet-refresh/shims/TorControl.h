#pragma once

#include "TorCommand.h"

namespace shims
{
	// shim version of Tor::ToControl with just the functionality requried by the UI
    class TorControl : public QObject
    {
        Q_OBJECT
        Q_ENUMS(Status TorStatus)

        Q_PROPERTY(bool hasOwnership READ hasOwnership CONSTANT)
        Q_PROPERTY(QString torVersion READ torVersion CONSTANT)
        // Status of Tor (and whether it believes it can connect)
        Q_PROPERTY(TorStatus torStatus READ torStatus NOTIFY torStatusChanged)
        Q_PROPERTY(QVariantMap bootstrapStatus READ bootstrapStatus NOTIFY bootstrapStatusChanged)
    public:
        enum TorStatus
        {
            TorError = -1,
            TorUnknown,
            TorOffline,
            TorReady
        };

        Q_INVOKABLE QObject *setConfiguration(const QVariantMap &options);
        QObject* setConfiguration(const QJsonObject& options);
        Q_INVOKABLE QJsonObject getConfiguration();
        Q_INVOKABLE QObject *beginBootstrap();

        // QVariant(Map) is not needed here, since QT handles the conversion to
        // a JS array for us: see https://doc.qt.io/qt-5/qtqml-cppintegration-data.html#sequence-type-to-javascript-array
        Q_INVOKABLE QList<QString> getBridgeTypes();
        std::vector<std::string> getBridgeStringsForType(const QString &bridgeType);

        TorControl(tego_context* context);

        /* Ownership means that tor is managed by this socket, and we
         * can shut it down, own its configuration, etc. */
        bool hasOwnership() const;
        bool hasBootstrappedSuccessfully() const;

        QString torVersion() const;
        TorStatus torStatus() const;
        QVariantMap bootstrapStatus() const;

        void setTorStatus(TorStatus);
        void setBootstrapStatus(int32_t progress, tego_tor_bootstrap_tag tag, QString&& summary);

        static TorControl* torControl;
        TorControlCommand* m_setConfigurationCommand = nullptr;
        TorStatus m_torStatus = TorUnknown;
        int m_bootstrapProgress = 0;
        tego_tor_bootstrap_tag m_bootstrapTag = tego_tor_bootstrap_tag_invalid;
        QString m_bootstrapSummary;

    signals:
        void torStatusChanged(int newStatus, int oldStatus);
        void bootstrapStatusChanged();

    private:
        tego_context* context;
    };
}