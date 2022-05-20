// Copyright (C) 2014, John Brooks <john.brooks@dereferenced.net>
//
// SPDX-License-Identifier: GPL-3.0-only

#ifndef USERIDENTITY_H
#define USERIDENTITY_H

#include "ContactsManager.h"

namespace Tor
{
    class HiddenService;
}

namespace Protocol
{
    class Connection;
}

class QTcpServer;

/* UserIdentity represents the local identity offered by the user.
 *
 * In particular, it represents the published hidden service, and
 * theoretically holds the list of contacts.
 *
 * At present, implementation (and settings) assumes that there is
 * only one identity, but some code is confusingly written to allow
 * for several.
 */
class UserIdentity : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(UserIdentity)

    friend class IdentityManager;
public:
    const int uniqueID;
    ContactsManager contacts;

    explicit UserIdentity(int uniqueID, const QString& serviceID, QObject *parent = 0);

    /* Properties */
    int getUniqueID() const { return uniqueID; }
    /* Hostname is .onion format, like ContactUser */
    QString hostname() const;
    QString contactID() const;

    ContactsManager *getContacts() { return &contacts; }

    /* State */
    Tor::HiddenService *hiddenService() const { return m_hiddenService; }

    /* Take ownership of an inbound connection. Returns the shared pointer to
     * the connection, and releases the reference held by UserIdentity. */
    QSharedPointer<Protocol::Connection> takeIncomingConnection(Protocol::Connection *connection);

signals:
    void incomingConnection(Protocol::Connection *connection);

private slots:
    void onIncomingConnection();

private:
    Tor::HiddenService *m_hiddenService;
    QTcpServer *m_incomingServer;
    QVector<QSharedPointer<Protocol::Connection>> m_incomingConnections;

    static UserIdentity *createIdentity(int uniqueID);

    void handleIncomingAuthedConnection(Protocol::Connection *connection);
    void setupService(const QString& serviceID);
};

Q_DECLARE_METATYPE(UserIdentity*)

#endif // USERIDENTITY_H
