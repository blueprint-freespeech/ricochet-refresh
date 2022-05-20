// Copyright (C) 2014, John Brooks <john.brooks@dereferenced.net>
//
// SPDX-License-Identifier: GPL-3.0-only

#ifndef IDENTITYMANAGER_H
#define IDENTITYMANAGER_H

// TODO: this needs to go entirely, we do not have multiple simultaneous UserIdentity objects
class IdentityManager : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(IdentityManager)

public:
    // serviceID : string ED25519-V3 keyblob pulled from config.json, or empty string to create one
    explicit IdentityManager(const QString& serviceID, QObject *parent = 0);
    ~IdentityManager();

    const QList<class UserIdentity*> &identities() const { return m_identities; }
    class UserIdentity *lookupHostname(const QString &hostname) const;
    class UserIdentity *lookupUniqueID(int uniqueID) const;

    class UserIdentity *createIdentity();

signals:
    void contactDeleted(class ContactUser *user, class UserIdentity *identity);
    void outgoingRequestAdded(class OutgoingContactRequest *request, class UserIdentity *identity);
    void incomingRequestAdded(class IncomingContactRequest *request, class UserIdentity *identity);
    void incomingRequestRemoved(class IncomingContactRequest *request, class UserIdentity *identity);

private slots:
    void onOutgoingRequest(class OutgoingContactRequest *request);
    void onIncomingRequest(class IncomingContactRequest *request);
    void onIncomingRequestRemoved(class IncomingContactRequest *request);

private:
    QList<class UserIdentity*> m_identities;
    int highestID;

    void addIdentity(class UserIdentity *identity);
};

extern class IdentityManager* identityManager;

#endif // IDENTITYMANAGER_H
