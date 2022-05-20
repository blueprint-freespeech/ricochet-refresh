// Copyright (C) 2014, John Brooks <john.brooks@dereferenced.net>
//
// SPDX-License-Identifier: GPL-3.0-only

#ifndef CONTACTSMANAGER_H
#define CONTACTSMANAGER_H

#include "core/IncomingRequestManager.h"

class OutgoingContactRequest;
class UserIdentity;
class IncomingRequestManager;

class ContactsManager : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(ContactsManager)

    friend class OutgoingContactRequest;

public:
    UserIdentity * const identity;
    IncomingRequestManager incomingRequests;

    explicit ContactsManager(UserIdentity *identity);

    IncomingRequestManager *incomingRequestManager() { return &incomingRequests; }

    const QList<ContactUser*> &contacts() const { return pContacts; }
    ContactUser *lookupSecret(const QByteArray &secret) const;
    ContactUser *lookupHostname(const QString &hostname) const;

    /* Create a new user and a contact request for that user. Use this instead of addContact.
     * Note that contactID should be an ricochet: ID. */
    ContactUser *createContactRequest(const QString &contactID, const QString &message);

    /* addContact will add the contact, but does not create a request. Use createContactRequest */
    ContactUser *addContact(const QString& hostname);

    static QString hostnameFromID(const QString &ID);

    // tego_user_type_allowed
    void addAllowedContacts(const QList<QString>& userHostnames);
    // tego_user_type_requesting
    void addIncomingRequests(const QList<QString>& userHostnames);
    // tego_user_type_blocked
    void addRejectedIncomingRequests(const QList<QString>& userHostnames);
    // tego_user_type_pending
    void addOutgoingRequests(const QList<QString>& userHostnames);
    // tego_user_type_rejected
    void addRejectedOutgoingRequests(const QList<QString>& userHostnames);

    int globalUnreadCount() const;

signals:
    void contactAdded(ContactUser *user);
    void outgoingRequestAdded(OutgoingContactRequest *request);

    void unreadCountChanged(ContactUser *user, int unreadCount);

    void contactStatusChanged(ContactUser* user, int status);

private slots:
    void contactDeleted(ContactUser *user);
    void onUnreadCountChanged();

private:
    QList<ContactUser*> pContacts;

    void connectSignals(ContactUser *user);
};

#endif // CONTACTSMANAGER_H
