// Copyright (C) 2014, John Brooks <john.brooks@dereferenced.net>
//
// SPDX-License-Identifier: GPL-3.0-only

#include "ContactsManager.h"
#include "IncomingRequestManager.h"
#include "OutgoingContactRequest.h"
#include "ContactIDValidator.h"
#include "ConversationModel.h"
#include "protocol/ChatChannel.h"

ContactsManager *contactsManager = 0;

ContactsManager::ContactsManager(UserIdentity *id)
    : identity(id), incomingRequests(this)
{
    contactsManager = this;
}


// tego_user_type_allowed
void ContactsManager::addAllowedContacts(const QList<QString>& userHostnames)
{
    for(const auto& hostname : userHostnames)
    {
        ContactUser *user = new ContactUser(identity, hostname, ContactUser::Offline, this);
        connectSignals(user);
        pContacts.append(user);
        emit contactAdded(user);
    }
}

// tego_user_type_requesting
void ContactsManager::addIncomingRequests(const QList<QString>& userHostnames)
{
    this->incomingRequests.loadRequests(userHostnames);
}

// tego_user_type_blocked
void ContactsManager::addRejectedIncomingRequests(const QList<QString>& userHostnames)
{
    for(const auto& hostname : userHostnames)
    {
        this->incomingRequests.addRejectedHost(hostname.toUtf8());
    }
}

// tego_user_type_pending
void ContactsManager::addOutgoingRequests(const QList<QString>& userHostnames)
{
    for(const auto& hostname : userHostnames)
    {
        this->createContactRequest(QString("ricochet:%1").arg(hostname), QString());
    }
}

// tego_user_type_rejected
void ContactsManager::addRejectedOutgoingRequests(const QList<QString>& userHostnames)
{
    for(const auto& hostname : userHostnames)
    {
        ContactUser *user = new ContactUser(identity, hostname, ContactUser::RequestRejected, this);

        connect(user, SIGNAL(contactDeleted(ContactUser*)), SLOT(contactDeleted(ContactUser*)));
        pContacts.append(user);

        // emit contactAdded(user);
    }
}

ContactUser *ContactsManager::addContact(const QString& hostname)
{
    ContactUser *user = new ContactUser(identity, hostname);
    user->setParent(this);
    connectSignals(user);

    qDebug() << "Added new contact" << hostname;

    pContacts.append(user);
    emit contactAdded(user);

    return user;
}

void ContactsManager::connectSignals(ContactUser *user)
{
    connect(user, SIGNAL(contactDeleted(ContactUser*)), SLOT(contactDeleted(ContactUser*)));
    connect(user->conversation(), &ConversationModel::unreadCountChanged, this, &ContactsManager::onUnreadCountChanged);
    connect(user, &ContactUser::statusChanged, [this,user]() { emit contactStatusChanged(user, user->status()); });
}

ContactUser *ContactsManager::createContactRequest(const QString &contactid, const QString &message)
{
    logger::println("contactId : {}", contactid);
    logger::println("message : {}", message);

    QString hostname = ContactIDValidator::hostnameFromID(contactid);
    if (hostname.isEmpty() || lookupHostname(contactid))
    {
        return 0;
    }

    bool b = blockSignals(true);
    const auto contactHostname = ContactIDValidator::hostnameFromID(contactid);
    ContactUser *user = addContact(contactHostname);
    blockSignals(b);
    if (!user)
        return user;
    user->setHostname(ContactIDValidator::hostnameFromID(contactid));

    OutgoingContactRequest::createNewRequest(user, message);

    /* Signal deferred from addContact to avoid changing the status immediately */
    Q_ASSERT(user->status() == ContactUser::RequestPending);
    emit contactAdded(user);
    return user;
}

void ContactsManager::contactDeleted(ContactUser *user)
{
    pContacts.removeOne(user);
}

ContactUser *ContactsManager::lookupHostname(const QString &hostname) const
{
    QString ohost = ContactIDValidator::hostnameFromID(hostname);
    if (ohost.isNull())
        ohost = hostname;

    if (!ohost.endsWith(QLatin1String(".onion")))
        ohost.append(QLatin1String(".onion"));

    for (QList<ContactUser*>::ConstIterator it = pContacts.begin(); it != pContacts.end(); ++it)
    {
        if (ohost.compare((*it)->hostname(), Qt::CaseInsensitive) == 0)
            return *it;
    }

    return 0;
}

void ContactsManager::onUnreadCountChanged()
{
    ConversationModel *model = qobject_cast<ConversationModel*>(sender());
    Q_ASSERT(model);
    if (!model)
        return;
    ContactUser *user = model->contact();

    emit unreadCountChanged(user, model->unreadCount());
}

int ContactsManager::globalUnreadCount() const
{
    int re = 0;
    foreach (ContactUser *u, pContacts) {
        if (u->conversation())
            re += u->conversation()->unreadCount();
    }
    return re;
}

