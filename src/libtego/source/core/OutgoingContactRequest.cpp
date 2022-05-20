// Copyright (C) 2014, John Brooks <john.brooks@dereferenced.net>
//
// SPDX-License-Identifier: GPL-3.0-only

#include "OutgoingContactRequest.h"
#include "ContactsManager.h"
#include "ContactUser.h"
#include "UserIdentity.h"
#include "IncomingRequestManager.h"
#include "utils/Useful.h"
#include "protocol/ContactRequestChannel.h"

#include "ed25519.hpp"
#include "context.hpp"
#include "user.hpp"
#include "globals.hpp"

OutgoingContactRequest *OutgoingContactRequest::createNewRequest(ContactUser *user, const QString &message)
{
    Q_ASSERT(!user->contactRequest());

    user->createContactRequest(message);
    Q_ASSERT(user->contactRequest());
    user->contactRequest()->setStatus(Pending);
    return user->contactRequest();
}

OutgoingContactRequest::OutgoingContactRequest(ContactUser *u, const QString& msg)
    : QObject(u), user(u)
    , m_status(Pending)
    , m_message(msg)
{
    emit user->identity->contacts.outgoingRequestAdded(this);

    attemptAutoAccept();
}

QString OutgoingContactRequest::message() const
{
    return m_message;
}

OutgoingContactRequest::Status OutgoingContactRequest::status() const
{
    return m_status;
}

void OutgoingContactRequest::setStatus(Status newStatus)
{
    Status oldStatus = status();
    if (newStatus == oldStatus)
        return;

    m_status = newStatus;

    if (m_status == Accepted || m_status == Error || m_status == Rejected)
    {
        // convert our hostname to just the service id raw string
        auto serviceIdString = user->hostname().chopped(tego::static_strlen(".onion")).toUtf8();
        // ensure valid service id
        auto serviceId = std::make_unique<tego_v3_onion_service_id>(serviceIdString.data(), serviceIdString.size());
        // create user id object from service id
        auto userId = std::make_unique<tego_user_id>(*serviceId.get());

        tego_bool_t requestAccepted = ((m_status == Accepted) ? TEGO_TRUE : TEGO_FALSE);

        tego::g_globals.context->callback_registry_.emit_chat_request_response_received(userId.release(), requestAccepted);
    }

    emit statusChanged(newStatus, oldStatus);
}

void OutgoingContactRequest::attemptAutoAccept()
{
    /* Check if there is an existing incoming request that matches this one; if so, treat this as accepted
     * automatically and accept that incoming request for this user */
    QByteArray hostname = user->hostname().toLatin1();

    IncomingContactRequest *incomingReq = user->identity->contacts.incomingRequests.requestFromHostname(hostname);
    if (incomingReq)
    {
        qDebug() << "Automatically accepting an incoming contact request matching a newly created outgoing request";

        accept();
        incomingReq->accept(user);
    }
}

void OutgoingContactRequest::sendRequest(const QSharedPointer<Protocol::Connection> &connection)
{
    if (connection != user->connection()) {
        TEGO_BUG() << "OutgoingContactRequest connection doesn't match the assigned user";
        return;
    }

    if (connection->purpose() != Protocol::Connection::Purpose::OutboundRequest) {
        TEGO_BUG() << "OutgoingContactRequest told to use a connection of invalid purpose" << int(connection->purpose());
        return;
    }

    // XXX timeouts
    Protocol::ContactRequestChannel *channel = new Protocol::ContactRequestChannel(Protocol::Channel::Outbound, connection.data());
    connect(channel, &Protocol::ContactRequestChannel::requestStatusChanged,
            this, &OutgoingContactRequest::requestStatusChanged);

    // On any final response, the channel will be closed. Unless the purpose has been
    // changed (to KnownContact, on accept), close the connection at that time. That
    // will eventually trigger a retry via ContactUser if the request is still valid.
    connect(channel, &Protocol::Channel::invalidated, this,
        [this,connection]() {
            if (connection->isConnected() &&
                connection->purpose() == Protocol::Connection::Purpose::OutboundRequest)
            {
                qDebug() << "Closing connection attached to an OutgoingContactRequest because ContactRequestChannel was closed";
                connection->close();
            }
        }
    );

    if (!message().isEmpty())
        channel->setMessage(message());

    if (!channel->openChannel()) {
        TEGO_BUG() << "Channel for outgoing contact request failed";
        return;
    }
}

void OutgoingContactRequest::removeRequest()
{
    if (user->connection()) {
        Protocol::Channel *channel = user->connection()->findChannel<Protocol::ContactRequestChannel>();
        if (channel)
            channel->closeChannel();
    }

    /* Clear the request settings */
    logger::trace();
    emit removed();
}

void OutgoingContactRequest::accept()
{
    setStatus(Accepted);
    emit accepted();
    removeRequest();
}

void OutgoingContactRequest::reject(bool error)
{
    setStatus(error ? Error : Rejected);

    if (user->connection()) {
        Protocol::Channel *channel = user->connection()->findChannel<Protocol::ContactRequestChannel>();
        if (channel)
            channel->closeChannel();
    }

    emit rejected();
}

void OutgoingContactRequest::cancel()
{
    removeRequest();
}

void OutgoingContactRequest::requestStatusChanged(int status)
{
    using namespace Protocol::Data::ContactRequest;
    switch (status) {
        case Response::Pending:
            setStatus(Acknowledged);
            break;
        case Response::Accepted:
            accept();
            break;
        case Response::Rejected:
            reject(false);
            break;
        case Response::Error:
            reject(true);
            break;
        default:
            TEGO_BUG() << "Unknown ContactRequest response status";
            break;
    }
}
