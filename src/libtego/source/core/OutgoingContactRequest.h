// Copyright (C) 2014, John Brooks <john.brooks@dereferenced.net>
//
// SPDX-License-Identifier: GPL-3.0-only

#ifndef OUTGOINGCONTACTREQUEST_H
#define OUTGOINGCONTACTREQUEST_H

class ContactUser;
class ContactRequestClient;

namespace Protocol {
    class Connection;
}

class OutgoingContactRequest : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(OutgoingContactRequest)

public:
    enum Status
    {
        Pending,
        Acknowledged,
        Accepted,
        Error,
        Rejected,
        FirstResult = Accepted
    };

    static OutgoingContactRequest *createNewRequest(ContactUser *user, const QString &message);

    ContactUser * const user;

    OutgoingContactRequest(ContactUser *user, const QString &message);
    virtual ~OutgoingContactRequest() = default;

    QString myNickname() const;
    QString message() const;
    Status status() const;

public slots:
    void accept();
    void reject(bool error);
    void cancel();

    void sendRequest(const QSharedPointer<Protocol::Connection> &connection);

signals:
    void statusChanged(int newStatus, int oldStatus);
    void accepted();
    void rejected();
    void removed();

private slots:
    void requestStatusChanged(int status);

private:
    Status m_status;
    QString m_message;

    void setStatus(Status newStatus);
    void removeRequest();
    void attemptAutoAccept();
};

#endif // OUTGOINGCONTACTREQUEST_H
