// Copyright (C) 2014, John Brooks <john.brooks@dereferenced.net>
//
// SPDX-License-Identifier: GPL-3.0-only

#ifndef CONVERSATIONMODEL_H
#define CONVERSATIONMODEL_H

#include "core/ContactUser.h"
#include "protocol/ChatChannel.h"
#include "protocol/FileChannel.h"

class ConversationModel : public QAbstractListModel
{
    Q_OBJECT
public:
    typedef Protocol::ChatChannel::MessageId MessageId;
    static_assert(std::is_same_v<MessageId, tego_message_id_t>);

    enum {
        TimestampRole = Qt::UserRole,
        IsOutgoingRole,
        StatusRole,
        SectionRole,
        TimespanRole
    };

    enum MessageStatus {
        Received,
        Queued,
        Sending,
        Delivered,
        Error
    };

    enum MessageType {
        Message,
        File
    };

    ConversationModel(QObject *parent = 0);

    ContactUser *contact() const { return m_contact; }
    void setContact(ContactUser *contact);

    int unreadCount() const { return m_unreadCount; }
    void resetUnreadCount();

    virtual QHash<int,QByteArray> roleNames() const;
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const;
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;

    std::tuple<tego_file_transfer_id_t, std::unique_ptr<tego_file_hash_t>, tego_file_size_t> sendFile(const QString &file_url);
    tego_message_id_t sendMessage(const QString &text);

    void acceptFile(tego_file_transfer_id_t id, const std::string& dest);
    void rejectFile(tego_file_transfer_id_t id);
    void cancelTransfer(tego_file_transfer_id_t id);

    void clear();

signals:
    void contactChanged();
    void unreadCountChanged();

private slots:
    void messageReceived(const QString &text, const QDateTime &time, MessageId id);
    void messageAcknowledged(MessageId id, bool accepted);
    void outboundChannelClosed();
    void sendQueuedMessages();
    void onContactStatusChanged();

    void onFileTransferRequestReceived(tego_file_transfer_id_t id, const QString& filename, tego_file_size_t fileSize, tego_file_hash_t hash);
    void onFileTransferAcknowledged(tego_file_transfer_id_t id, bool ack);
    void onFileTransferRequestResponded(tego_file_transfer_id_t id, tego_file_transfer_response_t response);
    void onFileTransferProgress(tego_file_transfer_id_t id, tego_file_transfer_direction_t direction, tego_file_size_t bytesTransmitted, tego_file_size_t bytesTotal);
    void onFileTransferFinished(tego_file_transfer_id_t id, tego_file_transfer_direction_t direction, tego_file_transfer_result_t result);

private:
    struct MessageData {
        MessageType type;
        QString text;
        tego_file_hash_t fileHash;
        QDateTime time;
        MessageId identifier;
        MessageStatus status;
        quint8 attemptCount;

        MessageData(MessageType m_type, const QString &contents, const QDateTime &t, MessageId id, MessageStatus stat)
            : type(m_type), text(contents), time(t), identifier(id), status(stat), attemptCount(0)
        {
        }
    };

    ContactUser *m_contact;
    QList<MessageData> messages;
    int m_unreadCount;

    // The peer might use recent message IDs between connections to handle
    // re-send. Start at a random ID to reduce chance of collisions, then increment
    MessageId lastMessageId;

    int indexOfIdentifier(MessageId identifier, bool isOutgoing) const;
    void prune();
};

#endif

