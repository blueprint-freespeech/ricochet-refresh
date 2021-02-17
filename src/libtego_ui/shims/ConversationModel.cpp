#include "ContactUser.h"
#include "ConversationModel.h"
#include "UserIdentity.h"

namespace shims
{
    ConversationModel::ConversationModel(QObject *parent)
    : QAbstractListModel(parent)
    , contactUser(nullptr)
    , messages({})
    , unreadCount(0)
    {
        connect(this, &ConversationModel::unreadCountChanged, [self=this](int prevCount, int currentCount) -> void
        {
            static int globalUnreadCount = 0;

            const auto delta = currentCount - prevCount;
            globalUnreadCount += delta;

            qDebug() << "globalUnreadCount:" << globalUnreadCount;
#ifdef Q_OS_MAC
            QtMac::setBadgeLabelText(globalUnreadCount == 0 ? QString() : QString::number(globalUnreadCount));
#endif
        });
    }

    QHash<int,QByteArray> ConversationModel::roleNames() const
    {
        QHash<int, QByteArray> roles;
        roles[Qt::DisplayRole] = "text";
        roles[TimestampRole] = "timestamp";
        roles[IsOutgoingRole] = "isOutgoing";
        roles[StatusRole] = "status";
        roles[SectionRole] = "section";
        roles[TimespanRole] = "timespan";
        roles[TypeRole] = "type";
        roles[TransferRole] = "transfer";
        return roles;
    }

    int ConversationModel::rowCount(const QModelIndex &parent) const
    {
        if (parent.isValid())
            return 0;
        return messages.size();
    }

    QVariant ConversationModel::data(const QModelIndex &index, int role) const
    {
        if (!index.isValid() || index.row() >= messages.size())
            return QVariant();

        const MessageData &message = messages[index.row()];

        switch (role) {
            case Qt::DisplayRole:
                if (message.type == TextMessage)
                {
                    return message.text;
                }
                else
                {
                    return QStringLiteral("not a text message");
                }

            case TimestampRole: return message.time;
            case IsOutgoingRole: return message.status != Received;
            case StatusRole: return message.status;

            case SectionRole: {
                if (contact()->getStatus() == ContactUser::Online)
                    return QString();
                if (index.row() < messages.size() - 1) {
                    const MessageData &next = messages[index.row()+1];
                    if (next.status != Received && next.status != Delivered)
                        return QString();
                }
                for (int i = 0; i <= index.row(); i++) {
                    if (messages[i].status == Received || messages[i].status == Delivered)
                        return QString();
                }
                return QStringLiteral("offline");
            }
            case TimespanRole: {
                if (index.row() < messages.size() - 1)
                    return messages[index.row() + 1].time.secsTo(messages[index.row()].time);
                else
                    return -1;
            }
            case TypeRole: {
                if (message.type == TextMessage) {
                    return QStringLiteral("text");
                }
                else if (message.type == TransferMessage) {
                    return QStringLiteral("transfer");
                }
                else {
                    return QStringLiteral("invalid");
                }
            case TransferRole:
                if (message.type == TransferMessage)
                {
                    QVariantMap transfer;
                    transfer["fileName"] = message.fileName;
                    transfer["fileSize"] = message.fileSize;
                    transfer["fileHash"] = message.fileHash;
                    transfer["transferId"] = message.transferId;
                    return transfer;
                }
            }
        }

        return QVariant();
    }

    shims::ContactUser* ConversationModel::contact() const
    {
        return contactUser;
    }

    void ConversationModel::setContact(shims::ContactUser *contact)
    {
        this->contactUser = contact;
        emit contactChanged();
    }

    int ConversationModel::getUnreadCount() const
    {
        return unreadCount;
    }

    void ConversationModel::resetUnreadCount()
    {
        this->setUnreadCount(0);
    }

    void ConversationModel::setUnreadCount(int count)
    {
        Q_ASSERT(count >= 0);

        const auto oldUnreadCount = this->unreadCount;
        if(oldUnreadCount != count)
        {
            this->unreadCount = count;
            emit unreadCountChanged(oldUnreadCount, unreadCount);

            auto userIdentity = shims::UserIdentity::userIdentity;
            auto contactsManager = userIdentity->getContacts();
            contactsManager->setUnreadCount(this->contactUser, count);
        }
    }

    void ConversationModel::sendMessage(const QString &text)
    {
        logger::println("sendMessage : {}", text);
        auto userIdentity = shims::UserIdentity::userIdentity;
        auto context = userIdentity->getContext();

        auto utf8Str = text.toUtf8();
        if (utf8Str.size() == 0)
        {
            return;
        }

        const auto userId = this->contactUser->toTegoUserId();
        tego_message_id_t messageId = 0;

        // send message and save off the id associated with it
        tego_context_send_message(
            context,
            userId.get(),
            utf8Str.data(),
            utf8Str.size(),
            &messageId,
            tego::throw_on_error());

        // store data locally for UI
        MessageData md;
        md.type = TextMessage;
        md.text = text;
        md.time = QDateTime::currentDateTime();
        md.identifier = messageId;
        md.status = Queued;

        this->beginInsertRows(QModelIndex(), 0, 0);
        this->messages.prepend(std::move(md));
        this->endInsertRows();
    }

    void ConversationModel::sendFile()
    {
        auto fileName =
            QFileDialog::getOpenFileName(
                nullptr,
                tr("Open File"),
                QDir::homePath(),
                nullptr);

        if (!fileName.isEmpty())
        {
            auto userIdentity = shims::UserIdentity::userIdentity;
            auto context = userIdentity->getContext();
            const auto path = fileName.toUtf8();
            const auto userId = this->contactUser->toTegoUserId();
            tego_attachment_id_t attachmentId;
            std::unique_ptr<tego_file_hash_t> fileHash;

            try
            {
                tego_context_send_attachment_request(
                    context,
                    userId.get(),
                    path.data(),
                    path.size(),
                    &attachmentId,
                    tego::out(fileHash),
                    tego::throw_on_error());

                logger::println("send file request id : {}, hash : {}", attachmentId, tego::to_string(fileHash.get()));

                MessageData md;
                md.type = TransferMessage;
                md.fileName = fileName;
                // todo: maybe update API to spit out the file size?
                md.fileSize = 0;
                md.fileHash = QString::fromStdString(tego::to_string(fileHash.get()));
                md.transferId = attachmentId;

                this->beginInsertRows(QModelIndex(), 0, 0);
                this->messages.prepend(std::move(md));
                this->endInsertRows();
            }
            catch(const std::runtime_error& err)
            {
                logger::println("error sending file request: {}", err.what());
                qWarning() << err.what();
            }
        }
    }

    void ConversationModel::clear()
    {
        if (messages.isEmpty())
        {
            return;
        }

        beginRemoveRows(QModelIndex(), 0, messages.size()-1);
        messages.clear();
        endRemoveRows();

        resetUnreadCount();
    }

    void ConversationModel::messageReceived(tego_message_id_t messageId, QDateTime timestamp, const QString& text)
    {
        logger::trace();
        logger::println(" messageId : {}", messageId);
        logger::println(" text : '{}'", text);
        logger::println(" time : {}", timestamp.toString());

        MessageData md;
        md.type = TextMessage;
        md.text = text;
        md.time = timestamp;
        md.identifier = messageId;
        md.status = Received;

        this->beginInsertRows(QModelIndex(), 0, 0);
        this->messages.prepend(std::move(md));
        this->endInsertRows();

        this->setUnreadCount(this->unreadCount + 1);
    }

    void ConversationModel::messageAcknowledged(tego_message_id_t messageId, bool accepted)
    {
        auto row = this->indexOfIdentifier(messageId, true);
        Q_ASSERT(row >= 0);

        MessageData &data = messages[row];
        data.status = accepted ? Delivered : Error;
        emit dataChanged(index(row, 0), index(row, 0));
    }

    int ConversationModel::indexOfIdentifier(tego_message_id_t messageId, bool isOutgoing) const
    {
        for (int i = 0; i < messages.size(); i++) {
            const auto& currentMessage = messages[i];

            if (currentMessage.identifier == messageId && (currentMessage.status != Received) == isOutgoing)
                return i;
        }
        return -1;
    }
}