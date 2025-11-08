#include "UserIdentity.h"
#include "ContactIDValidator.h"

namespace shims
{
    ContactIDValidator::ContactIDValidator(QObject *parent)
    : QRegularExpressionValidator(parent)
    {
        QRegularExpressionValidator::setRegularExpression(QRegularExpression(QStringLiteral("ricochet:([a-z2-7]{56})")));
    }

    void ContactIDValidator::fixup(QString &text) const
    {
        text = text.trimmed().toLower();
    }

    QValidator::State ContactIDValidator::validate(QString &text, int &pos) const
    {
        fixup(text);

        const auto result = QRegularExpressionValidator::validate(text, pos);
        switch(result) {
        case QValidator::Acceptable:
            if(isValidID(text)) {
                if (auto contact = matchingContact(text); contact != nullptr) {
                    emit matchesContact(contact->getNickname());
                    return QValidator::Invalid;
                }
                if (matchesIdentity(text)) {
                    emit matchesSelf();
                    return QValidator::Invalid;
                }
                emit acceptable();
                return QValidator::Acceptable;
            } else {
                emit invalidServiceId();
                return QValidator::Invalid;
            }
        case QValidator::Intermediate:
            emit intermediate();
            return QValidator::Intermediate;
        default:
            return result;
        }
    }

    shims::ContactUser* ContactIDValidator::matchingContact(const QString &text) const
    {
        auto contactsManager = UserIdentity::userIdentity->getContacts();
        return contactsManager->getShimContactByContactId(text);
    }

    bool ContactIDValidator::matchesIdentity(const QString &text) const
    {
        auto context = UserIdentity::userIdentity->getContext();

        std::unique_ptr<tego_user_id> userId;
        tego_context_get_host_user_id(context, tego::out(userId), tego::throw_on_error());

        std::unique_ptr<tego_v3_onion_service_id> serviceId;
        tego_user_id_get_v3_onion_service_id(userId.get(), tego::out(serviceId), tego::throw_on_error());

        char serviceIdString[TEGO_V3_ONION_SERVICE_ID_SIZE] = {0};
        tego_v3_onion_service_id_to_string(serviceId.get(), serviceIdString, sizeof(serviceIdString), tego::throw_on_error());

        auto utf8Text = text.mid(tego::static_strlen("ricochet:")).toUtf8();
        auto utf8ServiceId = QByteArray(serviceIdString, TEGO_V3_ONION_SERVICE_ID_LENGTH);

        return utf8Text == utf8ServiceId;
    }

    bool ContactIDValidator::isValidID(const QString &serviceID) const
    {
        auto strippedID = serviceID.mid(tego::static_strlen("ricochet:")).toUtf8();
        bool valid = tego_v3_onion_service_id_string_is_valid(strippedID.constData(), static_cast<size_t>(strippedID.size()), nullptr) == TEGO_TRUE;

        return valid;
    }
}
