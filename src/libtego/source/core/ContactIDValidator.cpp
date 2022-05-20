// Copyright (C) 2014, John Brooks <john.brooks@dereferenced.net>
//
// SPDX-License-Identifier: GPL-3.0-only

#include "IdentityManager.h"
#include "ContactIDValidator.h"
#include "utils/StringUtil.h"

// multiple consumers of this regex object seems to cause thread contention issues
// and segfaults, so make it thread_local to sidestep the issue for now
static thread_local QRegularExpression regex(QStringLiteral("ricochet:([a-z2-7]{56})"));

ContactIDValidator::ContactIDValidator(QObject *parent)
    : QRegularExpressionValidator(parent)
    , m_uniqueIdentity(identityManager->identities()[0])
{
    setRegularExpression(regex);
}

QValidator::State ContactIDValidator::validate(QString &text, int &pos) const
{
    Q_UNUSED(pos);
    fixup(text);
    if (text.isEmpty())
        return QValidator::Intermediate;

    QValidator::State re = QRegularExpressionValidator::validate(text, pos);
    if (re != QValidator::Acceptable) {
        if (re == QValidator::Invalid)
            emit failed();
        return re;
    }

    if (matchingContact(text) || matchesIdentity(text)) {
        emit failed();
        return QValidator::Invalid;
    }

    return re;
}

ContactUser *ContactIDValidator::matchingContact(const QString &text) const
{
    ContactUser *u = 0;
    if (m_uniqueIdentity)
        u = m_uniqueIdentity->contacts.lookupHostname(text);
    return u;
}

bool ContactIDValidator::matchesIdentity(const QString &text) const
{
    return m_uniqueIdentity && m_uniqueIdentity->hostname() == hostnameFromID(text);
}

void ContactIDValidator::fixup(QString &text) const
{
    text = text.trimmed().toLower();
}

bool ContactIDValidator::isValidID(const QString &text)
{
    return regex.match(text).hasMatch();
}

QString ContactIDValidator::hostnameFromID(const QString &ID)
{
    QRegularExpressionMatch match = regex.match(ID);
    if (!match.hasMatch())
        return QString();

    return match.captured(1) + QStringLiteral(".onion");
}

QString ContactIDValidator::idFromHostname(const QString &hostname)
{
    #define DOT_ONION ".onion"

    QString re = hostname.toLower();
    if (re.endsWith(DOT_ONION)) {
        re.chop(static_strlen(DOT_ONION));
    }

    re.prepend(QStringLiteral("ricochet:"));

    if (!isValidID(re))
        return QString();
    return re;
}

