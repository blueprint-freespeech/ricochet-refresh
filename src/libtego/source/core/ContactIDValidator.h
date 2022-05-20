// Copyright (C) 2014, John Brooks <john.brooks@dereferenced.net>
//
// SPDX-License-Identifier: GPL-3.0-only

#ifndef CONTACTIDVALIDATOR_H
#define CONTACTIDVALIDATOR_H

#include "UserIdentity.h"

class ContactIDValidator : public QRegularExpressionValidator
{
    Q_OBJECT
    Q_DISABLE_COPY(ContactIDValidator)

public:
    ContactIDValidator(QObject *parent = 0);

    static bool isValidID(const QString &text);
    static QString hostnameFromID(const QString &ID);
    static QString idFromHostname(const QString &hostname);
    static QString idFromHostname(const QByteArray &hostname) { return idFromHostname(QString::fromLatin1(hostname)); }

    virtual void fixup(QString &text) const;
    virtual State validate(QString &text, int &pos) const;

    ContactUser *matchingContact(const QString &text) const;
    bool matchesIdentity(const QString &text) const;

signals:
    void failed() const;

protected:
    UserIdentity *m_uniqueIdentity;
};

#endif // CONTACTIDVALIDATOR_H
