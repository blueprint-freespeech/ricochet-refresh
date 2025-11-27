#pragma once

namespace shims
{
    class ContactUser;
    class ContactIDValidator : public QRegularExpressionValidator
    {
        Q_OBJECT
        Q_DISABLE_COPY(ContactIDValidator)
    public:
        ContactIDValidator(QObject *parent = 0);

        virtual void fixup(QString &text) const;
        virtual State validate(QString &text, int &pos) const;

    signals:
        // fired when the service id is a new valid contact
        void acceptable() const;
        // fired when user input is maybe a valid contact
        void intermediate() const;
        // fired when the service-id matches the regex but is not a valid service id
        void invalidServiceId() const;
        // fired when the service-id is already a contact
        void matchesContact(QString) const;
        // fired when the service-id is ourself
        void matchesSelf() const;
    private:
        bool isValidID(const QString &serviceID) const;
        shims::ContactUser *matchingContact(const QString &text) const;
        bool matchesIdentity(const QString &text) const;
    };
}