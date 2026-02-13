#pragma once

#include "mock_ffi.hpp"
using namespace mock;

/*
SendMessageEvent: event is sent when the user submits a message through
a MessageEntryPanel
*/
class SendMessageEvent;
wxDECLARE_EVENT(wxEVT_SEND_MESSAGE, SendMessageEvent);
enum class MessageType;

class SendMessageEvent: public wxCommandEvent {
public:
    SendMessageEvent(const wxDateTime& timestamp, const wxString& text);

    SendMessageEvent(const SendMessageEvent&) = delete;
    ~SendMessageEvent() override;

    wxEvent* Clone() const override;

    MessageType get_message_type() const;
    const wxDateTime& get_timestamp() const;
    const wxString& get_text() const;

private:
    const MessageType message_type;
    const wxDateTime timestamp;

    union Data {
        wxString text;

        ~Data() {}
    };

    const Data data;
};

/*
ContactSelectedEvent: event is sent when the user selects a contact in the
ContactListPanel
*/
class ContactSelectedEvent;
wxDECLARE_EVENT(wxEVT_CONTACT_SELECTED, ContactSelectedEvent);

class ContactSelectedEvent: public wxCommandEvent {
public:
    explicit ContactSelectedEvent(std::optional<ContactHandle> contact_handle);
    wxEvent* Clone() const override;

    std::optional<ContactHandle> get_contact_handle() const;

private:
    const std::optional<ContactHandle> contact_handle;
};

/*
ContactRemovedEvent: event is sent when the user removes a contact from the
ContactListPanel
*/
class ContactRemovedEvent;
wxDECLARE_EVENT(wxEVT_CONTACT_REMOVED, ContactRemovedEvent);

class ContactRemovedEvent: public wxCommandEvent {
public:
    explicit ContactRemovedEvent(ContactHandle contact_handle);
    wxEvent* Clone() const override;

    ContactHandle get_contact_handle() const;

private:
    const ContactHandle contact_handle;
};
