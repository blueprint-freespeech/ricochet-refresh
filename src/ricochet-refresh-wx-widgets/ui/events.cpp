#include "events.hpp"

#include "enums.hpp"

wxDEFINE_EVENT(wxEVT_SEND_MESSAGE, SendMessageEvent);

SendMessageEvent::SendMessageEvent(const wxDateTime& timestamp, const wxString& text) :
    wxCommandEvent(wxEVT_SEND_MESSAGE),
    message_type(MessageType::Text),
    timestamp(timestamp),
    data {.text = text} {}

SendMessageEvent::~SendMessageEvent() {
    switch (this->message_type) {
        case MessageType::Text:
            this->data.text.~wxString();
            break;
        default:
            break;
    }
}

wxEvent* SendMessageEvent::Clone() const {
    switch (this->message_type) {
        case MessageType::Text:
            return new SendMessageEvent(this->timestamp, this->data.text);
        default:
            return nullptr;
    }
}

MessageType SendMessageEvent::get_message_type() const {
    return this->message_type;
}

const wxDateTime& SendMessageEvent::get_timestamp() const {
    return this->timestamp;
}

const wxString& SendMessageEvent::get_text() const {
    return this->data.text;
}