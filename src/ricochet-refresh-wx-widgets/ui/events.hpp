#pragma once

#include "mock_ffi.hpp"
using namespace mock;

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
