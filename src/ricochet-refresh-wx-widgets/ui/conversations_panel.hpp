#pragma once

#include "mock_ffi.hpp"
using namespace mock;

class ChatPanel;
class MessageEntryPanel;

class ConversationsPanel: public wxSplitterWindow {
public:
    ConversationsPanel(wxWindow* parent, std::span<const ContactHandle> contacts);

    void receive_message(
        const ContactHandle recipient,
        const wxDateTime& timestamp,
        const wxString& message
    );

private:
    void select_contact(const std::optional<ContactHandle> contact_handle);
    void remove_contact(ContactHandle contact_handle);

    wxBoxSizer* right_v_sizer = nullptr;

    struct ContactWidgets {
        wxBoxSizer* v_sizer;
        // Chat Widgets
        ChatPanel* chat_panel;
        MessageEntryPanel* message_entry_panel;
    };

    std::unordered_map<ContactHandle, ContactWidgets> contact_widgets;
};
