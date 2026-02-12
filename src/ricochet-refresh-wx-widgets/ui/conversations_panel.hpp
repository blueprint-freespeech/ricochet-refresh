#pragma once

#include "mock_ffi.hpp"
using namespace mock;

class ChatPanel;
class MessageEntryPanel;

class ConversationsPanel: public wxSplitterWindow {
public:
    explicit ConversationsPanel(wxWindow* parent);

private:
    struct ContactWidgets {
        ChatPanel* chat_panel;
        MessageEntryPanel* message_entry_panel;
    };

    std::unordered_map<ContactHandle, ContactWidgets> contact_widgets;
};
