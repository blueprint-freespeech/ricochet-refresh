#include "conversations_panel.hpp"

#include "chat_panel.hpp"
#include "contact_list_panel.hpp"
#include "events.hpp"
#include "message_entry_panel.hpp"
#include "strings.hpp"
#include "user_status_panel.hpp"

ConversationsPanel::ConversationsPanel(wxWindow* parent) :
    wxSplitterWindow(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxSP_LIVE_UPDATE) {
    // todo: contacts come into this constructor

    const static ContactHandle contacts[8] = {
        reinterpret_cast<ContactHandle>(0),
        reinterpret_cast<ContactHandle>(1),
        reinterpret_cast<ContactHandle>(2),
        reinterpret_cast<ContactHandle>(3),
        reinterpret_cast<ContactHandle>(4),
        reinterpret_cast<ContactHandle>(5),
        reinterpret_cast<ContactHandle>(6),
        reinterpret_cast<ContactHandle>(7),
    };

    auto left_panel = new wxPanel(this);
    auto right_panel = new wxPanel(this);

    // Contacts List + User Status

    auto left_v_sizer = new wxBoxSizer(wxVERTICAL);

    // todo: replace with actual implementation
    auto contact_list_panel = new ContactListPanel(left_panel, std::span(contacts, 8));
    contact_list_panel->Bind(wxEVT_CONTACT_SELECTED, [this](const ContactSelectedEvent& evt) {
        this->right_v_sizer->ShowItems(false);
        const auto contact_handle = evt.get_contact_handle();
        if (contact_handle) {
            if (auto it = this->contact_widgets.find(*contact_handle);
                it != this->contact_widgets.end()) {
                const auto& contact_widgets = it->second;
                this->right_v_sizer->Show(contact_widgets.v_sizer, true);
            }
        }
    });
    auto user_status_panel = new UserStatusPanel(left_panel);

    left_v_sizer->Add(contact_list_panel, 1, wxEXPAND);
    left_v_sizer->Add(user_status_panel, 0, wxEXPAND);

    left_panel->SetSizer(left_v_sizer);
    left_panel->SetMinSize(wxSize(288, -1));

    // Conversation + Chat Entry

    this->right_v_sizer = new wxBoxSizer(wxVERTICAL);

    for (auto contact_handle : contacts) {
        auto chat_panel = new ChatPanel(right_panel);
        // todo: load chat back-log from profile

        auto message_entry_panel = new MessageEntryPanel(right_panel);
        message_entry_panel->Bind(wxEVT_SEND_MESSAGE, [=, this](const SendMessageEvent& evt) {
            const auto& timestamp = evt.get_timestamp();
            const auto& text = evt.get_text();
            chat_panel->add_chat_message(timestamp, wxString("Me"), text);
        });

        auto v_sizer = new wxBoxSizer(wxVERTICAL);
        v_sizer->Add(chat_panel, 1, wxEXPAND);
        v_sizer->Add(message_entry_panel, 0, wxEXPAND);

        this->right_v_sizer->Add(v_sizer, 1, wxEXPAND);

        this->contact_widgets.insert({contact_handle, {v_sizer, chat_panel, message_entry_panel}});
    }
    this->right_v_sizer->ShowItems(false);

    right_panel->SetSizer(this->right_v_sizer);
    right_panel->SetMinSize(wxSize(288, -1));

    // Layout

    this->SetMinimumPaneSize(32); // prevent dbl-click collapse
    this->SplitVertically(left_panel, right_panel, 288);
    this->SetSashGravity(0.0);
}