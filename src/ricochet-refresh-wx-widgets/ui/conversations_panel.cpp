#include "conversations_panel.hpp"

#include "chat_panel.hpp"
#include "contact_list_panel.hpp"
#include "events.hpp"
#include "message_entry_panel.hpp"
#include "mock_ffi.hpp"
#include "strings.hpp"
#include "user_status_panel.hpp"

ConversationsPanel::ConversationsPanel(wxWindow* parent, std::span<const ContactHandle> contacts) :
    wxSplitterWindow(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxSP_LIVE_UPDATE) {
    auto left_panel = new wxPanel(this);
    auto right_panel = new wxPanel(this);

    // Contacts List + User Status

    auto left_v_sizer = new wxBoxSizer(wxVERTICAL);

    // todo: replace with actual implementation
    auto contact_list_panel = new ContactListPanel(left_panel, contacts);
    contact_list_panel->Bind(wxEVT_CONTACT_SELECTED, [this](const ContactSelectedEvent& evt) {
        this->select_contact(evt.get_contact_handle());
    });
    contact_list_panel->Bind(wxEVT_CONTACT_REMOVED, [this](ContactRemovedEvent& evt) {
        this->remove_contact(evt.get_contact_handle());
        evt.Skip();
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
            // todo: remove, this is just test plumbing
            this->receive_message(
                contact_handle,
                timestamp + wxTimeSpan(0, 0, 1),
                "auto-reply: I've received your message"
            );
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

void ConversationsPanel::receive_message(
    const ContactHandle recipient,
    const wxDateTime& timestamp,
    const wxString& message
) {
    if (auto it = this->contact_widgets.find(recipient); it != this->contact_widgets.end()) {
        auto& contact_widgets = it->second;
        const auto nickname = mock::nickname_from_contact_handle(recipient);
        contact_widgets.chat_panel->add_chat_message(timestamp, nickname, message);
    }
}

void ConversationsPanel::select_contact(const std::optional<ContactHandle> contact_handle) {
    // hide everything
    this->right_v_sizer->ShowItems(false);
    if (contact_handle) {
        if (auto it = this->contact_widgets.find(*contact_handle);
            it != this->contact_widgets.end()) {
            // show contact's widgets
            const auto& contact_widgets = it->second;
            this->right_v_sizer->Show(contact_widgets.v_sizer, true);
            this->right_v_sizer->Layout();
        }
    }
}

void ConversationsPanel::remove_contact(const ContactHandle contact_handle) {
    if (auto it = this->contact_widgets.find(contact_handle); it != this->contact_widgets.end()) {
        auto& v_sizer = it->second.v_sizer;

        // remove and delete children
        v_sizer->Clear(true);
        this->right_v_sizer->Detach(v_sizer);
        delete v_sizer;

        // trigger re-layout
        this->right_v_sizer->Layout();

        // remove our record
        this->contact_widgets.erase(it);
    }
}
