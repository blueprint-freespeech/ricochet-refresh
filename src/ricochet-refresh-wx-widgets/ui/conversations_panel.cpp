#include "conversations_panel.hpp"

#include "contact_list_panel.hpp"
#include "user_status_panel.hpp"

ConversationsPanel::ConversationsPanel(wxWindow* parent) :
    wxSplitterWindow(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxSP_LIVE_UPDATE) {
    auto left_panel = new wxPanel(this);
    auto right_panel = new wxPanel(this);

    // Contacts List + User Status

    auto left_v_sizer = new wxBoxSizer(wxVERTICAL);

    // todo: replace with actual implementation
    auto contacts_list_panel = new ContactListPanel(left_panel);
    auto user_status_panel = new UserStatusPanel(left_panel);

    left_v_sizer->Add(contacts_list_panel, 1, wxEXPAND);
    left_v_sizer->Add(user_status_panel, 0, wxEXPAND);

    left_panel->SetSizer(left_v_sizer);
    left_panel->SetMinSize(wxSize(288, -1));

    // Conversation + Chat Entry

    auto right_v_sizer = new wxBoxSizer(wxVERTICAL);

    // todo replace with actual implementation
    auto chat_panel = new wxPanel(right_panel);
    chat_panel->SetBackgroundColour(wxColour(0xFF, 0xFF, 0xAA));
    auto text_entry_panel = new wxPanel(right_panel);
    text_entry_panel->SetBackgroundColour(wxColour(0xFF, 0xAA, 0xAA));
    text_entry_panel->SetMinSize(wxSize(-1, 196));

    right_v_sizer->Add(chat_panel, 1, wxEXPAND);
    right_v_sizer->Add(text_entry_panel, 0, wxEXPAND);

    right_panel->SetSizer(right_v_sizer);
    right_panel->SetMinSize(wxSize(288, -1));

    // Layout

    this->SplitVertically(left_panel, right_panel, 288);
    this->SetSashGravity(0.0);
}