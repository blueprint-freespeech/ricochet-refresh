#include "chat_panel.hpp"

ChatPanel::ChatPanel(wxWindow* parent) :
    wxTextCtrl(
        parent,
        wxID_ANY,
        wxEmptyString,
        wxDefaultPosition,
        wxDefaultSize,
        wxTE_READONLY | wxTE_MULTILINE
    ) {}

void ChatPanel::add_chat_message(
    const wxDateTime timestamp,
    const wxString& nickname,
    const wxString& message
) {
    const auto line =
        wxString::Format("(%s) %s: %s\n", timestamp.FormatISOCombined(' '), nickname, message);
    this->AppendText(line);
}