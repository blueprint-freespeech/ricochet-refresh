#pragma once

// todo: make thsi a custom widget similar to wxRichTextCtrl
// (but purpose built for our needs)
class ChatPanel: public wxTextCtrl {
public:
    explicit ChatPanel(wxWindow* parent);

    void
    add_chat_message(const wxDateTime timestamp, const wxString& nickname, const wxString& message);

private:
};
