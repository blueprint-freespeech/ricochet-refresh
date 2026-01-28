#pragma once

class MessageEntryPanel: public wxPanel {
public:
    explicit MessageEntryPanel(wxWindow* parent);

private:
    void send_text_message(const wxString& text);

    // data
    wxTextCtrl* text_control = nullptr;
};