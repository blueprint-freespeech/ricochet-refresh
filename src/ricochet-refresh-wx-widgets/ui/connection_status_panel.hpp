#pragma once

#include "enums.hpp"

class ConnectionStatusPanel: public wxPanel {
public:
    explicit ConnectionStatusPanel(wxWindow* parent, wxString backend, ConnectionStatus);

private:
    void add_log(const wxString& log_line);
    void copy_tor_logs();
    void close();

    wxTextCtrl* logs_textbox = nullptr;
};
