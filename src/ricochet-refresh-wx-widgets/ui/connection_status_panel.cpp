#include "connection_status_panel.hpp"

#include "enums.hpp"
#include "fonts.hpp"
#include "strings.hpp"

ConnectionStatusPanel::ConnectionStatusPanel(
    wxWindow* parent,
    wxString backend,
    ConnectionStatus connection_status
) :
    wxPanel(parent) {
    auto v_sizer = new wxBoxSizer(wxVERTICAL);

    auto title = new wxStaticText(this, wxID_ANY, Strings::connection_status_panel_title());
    title->SetFont(Fonts::title_font());

    // status

    auto status_panel = new wxPanel(this);
    auto status_panel_h_sizer = new wxBoxSizer(wxHORIZONTAL);

    auto backend_text =
        new wxStaticText(status_panel, wxID_ANY, Strings::connection_status_panel_backend(backend));
    auto connection_status_text = new wxStaticText(
        status_panel,
        wxID_ANY,
        Strings::connection_status_panel_status(connection_status)
    );

    status_panel_h_sizer->Add(backend_text, 0, wxTOP, 8);
    status_panel_h_sizer->AddStretchSpacer(1);
    status_panel_h_sizer->Add(connection_status_text, 0, wxTop, 8);

    status_panel->SetSizer(status_panel_h_sizer);

    // logs

    this->logs_textbox = new wxTextCtrl(
        this,
        wxID_ANY,
        "",
        wxDefaultPosition,
        wxDefaultSize,
        wxTE_MULTILINE | wxTE_READONLY | wxTE_WORDWRAP
    );

    // buttons

    auto button_panel = new wxPanel(this);
    auto button_panel_h_sizer = new wxBoxSizer(wxHORIZONTAL);

    auto copy_logs_button = new wxButton(button_panel, wxID_ANY, Strings::copy_tor_logs());
    copy_logs_button->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { this->copy_tor_logs(); });
    auto ok_button = new wxButton(button_panel, wxID_OK, Strings::ok_button());
    ok_button->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { this->close(); });

    button_panel_h_sizer->Add(copy_logs_button, 0, wxTOP, 8);
    button_panel_h_sizer->AddStretchSpacer(1);
    button_panel_h_sizer->Add(ok_button, 0, wxTOP, 8);
    button_panel->SetSizer(button_panel_h_sizer);

    v_sizer->Add(title, 0, wxALIGN_LEFT, 0);
    v_sizer->Add(status_panel, 0, wxTOP | wxEXPAND, 4);
    v_sizer->Add(logs_textbox, 1, wxTOP | wxEXPAND, 4);
    v_sizer->Add(button_panel, 0, wxTOP | wxEXPAND, 0);
    this->SetSizerAndFit(v_sizer);

    // todo: handle via callback
    this->add_log("log line 1");
    this->add_log("log line 2");
}

void ConnectionStatusPanel::add_log(const wxString& log_line) {
    const auto insertion_point = this->logs_textbox->GetInsertionPoint();
    this->logs_textbox->AppendText(log_line);
    this->logs_textbox->AppendText(wxString("\n"));
    this->logs_textbox->SetInsertionPoint(insertion_point);
}

void ConnectionStatusPanel::copy_tor_logs() {
    std::cout << "Copy Tor Logs" << std::endl;
}

void ConnectionStatusPanel::close() {
    std::cout << "Close" << std::endl;
}