#include "bootstrap_panel.hpp"

#include "connected_panel.hpp"
#include "connecting_panel.hpp"
#include "disconnected_panel.hpp"
#include "fonts.hpp"
#include "metrics.hpp"
#include "strings.hpp"
#include "wrapped_static_text.hpp"

constexpr int BOOTSTRAP_PANEL_MIN_WIDTH = 600;
constexpr int BOOTSTRAP_PANEL_MIN_HEIGHT = 400;

BootstrapPanel::BootstrapPanel(wxWindow* parent) : wxPanel(parent) {
    auto root_h_sizer = new wxBoxSizer(wxHORIZONTAL);
    auto h_centered_panel = new wxPanel(this, wxID_ANY);
    h_centered_panel->SetMinSize(wxSize(BOOTSTRAP_PANEL_MIN_WIDTH, -1));

    root_h_sizer->AddStretchSpacer(1);
    root_h_sizer->Add(h_centered_panel, 0, wxEXPAND);
    root_h_sizer->AddStretchSpacer(1);

    auto v_sizer = new wxBoxSizer(wxVERTICAL);
    h_centered_panel->SetSizer(v_sizer);

    auto v_centered_panel =
        new wxPanel(h_centered_panel, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxBORDER_RAISED);
    v_centered_panel->SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_LISTBOX));
    v_centered_panel->SetMinSize(wxSize(-1, BOOTSTRAP_PANEL_MIN_HEIGHT));

    v_sizer->AddStretchSpacer(1);
    v_sizer->Add(v_centered_panel, 0, wxEXPAND);
    v_sizer->AddStretchSpacer(1);

    auto center_sizer = new wxBoxSizer(wxVERTICAL);
    this->disconnected_panel = new DisconnectedPanel(v_centered_panel);
    this->connecting_panel = new ConnectingPanel(v_centered_panel);
    this->connected_panel = new ConnectedPanel(v_centered_panel);

    center_sizer->Add(this->disconnected_panel, 1, wxEXPAND | wxALL, Metrics::PADDING_XLARGE);
    center_sizer->Add(this->connecting_panel, 1, wxEXPAND | wxALL, Metrics::PADDING_XLARGE);
    center_sizer->Add(this->connected_panel, 1, wxEXPAND | wxALL, Metrics::PADDING_XLARGE);

    this->disconnected_panel->Hide();
    this->connecting_panel->Hide();
    this->connected_panel->Hide();

    v_centered_panel->SetSizer(center_sizer);

    this->SetSizerAndFit(root_h_sizer);
}

void BootstrapPanel::ShowDisconnected() {
    this->disconnected_panel->Show();
    this->connecting_panel->Hide();
    this->connected_panel->Hide();
}

void BootstrapPanel::ShowConnecting() {
    this->disconnected_panel->Hide();
    this->connecting_panel->Show();
    this->connected_panel->Hide();
}

void BootstrapPanel::ShowConnected() {
    this->disconnected_panel->Hide();
    this->connecting_panel->Hide();
    this->connected_panel->Show();
}
