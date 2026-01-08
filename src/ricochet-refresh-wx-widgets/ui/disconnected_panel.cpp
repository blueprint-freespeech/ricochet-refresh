#include "disconnected_panel.hpp"

#include "enums.hpp"
#include "fonts.hpp"
#include "metrics.hpp"
#include "strings.hpp"
#include "wrapped_static_text.hpp"

DisconnectedPanel::DisconnectedPanel(wxWindow* parent) : wxPanel(parent) {
    auto v_sizer = new wxBoxSizer(wxVERTICAL);

    auto title = new wxStaticText(this, wxID_ANY, Strings::DisconnectedPanel::title());
    title->SetFont(Fonts::title_font());

    auto explainer_text =
        new WrappedStaticText(this, wxID_ANY, Strings::DisconnectedPanel::explainer_text());
    auto connect_automatically_toggle =
        new wxCheckBox(this, wxID_ANY, Strings::DisconnectedPanel::connect_automatically_toggle());
    connect_automatically_toggle->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent& evt) {
        this->set_quickstart(evt.IsChecked());
    });

    auto button_panel = new wxPanel(this, wxID_ANY);
    auto h_button_sizer = new wxBoxSizer(wxHORIZONTAL);

    auto configure_button =
        new wxButton(button_panel, wxID_ANY, Strings::DisconnectedPanel::configure_button());
    configure_button->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { this->configure(); });
    auto connect_button =
        new wxButton(button_panel, wxID_ANY, Strings::DisconnectedPanel::connect_button());
    connect_button->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { this->connect(); });

    h_button_sizer->AddStretchSpacer(1);
    h_button_sizer->Add(configure_button, 0, wxRIGHT, 8);
    h_button_sizer->Add(connect_button, 0);

    button_panel->SetSizer(h_button_sizer);

    v_sizer->Add(title, 0, wxALIGN_CENTER | wxBOTTOM, Metrics::VERTICAL_PADDING_LARGE);
    v_sizer->Add(
        explainer_text,
        0,
        wxEXPAND | wxALIGN_LEFT | wxBOTTOM,
        Metrics::VERTICAL_PADDING_MEDIUM
    );
    v_sizer->Add(connect_automatically_toggle, 0, wxALIGN_LEFT);
    v_sizer->AddStretchSpacer(1);
    v_sizer->Add(button_panel, 0, wxALIGN_RIGHT);

    this->SetSizerAndFit(v_sizer);
}

void DisconnectedPanel::set_quickstart(bool enabled) {
    std::cout << "Quickstart: " << (enabled ? "true" : "false") << std::endl;
}

void DisconnectedPanel::configure() {
    // todo: open the settings panel to the tor
    std::cout << "Configure" << std::endl;
}

void DisconnectedPanel::connect() {
    std::cout << "Connect" << std::endl;
}
