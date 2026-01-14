#include "general_settings_panel.hpp"

#include "fonts.hpp"
#include "metrics.hpp"
#include "strings.hpp"

GeneralSettingsPanel::GeneralSettingsPanel(wxWindow* parent) :
    wxScrolled<wxPanel>(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxVSCROLL) {
    this->SetScrollRate(0, this->FromDIP(Metrics::VSCROLL_RATE));

    auto v_sizer = new wxBoxSizer(wxVERTICAL);

    // Startup

    auto startup_heading =
        new wxStaticText(this, wxID_ANY, Strings::GeneralSettingsPanel::startup_heading());
    startup_heading->SetFont(Fonts::heading_font());

    auto start_only_single_instance_toggle = new wxCheckBox(
        this,
        wxID_ANY,
        Strings::GeneralSettingsPanel::start_only_single_instance_toggle()
    );
    start_only_single_instance_toggle->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent& evt) {
        this->set_start_only_single_instance(evt.IsChecked());
    });

    auto check_for_updates_on_launch_toggle = new wxCheckBox(
        this,
        wxID_ANY,
        Strings::GeneralSettingsPanel::check_for_updates_on_launch_toggle()
    );
    check_for_updates_on_launch_toggle->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent& evt) {
        this->set_check_for_updates(evt.IsChecked());
    });

    // Layout

    v_sizer->Add(startup_heading, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(start_only_single_instance_toggle, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(check_for_updates_on_launch_toggle, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    this->SetSizerAndFit(v_sizer);

    // todo: configure UX based on loaded settings
}

void GeneralSettingsPanel::set_start_only_single_instance(bool enabled) {
    std::cout << "Set Start only single instance: " << (enabled ? "True" : "False") << std::endl;
}

void GeneralSettingsPanel::set_check_for_updates(bool enabled) {
    std::cout << "Set Check for updates on launch: " << (enabled ? "True" : "False") << std::endl;
}