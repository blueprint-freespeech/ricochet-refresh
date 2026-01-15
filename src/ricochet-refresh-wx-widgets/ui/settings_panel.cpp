#include "settings_panel.hpp"

#include "connection_settings_panel.hpp"
#include "fonts.hpp"
#include "general_settings_panel.hpp"
#include "interface_settings_panel.hpp"
#include "metrics.hpp"
#include "strings.hpp"

SettingsPanel::SettingsPanel(wxWindow* parent) : wxPanel(parent) {
    auto v_sizer = new wxBoxSizer(wxVERTICAL);

    auto title = new wxStaticText(this, wxID_ANY, Strings::SettingsPanel::title());
    title->SetFont(Fonts::title_font());

    constexpr int SETTINGS_LISTBOX_CHOICE_COUNT = 3;
    wxString settings_listbox_choices[SETTINGS_LISTBOX_CHOICE_COUNT] = {
        Strings::SettingsPanel::general_settings_choice(),
        Strings::SettingsPanel::interface_settings_choice(),
        Strings::SettingsPanel::connection_settings_choice(),
    };

    auto settings_listbox = new wxListBox(
        this,
        wxID_ANY,
        wxDefaultPosition,
        wxDefaultSize,
        SETTINGS_LISTBOX_CHOICE_COUNT,
        settings_listbox_choices,
        wxLB_SINGLE
    );
    settings_listbox->Bind(wxEVT_LISTBOX, [this](wxCommandEvent& evt) {
        this->set_current_settings_panel(static_cast<Settings>(evt.GetInt()));
    });

    this->general_settings_panel = new GeneralSettingsPanel(this);
    this->interface_settings_panel = new InterfaceSettingsPanel(this);
    this->connection_settings_panel = new ConnectionSettingsPanel(this);

    // Layout

    v_sizer->Add(title, 0, wxEXPAND | wxALL, Metrics::PADDING_MEDIUM);

    auto h_sizer = new wxBoxSizer(wxHORIZONTAL);
    h_sizer->Add(settings_listbox, 0, wxEXPAND);
    h_sizer->Add(this->general_settings_panel, 1, wxEXPAND | wxALL, Metrics::PADDING_MEDIUM);
    h_sizer->Add(this->interface_settings_panel, 1, wxEXPAND | wxALL, Metrics::PADDING_MEDIUM);
    h_sizer->Add(this->connection_settings_panel, 1, wxEXPAND | wxALL, Metrics::PADDING_MEDIUM);
    v_sizer->Add(h_sizer, 1, wxEXPAND);

    auto button_sizer = new wxStdDialogButtonSizer();
    auto ok_button = new wxButton(this, wxID_OK);
    ok_button->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { this->ok(); });
    auto apply_button = new wxButton(this, wxID_APPLY);
    apply_button->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { this->apply(); });
    auto cancel_button = new wxButton(this, wxID_CANCEL);
    cancel_button->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { this->cancel(); });

    button_sizer->AddButton(ok_button);
    button_sizer->AddButton(cancel_button);
    button_sizer->AddButton(apply_button);
    button_sizer->Realize();

    v_sizer->Add(button_sizer, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);

    this->SetSizerAndFit(v_sizer);

    this->set_current_settings_panel(Settings::General);
}

void SettingsPanel::set_current_settings_panel(Settings settings) {
    switch (settings) {
        case Settings::General:
            this->show_general_settings();
            break;
        case Settings::Interface:
            this->show_interface_settings();
            break;
        case Settings::Connection:
            this->show_connection_settings();
            break;
    }
    this->Layout();
}

void SettingsPanel::show_general_settings() {
    this->general_settings_panel->Show();
    this->interface_settings_panel->Hide();
    this->connection_settings_panel->Hide();
}

void SettingsPanel::show_interface_settings() {
    this->general_settings_panel->Hide();
    this->interface_settings_panel->Show();
    this->connection_settings_panel->Hide();
}

void SettingsPanel::show_connection_settings() {
    this->general_settings_panel->Hide();
    this->interface_settings_panel->Hide();
    this->connection_settings_panel->Show();
}

void SettingsPanel::apply() {
    std::cout << "Apply Pressed" << std::endl;
}

void SettingsPanel::cancel() {
    std::cout << "Cancel Pressed" << std::endl;
}

void SettingsPanel::ok() {
    std::cout << "Ok Pressed" << std::endl;
}