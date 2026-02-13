#include "interface_settings_panel.hpp"

#include "enums.hpp"
#include "fonts.hpp"
#include "metrics.hpp"
#include "strings.hpp"

InterfaceSettingsPanel::InterfaceSettingsPanel(wxWindow* parent) :
    wxScrolled<wxPanel>(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxVSCROLL) {
    this->SetScrollRate(0, this->FromDIP(Metrics::VSCROLL_RATE));

    auto v_sizer = new wxBoxSizer(wxVERTICAL);

    // Language

    auto language_heading =
        new wxStaticText(this, wxID_ANY, Strings::InterfaceSettingsPanel::language_heading());
    language_heading->SetFont(Fonts::heading_font());

    auto language_h_sizer = new wxBoxSizer(wxHORIZONTAL);

    auto select_interface_language_label = new wxStaticText(
        this,
        wxID_ANY,
        Strings::InterfaceSettingsPanel::select_interface_language_label()
    );
    auto language_combobox = new wxComboBox(
        this,
        wxID_ANY,
        Strings::Enums::Language::system(),
        wxDefaultPosition,
        wxDefaultSize,
        Strings::InterfaceSettingsPanel::supported_languages(),
        wxCB_READONLY
    );
    language_combobox->Bind(wxEVT_COMBOBOX, [this](wxCommandEvent& evt) {
        this->set_interface_language(static_cast<Language>(evt.GetInt()));
    });

    language_h_sizer->Add(select_interface_language_label, 0, wxALIGN_CENTER_VERTICAL, 0);
    language_h_sizer->AddStretchSpacer(1);
    language_h_sizer->Add(language_combobox, 0, wxALIGN_CENTER_VERTICAL, 0);

    // Toolbars

    auto toolbars_heading =
        new wxStaticText(this, wxID_ANY, Strings::InterfaceSettingsPanel::toolbars_heading());
    toolbars_heading->SetFont(Fonts::heading_font());

    auto show_toolbar_toggle =
        new wxCheckBox(this, wxID_ANY, Strings::InterfaceSettingsPanel::show_toolbar_toggle());

    show_toolbar_toggle->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent& evt) {
        this->set_show_toolbar(evt.IsChecked());
    });

    auto button_style_h_sizer = new wxBoxSizer(wxHORIZONTAL);

    this->button_style_label =
        new wxStaticText(this, wxID_ANY, Strings::InterfaceSettingsPanel::button_style_label());

    this->button_style_combobox = new wxComboBox(
        this,
        wxID_ANY,
        Strings::InterfaceSettingsPanel::button_style_icons(),
        wxDefaultPosition,
        wxDefaultSize,
        Strings::InterfaceSettingsPanel::button_styles(),
        wxCB_READONLY
    );
    this->button_style_combobox->Bind(wxEVT_COMBOBOX, [this](wxCommandEvent& evt) {
        this->set_button_style(static_cast<ButtonStyle>(evt.GetInt()));
    });

    button_style_h_sizer->Add(this->button_style_label, 0, wxALIGN_CENTER_VERTICAL, 0);
    button_style_h_sizer->AddStretchSpacer(1);
    button_style_h_sizer->Add(this->button_style_combobox, 0, wxALIGN_CENTER_VERTICAL, 0);

    // Alerts

    auto alerts_heading =
        new wxStaticText(this, wxID_ANY, Strings::InterfaceSettingsPanel::alerts_heading());
    alerts_heading->SetFont(Fonts::heading_font());

    auto show_desktop_notifications_toggle = new wxCheckBox(
        this,
        wxID_ANY,
        Strings::InterfaceSettingsPanel::show_desktop_notifications_toggle()
    );
    show_desktop_notifications_toggle->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent& evt) {
        this->set_show_desktop_notifications(evt.IsChecked());
    });

    auto blink_taskbar_icon_toggle = new wxCheckBox(
        this,
        wxID_ANY,
        Strings::InterfaceSettingsPanel::blink_taskbar_icon_toggle()
    );
    blink_taskbar_icon_toggle->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent& evt) {
        this->set_blink_taskbar_icon(evt.IsChecked());
    });

    auto enable_audio_notifications_toggle = new wxCheckBox(
        this,
        wxID_ANY,
        Strings::InterfaceSettingsPanel::enable_audio_notifications_toggle()
    );
    enable_audio_notifications_toggle->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent& evt) {
        this->set_enable_audio_notifications(evt.IsChecked());
    });

    // Window

    auto window_heading =
        new wxStaticText(this, wxID_ANY, Strings::InterfaceSettingsPanel::window_heading());
    window_heading->SetFont(Fonts::heading_font());

    auto minimize_instead_of_exit_toggle = new wxCheckBox(
        this,
        wxID_ANY,
        Strings::InterfaceSettingsPanel::minimize_instead_of_exit_toggle()
    );
    minimize_instead_of_exit_toggle->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent& evt) {
        this->set_minimize_instead_of_exit(evt.IsChecked());
    });

    auto show_system_tray_icon_toggle = new wxCheckBox(
        this,
        wxID_ANY,
        Strings::InterfaceSettingsPanel::show_system_tray_icon_toggle()
    );
    show_system_tray_icon_toggle->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent& evt) {
        this->set_show_system_tray_icon(evt.IsChecked());
    });

    auto minimize_to_system_tray_v_sizer = new wxBoxSizer(wxVERTICAL);

    this->minimize_to_system_tray_toggle = new wxCheckBox(
        this,
        wxID_ANY,
        Strings::InterfaceSettingsPanel::minimize_to_system_tray_toggle()
    );
    this->minimize_to_system_tray_toggle->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent& evt) {
        this->set_minimize_to_system_tray(evt.IsChecked());
    });

    minimize_to_system_tray_v_sizer
        ->Add(minimize_to_system_tray_toggle, 0, wxLEFT, Metrics::HORIZONTAL_PADDING_XLARGE);

    // Layout

    v_sizer->Add(language_heading, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(language_h_sizer, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);

    v_sizer->Add(toolbars_heading, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(show_toolbar_toggle, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(button_style_h_sizer, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);

    v_sizer->Add(alerts_heading, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(show_desktop_notifications_toggle, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(blink_taskbar_icon_toggle, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(enable_audio_notifications_toggle, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);

    v_sizer->Add(window_heading, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(minimize_instead_of_exit_toggle, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(show_system_tray_icon_toggle, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(minimize_to_system_tray_v_sizer, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);

    this->SetSizerAndFit(v_sizer);

    // todo: configure UX based on loaded settings

    this->disable_button_style_controls();
    this->disable_system_tray_icon_controls();
}

void InterfaceSettingsPanel::set_interface_language(Language language) {
    std::cout << "Set Language: ";
    switch (language) {
        case Language::System:
            std::cout << Strings::Enums::Language::system();
            break;
        case Language::Arabic:
            std::cout << Strings::Enums::Language::ar();
            break;
        case Language::German:
            std::cout << Strings::Enums::Language::de();
            break;
        case Language::English:
            std::cout << Strings::Enums::Language::en();
            break;
        case Language::Spanish:
            std::cout << Strings::Enums::Language::es();
            break;
        case Language::Dutch:
            std::cout << Strings::Enums::Language::nl();
            break;
    }
    std::cout << std::endl;
}

void InterfaceSettingsPanel::set_show_toolbar(bool enabled) {
    std::cout << "Set Show toolbar: " << (enabled ? "True" : "False") << std::endl;
    if (enabled) {
        this->enable_button_style_controls();
    } else {
        this->disable_button_style_controls();
    }
}

void InterfaceSettingsPanel::set_button_style(ButtonStyle button_style) {
    std::cout << "Set Button style: ";
    switch (button_style) {
        case ButtonStyle::Icons:
            std::cout << "Icons";
            break;
        case ButtonStyle::Text:
            std::cout << "Text";
            break;
        case ButtonStyle::IconsAndText:
            std::cout << "Icons and Text";
            break;
        case ButtonStyle::IconsBesideText:
            std::cout << "Icons beside Text";
            break;
    }
    std::cout << std::endl;
}

void InterfaceSettingsPanel::set_show_desktop_notifications(bool enabled) {
    std::cout << "Set Show desktop notifications: " << (enabled ? "True" : "False") << std::endl;
}

void InterfaceSettingsPanel::set_blink_taskbar_icon(bool enabled) {
    std::cout << "Set Blink taskbar icon: " << (enabled ? "True" : "False") << std::endl;
}

void InterfaceSettingsPanel::set_enable_audio_notifications(bool enabled) {
    std::cout << "Set Enable audio notifications: " << (enabled ? "True" : "False") << std::endl;
}

void InterfaceSettingsPanel::set_minimize_instead_of_exit(bool enabled) {
    std::cout << "Set Minimze instead of exit: " << (enabled ? "True" : "False") << std::endl;
}

void InterfaceSettingsPanel::set_show_system_tray_icon(bool enabled) {
    std::cout << "Set Show system tray icon: " << (enabled ? "True" : "False") << std::endl;
    if (enabled) {
        this->enable_system_tray_icon_controls();
    } else {
        this->disable_system_tray_icon_controls();
    }
}

void InterfaceSettingsPanel::set_minimize_to_system_tray(bool enabled) {
    std::cout << "Set Minimize to system tray: " << (enabled ? "True" : "False") << std::endl;
}

void InterfaceSettingsPanel::enable_button_style_controls() {
    this->button_style_label->Enable();
    this->button_style_combobox->Enable();
}

void InterfaceSettingsPanel::disable_button_style_controls() {
    this->button_style_label->Disable();
    this->button_style_combobox->Disable();
}

void InterfaceSettingsPanel::enable_system_tray_icon_controls() {
    this->minimize_to_system_tray_toggle->Enable();
}

void InterfaceSettingsPanel::disable_system_tray_icon_controls() {
    this->minimize_to_system_tray_toggle->Disable();
}
