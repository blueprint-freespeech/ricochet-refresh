#include "connection_settings_panel.hpp"

#include "enums.hpp"
#include "fonts.hpp"
#include "metrics.hpp"
#include "strings.hpp"
#include "wrapped_static_text.hpp"

ConnectionSettingsPanel::ConnectionSettingsPanel(wxWindow* parent) :
    wxScrolled<wxPanel>(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxVSCROLL) {
    this->SetScrollRate(0, this->FromDIP(Metrics::VSCROLL_RATE));

    auto v_sizer = new wxBoxSizer(wxVERTICAL);

    // Backend

    auto backend_heading =
        new wxStaticText(this, wxID_ANY, Strings::ConnectionSettingsPanel::backend_heading());
    backend_heading->SetFont(Fonts::heading_font());

    auto backend_description = new WrappedStaticText(
        this,
        wxID_ANY,
        Strings::ConnectionSettingsPanel::backend_description()
    );

    auto bundled_legacy_tor_option = new wxRadioButton(
        this,
        wxID_ANY,
        Strings::ConnectionSettingsPanel::bundled_legacy_tor_option(),
        wxDefaultPosition,
        wxDefaultSize,
        wxRB_GROUP
    );
    bundled_legacy_tor_option->Bind(wxEVT_RADIOBUTTON, [this](wxCommandEvent&) {
        this->set_tor_backend(TorBackend::BundledLegacyTor);
    });
    auto external_legacy_tor_option = new wxRadioButton(
        this,
        wxID_ANY,
        Strings::ConnectionSettingsPanel::external_legacy_tor_option()
    );

    external_legacy_tor_option->Bind(wxEVT_RADIOBUTTON, [this](wxCommandEvent&) {
        this->set_tor_backend(TorBackend::ExternalLegacyTor);
    });

    auto in_process_arti_option = new wxRadioButton(
        this,
        wxID_ANY,
        Strings::ConnectionSettingsPanel::in_process_arti_option()
    );
    in_process_arti_option->Bind(wxEVT_RADIOBUTTON, [this](wxCommandEvent&) {
        this->set_tor_backend(TorBackend::InProcessArti);
    });

    // Quickstart

    auto quickstart_heading =
        new wxStaticText(this, wxID_ANY, Strings::ConnectionSettingsPanel::quickstart_heading());
    quickstart_heading->SetFont(Fonts::heading_font());

    auto quickstart_description = new WrappedStaticText(
        this,
        wxID_ANY,
        Strings::ConnectionSettingsPanel::quickstart_description()
    );

    auto connect_automatically_toggle = new wxCheckBox(
        this,
        wxID_ANY,
        Strings::ConnectionSettingsPanel::connect_automatically_toggle()
    );
    connect_automatically_toggle->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent& evt) {
        this->set_connect_automatically(evt.IsChecked());
    });

    // Bridges

    auto bridges_heading =
        new wxStaticText(this, wxID_ANY, Strings::ConnectionSettingsPanel::bridges_heading());
    bridges_heading->SetFont(Fonts::heading_font());
    auto bridges_description = new WrappedStaticText(
        this,
        wxID_ANY,
        Strings::ConnectionSettingsPanel::bridges_description()
    );
    auto use_bridges_toggle =
        new wxCheckBox(this, wxID_ANY, Strings::ConnectionSettingsPanel::use_bridges_toggle());
    use_bridges_toggle->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent& evt) {
        this->set_use_bridges(evt.IsChecked());
    });

    this->builtin_bridge_option = new wxRadioButton(
        this,
        wxID_ANY,
        Strings::ConnectionSettingsPanel::builtin_bridge_option(),
        wxDefaultPosition,
        wxDefaultSize,
        wxRB_GROUP
    );
    this->builtin_bridge_option->Bind(wxEVT_RADIOBUTTON, [this](wxCommandEvent&) {
        this->set_bridge_type(BridgeType::Builtin);
    });
    this->custom_bridge_option =
        new wxRadioButton(this, wxID_ANY, Strings::ConnectionSettingsPanel::custom_bridge_option());
    this->custom_bridge_option->Bind(wxEVT_RADIOBUTTON, [this](wxCommandEvent&) {
        this->set_bridge_type(BridgeType::Custom);
    });

    this->obfs4_bridge_option = new wxRadioButton(
        this,
        wxID_ANY,
        Strings::ConnectionSettingsPanel::obfs4_bridge_option(),
        wxDefaultPosition,
        wxDefaultSize,
        wxRB_GROUP
    );
    this->obfs4_bridge_option->Bind(wxEVT_RADIOBUTTON, [this](wxCommandEvent&) {
        this->set_builtin_bridge(BuiltinBridge::Obfs4);
    });
    this->snowflake_bridge_option = new wxRadioButton(
        this,
        wxID_ANY,
        Strings::ConnectionSettingsPanel::snowflake_bridge_option()
    );
    this->snowflake_bridge_option->Bind(wxEVT_RADIOBUTTON, [this](wxCommandEvent&) {
        this->set_builtin_bridge(BuiltinBridge::Snowflake);
    });
    this->meek_bridge_option =
        new wxRadioButton(this, wxID_ANY, Strings::ConnectionSettingsPanel::meek_bridge_option());
    this->meek_bridge_option->Bind(wxEVT_RADIOBUTTON, [this](wxCommandEvent&) {
        this->set_builtin_bridge(BuiltinBridge::Meek);
    });

    this->obfs4_bridge_description = new WrappedStaticText(
        this,
        wxID_ANY,
        Strings::ConnectionSettingsPanel::obfs4_bridge_description()
    );
    this->snowflake_bridge_description = new WrappedStaticText(
        this,
        wxID_ANY,
        Strings::ConnectionSettingsPanel::snowflake_bridge_description()
    );
    this->meek_bridge_description = new WrappedStaticText(
        this,
        wxID_ANY,
        Strings::ConnectionSettingsPanel::meek_bridge_description()
    );

    this->custom_bridge_textbox = new wxTextCtrl(
        this,
        wxID_ANY,
        wxEmptyString,
        wxDefaultPosition,
        wxDefaultSize,
        wxTE_MULTILINE
    );
    auto custom_bridge_textbox_line_height = Metrics::line_height(*this->custom_bridge_textbox);
    this->custom_bridge_textbox->SetMinSize(wxSize(-1, 4 * custom_bridge_textbox_line_height));
    this->custom_bridge_textbox->SetHint(
        Strings::ConnectionSettingsPanel::custom_bridge_textbox_hint()
    );

    // Network settings

    auto network_settings_heading = new wxStaticText(
        this,
        wxID_ANY,
        Strings::ConnectionSettingsPanel::network_settings_heading()
    );
    network_settings_heading->SetFont(Fonts::heading_font());

    auto network_settings_description = new WrappedStaticText(
        this,
        wxID_ANY,
        Strings::ConnectionSettingsPanel::network_settings_description()
    );

    auto use_proxy_toggle =
        new wxCheckBox(this, wxID_ANY, Strings::ConnectionSettingsPanel::use_proxy_toggle());
    use_proxy_toggle->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent& evt) {
        this->set_use_proxy(evt.IsChecked());
    });

    this->proxy_type_label =
        new wxStaticText(this, wxID_ANY, Strings::ConnectionSettingsPanel::proxy_type_label());

    this->proxy_type_combobox = new wxComboBox(
        this,
        wxID_ANY,
        Strings::ConnectionSettingsPanel::proxy_socks5(),
        wxDefaultPosition,
        wxDefaultSize,
        Strings::ConnectionSettingsPanel::proxy_types(),
        wxCB_READONLY
    );
    this->proxy_type_combobox->Bind(wxEVT_COMBOBOX, [this](wxCommandEvent& evt) {
        this->set_proxy_type(static_cast<ProxyType>(evt.GetInt()));
    });

    this->proxy_address_label =
        new wxStaticText(this, wxID_ANY, Strings::ConnectionSettingsPanel::proxy_address_label());
    this->proxy_address_textbox = new wxTextCtrl(this, wxID_ANY);
    this->proxy_address_textbox->SetHint(
        Strings::ConnectionSettingsPanel::proxy_address_textbox_hint()
    );
    this->proxy_port_label =
        new wxStaticText(this, wxID_ANY, Strings::ConnectionSettingsPanel::proxy_port_label());
    auto proxy_port_validator = wxIntegerValidator<uint16_t>(&this->proxy_port);
    proxy_port_validator.SetRange(1, 65535);
    this->proxy_port_textbox = new wxTextCtrl(
        this,
        wxID_ANY,
        wxEmptyString,
        wxDefaultPosition,
        wxDefaultSize,
        wxTE_RIGHT,
        proxy_port_validator
    );
    this->proxy_port_textbox->SetMinSize(
        wxSize(7 * Metrics::zero_width(*this->proxy_port_textbox), -1)
    );
    this->proxy_username_label =
        new wxStaticText(this, wxID_ANY, Strings::ConnectionSettingsPanel::proxy_username_label());
    this->proxy_username_textbox = new wxTextCtrl(this, wxID_ANY);
    this->proxy_username_textbox->SetHint(
        Strings::ConnectionSettingsPanel::proxy_username_textbox_hint()
    );
    this->proxy_password_label =
        new wxStaticText(this, wxID_ANY, Strings::ConnectionSettingsPanel::proxy_password_label());
    this->proxy_password_textbox = new wxTextCtrl(
        this,
        wxID_ANY,
        wxEmptyString,
        wxDefaultPosition,
        wxDefaultSize,
        wxTE_PASSWORD
    );
    this->proxy_password_textbox->SetHint(
        Strings::ConnectionSettingsPanel::proxy_password_textbox_hint()
    );

    auto firewall_toggle =
        new wxCheckBox(this, wxID_ANY, Strings::ConnectionSettingsPanel::firewall_toggle());
    firewall_toggle->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent& evt) {
        this->set_use_firewall(evt.IsChecked());
    });
    this->allowed_ports_label =
        new wxStaticText(this, wxID_ANY, Strings::ConnectionSettingsPanel::allowed_ports_label());
    this->allowed_ports_textbox = new wxTextCtrl(this, wxID_ANY);
    allowed_ports_textbox->SetHint(Strings::ConnectionSettingsPanel::allowed_ports_textbox_hint());

    // Layout

    v_sizer->Add(backend_heading, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(backend_description, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(bundled_legacy_tor_option, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_SMALL);
    v_sizer->Add(external_legacy_tor_option, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_SMALL);
    v_sizer->Add(in_process_arti_option, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);

    v_sizer->Add(quickstart_heading, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(quickstart_description, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(
        connect_automatically_toggle,
        0,
        wxEXPAND | wxBOTTOM,
        Metrics::VERTICAL_PADDING_MEDIUM
    );

    v_sizer->Add(bridges_heading, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(bridges_description, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(use_bridges_toggle, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);

    auto bridges_v_sizer = new wxBoxSizer(wxVERTICAL);
    v_sizer->Add(bridges_v_sizer, 0, wxEXPAND | wxLEFT, Metrics::HORIZONTAL_PADDING_XLARGE);
    bridges_v_sizer->Add(this->builtin_bridge_option, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_SMALL);
    auto builtin_bridges_v_sizer = new wxBoxSizer(wxVERTICAL);
    builtin_bridges_v_sizer
        ->Add(this->obfs4_bridge_option, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_SMALL);
    builtin_bridges_v_sizer->Add(
        this->obfs4_bridge_description,
        0,
        wxEXPAND | wxBOTTOM,
        Metrics::VERTICAL_PADDING_SMALL
    );
    builtin_bridges_v_sizer
        ->Add(this->snowflake_bridge_option, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_SMALL);
    builtin_bridges_v_sizer->Add(
        this->snowflake_bridge_description,
        0,
        wxEXPAND | wxBOTTOM,
        Metrics::VERTICAL_PADDING_SMALL
    );
    builtin_bridges_v_sizer
        ->Add(this->meek_bridge_option, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_SMALL);
    builtin_bridges_v_sizer->Add(
        this->meek_bridge_description,
        0,
        wxEXPAND | wxBOTTOM,
        Metrics::VERTICAL_PADDING_SMALL
    );

    bridges_v_sizer
        ->Add(builtin_bridges_v_sizer, 0, wxEXPAND | wxLEFT, Metrics::HORIZONTAL_PADDING_XLARGE);
    bridges_v_sizer->Add(this->custom_bridge_option, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_SMALL);
    bridges_v_sizer->Add(
        this->custom_bridge_textbox,
        0,
        wxEXPAND | wxLEFT,
        Metrics::HORIZONTAL_PADDING_XLARGE
    );

    v_sizer->AddSpacer(Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(network_settings_heading, 0, wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(
        network_settings_description,
        0,
        wxEXPAND | wxBOTTOM,
        Metrics::VERTICAL_PADDING_MEDIUM
    );

    v_sizer->Add(use_proxy_toggle, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);

    auto proxy_v_sizer = new wxBoxSizer(wxVERTICAL);

    auto proxy_h_sizer_1 = new wxBoxSizer(wxHORIZONTAL);
    proxy_h_sizer_1->Add(this->proxy_type_label, 0, wxALIGN_CENTER_VERTICAL);
    proxy_h_sizer_1->AddStretchSpacer(1);
    proxy_h_sizer_1->Add(this->proxy_type_combobox, 0, wxALIGN_CENTER_VERTICAL);

    proxy_v_sizer->Add(proxy_h_sizer_1, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);

    auto proxy_h_sizer_2 = new wxBoxSizer(wxHORIZONTAL);
    proxy_h_sizer_2->Add(
        this->proxy_address_label,
        0,
        wxALIGN_CENTER_VERTICAL | wxRIGHT,
        Metrics::HORIZONTAL_PADDING_SMALL
    );
    proxy_h_sizer_2->Add(this->proxy_address_textbox, 1, wxALIGN_CENTER_VERTICAL);
    proxy_h_sizer_2->Add(
        this->proxy_port_label,
        0,
        wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT,
        Metrics::HORIZONTAL_PADDING_SMALL
    );
    proxy_h_sizer_2->Add(this->proxy_port_textbox, 0, wxALIGN_CENTER_VERTICAL);

    proxy_v_sizer->Add(proxy_h_sizer_2, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);

    auto proxy_h_sizer_3 = new wxBoxSizer(wxHORIZONTAL);
    proxy_h_sizer_3->Add(
        this->proxy_username_label,
        0,
        wxALIGN_CENTER_VERTICAL | wxRIGHT,
        Metrics::HORIZONTAL_PADDING_SMALL
    );
    proxy_h_sizer_3->Add(this->proxy_username_textbox, 1, wxALIGN_CENTER_VERTICAL);
    proxy_h_sizer_3->Add(
        this->proxy_password_label,
        0,
        wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT,
        Metrics::HORIZONTAL_PADDING_SMALL
    );
    proxy_h_sizer_3->Add(this->proxy_password_textbox, 1, wxALIGN_CENTER_VERTICAL);

    proxy_v_sizer->Add(proxy_h_sizer_3, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);

    v_sizer->Add(proxy_v_sizer, 0, wxEXPAND | wxLEFT, Metrics::HORIZONTAL_PADDING_XLARGE);

    v_sizer->Add(firewall_toggle, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);

    auto firewall_v_sizer = new wxBoxSizer(wxVERTICAL);

    auto firewall_h_sizer = new wxBoxSizer(wxHORIZONTAL);
    firewall_h_sizer->Add(
        this->allowed_ports_label,
        0,
        wxALIGN_CENTER_VERTICAL | wxLEFT,
        Metrics::HORIZONTAL_PADDING_SMALL
    );
    firewall_h_sizer->Add(this->allowed_ports_textbox, 1, wxALIGN_CENTER_VERTICAL);

    firewall_v_sizer->Add(firewall_h_sizer, 0, wxEXPAND);
    v_sizer->Add(firewall_v_sizer, 0, wxEXPAND | wxLEFT, Metrics::HORIZONTAL_PADDING_XLARGE);

    this->SetSizerAndFit(v_sizer);

    // todo configure UX from loaded settings
    this->disable_bridge_controls();
    this->disable_builtin_bridge_controls();
    this->disable_custom_bridge_controls();
    this->disable_proxy_address_controls();
    this->disable_proxy_authentication_controls();
    this->disable_firewall_controls();
}

void ConnectionSettingsPanel::set_tor_backend(TorBackend tor_backend) {
    switch (tor_backend) {
        case TorBackend::BundledLegacyTor:
            std::cout << "Set Backend: Bundled Legacy Tor" << std::endl;
            break;
        case TorBackend::ExternalLegacyTor:
            std::cout << "Set Backend: External Legacy Tor" << std::endl;
            break;
        case TorBackend::InProcessArti:
            std::cout << "Set Backend: In-Process Arti" << std::endl;
            break;
    }
}

void ConnectionSettingsPanel::set_connect_automatically(bool enabled) {
    std::cout << "Set Connect Automatically: " << (enabled ? "true" : "false") << std::endl;
}

void ConnectionSettingsPanel::set_use_bridges(bool enabled) {
    std::cout << "Set Use Bridges: " << (enabled ? "true" : "false") << std::endl;
    if (enabled) {
        this->enable_bridge_controls();
        if (this->builtin_bridge_option->GetValue()) {
            this->enable_builtin_bridge_controls();
            this->disable_custom_bridge_controls();
        } else if (this->custom_bridge_option->GetValue()) {
            this->disable_builtin_bridge_controls();
            this->enable_custom_bridge_controls();
        }
    } else {
        this->disable_bridge_controls();
        this->disable_builtin_bridge_controls();
        this->disable_custom_bridge_controls();
    }
}

void ConnectionSettingsPanel::set_bridge_type(BridgeType bridge_type) {
    switch (bridge_type) {
        case BridgeType::Builtin:
            std::cout << "Set BridgeType: Builtin" << std::endl;
            this->enable_builtin_bridge_controls();
            this->disable_custom_bridge_controls();
            break;
        case BridgeType::Custom:
            std::cout << "Set BridgeType: Custom" << std::endl;
            this->disable_builtin_bridge_controls();
            this->enable_custom_bridge_controls();
            break;
    }
}

void ConnectionSettingsPanel::set_builtin_bridge(BuiltinBridge builtin_bridge) {
    switch (builtin_bridge) {
        case BuiltinBridge::Obfs4:
            std::cout << "Set BuiltinBridge: Obfs4" << std::endl;
            break;
        case BuiltinBridge::Snowflake:
            std::cout << "Set BuiltinBridge: Snowflake" << std::endl;
            break;
        case BuiltinBridge::Meek:
            std::cout << "Set BuiltinBridge: Meek" << std::endl;
            break;
    }
}

void ConnectionSettingsPanel::set_use_proxy(bool enabled) {
    std::cout << "Set Use Proxy: " << (enabled ? "true" : "false") << std::endl;
    if (enabled) {
        this->enable_proxy_address_controls();
        const auto& proxy_type = static_cast<ProxyType>(this->proxy_type_combobox->GetSelection());
        if (proxy_type == ProxyType::SOCKS5 || proxy_type == ProxyType::HTTPS) {
            this->enable_proxy_authentication_controls();
        } else {
            this->disable_proxy_authentication_controls();
        }
    } else {
        this->disable_proxy_address_controls();
        this->disable_proxy_authentication_controls();
    }
}

void ConnectionSettingsPanel::set_proxy_type(ProxyType proxy_type) {
    switch (proxy_type) {
        case ProxyType::SOCKS4:
            std::cout << "Set Proxy Type: SOCKS4" << std::endl;
            this->disable_proxy_authentication_controls();
            break;
        case ProxyType::SOCKS5:
            std::cout << "Set Proxy Type: SOCKS5" << std::endl;
            this->enable_proxy_authentication_controls();
            break;
        case ProxyType::HTTPS:
            std::cout << "Set Proxy Type: HTTPS" << std::endl;
            this->enable_proxy_authentication_controls();
            break;
    }
}

void ConnectionSettingsPanel::set_use_firewall(bool enabled) {
    std::cout << "Set Use Firewall: " << (enabled ? "true" : "false") << std::endl;
    if (enabled) {
        this->enable_firewall_controls();
    } else {
        this->disable_firewall_controls();
    }
}

void ConnectionSettingsPanel::enable_bridge_controls() {
    this->builtin_bridge_option->Enable();
    this->custom_bridge_option->Enable();
}

void ConnectionSettingsPanel::enable_builtin_bridge_controls() {
    this->obfs4_bridge_option->Enable();
    this->obfs4_bridge_description->Enable();
    this->snowflake_bridge_option->Enable();
    this->snowflake_bridge_description->Enable();
    this->meek_bridge_option->Enable();
    this->meek_bridge_description->Enable();
}

void ConnectionSettingsPanel::enable_custom_bridge_controls() {
    this->custom_bridge_textbox->Enable();
}

void ConnectionSettingsPanel::enable_proxy_address_controls() {
    this->proxy_type_label->Enable();
    this->proxy_type_combobox->Enable();
    this->proxy_address_label->Enable();
    this->proxy_address_textbox->Enable();
    this->proxy_port_label->Enable();
    this->proxy_port_textbox->Enable();
}

void ConnectionSettingsPanel::enable_proxy_authentication_controls() {
    this->proxy_username_label->Enable();
    this->proxy_username_textbox->Enable();
    this->proxy_password_label->Enable();
    this->proxy_password_textbox->Enable();
}

void ConnectionSettingsPanel::enable_firewall_controls() {
    this->allowed_ports_label->Enable();
    this->allowed_ports_textbox->Enable();
}

void ConnectionSettingsPanel::disable_bridge_controls() {
    this->builtin_bridge_option->Disable();
    this->custom_bridge_option->Disable();
    this->disable_builtin_bridge_controls();
    this->disable_custom_bridge_controls();
}

void ConnectionSettingsPanel::disable_builtin_bridge_controls() {
    this->obfs4_bridge_option->Disable();
    this->obfs4_bridge_description->Disable();
    this->snowflake_bridge_option->Disable();
    this->snowflake_bridge_description->Disable();
    this->meek_bridge_option->Disable();
    this->meek_bridge_description->Disable();
}

void ConnectionSettingsPanel::disable_custom_bridge_controls() {
    this->custom_bridge_textbox->Disable();
}

void ConnectionSettingsPanel::disable_proxy_address_controls() {
    this->proxy_type_label->Disable();
    this->proxy_type_combobox->Disable();
    this->proxy_address_label->Disable();
    this->proxy_address_textbox->Disable();
    this->proxy_port_label->Disable();
    this->proxy_port_textbox->Disable();
}

void ConnectionSettingsPanel::disable_proxy_authentication_controls() {
    this->proxy_username_label->Disable();
    this->proxy_username_textbox->Disable();
    this->proxy_password_label->Disable();
    this->proxy_password_textbox->Disable();
}

void ConnectionSettingsPanel::disable_firewall_controls() {
    this->allowed_ports_label->Disable();
    this->allowed_ports_textbox->Disable();
}