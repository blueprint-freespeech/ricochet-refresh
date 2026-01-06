#pragma once

struct WrappedStaticText;

enum class TorBackend;
enum class BridgeType;
enum class BuiltinBridge;
enum class ProxyType;

class ConnectionSettingsPanel: public wxScrolled<wxPanel> {
public:
    explicit ConnectionSettingsPanel(wxWindow* parent);

private:
    // setters
    void set_tor_backend(TorBackend);
    void set_connect_automatically(bool);
    void set_use_bridges(bool);
    void set_bridge_type(BridgeType);
    void set_builtin_bridge(BuiltinBridge);
    void set_use_proxy(bool);
    void set_proxy_type(ProxyType);
    void set_use_firewall(bool);

    void enable_bridge_controls();
    void enable_builtin_bridge_controls();
    void enable_custom_bridge_controls();
    void enable_proxy_address_controls();
    void enable_proxy_authentication_controls();
    void enable_firewall_controls();
    void disable_bridge_controls();
    void disable_builtin_bridge_controls();
    void disable_custom_bridge_controls();
    void disable_proxy_address_controls();
    void disable_proxy_authentication_controls();
    void disable_firewall_controls();

    // widgets
    wxRadioButton* builtin_bridge_option = nullptr;
    wxRadioButton* obfs4_bridge_option = nullptr;
    WrappedStaticText* obfs4_bridge_description = nullptr;
    wxRadioButton* snowflake_bridge_option = nullptr;
    WrappedStaticText* snowflake_bridge_description = nullptr;
    wxRadioButton* meek_bridge_option = nullptr;
    WrappedStaticText* meek_bridge_description = nullptr;
    wxRadioButton* custom_bridge_option = nullptr;
    wxTextCtrl* custom_bridge_textbox = nullptr;
    wxStaticText* proxy_type_label = nullptr;
    wxComboBox* proxy_type_combobox = nullptr;
    wxStaticText* proxy_address_label = nullptr;
    wxTextCtrl* proxy_address_textbox = nullptr;
    wxStaticText* proxy_port_label = nullptr;
    wxTextCtrl* proxy_port_textbox = nullptr;
    wxStaticText* proxy_username_label = nullptr;
    wxTextCtrl* proxy_username_textbox = nullptr;
    wxStaticText* proxy_password_label = nullptr;
    wxTextCtrl* proxy_password_textbox = nullptr;
    wxStaticText* allowed_ports_label = nullptr;
    wxTextCtrl* allowed_ports_textbox = nullptr;

    // data
    TorBackend backend;
    bool connect_automatically;
    bool use_bridges;
    BridgeType bridge_type;
    BuiltinBridge builtin_bridge;
    wxString custom_bridges;
    uint16_t proxy_port;
    wxString proxy_address;
    wxString proxy_username;
    wxString proxy_password;
    bool use_firewall;
    wxString allowed_ports;
};