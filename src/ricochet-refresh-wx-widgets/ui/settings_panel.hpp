#pragma once

class GeneralSettingsPanel;
class InterfaceSettingsPanel;
class ConnectionSettingsPanel;
enum class Settings;

class SettingsPanel: public wxPanel {
public:
    explicit SettingsPanel(wxWindow* parent);

private:
    // setters
    void set_current_settings_panel(Settings);

    // actions
    void show_general_settings();
    void show_interface_settings();
    void show_connection_settings();

    void apply();
    void cancel();
    void ok();

    // widgets
    GeneralSettingsPanel* general_settings_panel = nullptr;
    InterfaceSettingsPanel* interface_settings_panel = nullptr;
    ConnectionSettingsPanel* connection_settings_panel = nullptr;
};
