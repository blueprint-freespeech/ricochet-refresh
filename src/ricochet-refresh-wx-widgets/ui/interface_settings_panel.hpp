#pragma once

enum class Language;
enum class ButtonStyle;

class InterfaceSettingsPanel: public wxScrolled<wxPanel> {
public:
    explicit InterfaceSettingsPanel(wxWindow* parent);

private:
    // setters
    void set_interface_language(Language);
    void set_show_toolbar(bool);
    void set_button_style(ButtonStyle);
    void set_show_desktop_notifications(bool);
    void set_blink_taskbar_icon(bool);
    void set_enable_audio_notifications(bool);
    void set_minimize_instead_of_exit(bool);
    void set_show_system_tray_icon(bool);
    void set_minimize_to_system_tray(bool);

    void enable_button_style_controls();
    void enable_system_tray_icon_controls();

    void disable_button_style_controls();
    void disable_system_tray_icon_controls();

    // widgets
    wxStaticText* button_style_label = nullptr;
    wxComboBox* button_style_combobox = nullptr;
    wxCheckBox* minimize_to_system_tray_toggle = nullptr;
};
