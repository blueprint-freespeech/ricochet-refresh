#pragma once

class GeneralSettingsPanel: public wxScrolled<wxPanel> {
public:
    explicit GeneralSettingsPanel(wxWindow* parent);

private:
    // setters
    void set_start_only_single_instance(bool);
    void set_check_for_updates(bool);
};