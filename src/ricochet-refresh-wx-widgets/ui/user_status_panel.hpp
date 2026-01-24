#pragma once

enum class Visibility;

class UserStatusPanel: public wxPanel {
public:
    UserStatusPanel(wxWindow* parent);

private:
    // event handlers
    void on_profile_button_clicked();

    // setters+getters
    void set_visibility(Visibility visibility);
};
