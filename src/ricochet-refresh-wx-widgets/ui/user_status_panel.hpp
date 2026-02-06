#pragma once

enum class Visibility;

class UserStatusPanel: public wxPanel {
public:
    explicit UserStatusPanel(wxWindow* parent);

private:
    // event handlers
    void on_profile_button_clicked();

    // setters+getters
    void set_visibility(Visibility visibility);
};
