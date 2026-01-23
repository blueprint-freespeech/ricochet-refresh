#pragma once
class ContactListPanel;

class ContactPanel: public wxControl {
public:
    ContactPanel(ContactListPanel* parent, const wxString& nickname, const wxBitmap& avatar);

private:
    // event handlers
    void on_paint(const wxPaintEvent&);
    void on_set_focus(wxFocusEvent&);
    void on_kill_focus(wxFocusEvent&);
    void on_left_down(const wxMouseEvent&);
    void on_char(wxKeyEvent&);

    // setters+getters
    void set_selected(bool);
    bool get_selected() const;
    void set_nickname(const wxString&);
    const wxString& get_nickname() const;
    void set_avatar(const wxBitmap&);

    bool selected = false;
    wxString nickname;
    wxBitmap avatar;

    friend class ContactListPanel;
};
