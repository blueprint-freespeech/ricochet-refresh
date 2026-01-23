#pragma once

class ContactListPanel;
enum class ContactGroup;

wxDECLARE_EVENT(wxEVT_CONTACT_GROUP_EXPAND, wxCommandEvent);
wxDECLARE_EVENT(wxEVT_CONTACT_GROUP_COLLAPSE, wxCommandEvent);

class ContactGroupHeadingPanel: public wxControl {
public:
    ContactGroupHeadingPanel(ContactListPanel* parent, ContactGroup contact_group, bool expanded);

private:
    // event handlers
    void on_paint(const wxPaintEvent&);
    void on_set_focus(wxFocusEvent&);
    void on_kill_focus(wxFocusEvent&);
    void on_left_down(const wxMouseEvent&);
    void on_char(wxKeyEvent&);

    // setters
    void set_expanded(bool expanded);

    // event emitters
    void emit_expand_event();
    void emit_collapse_event();

    ContactGroup contact_group;
    bool expanded = false;
};