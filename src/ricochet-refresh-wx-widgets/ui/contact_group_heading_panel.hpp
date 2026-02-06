#pragma once

class ContactListPanel;
enum class ContactGroup;

class ContactGroupHeadingPanel: public wxControl {
public:
    ContactGroupHeadingPanel(ContactListPanel* parent, ContactGroup contact_group, bool expanded);

    // setters/getters
    void set_selected(bool selected);
    bool get_selected() const;
    void set_mouse_hovering(bool mouse_hovering);
    bool get_mouse_hovering() const;
    void set_expanded(bool expanded);
    bool get_expanded() const;
    ContactGroup get_contact_group() const;

private:
    // event handlers
    void on_paint(const wxPaintEvent&);

    ContactGroup contact_group;
    // render state flags
    bool selected = false;
    bool mouse_hovering = false;
    bool expanded = false;
};