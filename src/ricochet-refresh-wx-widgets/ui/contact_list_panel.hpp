#pragma once
#include "enums.hpp"

// todo: replace with backend user-handle type
typedef void* ContactHandle;
struct ContactGroupHeadingPanel;
struct ContactPanel;

class ContactListPanel: public wxScrolled<wxControl> {
public:
    ContactListPanel(wxWindow* parent, std::span<const ContactHandle> contacts);

    void add_contact(
        ContactHandle contact_handle,
        const wxString& nickname,
        const wxBitmap& avatar,
        ContactGroup contact_group
    );
    void remove_contact(ContactHandle contact_handle);

private:
    // event handlers
    void on_char(wxKeyEvent&);

    // setters/getters

    void
    set_selected_contact_group_heading_panel(ContactGroupHeadingPanel* contact_group_heading_panel);
    void set_selected_contact_panel(ContactPanel* contact_panel);

    void set_group_expanded(ContactGroup contact_group, bool expanded);
    bool get_group_expanded(ContactGroup contact_group) const;

    // navigation methods
    void navigate_up();
    void navigate_down();
    void navigate_out();
    void navigate_in();

    void remove_contact_panel(ContactPanel* contact_panel);

    // parent group nodes for each of our contact groups
    ContactGroupHeadingPanel* group_heading_panel[static_cast<size_t>(ContactGroup::Count)];
    // box-sizers containing each of the contacts within each group
    wxBoxSizer* group_v_sizer[static_cast<size_t>(ContactGroup::Count)];

    // pointers to currently selected item in list (group or contact)
    ContactGroupHeadingPanel* selected_contact_group_heading_panel = nullptr;
    ContactPanel* selected_contact_panel = nullptr;

    std::unordered_map<ContactHandle, ContactPanel*> contact_map;
};
