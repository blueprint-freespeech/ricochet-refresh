#pragma once
#include "enums.hpp"

// todo: replace with backend user-handle type
typedef void* ContactHandle;
struct ContactGroupHeadingPanel;
struct ContactPanel;

class ContactListPanel: public wxScrolled<wxPanel> {
public:
    ContactListPanel(wxWindow* parent);

    void add_contact(
        ContactHandle contact_handle,
        const wxString& nickname,
        const wxBitmap& avatar,
        ContactGroup contact_group
    );
    void remove_contact(ContactHandle contact_handle);

private:
    // setters
    void set_selected_contact_panel(ContactPanel* contact_panel);
    void set_group_expanded(ContactGroup contact_group, bool expanded);

    ContactGroupHeadingPanel* group_heading_panel[static_cast<int>(ContactGroup::Count)];
    wxBoxSizer* group_v_sizer[static_cast<int>(ContactGroup::Count)];
    bool group_expanded[static_cast<int>(ContactGroup::Count)];

    std::unordered_map<ContactHandle, ContactPanel*> contact_map;
    ContactPanel* selected_contact_panel = nullptr;

    friend class ContactPanel;
};
