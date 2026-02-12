#pragma once

#include "mock_ffi.hpp"
using namespace mock;

class ContactListPanel;

class ContactPanel: public wxControl {
public:
    ContactPanel(
        ContactListPanel* parent,
        const ContactHandle contact_handle,
        const wxString& nickname,
        const wxBitmap& avatar
    );

    // insert 'first' before 'second'
    static void insert_before(ContactPanel* first, ContactPanel* second);
    // add 'first' after 'second'
    static void add_after(ContactPanel* first, ContactPanel* second);
    // remove 'panel' from its neighbors
    static void remove(ContactPanel* panel);

    ContactPanel* get_previous();
    ContactPanel* get_next();

    // setters+getters
    void set_selected(bool);
    bool get_selected() const;
    void set_mouse_hovering(bool mouse_hovering);
    bool get_mouse_hovering() const;

    ContactHandle get_contact_handle() const;
    void set_nickname(const wxString&);
    const wxString& get_nickname() const;
    void set_avatar(const wxBitmap&);

private:
    // event handlers
    void on_paint(const wxPaintEvent&);

    ContactPanel* previous = nullptr;
    ContactPanel* next = nullptr;

    // render data
    ContactHandle contact_handle;
    wxString nickname;
    wxBitmap avatar;

    // render state flags
    bool selected = false;
    bool mouse_hovering = false;
};
