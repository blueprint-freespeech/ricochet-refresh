#include "contact_panel.hpp"

#include "contact_list_panel.hpp"
#include "metrics.hpp"

ContactPanel::ContactPanel(
    ContactListPanel* parent,
    const wxString& nickname,
    const wxBitmap& avatar
) :
    wxControl(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxBORDER_NONE),
    nickname(nickname),
    avatar(avatar) {
    this->SetBackgroundStyle(wxBG_STYLE_PAINT);
    this->SetMinSize(
        wxSize(wxDefaultCoord, Metrics::AVATAR_SIZE + Metrics::HORIZONTAL_PADDING_MEDIUM * 2)
    );

    // window events
    this->Bind(wxEVT_PAINT, &ContactPanel::on_paint, this);

    // input events
    this->Bind(wxEVT_ENTER_WINDOW, [this](const wxMouseEvent&) { this->set_mouse_hovering(true); });
    this->Bind(wxEVT_LEAVE_WINDOW, [this](const wxMouseEvent&) {
        this->set_mouse_hovering(false);
    });
}

// linked list management

void ContactPanel::insert_before(ContactPanel* a, ContactPanel* b) {
    // verify 'a' is not already in a list
    assert(a->previous == nullptr);
    assert(a->next == nullptr);
    assert(a != b);

    // before:
    // b-1 <-> b <-> b+1
    // after:
    // b-1 <-> a <-> b <-> b+1

    a->previous = b->previous;
    b->previous = a;
    a->next = b;
}

void ContactPanel::add_after(ContactPanel* a, ContactPanel* b) {
    // veiry 'a' is not already in a list
    assert(a->previous == nullptr);
    assert(a->next == nullptr);
    assert(a != b);

    // before:
    // b-1 <-> b <-> b+1
    // after:
    // b-1 <-> b <-> a <-> b+1

    a->next = b->next;
    b->next = a;
    a->previous = b;
}

void ContactPanel::remove(ContactPanel* panel) {
    // before:
    // p-1 <-> p <-> p+1
    // after:
    // p-1 <-> p+1

    auto previous = panel->previous;
    auto next = panel->next;

    if (previous) {
        if (next) {
            next->previous = previous;
            previous->next = next;
        } else {
            previous->next = nullptr;
        }
    } else if (next) {
        next->previous = nullptr;
    } else {
        // niks te doen
    }

    panel->next = panel->previous = nullptr;
}

ContactPanel* ContactPanel::get_previous() {
    return this->previous;
}

ContactPanel* ContactPanel::get_next() {
    return this->next;
}

// event handlers

void ContactPanel::on_paint(const wxPaintEvent&) {
    wxAutoBufferedPaintDC dc(this);
    const auto bg_colour = [this]() {
        if (this->get_selected()) {
            return wxSystemSettings::GetColour(wxSYS_COLOUR_HIGHLIGHT);
        } else if (this->get_mouse_hovering()) {
            return wxSystemSettings::GetColour(wxSYS_COLOUR_BTNHIGHLIGHT);
        } else {
            return this->GetParent()->GetBackgroundColour();
        }
    }();
    dc.SetBackground(wxBrush(bg_colour));
    dc.Clear();
    dc.SetBackground(wxNullBrush);

    const auto client_rect = this->GetClientRect();

    // draw avatar
    const auto avatar_size = Metrics::AVATAR_SIZE;
    const auto h_padding = Metrics::HORIZONTAL_PADDING_MEDIUM;

    const auto avatar_x = client_rect.x + h_padding;
    const auto avatar_y = client_rect.y + (client_rect.GetHeight() - avatar_size) / 2;
    const auto avatar_rect = wxRect(avatar_x, avatar_y, avatar_size, avatar_size);

    dc.DrawBitmap(this->avatar, avatar_rect.GetPosition());

    // draw nickname

    dc.SetFont(this->GetFont());
    const auto text_colour = [this]() {
        if (this->get_selected()) {
            return wxSystemSettings::GetColour(wxSYS_COLOUR_LISTBOXHIGHLIGHTTEXT);
        } else {
            return wxSystemSettings::GetColour(wxSYS_COLOUR_LISTBOXTEXT);
        }
    }();
    dc.SetTextForeground(text_colour);

    auto nickname = this->nickname;

    wxCoord text_w, text_h;
    dc.GetTextExtent(nickname, &text_w, &text_h);

    const auto text_x = avatar_rect.GetRight() + h_padding;
    const auto text_y_center = client_rect.GetTop() + client_rect.GetHeight() / 2;
    const auto text_y = text_y_center - text_h / 2;

    // elide long nicknames
    const auto available_width = client_rect.GetRight() - text_x;
    if (text_w > available_width) {
        nickname = wxControl::Ellipsize(nickname, dc, wxELLIPSIZE_END, available_width);
    }
    dc.DrawText(nickname, wxPoint(text_x, text_y));
}

// setters+getters
void ContactPanel::set_selected(bool selected) {
    if (selected != this->selected) {
        this->selected = selected;
        // focus so we scroll into view in parent when selected
        if (selected) {
            this->SetFocus();
        }
        this->Refresh();
    }
}

bool ContactPanel::get_selected() const {
    return this->selected;
}

void ContactPanel::set_mouse_hovering(bool mouse_hovering) {
    if (this->mouse_hovering != mouse_hovering) {
        this->mouse_hovering = mouse_hovering;
        this->Refresh();
    }
}

bool ContactPanel::get_mouse_hovering() const {
    return this->mouse_hovering;
}

const wxString& ContactPanel::get_nickname() const {
    return this->nickname;
}