#include "contact_group_heading_panel.hpp"

#include "contact_list_panel.hpp"
#include "metrics.hpp"
#include "strings.hpp"

ContactGroupHeadingPanel::ContactGroupHeadingPanel(
    ContactListPanel* parent,
    ContactGroup contact_group,
    bool expanded
) :
    wxControl(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxBORDER_NONE),
    contact_group(contact_group),
    expanded(expanded) {
    this->SetBackgroundStyle(wxBG_STYLE_PAINT);
    this->SetMinSize(wxSize(wxDefaultCoord, Metrics::line_height(*this) * 5 / 4));

    // window events
    this->Bind(wxEVT_PAINT, &ContactGroupHeadingPanel::on_paint, this);

    // input events
    this->Bind(wxEVT_ENTER_WINDOW, [this](const wxMouseEvent&) { this->set_mouse_hovering(true); });
    this->Bind(wxEVT_LEAVE_WINDOW, [this](const wxMouseEvent&) {
        this->set_mouse_hovering(false);
    });
}

void ContactGroupHeadingPanel::on_paint(const wxPaintEvent&) {
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

    // draw heading

    dc.SetFont(this->GetFont());
    const auto text_colour = [this]() {
        if (this->get_selected()) {
            return wxSystemSettings::GetColour(wxSYS_COLOUR_LISTBOXHIGHLIGHTTEXT);
        } else {
            return wxSystemSettings::GetColour(wxSYS_COLOUR_LISTBOXTEXT);
        }
    }();
    dc.SetTextForeground(text_colour);

    auto heading = Strings::ContactGroupPanel::group_label(this->contact_group, this->expanded);

    wxCoord text_w, text_h;
    dc.GetTextExtent(heading, &text_w, &text_h);

    const auto text_x = 0;
    const auto text_y_center = client_rect.GetTop() + client_rect.GetHeight() / 2;
    const auto text_y = text_y_center - text_h / 2;

    // elide long heading
    const auto available_width = client_rect.GetWidth();

    if (text_w > available_width) {
        heading = wxControl::Ellipsize(heading, dc, wxELLIPSIZE_END, available_width);
    }
    dc.DrawText(heading, wxPoint(text_x, text_y));
}

// setters+getters

void ContactGroupHeadingPanel::set_selected(bool selected) {
    if (this->selected != selected) {
        this->selected = selected;
        // focus so we scroll into view in parent when selected
        if (selected) {
            this->SetFocus();
        }
        this->Refresh();
    }
}

bool ContactGroupHeadingPanel::get_selected() const {
    return this->selected;
}

void ContactGroupHeadingPanel::set_mouse_hovering(bool mouse_hovering) {
    if (this->mouse_hovering != mouse_hovering) {
        this->mouse_hovering = mouse_hovering;
        this->Refresh();
    }
}

bool ContactGroupHeadingPanel::get_mouse_hovering() const {
    return this->mouse_hovering;
}

void ContactGroupHeadingPanel::set_expanded(bool expanded) {
    if (this->expanded != expanded) {
        this->expanded = expanded;
        this->Refresh();
    }
}

bool ContactGroupHeadingPanel::get_expanded() const {
    return this->expanded;
}

ContactGroup ContactGroupHeadingPanel::get_contact_group() const {
    return this->contact_group;
}