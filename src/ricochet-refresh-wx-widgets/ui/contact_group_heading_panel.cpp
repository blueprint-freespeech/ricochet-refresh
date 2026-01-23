#include "contact_group_heading_panel.hpp"

#include "contact_list_panel.hpp"
#include "metrics.hpp"
#include "strings.hpp"

wxDEFINE_EVENT(wxEVT_CONTACT_GROUP_EXPAND, wxCommandEvent);
wxDEFINE_EVENT(wxEVT_CONTACT_GROUP_COLLAPSE, wxCommandEvent);

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
    this->Bind(wxEVT_SET_FOCUS, &ContactGroupHeadingPanel::on_set_focus, this);
    this->Bind(wxEVT_KILL_FOCUS, &ContactGroupHeadingPanel::on_kill_focus, this);

    // input events
    this->Bind(wxEVT_LEFT_DOWN, &ContactGroupHeadingPanel::on_left_down, this);
    this->Bind(wxEVT_CHAR, &ContactGroupHeadingPanel::on_char, this);
}

void ContactGroupHeadingPanel::on_paint(const wxPaintEvent&) {
    wxAutoBufferedPaintDC dc(this);
    const auto bg_colour = this->GetParent()->GetBackgroundColour();
    dc.SetBackground(wxBrush(bg_colour));
    dc.Clear();
    dc.SetBackground(wxNullBrush);

    const auto client_rect = this->GetClientRect();

    // draw heading

    dc.SetFont(this->GetFont());
    auto colour = wxSystemSettings::GetColour(wxSYS_COLOUR_LISTBOXTEXT);
    dc.SetTextForeground(colour);

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

    // draw focus rect
    if (this->HasFocus()) {
        // todo: this doesn't work on macOS
        wxRendererNative::Get().DrawFocusRect(this, dc, client_rect, wxCONTROL_SELECTED);
    }
}

void ContactGroupHeadingPanel::on_set_focus(wxFocusEvent& event) {
    const auto heading = [this]() {
        switch (this->contact_group) {
            case ContactGroup::Connected:
                return "Connected";
            case ContactGroup::Disconnected:
                return "Disconnected";
            case ContactGroup::Requesting:
                return "Requesting";
            case ContactGroup::Blocked:
                return "Blocked";
            default:
                return "";
        }
    }();
    std::cout << "Focus: " << heading << " group " << std::endl;

    this->Refresh();
    event.Skip();
}

void ContactGroupHeadingPanel::on_kill_focus(wxFocusEvent& event) {
    this->Refresh();
    event.Skip();
}

void ContactGroupHeadingPanel::on_left_down(const wxMouseEvent&) {
    this->set_expanded(!this->expanded);
    this->SetFocus();
    this->Refresh();
}

void ContactGroupHeadingPanel::on_char(wxKeyEvent& event) {
    const auto key_code = event.GetKeyCode();
    switch (key_code) {
        case WXK_SPACE:
        case WXK_RETURN:
        case WXK_NUMPAD_ENTER:
            this->set_expanded(!this->expanded);
            this->Refresh();
            break;
        default:
            event.Skip();
            break;
    }
}

void ContactGroupHeadingPanel::set_expanded(bool expanded) {
    this->expanded = expanded;
    if (this->expanded) {
        this->emit_expand_event();
    } else {
        this->emit_collapse_event();
    }
}

void ContactGroupHeadingPanel::emit_expand_event() {
    wxCommandEvent evt(wxEVT_CONTACT_GROUP_EXPAND, GetId());
    evt.SetEventObject(this);
    ProcessWindowEvent(evt);
}

void ContactGroupHeadingPanel::emit_collapse_event() {
    wxCommandEvent evt(wxEVT_CONTACT_GROUP_COLLAPSE, GetId());
    evt.SetEventObject(this);
    ProcessWindowEvent(evt);
}
