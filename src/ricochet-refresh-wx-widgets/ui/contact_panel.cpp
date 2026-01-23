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
    this->Bind(wxEVT_SET_FOCUS, &ContactPanel::on_set_focus, this);
    this->Bind(wxEVT_KILL_FOCUS, &ContactPanel::on_kill_focus, this);

    // input events
    this->Bind(wxEVT_LEFT_DOWN, &ContactPanel::on_left_down, this);
    this->Bind(wxEVT_CHAR, &ContactPanel::on_char, this);
}

// event handlers

void ContactPanel::on_paint(const wxPaintEvent&) {
    wxAutoBufferedPaintDC dc(this);
    const auto bg_colour = [this]() {
        if (this->get_selected()) {
            return wxSystemSettings::GetColour(wxSYS_COLOUR_HIGHLIGHT);
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
    if (this->get_selected()) {
        auto colour = wxSystemSettings::GetColour(wxSYS_COLOUR_LISTBOXHIGHLIGHTTEXT);
        dc.SetTextForeground(colour);
    } else {
        auto colour = wxSystemSettings::GetColour(wxSYS_COLOUR_LISTBOXTEXT);
        dc.SetTextForeground(colour);
    }

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

    // draw focus rect
    if (this->HasFocus()) {
        // todo: this doesn't work on macOS
        wxRendererNative::Get().DrawFocusRect(this, dc, client_rect, wxCONTROL_SELECTED);
    }
}

void ContactPanel::on_set_focus(wxFocusEvent& event) {
    this->Refresh();
    event.Skip();

    std::cout << "Focus: " << this->nickname << std::endl;
}

void ContactPanel::on_kill_focus(wxFocusEvent& event) {
    this->Refresh();
    event.Skip();
}

void ContactPanel::on_left_down(const wxMouseEvent&) {
    this->set_selected(true);
    this->SetFocus();
}

void ContactPanel::on_char(wxKeyEvent& event) {
    const auto key_code = event.GetKeyCode();
    switch (key_code) {
        case WXK_SPACE:
        case WXK_RETURN:
        case WXK_NUMPAD_ENTER:
            this->set_selected(true);
            break;
        default:
            event.Skip();
            break;
    }
}

// setters+getters
void ContactPanel::set_selected(bool selected) {
    if (selected != this->selected) {
        this->selected = selected;
        this->Refresh();

        if (this->selected) {
            if (auto contact_list_panel = dynamic_cast<ContactListPanel*>(this->GetParent());
                contact_list_panel) {
                contact_list_panel->set_selected_contact_panel(this);
            }
        }
    }
}

bool ContactPanel::get_selected() const {
    return this->selected;
}

const wxString& ContactPanel::get_nickname() const {
    return this->nickname;
}