#include "contact_list_panel.hpp"

#include "contact_group_heading_panel.hpp"
#include "contact_panel.hpp"
#include "enums.hpp"
#include "metrics.hpp"
#include "mock_ffi.hpp"
#include "strings.hpp"

using namespace mock;

ContactListPanel::ContactListPanel(wxWindow* parent, std::span<const ContactHandle> contacts) :
    wxScrolled<wxControl>(
        parent,
        wxID_ANY,
        wxDefaultPosition,
        wxDefaultSize,
        wxVSCROLL | wxWANTS_CHARS
    ) {
    this->SetScrollRate(0, this->FromDIP(Metrics::VSCROLL_RATE));
    this->SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_LISTBOX));

    auto v_sizer = new wxBoxSizer(wxVERTICAL);
    v_sizer->AddSpacer(Metrics::VERTICAL_PADDING_SMALL);

    for (auto i = 0; i < static_cast<int>(ContactGroup::Count); ++i) {
        const auto contact_group = static_cast<ContactGroup>(i);
        // todo: load expanded from profile
        const auto expanded = true;
        auto group_heading_panel = new ContactGroupHeadingPanel(this, contact_group, expanded);
        group_heading_panel->Bind(wxEVT_LEFT_DOWN, [=, this](wxMouseEvent&) {
            const auto expanded = this->get_group_expanded(contact_group);
            this->set_group_expanded(contact_group, !expanded);
            this->set_selected_contact_group_heading_panel(group_heading_panel);
        });

        this->group_heading_panel[i] = group_heading_panel;
        this->group_v_sizer[i] = new wxBoxSizer(wxVERTICAL);

        // Layout
        v_sizer->Add(group_heading_panel, 0, wxEXPAND);
        v_sizer->Add(this->group_v_sizer[i], 0, wxEXPAND);
    }

    for (const auto contact_handle : contacts) {
        this->add_contact(
            contact_handle,
            nickname_from_contact_handle(contact_handle),
            avatar_from_contact_handle(contact_handle),
            ContactGroup::Disconnected
        );
    }

    this->Bind(wxEVT_CHAR, &ContactListPanel::on_char, this);

    this->SetSizerAndFit(v_sizer);
}

void ContactListPanel::add_contact(
    ContactHandle contact_handle,
    const wxString& nickname,
    const wxBitmap& avatar,
    ContactGroup contact_group
) {
    assert(this->contact_map.find(contact_handle) == this->contact_map.end());

    auto contact_panel = new ContactPanel(this, nickname, avatar);
    contact_panel->Bind(wxEVT_LEFT_DOWN, [=, this](wxMouseEvent& event) {
        this->set_selected_contact_panel(contact_panel);
    });

    this->contact_map.insert({contact_handle, contact_panel});

    // figure out which sizer and where in that sizer
    // to insert this ContactPanel
    const auto cg = static_cast<int>(contact_group);
    auto v_sizer = this->group_v_sizer[cg];
    const auto expanded = this->get_group_expanded(contact_group);

    const auto item_count = v_sizer->GetItemCount();
    if (item_count > 0) {
        // insert contact alphabetically
        size_t i = 0;
        for (auto item : v_sizer->GetChildren()) {
            auto window = item->GetWindow();
            auto cp = dynamic_cast<ContactPanel*>(window);
            assert(cp != nullptr);
            // todo: implement locale-aware compare
            if (cp->get_nickname() > nickname) {
                v_sizer->Insert(i, contact_panel, 0, wxEXPAND);
                ContactPanel::insert_before(contact_panel, cp);
                break;
            } else if (i == item_count - 1) {
                v_sizer->Add(contact_panel, 0, wxEXPAND);
                ContactPanel::add_after(contact_panel, cp);
                break;
            }
            ++i;
        }
    } else {
        v_sizer->Add(contact_panel, 0, wxEXPAND);
    }
    v_sizer->Show(contact_panel, expanded);
    this->Layout();
}

void ContactListPanel::remove_contact(ContactHandle contact_handle) {
    if (auto it = this->contact_map.find(contact_handle); it != this->contact_map.end()) {
        // remove widget
        auto contact_panel = it->second;
        if (contact_panel == this->selected_contact_panel) {
            this->selected_contact_panel = nullptr;
        }
        ContactPanel::remove(contact_panel);

        auto sizer = contact_panel->GetContainingSizer();
        sizer->Detach(contact_panel);
        contact_panel->Destroy();
        this->Layout();
    }
}

void ContactListPanel::on_char(wxKeyEvent& evt) {
    switch (evt.GetKeyCode()) {
        case WXK_UP:
        case WXK_NUMPAD_UP:
            this->navigate_up();
            break;
        case WXK_DOWN:
        case WXK_NUMPAD_DOWN:
            this->navigate_down();
            break;
        case WXK_LEFT:
        case WXK_NUMPAD_LEFT:
            if (const auto layout_direction = wxUILocale::GetCurrent().GetLayoutDirection();
                layout_direction == wxLayout_LeftToRight) {
                this->navigate_out();
            } else {
                this->navigate_in();
            }
            break;
        case WXK_RIGHT:
        case WXK_NUMPAD_RIGHT:
            if (const auto layout_direction = wxUILocale::GetCurrent().GetLayoutDirection();
                layout_direction == wxLayout_LeftToRight) {
                this->navigate_in();
            } else {
                this->navigate_out();
            }
            break;
        case WXK_DELETE:
            if (this->selected_contact_panel) {
                this->remove_contact_panel(this->selected_contact_panel);
            }
            break;
        default:
            this->HandleAsNavigationKey(evt);
            break;
    }

    if (this->selected_contact_group_heading_panel) {
        std::cout << "Selected ContactGroupHeadingPanel: "
                  << Strings::ContactGroupPanel::group_label(
                         this->selected_contact_group_heading_panel->get_contact_group(),
                         true
                     )
                  << std::endl;
    } else if (this->selected_contact_panel) {
        std::cout << "Selected ContactPanel: " << this->selected_contact_panel->get_nickname()
                  << std::endl;
    }
}

void ContactListPanel::set_selected_contact_group_heading_panel(
    ContactGroupHeadingPanel* contact_group_heading_panel
) {
    // handle contact group heading panel
    if (this->selected_contact_group_heading_panel) {
        this->selected_contact_group_heading_panel->set_selected(false);
    }
    this->selected_contact_group_heading_panel = contact_group_heading_panel;
    this->selected_contact_group_heading_panel->set_selected(true);

    // handle contact panel
    if (this->selected_contact_panel) {
        this->selected_contact_panel->set_selected(false);
        this->selected_contact_panel = nullptr;
    }

    this->SetFocus();
}

void ContactListPanel::set_selected_contact_panel(ContactPanel* contact_panel) {
    // handle contact group heading panel
    if (this->selected_contact_group_heading_panel) {
        this->selected_contact_group_heading_panel->set_selected(false);
        this->selected_contact_group_heading_panel = nullptr;
    }

    // handle contact panel
    if (this->selected_contact_panel) {
        this->selected_contact_panel->set_selected(false);
    }
    this->selected_contact_panel = contact_panel;
    this->selected_contact_panel->set_selected(true);

    this->SetFocus();
}

void ContactListPanel::set_group_expanded(ContactGroup contact_group, bool expanded) {
    const auto i = static_cast<int>(contact_group);
    auto contact_group_heading_panel = this->group_heading_panel[i];
    if (contact_group_heading_panel->get_expanded() != expanded) {
        auto v_sizer = this->group_v_sizer[i];
        v_sizer->ShowItems(expanded);
        this->SendSizeEvent();
        contact_group_heading_panel->set_expanded(expanded);
    }
}

bool ContactListPanel::get_group_expanded(ContactGroup contact_group) const {
    const auto i = static_cast<int>(contact_group);
    const auto contact_group_heading_panel = this->group_heading_panel[i];
    return contact_group_heading_panel->get_expanded();
}

void ContactListPanel::navigate_up() {
    // handle contact group heading panel currently selected
    if (this->selected_contact_group_heading_panel) {
        const auto contact_group = this->selected_contact_group_heading_panel->get_contact_group();
        // only move up if we aren't the top group
        if (static_cast<int>(contact_group) > 0) {
            const auto prev_contact_group =
                static_cast<ContactGroup>(static_cast<int>(contact_group) - 1);
            auto v_sizer = this->group_v_sizer[static_cast<int>(prev_contact_group)];
            // move to previous group if no children or if collapsed
            if (v_sizer->IsEmpty() || !this->get_group_expanded(prev_contact_group)) {
                auto contact_group_heading_panel =
                    this->group_heading_panel[static_cast<int>(prev_contact_group)];
                this->set_selected_contact_group_heading_panel(contact_group_heading_panel);
                // otherwise move to last contact in prev group
            } else {
                auto sizer_item = v_sizer->GetChildren().back();
                auto contact_panel = dynamic_cast<ContactPanel*>(sizer_item->GetWindow());
                this->set_selected_contact_panel(contact_panel);
            }
        }
        // handle contact panel currently selected
    } else if (this->selected_contact_panel) {
        auto prev_contact_panel = this->selected_contact_panel->get_previous();
        // select previous contact panel
        if (prev_contact_panel) {
            this->set_selected_contact_panel(prev_contact_panel);
            // select previous contact group heading panel
        } else {
            auto containing_sizer = this->selected_contact_panel->GetContainingSizer();
            auto i = 0;
            for (; i < static_cast<int>(ContactGroup::Count); ++i) {
                if (containing_sizer == this->group_v_sizer[i]) {
                    break;
                }
            }
            if (i < static_cast<int>(ContactGroup::Count)) {
                auto contact_group_heading_panel = this->group_heading_panel[i];
                this->set_selected_contact_group_heading_panel(contact_group_heading_panel);
            }
        }
    } else {
        this->set_selected_contact_group_heading_panel(this->group_heading_panel[0]);
    }
}

void ContactListPanel::navigate_down() {
    // handle contact group heading panel currently selected
    if (this->selected_contact_group_heading_panel) {
        const auto contact_group = this->selected_contact_group_heading_panel->get_contact_group();

        auto v_sizer = this->group_v_sizer[static_cast<int>(contact_group)];
        // select first child if expanded
        if (!v_sizer->IsEmpty() && this->get_group_expanded(contact_group)) {
            auto sizer_item = v_sizer->GetChildren().front();
            auto contact_panel = dynamic_cast<ContactPanel*>(sizer_item->GetWindow());
            this->set_selected_contact_panel(contact_panel);
            // select next group
        } else if (static_cast<int>(contact_group) + 1 < static_cast<int>(ContactGroup::Count)) {
            auto contact_group_heading_panel =
                this->group_heading_panel[static_cast<int>(contact_group) + 1];
            this->set_selected_contact_group_heading_panel(contact_group_heading_panel);
        }
    } else if (this->selected_contact_panel) {
        auto next = this->selected_contact_panel->get_next();
        // select next contact if it exists
        if (next) {
            this->set_selected_contact_panel(next);
            // select next group
        } else {
            auto containing_sizer = this->selected_contact_panel->GetContainingSizer();
            auto i = 0;
            for (; i < static_cast<int>(ContactGroup::Count); ++i) {
                if (containing_sizer == this->group_v_sizer[i]) {
                    break;
                }
            }
            if (i + 1 < static_cast<int>(ContactGroup::Count)) {
                auto contact_group_heading_panel = this->group_heading_panel[i + 1];
                this->set_selected_contact_group_heading_panel(contact_group_heading_panel);
            }
        }
    } else {
        this->set_selected_contact_group_heading_panel(this->group_heading_panel[0]);
    }
}

void ContactListPanel::navigate_out() {
    // heading panel is already selected so just expanda it
    if (this->selected_contact_group_heading_panel) {
        auto contact_group = this->selected_contact_group_heading_panel->get_contact_group();
        this->set_group_expanded(contact_group, false);
        // contact panel is selected so select its parent group
    } else if (this->selected_contact_panel) {
        auto containing_sizer = this->selected_contact_panel->GetContainingSizer();
        for (auto i = 0; i < static_cast<int>(ContactGroup::Count); ++i) {
            if (containing_sizer == this->group_v_sizer[i]) {
                auto contact_group_heading_panel = this->group_heading_panel[i];
                this->set_selected_contact_group_heading_panel(contact_group_heading_panel);
                break;
            }
        }
    } else {
        this->set_selected_contact_group_heading_panel(this->group_heading_panel[0]);
    }
}

void ContactListPanel::navigate_in() {
    if (this->selected_contact_group_heading_panel) {
        for (auto i = 0; i < static_cast<int>(ContactGroup::Count); ++i) {
            if (this->selected_contact_group_heading_panel == this->group_heading_panel[i]) {
                this->set_group_expanded(static_cast<ContactGroup>(i), true);
            }
        }
    } else if (this->selected_contact_panel) {
        // no-op
    } else {
        this->set_selected_contact_group_heading_panel(this->group_heading_panel[0]);
    }
}

void ContactListPanel::remove_contact_panel(ContactPanel* contact_panel) {
    auto containing_sizer = contact_panel->GetContainingSizer();
    auto begin = std::begin(this->group_v_sizer);
    auto end = std::end(this->group_v_sizer);
    if (auto it = std::find(begin, end, containing_sizer); it != end) {
        if (*it == containing_sizer) {
            containing_sizer->Detach(contact_panel);
            ContactPanel::remove(contact_panel);
            contact_panel->Destroy();
            this->Layout();
            if (this->selected_contact_panel == contact_panel) {
                this->selected_contact_panel = nullptr;
            }
        }
    }
}