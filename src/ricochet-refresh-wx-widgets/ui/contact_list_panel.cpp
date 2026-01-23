#include "contact_list_panel.hpp"

#include "contact_group_heading_panel.hpp"
#include "contact_panel.hpp"
#include "enums.hpp"
#include "metrics.hpp"
#include "strings.hpp"

ContactListPanel::ContactListPanel(wxWindow* parent) :
    wxScrolled<wxPanel>(
        parent,
        wxID_ANY,
        wxDefaultPosition,
        wxDefaultSize,
        wxVSCROLL | wxTAB_TRAVERSAL
    ) {
    this->SetScrollRate(0, this->FromDIP(Metrics::VSCROLL_RATE));
    this->SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_LISTBOX));

    auto v_sizer = new wxBoxSizer(wxVERTICAL);

    // todo: load actual avatars
    constexpr unsigned char avatar_data[] = {0xFF, 0xAA, 0xFF};
    const auto avatar_size = Metrics::AVATAR_SIZE;
    auto avatar_image = wxImage(1, 1, const_cast<unsigned char*>(avatar_data), true);
    avatar_image.Rescale(avatar_size, avatar_size, wxIMAGE_QUALITY_BILINEAR);
    const auto debug_avatar = wxBitmap(avatar_image);

    v_sizer->AddSpacer(Metrics::VERTICAL_PADDING_SMALL);

    for (auto i = 0; i < static_cast<int>(ContactGroup::Count); ++i) {
        const auto contact_group = static_cast<ContactGroup>(i);
        // todo: load expanded from profile
        const auto expanded = true;
        auto group_heading_panel = new ContactGroupHeadingPanel(this, contact_group, expanded);
        group_heading_panel->Bind(wxEVT_CONTACT_GROUP_EXPAND, [=, this](wxCommandEvent&) {
            this->set_group_expanded(contact_group, true);
        });
        group_heading_panel->Bind(wxEVT_CONTACT_GROUP_COLLAPSE, [=, this](wxCommandEvent&) {
            this->set_group_expanded(contact_group, false);
        });

        this->group_heading_panel[i] = group_heading_panel;
        this->group_v_sizer[i] = new wxBoxSizer(wxVERTICAL);
        this->group_expanded[i] = expanded;

        // Layout
        v_sizer->Add(group_heading_panel, 0, wxEXPAND);
        v_sizer->Add(this->group_v_sizer[i], 0, wxEXPAND);
    }

    // todo: load from profile
    this->add_contact(
        reinterpret_cast<ContactHandle>(0),
        "Alice",
        debug_avatar,
        ContactGroup::Connected
    );
    this->add_contact(
        reinterpret_cast<ContactHandle>(3),
        "Claire",
        debug_avatar,
        ContactGroup::Disconnected
    );
    this->add_contact(
        reinterpret_cast<ContactHandle>(2),
        "Bridgette",
        debug_avatar,
        ContactGroup::Disconnected
    );
    this->add_contact(
        reinterpret_cast<ContactHandle>(4),
        "Danielle",
        debug_avatar,
        ContactGroup::Requesting
    );
    this->add_contact(
        reinterpret_cast<ContactHandle>(5),
        "Erica",
        debug_avatar,
        ContactGroup::Requesting
    );
    this->add_contact(
        reinterpret_cast<ContactHandle>(6),
        "Felicia",
        debug_avatar,
        ContactGroup::Requesting
    );
    this->add_contact(
        reinterpret_cast<ContactHandle>(7),
        "Gabriella",
        debug_avatar,
        ContactGroup::Blocked
    );
    this->add_contact(
        reinterpret_cast<ContactHandle>(8),
        "Henrietta",
        debug_avatar,
        ContactGroup::Blocked
    );

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
    this->contact_map.insert({contact_handle, contact_panel});

    const auto cg = static_cast<int>(contact_group);
    auto v_sizer = this->group_v_sizer[cg];
    const auto expanded = this->group_expanded[cg];

    const auto item_count = v_sizer->GetItemCount();
    if (item_count > 0) {
        // insert contact alphabetically
        for (auto i = 0; i < item_count; ++i) {
            auto item = v_sizer->GetItem(i)->GetWindow();
            auto cp = dynamic_cast<ContactPanel*>(item);
            assert(cp != nullptr);
            // todo: implement locale-aware compare
            if (cp->get_nickname() > nickname) {
                v_sizer->Insert(i, contact_panel, 0, wxEXPAND);
                v_sizer->Show(contact_panel, expanded);
                contact_panel->MoveBeforeInTabOrder(cp);
                this->Layout();
                return;
            }
        }
        // contact should appear last
        auto last_item = v_sizer->GetItem(item_count - 1)->GetWindow();
        v_sizer->Add(contact_panel, 0, wxEXPAND);
        v_sizer->Show(contact_panel, expanded);
        contact_panel->MoveAfterInTabOrder(last_item);
        this->Layout();
    } else {
        auto group_heading_panel = this->group_heading_panel[cg];
        v_sizer->Add(contact_panel, 0, wxEXPAND);
        v_sizer->Show(contact_panel, expanded);
        contact_panel->MoveAfterInTabOrder(group_heading_panel);
        this->Layout();
    }
}

void ContactListPanel::remove_contact(ContactHandle contact_handle) {
    if (auto it = this->contact_map.find(contact_handle); it != this->contact_map.end()) {
        auto contact_panel = it->second;
        auto sizer = contact_panel->GetContainingSizer();
        sizer->Detach(contact_panel);
        if (this->selected_contact_panel = contact_panel) {
            this->selected_contact_panel = nullptr;
        }
        contact_panel->Destroy();
        this->Layout();
    }
}

void ContactListPanel::set_selected_contact_panel(ContactPanel* contact_panel) {
    // todo: we also need to update the chat panel
    if (this->selected_contact_panel == contact_panel) {
        return;
    } else if (this->selected_contact_panel) {
        this->selected_contact_panel->set_selected(false);
    }
    this->selected_contact_panel = contact_panel;
}

void ContactListPanel::set_group_expanded(ContactGroup contact_group, bool expanded) {
    const auto i = static_cast<int>(contact_group);
    if (this->group_expanded[i] != expanded) {
        this->group_expanded[i] = expanded;

        auto v_sizer = this->group_v_sizer[i];
        v_sizer->ShowItems(expanded);
        this->SendSizeEvent();
    }
}