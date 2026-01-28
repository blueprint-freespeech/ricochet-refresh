#include "contact_list_panel.hpp"

#include "contact_group_heading_panel.hpp"
#include "contact_panel.hpp"
#include "enums.hpp"
#include "metrics.hpp"
#include "mock_ffi.hpp"
#include "strings.hpp"

using namespace mock;

ContactListPanel::ContactListPanel(wxWindow* parent, std::span<const ContactHandle> contacts) :
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

    for (const auto contact_handle : contacts) {
        this->add_contact(
            contact_handle,
            nickname_from_contact_handle(contact_handle),
            avatar_from_contact_handle(contact_handle),
            ContactGroup::Disconnected
        );
    }

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