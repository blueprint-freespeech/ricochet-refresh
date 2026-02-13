#include "user_status_panel.hpp"

#include "enums.hpp"
#include "metrics.hpp"
#include "strings.hpp"

UserStatusPanel::UserStatusPanel(wxWindow* parent) : wxPanel(parent) {
    auto h_sizer = new wxBoxSizer(wxHORIZONTAL);

    wxString visibility_options[static_cast<size_t>(Visibility::Count)] = {
        Strings::UserStatusPanel::visibility_option(Visibility::Online),
        Strings::UserStatusPanel::visibility_option(Visibility::Restricted),
        Strings::UserStatusPanel::visibility_option(Visibility::Hidden),
        Strings::UserStatusPanel::visibility_option(Visibility::Offline),
    };

    // todo: would neeed a custom widget to render as we envisioned using wxOwnerDrawnComboBox
    auto visibility_choice = new wxChoice(
        this,
        wxID_ANY,
        wxDefaultPosition,
        wxDefaultSize,
        static_cast<int>(Visibility::Count),
        visibility_options
    );
    // todo: load default visibility from profile
    visibility_choice->SetSelection(static_cast<int>(Visibility::Online));
    visibility_choice->Bind(wxEVT_CHOICE, [this](const wxCommandEvent& event) {
        this->set_visibility(static_cast<Visibility>(event.GetInt()));
    });

    constexpr unsigned char avatar_data[] = {0xFF, 0xAA, 0xFF};
    const auto avatar_size = Metrics::AVATAR_SIZE;
    auto avatar_image = wxImage(1, 1, const_cast<unsigned char*>(avatar_data), true);
    avatar_image.Rescale(avatar_size, avatar_size, wxIMAGE_QUALITY_BILINEAR);
    const auto debug_avatar = wxBitmap(avatar_image);

    auto profile_button = new wxBitmapButton(this, wxID_ANY, debug_avatar);
    profile_button->Bind(wxEVT_BUTTON, [this](const wxCommandEvent&) {
        this->on_profile_button_clicked();
    });

    // Layout
    h_sizer->Add(visibility_choice, 1, wxEXPAND);
    h_sizer->Add(profile_button, 0, wxEXPAND);

    this->SetSizerAndFit(h_sizer);
}

void UserStatusPanel::on_profile_button_clicked() {
    std::cout << "Profile Button Pressed" << std::endl;
}

void UserStatusPanel::set_visibility(Visibility visibility) {
    std::cout << "Set Visibility: " << Strings::Enums::Visibility::to_string(visibility)
              << std::endl;
}
