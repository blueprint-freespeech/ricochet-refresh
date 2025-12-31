#include "connected_panel.hpp"

#include "fonts.hpp"
#include "metrics.hpp"
#include "strings.hpp"

ConnectedPanel::ConnectedPanel(wxWindow* parent) : wxPanel(parent) {
    auto v_sizer = new wxBoxSizer(wxVERTICAL);

    auto title = new wxStaticText(this, wxID_ANY, Strings::ConnectedPanel::title());
    title->SetFont(Fonts::title_font());

    auto create_profile_button =
        new wxButton(this, wxID_ANY, Strings::ConnectedPanel::create_profile_button());
    create_profile_button->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { this->create_profile(); });
    auto open_profile_button =
        new wxButton(this, wxID_ANY, Strings::ConnectedPanel::open_profile_button());
    open_profile_button->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { this->open_profile(); });
    auto import_profile_button =
        new wxButton(this, wxID_ANY, Strings::ConnectedPanel::import_profile_button());
    import_profile_button->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { this->import_profile(); });

    auto recent_profiles_label =
        new wxStaticText(this, wxID_ANY, Strings::ConnectedPanel::recent_profiles_label());

    this->recent_profiles_listbox = new wxListBox(this, wxID_ANY);
    auto recent_profiles = this->get_recent_profiles();
    this->set_recent_profiles(recent_profiles);

    recent_profiles_listbox->Bind(wxEVT_LISTBOX_DCLICK, [=, this](wxCommandEvent& evt) {
        this->open_recent_profile(evt.GetInt());
    });

    v_sizer->Add(title, 0, wxALIGN_CENTER | wxBOTTOM, Metrics::VERTICAL_PADDING_LARGE);
    v_sizer->Add(create_profile_button, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(open_profile_button, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(import_profile_button, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(recent_profiles_label, 0, wxEXPAND | wxBOTTOM, Metrics::VERTICAL_PADDING_MEDIUM);
    v_sizer->Add(this->recent_profiles_listbox, 1, wxEXPAND);

    this->SetSizerAndFit(v_sizer);
}

std::vector<std::filesystem::path> ConnectedPanel::get_recent_profiles() {
    // todo: read from configuration file
    std::vector<std::filesystem::path> result = {
        std::filesystem::path(u8"/path/to/profile.rr-profile"),
        std::filesystem::path(u8"/home/foo/profile.rr-profile"),
        std::filesystem::path(u8"/media/foo/USB-Drive/profile.rr-profile"),
    };
    return result;
}

void ConnectedPanel::create_profile() {
    std::cout << "create profile" << std::endl;
}

void ConnectedPanel::open_profile() {
    std::cout << "open profile" << std::endl;
}

void ConnectedPanel::import_profile() {
    std::cout << "import profile" << std::endl;
}

void ConnectedPanel::open_recent_profile(int index) {
    const auto profile_path_string = this->recent_profiles_listbox->GetString(index).utf8_string();
    const auto profile_path = std::filesystem::path(profile_path_string);

    // todo: load the profile, popup error box if file not found
    std::cout << "profile_path: " << profile_path << std::endl;
}

void ConnectedPanel::set_recent_profiles(const std::vector<std::filesystem::path>& profile_paths) {
    std::vector<wxString> profile_path_strings;
    profile_path_strings.reserve(profile_paths.size());

    for (auto& path : profile_paths) {
        auto path_utf8 = path.u8string();
        auto path_wxstring = wxString::FromUTF8Unchecked(
            reinterpret_cast<const char*>(path_utf8.data()),
            path_utf8.length()
        );
        profile_path_strings.push_back(path_wxstring);
    }

    this->recent_profiles_listbox->Set(profile_path_strings);
}
