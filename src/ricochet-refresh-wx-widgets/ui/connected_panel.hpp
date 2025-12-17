#pragma once

class ConnectedPanel: public wxPanel {
public:
    explicit ConnectedPanel(wxWindow* parent);

private:
    wxListBox* recent_profiles_listbox = nullptr;

    // get the recent profiles from settings
    static std::vector<std::filesystem::path> get_recent_profiles();
    void create_profile();
    void open_profile();
    void import_profile();
    void open_recent_profile(int index);
    void set_recent_profiles(const std::vector<std::filesystem::path>& profile_paths);
};
