#pragma once

class MainFrame: public wxFrame {
public:
    MainFrame();

private:
    void setup_menubar();

    // Event Handlers
    void on_exit(wxCommandEvent& event) {
        this->Close(true);
    }
};
