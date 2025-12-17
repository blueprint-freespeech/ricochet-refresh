#pragma once

class MainFrame: public wxFrame {
public:
    MainFrame();

private:
    // Event Handlers
    void on_exit(wxCommandEvent& event) {
        this->Close(true);
    }
};
