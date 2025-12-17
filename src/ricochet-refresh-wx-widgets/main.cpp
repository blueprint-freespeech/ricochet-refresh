#include "strings.hpp"
#include "ui/main_frame.hpp"

class App: public wxApp {
public:
    bool OnInit() override {
        if (!wxApp::OnInit()) {
            return false;
        }

        Strings::init();

        auto main_frame = new MainFrame();
        main_frame->Show(true);
        return true;
    }
};

wxIMPLEMENT_APP(App);
