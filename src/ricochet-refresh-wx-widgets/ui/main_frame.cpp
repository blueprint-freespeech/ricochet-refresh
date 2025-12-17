#include "main_frame.hpp"

#include "bootstrap_panel.hpp"
#include "strings.hpp"

MainFrame::MainFrame() : wxFrame(nullptr, wxID_ANY, Strings::frame_title()) {
    // Create MenuBar
    auto menuBar = new wxMenuBar();
    // Craete File Menu
    auto menuFile = new wxMenu();
    menuFile->Append(wxID_EXIT, Strings::menu_quit());

    // Add Menus to MenUBar
    menuBar->Append(menuFile, Strings::menu_bar_file());
    this->SetMenuBar(menuBar);

    auto panel = new BootstrapPanel(this);
    // panel->ShowDisconnected();
    // panel->ShowConnecting();
    panel->ShowConnected();

    this->SetMinSize(wxSize(800, 600));
    this->SetSize(wxSize(800, 600));

    // Bind Event Handlers
    this->Bind(wxEVT_MENU, &MainFrame::on_exit, this, wxID_EXIT);
}
