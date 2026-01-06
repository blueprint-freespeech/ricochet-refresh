#include "main_frame.hpp"

#include "bootstrap_panel.hpp"
#include "connection_settings_panel.hpp"
#include "connection_status_panel.hpp"
#include "enums.hpp"
#include "strings.hpp"

MainFrame::MainFrame() : wxFrame(nullptr, wxID_ANY, Strings::MainFrame::title()) {
    // Create MenuBar
    auto menuBar = new wxMenuBar();
    // Craete File Menu
    auto menuFile = new wxMenu();
    menuFile->Append(wxID_EXIT, Strings::MainFrame::MenuBar::Menu::quit());

    // Add Menus to MenUBar
    menuBar->Append(menuFile, Strings::MainFrame::MenuBar::file());
    this->SetMenuBar(menuBar);

    // auto panel = new BootstrapPanel(this);
    // panel->ShowDisconnected();
    // panel->ShowConnecting();
    // panel->ShowConnected();

    // auto panel = new ConnectionStatusPanel(
    //     this,
    //     Strings::ConnectionStatusPanel::bundled_client_string("tor", "0.4.8.21"),
    //     ConnectionStatus::Online
    // );

    auto panel = new ConnectionSettingsPanel(this);

    this->SetMinSize(wxSize(800, 600));
    this->SetSize(wxSize(800, 600));

    // Bind Event Handlers
    this->Bind(wxEVT_MENU, &MainFrame::on_exit, this, wxID_EXIT);
}
