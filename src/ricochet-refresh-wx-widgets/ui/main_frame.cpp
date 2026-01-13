#include "main_frame.hpp"

#include "bootstrap_panel.hpp"
#include "connection_settings_panel.hpp"
#include "connection_status_panel.hpp"
#include "enums.hpp"
#include "interface_settings_panel.hpp"
#include "strings.hpp"
#include "wrapped_static_text.hpp"

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

    // auto panel = new ConnectionSettingsPanel(this);

    auto panel = new InterfaceSettingsPanel(this);

    // auto top_string =
    //     "Ricochet Refresh est applicatio nuntiorum inter pares quae Tor utitur ad clientes connectendos. Cum Ricochet Refresh incipis, servitium Tor occultum in computatro tuo creat. Inscriptio huius servitii occulti est identitas tua anonyma in rete Tor et modus quo alii tecum communicare poterunt.";
    // auto left_string =
    //     "Ricochet Refresh is a peer-to-peer messenger app that uses Tor to connect clients. When you start Ricochet Refresh it creates a Tor hidden service on your computer. The address of this hidden service is your anonymous identity on the Tor network and how others will be able to communicate with you.";
    // auto right_string =
    //     "Ricochet Refresh is een peer-to-peer berichtenapp die Tor gebruikt om gebruikers met elkaar te verbinden. Wanneer je Ricochet Refresh start, wordt er een Tor hidden service op je computer aangemaakt. Het adres van deze hidden service is je anonieme identiteit op het Tor-netwerk en bepaalt hoe anderen met je kunnen communiceren.";

    // auto panel = new wxPanel(this, wxID_ANY);

    // auto top_text = new WrappedStaticText(panel, wxID_ANY, top_string);
    // auto left_text = new WrappedStaticText(panel, wxID_ANY, left_string);
    // auto right_text = new WrappedStaticText(panel, wxID_ANY, right_string);

    // auto v_sizer = new wxBoxSizer(wxVERTICAL);

    // auto h_sizer = new wxBoxSizer(wxHORIZONTAL);
    // v_sizer->Add(top_text, 0, wxEXPAND | wxALL, 8);

    // h_sizer->Add(left_text, 1, wxEXPAND | wxRIGHT, 4);
    // h_sizer->Add(right_text, 1, wxEXPAND | wxLEFT, 4);

    // v_sizer->Add(h_sizer, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);

    // panel->SetSizer(v_sizer);

    this->SetMinSize(wxSize(800, 600));
    this->SetSize(wxSize(800, 600));

    // Bind Event Handlers
    this->Bind(wxEVT_MENU, &MainFrame::on_exit, this, wxID_EXIT);
}
