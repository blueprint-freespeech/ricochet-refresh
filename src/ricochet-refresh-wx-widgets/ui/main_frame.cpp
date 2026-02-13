#include "main_frame.hpp"

#include "bootstrap_panel.hpp"
#include "connection_settings_panel.hpp"
#include "connection_status_panel.hpp"
#include "conversations_panel.hpp"
#include "enums.hpp"
#include "general_settings_panel.hpp"
#include "interface_settings_panel.hpp"
#include "settings_panel.hpp"
#include "strings.hpp"
#include "wrapped_static_text.hpp"

MainFrame::MainFrame() : wxFrame(nullptr, wxID_ANY, Strings::MainFrame::title()) {
    this->setup_menubar();

    // auto panel = new BootstrapPanel(this);
    // panel->ShowDisconnected();
    // panel->ShowConnecting();
    // panel->ShowConnected();

    // auto panel = new ConnectionStatusPanel(
    //     this,
    //     Strings::ConnectionStatusPanel::bundled_client_string("tor", "0.4.8.21"),
    //     ConnectionStatus::Online
    // );

    // auto panel = new GeneralSettingsPanel(this);
    // auto panel = new InterfaceSettingsPanel(this);
    // auto panel = new ConnectionSettingsPanel(this);

    // auto panel = new SettingsPanel(this);

    const static ContactHandle contacts[8] = {
        reinterpret_cast<ContactHandle>(0),
        reinterpret_cast<ContactHandle>(1),
        reinterpret_cast<ContactHandle>(2),
        reinterpret_cast<ContactHandle>(3),
        reinterpret_cast<ContactHandle>(4),
        reinterpret_cast<ContactHandle>(5),
        reinterpret_cast<ContactHandle>(6),
        reinterpret_cast<ContactHandle>(7),
    };
    auto panel = new ConversationsPanel(this, std::span(contacts, 8));

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

void MainFrame::setup_menubar() {
    // create MenuBar
    auto menu_bar = new wxMenuBar();

    // create Profile menu
    auto profile_menu = new wxMenu();
    auto new_profile =
        profile_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Profile::new_profile());
    auto open_profile =
        profile_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Profile::open_profile());
    auto save_profile_as = profile_menu->Append(
        wxID_ANY,
        Strings::MainFrame::MenuBar::Menu::Profile::save_profile_as()
    );
    auto edit_profile =
        profile_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Profile::edit_profile());

    profile_menu->AppendSeparator();

    auto close_profile =
        profile_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Profile::close_profile());
    auto logout =
        profile_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Profile::logout());

    profile_menu->AppendSeparator();

    auto copy_user_id =
        profile_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Profile::copy_user_id());
    auto set_visibility_menu = new wxMenu();
    auto visible = set_visibility_menu->Append(
        wxID_ANY,
        Strings::MainFrame::MenuBar::Menu::Profile::SetVisibility::visible()
    );
    auto restricted = set_visibility_menu->Append(
        wxID_ANY,
        Strings::MainFrame::MenuBar::Menu::Profile::SetVisibility::restricted()
    );
    auto hidden = set_visibility_menu->Append(
        wxID_ANY,
        Strings::MainFrame::MenuBar::Menu::Profile::SetVisibility::hidden()
    );
    auto offline = set_visibility_menu->Append(
        wxID_ANY,
        Strings::MainFrame::MenuBar::Menu::Profile::SetVisibility::offline()
    );

    auto set_visibility = profile_menu->AppendSubMenu(
        set_visibility_menu,
        Strings::MainFrame::MenuBar::Menu::Profile::set_visibility()
    );

    profile_menu->AppendSeparator();

    auto logout_all =
        profile_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Profile::logout_all());
    auto _quit =
        profile_menu->Append(wxID_EXIT, Strings::MainFrame::MenuBar::Menu::Profile::quit());

    // create Contacts menu
    auto contacts_menu = new wxMenu();
    auto add_contact =
        contacts_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Contacts::add_contact());
    auto delete_contact = contacts_menu->Append(
        wxID_ANY,
        Strings::MainFrame::MenuBar::Menu::Contacts::delete_contact()
    );
    auto connect_contact = contacts_menu->Append(
        wxID_ANY,
        Strings::MainFrame::MenuBar::Menu::Contacts::connect_contact()
    );
    auto disconnect_contact = contacts_menu->Append(
        wxID_ANY,
        Strings::MainFrame::MenuBar::Menu::Contacts::disconnect_contact()
    );
    auto block_contact = contacts_menu->Append(
        wxID_ANY,
        Strings::MainFrame::MenuBar::Menu::Contacts::block_contact()
    );
    auto unblock_contact = contacts_menu->Append(
        wxID_ANY,
        Strings::MainFrame::MenuBar::Menu::Contacts::unblock_contact()
    );

    // create Chat menu
    auto chat_menu = new wxMenu();
    auto export_logs =
        chat_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Chat::export_logs());
    auto delete_logs =
        chat_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Chat::delete_logs());

    // create Tools menu
    auto tools_menu = new wxMenu();
    auto downloads =
        tools_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Tools::downloads());
    auto tor_logs =
        tools_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Tools::tor_logs());
    auto settings =
        tools_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Tools::settings());

    // create Help menu
    auto help_menu = new wxMenu();
    auto manual = help_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Help::manual());
    auto changelog =
        help_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Help::changelog());
    auto licenses =
        help_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Help::licenses());
    help_menu->AppendSeparator();
    auto check_for_updates =
        help_menu->Append(wxID_ANY, Strings::MainFrame::MenuBar::Menu::Help::check_for_updates());
    auto about = help_menu->Append(wxID_ABOUT, Strings::MainFrame::MenuBar::Menu::Help::about());

    // add Menus to MenUBar
    menu_bar->Append(profile_menu, Strings::MainFrame::MenuBar::profile());
    menu_bar->Append(contacts_menu, Strings::MainFrame::MenuBar::contacts());
    menu_bar->Append(chat_menu, Strings::MainFrame::MenuBar::chat());
    menu_bar->Append(tools_menu, Strings::MainFrame::MenuBar::tools());
    menu_bar->Append(help_menu, Strings::MainFrame::MenuBar::help());

    this->SetMenuBar(menu_bar);
}
