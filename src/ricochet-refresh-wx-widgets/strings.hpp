#pragma once

#include "enums.hpp"

//clang-format off
class Strings {
public:
    static void init();

    static wxString translate(const char8_t str[]);
    static wxString translate_plural(const char8_t single[], const char8_t plural[], unsigned n);

    static wxString frame_title() {
        /* Titlebar String */
        return translate(u8"Ricochet-Refresh");
    }

    static wxString menu_bar_file() {
        return translate(u8"&File");
    }

    static wxString menu_quit() {
        return translate(u8"&Quit");
    }

    // bootstrapping strings
    static wxString connect_panel_title_disconnected() {
        return translate(u8"Connect to Tor");
    }

    static wxString connect_panel_title_connecting() {
        return translate(u8"Establishing a Connection");
    }

    static wxString connect_panel_title_connected() {
        return translate(u8"Connected");
    }

    static wxString connect_panel_explainer_text() {
        return translate(
            u8"Ricochet-Refresh routes your traffic over the Tor network, run by thousands of volunteers from around the world."
        );
    };

    static wxString connect_panel_connect_automatically_toggle() {
        return translate(u8"Always connect automatically");
    }

    static wxString connect_panel_button_configure() {
        return translate(u8"Configure…");
    }

    static wxString connect_panel_button_connect() {
        return translate(u8"Connect");
    }

    static wxString connect_panel_button_view_logs() {
        return translate(u8"View Logs…");
    }

    static wxString connect_panel_button_cancel() {
        return translate(u8"Cancel");
    }

    static wxString connect_panel_button_create_profile() {
        return translate(u8"Create new profile…");
    }

    static wxString connect_panel_button_open_profile() {
        return translate(u8"Open existing profile   ");
    }

    static wxString connect_panel_button_import_profile() {
        return translate(u8"Import legacy profile…");
    }

    static wxString connect_panel_label_recent_profiles() {
        return translate(u8"Recent profiles:");
    }

    static wxString connection_status_panel_title() {
        return translate(u8"Connection Status");
    }

    static wxString connection_status_panel_backend(wxString backend_type) {
        auto fmt_string = translate(u8"Backend: %s");
        return wxString::Format(fmt_string, backend_type);
    }

    static wxString
    connection_status_panel_bundled_client(const wxString& client, const wxString& version) {
        /* Bundled out-of-process tor implemenation (e.g. "bundled tor version 0.4.8.21, bundled arti version 1.8.0, etc)" */
        auto fmt_string = translate(u8"bundled %s version %s");
        return wxString::Format(fmt_string, client, version);
    }

    static wxString connection_status_panel_status(ConnectionStatus connection_status) {
        auto connection_status_string = [=]() {
            switch (connection_status) {
                case ConnectionStatus::Offline:
                    return translate(u8"Offline");
                case ConnectionStatus::Connecting:
                    return translate(u8"Connecting");
                case ConnectionStatus::Online:
                    return translate(u8"Online");
                default:
                    return translate(u8"Unknown");
            }
        }();

        std::cout << connection_status_string.utf8_string() << std::endl;

        auto fmt_string = translate(u8"Status: %s");
        return wxString::Format(fmt_string, connection_status_string);
    }

    static wxString copy_tor_logs() {
        return translate(u8"Copy Logs to Clipboard");
    }

    static wxString ok_button() {
        return translate(u8"Ok");
    }
};
