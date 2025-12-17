#pragma once

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
        return translate(u8"Open existing profile…");
    }

    static wxString connect_panel_button_import_profile() {
        return translate(u8"Import legacy profile…");
    }

    static wxString connect_panel_label_recent_profiles() {
        return translate(u8"Recent profiles:");
    }
};
