#pragma once

#include "enums.hpp"

//clang-format off
class Strings {
public:
    static void init();

    static wxString translate(const char8_t str[]);
    static wxString translate_plural(const char8_t single[], const char8_t plural[], unsigned n);

    struct Common {
        static wxString app_name() {
            // we don't want to translate the application name
            return wxString("Ricochet-Refresh");
        }

        static wxString ok_button() {
            return translate(u8"Ok");
        }
    };

    struct MainFrame {
        static wxString title() {
            /* Titlebar String */
            return Common::app_name();
        }

        struct MenuBar {
            static wxString file() {
                return translate(u8"&File");
            }

            struct Menu {
                static wxString quit() {
                    return translate(u8"&Quit");
                }
            };
        };
    };

    struct DisconnectedPanel {
        static wxString title() {
            return translate(u8"Connect to Tor");
        }

        static wxString explainer_text() {
            return translate(
                u8"Ricochet-Refresh routes your traffic over the Tor network, run by thousands of volunteers from around the world."
            );
        }

        static wxString connect_automatically_toggle() {
            return translate(u8"Always connect automatically");
        }

        static wxString configure_button() {
            return translate(u8"Configure…");
        }

        static wxString connect_button() {
            return translate(u8"Connect");
        }
    };

    struct ConnectingPanel {
        static wxString title() {
            return translate(u8"Establishing a Connection");
        }

        static wxString explainer_text() {
            return DisconnectedPanel::explainer_text();
        }

        static wxString view_logs_button() {
            return translate(u8"View Logs…");
        }

        static wxString cancel_button() {
            return translate(u8"Cancel");
        }
    };

    struct ConnectedPanel {
        static wxString title() {
            return translate(u8"Connected");
        }

        static wxString create_profile_button() {
            return translate(u8"Create new profile…");
        }

        static wxString open_profile_button() {
            return translate(u8"Open existing profile");
        }

        static wxString import_profile_button() {
            return translate(u8"Import legacy profile…");
        }

        static wxString recent_profiles_label() {
            return translate(u8"Recent profiles:");
        }
    };

    struct ConnectionStatusPanel {
        static wxString title() {
            return translate(u8"Connection Status");
        }

        static wxString bundled_client_string(const wxString& client, const wxString& version) {
            /* Bundled out-of-process tor implemenation (e.g. "bundled tor (version 0.4.8.21), bundled arti (version 1.8.0), etc)" */
            auto fmt_string = translate(u8"bundled %s (version %s)");
            return wxString::Format(fmt_string, client, version);
        }

        static wxString backend_label(const wxString& backend_type) {
            auto fmt_string = translate(u8"Backend: %s");
            return wxString::Format(fmt_string, backend_type);
        }

        static wxString status_label(const ConnectionStatus connection_status) {
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

            auto fmt_string = translate(u8"Status: %s");
            return wxString::Format(fmt_string, connection_status_string);
        }

        static wxString copy_tor_logs_button() {
            return translate(u8"Copy Logs to Clipboard");
        }

        static wxString ok_button() {
            return Common::ok_button();
        }
    };
};
