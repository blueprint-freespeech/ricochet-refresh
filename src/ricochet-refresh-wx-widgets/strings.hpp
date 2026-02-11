#pragma once

#include "enums.hpp"
#include "locale.hpp"

//clang-format off
class Strings {
public:
    static wxString from_utf8(const char8_t str[]);

    struct Common {
        static wxString app_name() {
            // we don't want to translate the application name
            return from_utf8(u8"Ricochet-Refresh");
        }

        static wxString close_button() {
            return Locale::translate(u8"Close");
        }

        static wxString new_line() {
            return from_utf8(u8"\n");
        }
    };

    struct MainFrame {
        static wxString title() {
            /* Titlebar String */
            return Common::app_name();
        }

        struct MenuBar {
            static wxString file() {
                return Locale::translate(u8"&File");
            }

            struct Menu {
                static wxString quit() {
                    return Locale::translate(u8"&Quit");
                }
            };
        };
    };

    struct DisconnectedPanel {
        static wxString title() {
            return Locale::translate(u8"Connect to Tor");
        }

        static wxString explainer_text() {
            return Locale::translate(
                u8"Ricochet-Refresh routes your traffic over the Tor network, run by thousands of volunteers from around the world."
            );
        }

        static wxString connect_automatically_toggle() {
            return Locale::translate(u8"Always connect automatically");
        }

        static wxString configure_button() {
            return Locale::translate(u8"Configure…");
        }

        static wxString connect_button() {
            return Locale::translate(u8"Connect");
        }
    };

    struct ConnectingPanel {
        static wxString title() {
            return Locale::translate(u8"Establishing a Connection");
        }

        static wxString explainer_text() {
            return DisconnectedPanel::explainer_text();
        }

        static wxString view_logs_button() {
            return Locale::translate(u8"View Logs…");
        }

        static wxString cancel_button() {
            return Locale::translate(u8"Cancel");
        }
    };

    struct ConnectedPanel {
        static wxString title() {
            return Locale::translate(u8"Connected");
        }

        static wxString create_profile_button() {
            return Locale::translate(u8"Create new profile…");
        }

        static wxString open_profile_button() {
            return Locale::translate(u8"Open existing profile");
        }

        static wxString import_profile_button() {
            return Locale::translate(u8"Import legacy profile…");
        }

        static wxString recent_profiles_label() {
            return Locale::translate(u8"Recent profiles:");
        }
    };

    struct ConnectionStatusPanel {
        static wxString title() {
            return Locale::translate(u8"Connection Status");
        }

        static wxString bundled_client_string(const wxString& client, const wxString& version) {
            /* Bundled out-of-process tor implemenation (e.g. "bundled tor (version 0.4.8.21), bundled arti (version 1.8.0), etc)" */
            auto fmt_string = Locale::translate(u8"bundled %s (version %s)");
            return wxString::Format(fmt_string, client, version);
        }

        static wxString backend_label(const wxString& backend_type) {
            auto fmt_string = Locale::translate(u8"Backend: %s");
            return wxString::Format(fmt_string, backend_type);
        }

        static wxString status_label(const ConnectionStatus connection_status) {
            auto connection_status_string = [=]() {
                switch (connection_status) {
                    case ConnectionStatus::Offline:
                        return Locale::translate(u8"Offline");
                    case ConnectionStatus::Connecting:
                        return Locale::translate(u8"Connecting");
                    case ConnectionStatus::Online:
                        return Locale::translate(u8"Online");
                    default:
                        return Locale::translate(u8"Unknown");
                }
            }();

            auto fmt_string = Locale::translate(u8"Status: %s");
            return wxString::Format(fmt_string, connection_status_string);
        }

        static wxString copy_tor_logs_button() {
            return Locale::translate(u8"Copy Logs to Clipboard");
        }

        static wxString close_button() {
            return Common::close_button();
        }
    };

    struct ConnectionSettingsPanel {
        static wxString backend_heading() {
            return Locale::translate(u8"Backend");
        }

        static wxString backend_description() {
            return Locale::translate(u8"Select which underlying Tor implementation to use.");
        }

        static wxString bundled_legacy_tor_option() {
            return Locale::translate(u8"Bundled legacy tor (Default)");
        }

        static wxString external_legacy_tor_option() {
            return Locale::translate(u8"External legacy tor");
        }

        static wxString in_process_arti_option() {
            return Locale::translate(u8"In-Process Arti");
        }

        static wxString quickstart_heading() {
            return Locale::translate(u8"Quickstart");
        }

        static wxString quickstart_description() {
            auto fmt_string = Locale::translate(
                u8"Quickstart connects %s to the Tor network automatically when launched, based on your last used connection setttings."
            );
            return wxString::Format(fmt_string, Strings::Common::app_name());
        }

        static wxString connect_automatically_toggle() {
            return DisconnectedPanel::connect_automatically_toggle();
        }

        static wxString bridges_heading() {
            return Locale::translate(u8"Bridges");
        }

        static wxString bridges_description() {
            return Locale::translate(
                u8"Bridges help you securely access the Tor network in places where Tor is blocked. Depending on where you are, one bridge may work better than another."
            );
        }

        static wxString use_bridges_toggle() {
            return Locale::translate(u8"Use bridges");
        }

        static wxString builtin_bridge_option() {
            auto fmt_string = Locale::translate(u8"Choose from one of %s's built-in bridges");
            return wxString::Format(fmt_string, Strings::Common::app_name());
        }

        static wxString custom_bridge_option() {
            return Locale::translate(u8"Enter bridge addresses you already know");
        }

        static wxString obfs4_bridge_option() {
            return from_utf8(u8"obfs4");
        }

        static wxString obfs4_bridge_description() {
            return Locale::translate(
                u8"Makes your Tor traffic look like random data. May not work in heavily censored regions."
            );
        }

        static wxString snowflake_bridge_option() {
            return from_utf8(u8"Snowflake");
        }

        static wxString snowflake_bridge_description() {
            return Locale::translate(
                u8"Routes your connection through Snowflake proxies to make it look like you’re placing a video call, for example."
            );
        }

        static wxString meek_bridge_option() {
            return from_utf8(u8"meek");
        }

        static wxString meek_bridge_description() {
            return Locale::translate(
                u8"Connects you to the Tor network through a big cloud provider. May work in heavily censored regions, but is usually very slow."
            );
        }

        static wxString custom_bridge_textbox_hint() {
            // todo: use a list-formatter from icu crate to build list of supported transports
            // https://docs.rs/icu/2.1.1/icu/list/index.html
            return Locale::translate(
                u8"Supported transports: meek_lite, obfs2, obfs3, obfs4, scramblesuit, webtunnel, snowflake, and conjure"
            );
        }

        static wxString network_settings_heading() {
            return Locale::translate(u8"Network Settings");
        }

        static wxString network_settings_description() {
            auto fmt_string = Locale::translate(u8"Configure how %s connects to the internet.");
            return wxString::Format(fmt_string, Common::app_name());
        }

        static wxString use_proxy_toggle() {
            return Locale::translate(u8"I use a proxy to connect to the internet");
        }

        static wxString proxy_type_label() {
            return Locale::translate(u8"Proxy type");
        }

        static wxString proxy_socks4() {
            return from_utf8(u8"SOCKS4");
        }

        static wxString proxy_socks5() {
            return from_utf8(u8"SOCKS5");
        }

        static wxString proxy_https() {
            return from_utf8(u8"HTTPS");
        }

        static wxArrayString proxy_types() {
            auto proxy_types = wxArrayString();
            proxy_types.Add(proxy_socks4());
            proxy_types.Add(proxy_socks5());
            proxy_types.Add(proxy_https());
            return proxy_types;
        }

        static wxString proxy_address_label() {
            return Locale::translate(u8"Address");
        }

        static wxString proxy_address_textbox_hint() {
            return Locale::translate(u8"IP address or hostname");
        }

        static wxString proxy_port_label() {
            return Locale::translate(u8"Port");
        }

        static wxString proxy_username_label() {
            return Locale::translate(u8"Username");
        }

        static wxString proxy_username_textbox_hint() {
            return Locale::translate(u8"Optional");
        }

        static wxString proxy_password_label() {
            return Locale::translate(u8"Password");
        }

        static wxString proxy_password_textbox_hint() {
            return proxy_username_textbox_hint();
        }

        static wxString firewall_toggle() {
            return Locale::translate(
                u8"This computer goes through a firewall that only allows connections to certain ports"
            );
        }

        static wxString allowed_ports_label() {
            return Locale::translate(u8"Allowed ports");
        }

        static wxString allowed_ports_textbox_hint() {
            // not translating this string is intentional, the tor backend expects a list in
            // this particular format
            return from_utf8(u8"80,443");
        }
    };

    struct Language {
        static wxString system() {
            return Locale::translate(u8"System language");
        }

        // not translating these functions is intentional as the
        // language names are translated to the name of each language
        // in the given language

        static wxString ar() {
            // note: we force rendering the reversed arabic word for
            // arabic (العربية) left to right using the
            // LEFT-TO-RIGHT OVERRIDE control character (\u202d) so that
            // (ar) always appears to the right rather than
            // relying on potentially platform-specific BiDi rendering
            return from_utf8(u8"\u202dةيبرعلا (ar)");
        }

        static wxString de() {
            return from_utf8(u8"Deutsch (de)");
        }

        static wxString en() {
            return from_utf8(u8"English (en)");
        }

        static wxString es() {
            return from_utf8(u8"Español (es)");
        }

        static wxString nl() {
            return from_utf8(u8"Nederlands (nl)");
        }
    };

    struct InterfaceSettingsPanel {
        static wxString language_heading() {
            return Locale::translate(u8"Language");
        }

        static wxString select_interface_language_label() {
            return Locale::translate(u8"Select interface language");
        }

        static wxArrayString supported_languages() {
            // should be sorted in order by their language code
            auto supported_languages = wxArrayString();
            supported_languages.Add(Language::system());
            supported_languages.Add(Language::ar());
            supported_languages.Add(Language::de());
            supported_languages.Add(Language::en());
            supported_languages.Add(Language::es());
            supported_languages.Add(Language::nl());

            return supported_languages;
        }

        static wxString toolbars_heading() {
            return Locale::translate(u8"Toolbars");
        }

        static wxString show_toolbar_toggle() {
            return Locale::translate(u8"Show toolbar");
        }

        static wxString button_style_label() {
            return Locale::translate(u8"Button style");
        }

        static wxString button_style_icons() {
            return Locale::translate(u8"Icons");
        }

        static wxString button_style_text() {
            return Locale::translate(u8"Text");
        }

        static wxString button_style_icons_and_text() {
            return Locale::translate(u8"Icons and Text");
        }

        static wxString button_style_icons_beside_text() {
            return Locale::translate(u8"Icons beside Text");
        }

        static wxArrayString button_styles() {
            auto button_styles = wxArrayString();
            button_styles.Add(button_style_icons());
            button_styles.Add(button_style_text());
            button_styles.Add(button_style_icons_and_text());
            button_styles.Add(button_style_icons_beside_text());

            return button_styles;
        }

        static wxString alerts_heading() {
            return Locale::translate(u8"Alerts");
        }

        static wxString show_desktop_notifications_toggle() {
            return Locale::translate(u8"Show desktop notifications");
        }

        static wxString blink_taskbar_icon_toggle() {
            return Locale::translate(u8"Blink taskbar icon");
        }

        static wxString enable_audio_notifications_toggle() {
            return Locale::translate(u8"Enable audio notifications");
        }

        static wxString window_heading() {
            return Locale::translate(u8"Window");
        }

        static wxString minimize_instead_of_exit_toggle() {
            return Locale::translate(u8"Minimize instead of exit");
        }

        static wxString show_system_tray_icon_toggle() {
            return Locale::translate(u8"Show system tray icon");
        }

        static wxString minimize_to_system_tray_toggle() {
            return Locale::translate(u8"Minimize to system tray");
        }
    };

    struct GeneralSettingsPanel {
        static wxString startup_heading() {
            return Locale::translate(u8"Startup");
        }

        static wxString start_only_single_instance_toggle() {
            auto fmt_string = Locale::translate(u8"Start only single instance of %s");
            return wxString::Format(fmt_string, Common::app_name());
        }

        static wxString check_for_updates_on_launch_toggle() {
            return Locale::translate(u8"Check for updates on launch");
        }
    };

    struct SettingsPanel {
        static wxString title() {
            return Locale::translate(u8"Settings");
        }

        static wxString general_settings_choice() {
            return Locale::translate(u8"General");
        }

        static wxString interface_settings_choice() {
            return Locale::translate(u8"Interface");
        }

        static wxString connection_settings_choice() {
            return Locale::translate(u8"Connection");
        }
    };

    struct ContactGroupPanel {
        static wxString group_label(ContactGroup contact_group) {
            switch (contact_group) {
                case ContactGroup::Connected:
                    return Locale::translate(u8"Connected");
                case ContactGroup::Disconnected:
                    return Locale::translate(u8"Disconnected");
                case ContactGroup::Requesting:
                    return Locale::translate(u8"Requesting");
                case ContactGroup::Blocked:
                    return Locale::translate(u8"Blocked");
                default:
                    return wxEmptyString;
            }
        }
    };

    struct Visibility {
        static wxString online() {
            return Locale::translate(u8"Online");
        }

        static wxString restricted() {
            return Locale::translate(u8"Restricted");
        }

        static wxString hidden() {
            return Locale::translate(u8"Hidden");
        }

        static wxString offline() {
            return Locale::translate(u8"Offline");
        }

        static wxString to_string(::Visibility visibility) {
            switch (visibility) {
                case ::Visibility::Online:
                    return online();
                case ::Visibility::Restricted:
                    return restricted();
                case ::Visibility::Hidden:
                    return hidden();
                case ::Visibility::Offline:
                    return offline();
                default:
                    return wxEmptyString;
            }
        }
    };

    struct UserStatusPanel {
        static wxString visibility_option(::Visibility visibility) {
            auto fmt_string = [=]() -> wxString {
                if (Locale::get_layout_direction() == LayoutDirection::RightToLeft) {
                    return from_utf8(u8"\u202b%s\u202c %s");
                } else {
                    return from_utf8(u8"%s %s");
                }
            }();
            wxString icon;
            switch (visibility) {
                case ::Visibility::Online:
                    icon = from_utf8(u8"●");
                    break;
                case ::Visibility::Restricted:
                    icon = from_utf8(u8"○");
                    break;
                case ::Visibility::Hidden:
                    icon = from_utf8(u8"▤");
                    break;
                case ::Visibility::Offline:
                    icon = from_utf8(u8"■");
                    break;
                default:
                    break;
            }
            auto option = Strings::Visibility::to_string(visibility);
            return wxString::Format(fmt_string, icon, option);
        }
    };

    struct MessageEntryPanel {
        static wxString bold_button() {
            return from_utf8(u8"B");
        }

        static wxString italic_button() {
            return from_utf8(u8"I");
        }

        static wxString underline_button() {
            return from_utf8(u8"U\u0332");
        }

        static wxString send_message_button() {
            if (Locale::get_layout_direction() == LayoutDirection::RightToLeft) {
                return from_utf8(u8"◁");
            } else {
                return from_utf8(u8"▷");
            }
        }
    };
};
