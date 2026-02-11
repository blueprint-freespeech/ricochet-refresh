#include "strings.hpp"

wxString Strings::from_utf8(const char8_t str[]) {
    return wxString::FromUTF8(reinterpret_cast<const char*>(str));
}
