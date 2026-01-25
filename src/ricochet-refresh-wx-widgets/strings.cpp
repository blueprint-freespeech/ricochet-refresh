#include "strings.hpp"

void Strings::init() {
    // load platform
    wxUILocale::UseDefault();

    // get executable's parent directory
    const auto executable_path_string = wxStandardPaths::Get().GetExecutablePath();
    const std::filesystem::path executable_path(executable_path_string.utf8_string());
    const auto executable_parent_path = executable_path.parent_path();

    // add to catalog path
    wxFileTranslationsLoader::AddCatalogLookupPathPrefix(executable_parent_path.c_str());

    // load translations
    auto translations = new wxTranslations();
    wxTranslations::Set(translations);
    if (!translations->AddCatalog("ricochet-refresh")) {
        wxLogError("Could not load ricochet-refresh catalog");
    }
}

wxString Strings::raw(const char8_t str[]) {
    return wxString::FromUTF8(reinterpret_cast<const char*>(str));
}

wxString Strings::translate(const char8_t str[]) {
    return wxGetTranslation(wxString::FromUTF8(reinterpret_cast<const char*>(str)));
}

// cppcheck-suppress unusedFunction
wxString Strings::translate_plural(const char8_t single[], const char8_t plural[], unsigned n) {
    return wxGetTranslation(
        wxString::FromUTF8(reinterpret_cast<const char*>(single)),
        wxString::FromUTF8(reinterpret_cast<const char*>(plural)),
        n
    );
}
