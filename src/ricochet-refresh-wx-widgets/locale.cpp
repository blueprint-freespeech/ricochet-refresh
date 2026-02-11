#include "locale.hpp"

#include "enums.hpp"

void Locale::init() {
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

LayoutDirection Locale::get_layout_direction() {
    const static LayoutDirection layout_direction = []() {
        const auto layout_direction = wxUILocale::GetCurrent().GetLayoutDirection();
        switch (layout_direction) {
            case wxLayout_RightToLeft:
                return LayoutDirection::RightToLeft;
            case wxLayout_LeftToRight:
            default:
                return LayoutDirection::LeftToRight;
        }
    }();
    return layout_direction;
}

Ordering Locale::string_compare(const wxString& a, const wxString& b) {
    // todo: actually implement locale-specific comparison
    auto result = a.Cmp(b);
    if (result < 0) {
        return Ordering::Less;
    } else if (result > 0) {
        return Ordering::Greater;
    } else {
        return Ordering::Equal;
    }
}

wxString Locale::translate(const char8_t str[]) {
    return wxGetTranslation(wxString::FromUTF8(reinterpret_cast<const char*>(str)));
}

wxString Locale::translate_plural(const char8_t single[], const char8_t plural[], unsigned n) {
    return wxGetTranslation(
        wxString::FromUTF8(reinterpret_cast<const char*>(single)),
        wxString::FromUTF8(reinterpret_cast<const char*>(plural)),
        n
    );
}