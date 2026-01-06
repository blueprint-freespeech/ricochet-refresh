#include "fonts.hpp"

const wxFont& Fonts::title_font() {
    static const wxFont& font = wxFont(wxFontInfo()).Larger().Larger().Bold();
    return font;
}

const wxFont& Fonts::heading_font() {
    static const wxFont& font = wxFont(wxFontInfo()).Larger().Bold();
    return font;
}
