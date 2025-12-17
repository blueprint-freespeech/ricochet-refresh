#include "fonts.hpp"

const wxFont& Fonts::title_font() {
    static const wxFont& font = wxFont(wxFontInfo()).Larger().Larger().Bold();
    return font;
}