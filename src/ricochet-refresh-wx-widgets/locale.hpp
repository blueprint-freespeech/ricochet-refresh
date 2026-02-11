#pragma once

enum class LayoutDirection;
enum class Ordering;

class Locale {
public:
    static void init();

    static LayoutDirection get_layout_direction();
    static Ordering string_compare(const wxString& a, const wxString& b);

private:
    static wxString translate(const char8_t str[]);
    static wxString translate_plural(const char8_t single[], const char8_t plural[], unsigned n);
    friend class Strings;
};
