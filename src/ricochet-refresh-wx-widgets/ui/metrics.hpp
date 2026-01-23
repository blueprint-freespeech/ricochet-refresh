#pragma once

class Metrics {
public:
    constexpr static int PADDING_NONE = 0;
    constexpr static int PADDING_SMALL = 4;
    constexpr static int PADDING_MEDIUM = 8;
    constexpr static int PADDING_LARGE = 16;
    constexpr static int PADDING_XLARGE = 24;

    constexpr static int VERTICAL_PADDING_NONE = 0;
    constexpr static int VERTICAL_PADDING_SMALL = 4;
    constexpr static int VERTICAL_PADDING_MEDIUM = 8;
    constexpr static int VERTICAL_PADDING_LARGE = 16;
    constexpr static int VERTICAL_PADDING_XLARGE = 24;

    constexpr static int HORIZONTAL_PADDING_NONE = 0;
    constexpr static int HORIZONTAL_PADDING_SMALL = 4;
    constexpr static int HORIZONTAL_PADDING_MEDIUM = 8;
    constexpr static int HORIZONTAL_PADDING_LARGE = 16;
    constexpr static int HORIZONTAL_PADDING_XLARGE = 24;

    constexpr static int AVATAR_SIZE = 48;

    // todo: should these be set differently?
    constexpr static int VSCROLL_RATE = 10;
    constexpr static int HSCROLL_RATE = 10;

    // font metrics
    static int line_height(wxWindow& win);
    static int zero_width(wxWindow& win);
};
