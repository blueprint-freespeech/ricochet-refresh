#include "metrics.hpp"

int Metrics::line_height(wxWindow& win) {
    const wxClientDC dc(&win);
    auto extent = dc.GetTextExtent("M");
    return extent.GetHeight();
}

int Metrics::zero_width(wxWindow& win) {
    const wxClientDC dc(&win);
    auto extent = dc.GetTextExtent("0");
    return extent.GetWidth();
}
