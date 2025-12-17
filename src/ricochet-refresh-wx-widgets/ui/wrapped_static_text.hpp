#pragma once

// wrapper around a wxPanel containing a single child wxStaticText
// whose size is set by a parent sizer
class WrappedStaticText: public wxPanel {
public:
    WrappedStaticText(
        wxWindow* parent,
        wxWindowID id,
        const wxString& label,
        const wxPoint& pos = wxDefaultPosition,
        const wxSize& size = wxDefaultSize
    );

    wxSize DoGetBestSize() const override;

private:
    const wxString label;
    std::vector<wxString> line_buffer;
    wxSize previous_size;
};
