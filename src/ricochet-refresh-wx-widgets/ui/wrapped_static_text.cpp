#include "wrapped_static_text.hpp"

static std::tuple<wxString, wxSize> get_wrapped_string_size(
    wxWindow& win,
    const wxString& text,
    std::vector<wxString>& line_buffer,
    int max_width
) {
    struct wxStringWrapper: public wxTextWrapper {
    public:
        wxStringWrapper(
            wxWindow* win,
            const wxString& text,
            std::vector<wxString>& line_buffer,
            int max_width
        ) :
            line_buffer(line_buffer) {
            this->line_buffer.clear();
            this->Wrap(win, text, max_width);
        }

        wxString get_text() const {
            wxString result;
            result.Alloc(this->size);

            const wxString NEWLINE("\n");
            if (auto it = this->line_buffer.begin(); it != this->line_buffer.end()) {
                result.Append(*it);

                for (++it; it != this->line_buffer.end(); ++it) {
                    result.Append(NEWLINE);
                    result.Append(*it);
                }
            }
            return result;
        }

    protected:
        // cppcheck-suppress unusedFunction
        virtual void OnOutputLine(const wxString& line) {
            this->line_buffer.push_back(line);
            this->size += line.Len();
        }

        // cppcheck-suppress unusedFunction
        virtual void OnNewLine() {
            this->size += 1;
        }

    private:
        size_t size = 0;
        std::vector<wxString>& line_buffer;
    };

    wxStringWrapper wrapper(&win, text, line_buffer, max_width);
    auto wrapped_text = wrapper.get_text().Trim();

    const wxClientDC dc(&win);
    auto size = dc.GetMultiLineTextExtent(wrapped_text);

    return std::make_tuple(wrapped_text, size);
}

WrappedStaticText::WrappedStaticText(
    wxWindow* parent,
    wxWindowID id,
    const wxString& label,
    const wxPoint& pos,
    const wxSize& size
) :
    wxPanel(parent, id, pos, size),
    label(label) {
    auto static_text = new wxStaticText(this, wxID_ANY, wxEmptyString);

    this->Bind(wxEVT_SIZE, [=, this](wxSizeEvent& evt) {
        const auto size = evt.GetSize();

        // only do wrapping logic if the new size is different
        // from our previous size
        if (this->previous_size != size) {
            this->previous_size = size;
            const auto width = size.GetWidth();

            wxString text;
            wxSize extent;
            std::tie(text, extent) =
                get_wrapped_string_size(*this, this->label, this->line_buffer, width);

            static_text->SetLabel(text);

            this->SetMinSize(wxSize(-1, extent.GetHeight()));

            // force parent to re-layout if we need more vertical space
            if (extent.GetHeight() > size.GetHeight()) {
                this->PostSizeEventToParent();
            }

            evt.Skip();
        }
    });
}

wxSize WrappedStaticText::DoGetBestSize() const {
    return wxDefaultSize;
}
