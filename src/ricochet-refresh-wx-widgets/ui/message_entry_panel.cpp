#include "message_entry_panel.hpp"

#include "events.hpp"
#include "metrics.hpp"
#include "strings.hpp"

MessageEntryPanel::MessageEntryPanel(wxWindow* parent) : wxPanel(parent) {
    auto v_sizer = new wxBoxSizer(wxVERTICAL);

    auto button_sizer = new wxBoxSizer(wxHORIZONTAL);

    auto button_font = this->GetFont();
    button_font.SetFamily(wxFONTFAMILY_ROMAN);
    const auto line_height = Metrics::line_height(*this);
    // next largest multiple of 4
    const auto size = line_height + 4 - (line_height % 4);
    const auto button_size = wxSize(size, size);

    auto bold_button = new wxButton(
        this,
        wxID_ANY,
        Strings::MessageEntryPanel::bold_button(),
        wxDefaultPosition,
        button_size
    );
    bold_button->SetFont(button_font.Bold());

    auto italic_button = new wxButton(
        this,
        wxID_ANY,
        Strings::MessageEntryPanel::italic_button(),
        wxDefaultPosition,
        button_size
    );
    italic_button->SetFont(button_font.Italic());

    auto underline_button = new wxButton(
        this,
        wxID_ANY,
        Strings::MessageEntryPanel::underline_button(),
        wxDefaultPosition,
        button_size
    );
    underline_button->SetFont(button_font);

    auto text_entry_sizer = new wxBoxSizer(wxHORIZONTAL);

    this->text_control = new wxTextCtrl(
        this,
        wxID_ANY,
        wxEmptyString,
        wxDefaultPosition,
        wxDefaultSize,
        wxTE_MULTILINE | wxTE_PROCESS_ENTER
    );
    this->text_control->SetMinSize(wxSize(wxDefaultCoord, 4 * line_height));
    this->text_control->Bind(wxEVT_CHAR, [this](wxKeyEvent& evt) {
        switch (evt.GetKeyCode()) {
            case WXK_RETURN:
            case WXK_NUMPAD_ENTER: {
                if (evt.ShiftDown()) {
                    this->text_control->AppendText('\n');
                } else {
                    const auto& text = this->text_control->GetValue();
                    this->send_text_message(text);
                }
                break;
            }
            default:
                evt.Skip();
                break;
        }
    });

    auto send_message_button =
        new wxButton(this, wxID_ANY, Strings::MessageEntryPanel::send_message_button());
    send_message_button->SetFont(button_font.Larger().Larger().Larger());
    send_message_button->Bind(wxEVT_BUTTON, [=, this](const wxCommandEvent&) {
        const auto& text = this->text_control->GetValue();
        this->send_text_message(text);
    });

    // Layout

    button_sizer->Add(bold_button, 0);
    button_sizer->Add(italic_button, 0);
    button_sizer->Add(underline_button, 0);

    text_entry_sizer->Add(text_control, 1, wxEXPAND);
    text_entry_sizer->Add(send_message_button, 0, wxEXPAND);

    v_sizer->Add(button_sizer, 0, wxEXPAND);
    v_sizer->Add(text_entry_sizer, 0, wxEXPAND);

    this->SetSizerAndFit(v_sizer);
}

void MessageEntryPanel::send_text_message(const wxString& text) {
    if (!text.empty()) {
        const auto timestamp = wxDateTime::UNow();
        auto evt = SendMessageEvent(timestamp, text);
        evt.SetEventObject(this);
        this->GetEventHandler()->ProcessEvent(evt);
        this->text_control->ChangeValue(wxEmptyString);
    }
}