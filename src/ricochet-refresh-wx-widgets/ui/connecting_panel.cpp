#include "connecting_panel.hpp"

#include "fonts.hpp"
#include "strings.hpp"
#include "wrapped_static_text.hpp"

ConnectingPanel::ConnectingPanel(wxWindow* parent) : wxPanel(parent) {
    auto v_sizer = new wxBoxSizer(wxVERTICAL);

    auto title = new wxStaticText(this, wxID_ANY, Strings::ConnectingPanel::title());
    title->SetFont(Fonts::title_font());

    auto explainer_text =
        new WrappedStaticText(this, wxID_ANY, Strings::ConnectingPanel::explainer_text());
    this->progress_bar = new wxGauge(this, wxID_ANY, 100);
    auto button_panel = new wxPanel(this, wxID_ANY);
    auto h_button_sizer = new wxBoxSizer(wxHORIZONTAL);

    auto view_logs_button =
        new wxButton(button_panel, wxID_ANY, Strings::ConnectingPanel::view_logs_button());
    view_logs_button->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { this->view_logs(); });
    auto cancel_button =
        new wxButton(button_panel, wxID_ANY, Strings::ConnectingPanel::cancel_button());
    cancel_button->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { this->cancel(); });

    h_button_sizer->AddStretchSpacer(1);
    h_button_sizer->Add(view_logs_button, 0, wxRIGHT, 8);
    h_button_sizer->Add(cancel_button, 0);

    button_panel->SetSizer(h_button_sizer);

    v_sizer->Add(title, 0, wxALIGN_CENTER, 0);
    v_sizer->Add(explainer_text, 0, wxTOP | wxALIGN_LEFT, 16);
    v_sizer->Add(progress_bar, 0, wxTOP | wxEXPAND, 24);
    v_sizer->AddStretchSpacer(1);
    v_sizer->Add(button_panel, 0, wxTOP | wxALIGN_RIGHT, 16);

    this->SetSizerAndFit(v_sizer);

    // todo: update based on boostrap progress callbacks
    this->update_progress_bar(27u);
}

void ConnectingPanel::update_progress_bar(unsigned n) {
    n = std::min(100u, n);
    this->progress_bar->SetValue(n);
}

void ConnectingPanel::view_logs() {
    // todo: open the tor logs pane
    std::cout << "View Logs" << std::endl;
}

void ConnectingPanel::cancel() {
    // todo: cancel bootstrap and send us back to disconnected pane
    std::cout << "Cancel" << std::endl;
}