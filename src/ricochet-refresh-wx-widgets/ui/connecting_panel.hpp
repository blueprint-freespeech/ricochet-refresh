#pragma once

class ConnectingPanel: public wxPanel {
public:
    explicit ConnectingPanel(wxWindow* parent);

private:
    void update_progress_bar(unsigned n);
    void view_logs();
    void cancel();

    wxGauge* progress_bar = nullptr;
};
