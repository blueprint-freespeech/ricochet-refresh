#pragma once

class DisconnectedPanel: public wxPanel {
public:
    explicit DisconnectedPanel(wxWindow* parent);

private:
    void set_quickstart(bool enabled);
    void configure();
    void connect();
};
