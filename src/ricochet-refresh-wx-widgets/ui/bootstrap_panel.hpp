#pragma once

class BootstrapPanel: public wxPanel {
public:
    explicit BootstrapPanel(wxWindow* parent);
    void ShowDisconnected();
    void ShowConnecting();
    void ShowConnected();

private:
    class DisconnectedPanel* disconnected_panel = nullptr;
    class ConnectingPanel* connecting_panel = nullptr;
    class ConnectedPanel* connected_panel = nullptr;
};
