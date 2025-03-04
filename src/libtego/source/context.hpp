#pragma once

#include "signals.hpp"
#include "tor.hpp"
#include "user.hpp"

#include "tor/TorControl.h"
#include "tor/TorManager.h"
#include "core/IdentityManager.h"

//
// Tego Context
//

struct tego_context
{
public:
    tego_context();

    void start_tor(const tego_tor_launch_config* config);
    bool get_tor_daemon_configured() const;
    size_t get_tor_logs_size() const;
    const std::vector<std::string>& get_tor_logs() const;
    const char* get_tor_version_string() const;
    tego_tor_control_status get_tor_control_status() const;
    tego_tor_process_status get_tor_process_status() const;
    tego_tor_network_status get_tor_network_status() const;
    int32_t get_tor_bootstrap_progress() const;
    tego_tor_bootstrap_tag get_tor_bootstrap_tag() const;
    void start_service(
        tego_ed25519_private_key const* hostPrivateKey,
        tego_user_id const* const* userBuffer,
        tego_user_type* const userTypeBuffer,
        size_t userCount);
    void start_service();
    void update_tor_daemon_config(const tego_tor_daemon_config* config);
    void update_disable_network_flag(bool disableNetwork);
    void save_tor_daemon_config();
    void set_host_onion_service_state(tego_host_onion_service_state state);
    std::unique_ptr<tego_user_id> get_host_user_id() const;
    tego_host_onion_service_state get_host_onion_service_state() const;
    void send_chat_request(
        const tego_user_id* user,
        const char* message,
        size_t messageLength);
    void acknowledge_chat_request(
        const tego_user_id* user,
        tego_chat_acknowledge response);
    tego_message_id send_message(
        const tego_user_id* user,
        const std::string& message);
    tego_user_type get_user_type(tego_user_id const* user) const;
    size_t get_user_count() const;
    std::vector<tego_user_id*> get_users() const;
    void forget_user(const tego_user_id* user);
    std::tuple<tego_file_transfer_id, std::unique_ptr<tego_file_hash>, tego_file_size> send_file_transfer_request(
        tego_user_id const* user,
        std::string const& filePath);
    void respond_file_transfer_request(
        tego_user_id const* user,
        tego_file_transfer_id fileTransfer,
        tego_file_transfer_response response,
        std::string const& destPath);
    void cancel_file_transfer_transfer(
        tego_user_id const* user,
        tego_file_transfer_id);

    tego::callback_registry callback_registry_;
    tego::callback_queue callback_queue_;
    // anything that touches internal state should do so through
    // this 'global' (actually per tego_context) mutex
    std::mutex mutex_;

    // TODO: figure out ownership of these Qt types
    Tor::TorManager* torManager = nullptr;
    Tor::TorControl* torControl = nullptr;
    IdentityManager* identityManager = nullptr;

    // we store the thread id that this context is associated with
    // calls which go into our qt internals must be called from the same
    // thread as the context was created on
    // (this is not entirely true, they must be called from the thread with the Qt
    // event loop, which in our case is the thread the context is created on)
    std::thread::id threadId;
private:
    class ContactUser* getContactUser(const tego_user_id*) const;

    mutable std::string torVersion;
    mutable std::vector<std::string> torLogs;
    tego_host_onion_service_state hostUserState = tego_host_onion_service_state_none;
};