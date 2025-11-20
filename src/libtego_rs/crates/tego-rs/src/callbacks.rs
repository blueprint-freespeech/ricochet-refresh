// extern
use tor_interface::tor_crypto::V3OnionServiceId;

// internal crates
use crate::ffi::*;

// todo: remove unused callbacks
#[allow(dead_code)]
pub(crate) enum CallbackData {
    TorErrorOccurred,
    UpdateTorDaemonConfigSucceeded,
    TorControlStatusChanged,
    TorProcessStatusChanged,
    TorNetworkStatusChanged {
        status: tego_tor_network_status,
    },
    TorBootstrapStatusChanged {
        progress: u32,
        tag: String,
    },
    TorLogReceived {
        line: String,
    },
    HostOnionServiceStateChanged {
        state: tego_host_onion_service_state,
    },
    ChatRequestReceived {
        service_id: V3OnionServiceId,
        message: String,
    },
    ChatRequestResponseReceived {
        service_id: V3OnionServiceId,
        accepted_request: bool,
    },
    MessageReceived {
        service_id: V3OnionServiceId,
        timestamp: std::time::SystemTime,
        message_id: tego_message_id,
        message: String,
    },
    MessageAcknowledged {
        service_id: V3OnionServiceId,
        message_id: tego_message_id,
        accepted: bool,
    },
    FileTransferRequestReceived {
        sender: V3OnionServiceId,
        file_transfer_id: tego_file_transfer_id,
        file_name: String,
        file_size: u64,
    },
    FileTransferRequestAcknowledged {
        service_id: V3OnionServiceId,
        file_transfer_id: tego_file_transfer_id,
        accepted: bool,
    },
    FileTransferRequestResponseReceived {
        service_id: V3OnionServiceId,
        file_transfer_id: tego_file_transfer_id,
        response: tego_file_transfer_response,
    },
    FileTransferProgress {
        user_id: V3OnionServiceId,
        file_transfer_id: tego_file_transfer_id,
        direction: tego_file_transfer_direction,
        bytes_complete: u64,
        bytes_total: u64,
    },
    FileTransferComplete {
        user_id: V3OnionServiceId,
        file_transfer_id: tego_file_transfer_id,
        direction: tego_file_transfer_direction,
        result: tego_file_transfer_result,
    },
    UserStatusChanged {
        service_id: V3OnionServiceId,
        status: tego_user_status,
    },
    NewIdentityCreated,
}

#[derive(Default)]
pub(crate) struct Callbacks {
    pub on_tor_network_status_changed: tego_tor_network_status_changed_callback,
    pub on_tor_bootstrap_status_changed: tego_tor_bootstrap_status_changed_callback,
    pub on_tor_log_received: tego_tor_log_received_callback,
    pub on_host_onion_service_state_changed: tego_host_onion_service_state_changed_callback,
    pub on_chat_request_received: tego_chat_request_received_callback,
    pub on_chat_request_response_received: tego_chat_request_response_received_callback,
    pub on_message_received: tego_message_received_callback,
    pub on_message_acknowledged: tego_message_acknowledged_callback,
    pub on_file_transfer_request_received: tego_file_transfer_request_received_callback,
    pub on_file_transfer_request_acknowledged: tego_file_transfer_request_acknowledged_callback,
    pub on_file_transfer_request_response_received:
        tego_file_transfer_request_response_received_callback,
    pub on_file_transfer_progress: tego_file_transfer_progress_callback,
    pub on_file_transfer_complete: tego_file_transfer_complete_callback,
    pub on_user_status_changed: tego_user_status_changed_callback,
}
