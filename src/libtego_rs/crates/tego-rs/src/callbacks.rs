// std
use std::ffi::CString;
// extern
use anyhow::{Context, Result};
use tor_interface::tor_crypto::V3OnionServiceId;

// internal crates
use crate::ffi::*;
use crate::macros::*;

#[allow(dead_code)]
pub(crate) enum CallbackData {
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

impl Callbacks {
    pub fn invoke(&self, context: *mut tego_context, callback_data: CallbackData) -> Result<()> {
        use CallbackData::*;
        match callback_data {
            TorNetworkStatusChanged { status } => {
                let on_tor_network_status_changed = self
                    .on_tor_network_status_changed
                    .context("missing on_tor_network_status_changed callback")?;
                log_trace!("invoke on_tor_network_status_changed");

                on_tor_network_status_changed(context, status);
            }
            TorBootstrapStatusChanged { progress, tag } => {
                let on_tor_bootstrap_status_changed = self
                    .on_tor_bootstrap_status_changed
                    .context("missing on_tor_bootstrap_status_changed callback")?;
                log_trace!("invoke on_tor_bootstrap_status_changed");

                on_tor_bootstrap_status_changed(context, progress as i32, tag.as_str().into());
            }
            TorLogReceived { line } => {
                let on_tor_log_received = self
                    .on_tor_log_received
                    .context("missing on_tor_log_received callback")?;
                log_trace!("invoke on_tor_log_received");

                let line =
                    CString::new(line.replace("\0", "")).expect("tor log line contains null-byte");
                let line_len = line.as_bytes().len();
                let line = line.as_c_str().as_ptr();

                on_tor_log_received(context, line, line_len);
            }
            HostOnionServiceStateChanged { state } => {
                let on_host_onion_service_state_changed = self
                    .on_host_onion_service_state_changed
                    .context("missing on_host_onion_service_state_changed callback")?;
                log_trace!("invoke on_host_onion_service_state_changed");

                on_host_onion_service_state_changed(context, state);
            }
            ChatRequestReceived {
                service_id,
                message,
            } => {
                let on_chat_request_received = self
                    .on_chat_request_received
                    .context("missing on_chat_request_received callback")?;
                log_trace!("invoke on_chat_request_received");

                let sender = get_object_map().insert(TegoObject::UserId(service_id));
                let message = CString::new(message.replace("\0", ""))
                    .expect("chat request message contains null-byte");
                let message_len = message.as_bytes().len();

                on_chat_request_received(
                    context,
                    sender as *const tego_user_id,
                    message.as_c_str().as_ptr(),
                    message_len,
                );

                get_object_map().remove(&sender);
            }
            ChatRequestResponseReceived {
                service_id,
                accepted_request,
            } => {
                let on_chat_request_response_received = self
                    .on_chat_request_response_received
                    .context("missing on_chat_request_response_received callback")?;
                log_trace!("invoke on_chat_request_response_received");

                let sender = get_object_map().insert(TegoObject::UserId(service_id));
                let accepted_request = if accepted_request {
                    TEGO_TRUE
                } else {
                    TEGO_FALSE
                };

                on_chat_request_response_received(
                    context,
                    sender as *const tego_user_id,
                    accepted_request,
                );

                get_object_map().remove(&sender);
            }
            MessageReceived {
                service_id,
                timestamp,
                message_id,
                message,
            } => {
                let on_message_received = self
                    .on_message_received
                    .context("missing on_message_received callback")?;
                log_trace!("invoke on_message_received");

                let user = get_object_map().insert(TegoObject::UserId(service_id));
                let timestamp = timestamp
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::ZERO);
                let timestamp = timestamp.as_millis() as tego_time;
                assert!(timestamp > 0);
                let message = CString::new(message.replace("\0", ""))
                    .expect("chat message contains null-byte");
                let message_len = message.as_bytes().len();

                on_message_received(
                    context,
                    user as *const tego_user_id,
                    timestamp,
                    message_id,
                    message.as_c_str().as_ptr(),
                    message_len,
                );

                get_object_map().remove(&user);
            }
            MessageAcknowledged {
                service_id,
                message_id,
                accepted,
            } => {
                let on_message_acknowledged = self
                    .on_message_acknowledged
                    .context("missing on_message_acknowledged callback")?;
                log_trace!("invoke on_message_acknowledged");

                let user = get_object_map().insert(TegoObject::UserId(service_id));
                let accepted = if accepted { TEGO_TRUE } else { TEGO_FALSE };

                on_message_acknowledged(context, user as *const tego_user_id, message_id, accepted);

                get_object_map().remove(&user);
            }
            FileTransferRequestReceived {
                sender,
                file_transfer_id,
                file_name,
                file_size,
            } => {
                let on_file_transfer_request_received = self
                    .on_file_transfer_request_received
                    .context("missing on_file_transfer_request_received callback")?;
                log_trace!("invoke on_file_transfer_request_received");

                let sender = get_object_map().insert(TegoObject::UserId(sender));
                let file_name = CString::new(file_name.replace("\0", ""))
                    .expect("file name contains null-byte");
                let file_name_length = file_name.as_bytes().len();
                let file_name = file_name.as_c_str().as_ptr();

                on_file_transfer_request_received(
                    context,
                    sender as *const tego_user_id,
                    file_transfer_id,
                    file_name,
                    file_name_length,
                    file_size,
                );

                get_object_map().remove(&sender);
            }
            FileTransferRequestAcknowledged {
                service_id,
                file_transfer_id,
                accepted,
            } => {
                let on_file_transfer_request_acknowledged = self
                    .on_file_transfer_request_acknowledged
                    .context("missing on_file_transfer_request_acknowledged callback")?;
                log_trace!("invoke on_file_transfer_request_acknowledged");

                let user = get_object_map().insert(TegoObject::UserId(service_id));
                let accepted = if accepted { TEGO_TRUE } else { TEGO_FALSE };

                on_file_transfer_request_acknowledged(
                    context,
                    user as *const tego_user_id,
                    file_transfer_id,
                    accepted,
                );

                get_object_map().remove(&user);
            }
            FileTransferRequestResponseReceived {
                service_id,
                file_transfer_id,
                response,
            } => {
                let on_file_transfer_request_response_received = self
                    .on_file_transfer_request_response_received
                    .context("missing on_file_transfer_request_response_received callback")?;
                log_trace!("invoke on_file_transfer_request_response_received");

                let user = get_object_map().insert(TegoObject::UserId(service_id));

                on_file_transfer_request_response_received(
                    context,
                    user as *const tego_user_id,
                    file_transfer_id,
                    response,
                );
                get_object_map().remove(&user);
            }
            FileTransferProgress {
                user_id,
                file_transfer_id,
                direction,
                bytes_complete,
                bytes_total,
            } => {
                let on_file_transfer_progress = self
                    .on_file_transfer_progress
                    .context("missing on_file_transfer_progress callback")?;
                log_trace!("invoke on_file_transfer_progress");

                let user_id = get_object_map().insert(TegoObject::UserId(user_id));

                on_file_transfer_progress(
                    context,
                    user_id as *const tego_user_id,
                    file_transfer_id,
                    direction,
                    bytes_complete,
                    bytes_total,
                );

                get_object_map().remove(&user_id);
            }
            FileTransferComplete {
                user_id,
                file_transfer_id,
                direction,
                result,
            } => {
                let on_file_transfer_complete = self
                    .on_file_transfer_complete
                    .context("missing on_file_transfer_complete callback")?;
                log_trace!("invoke on_file_transfer_complete");

                let user_id = get_object_map().insert(TegoObject::UserId(user_id));

                on_file_transfer_complete(
                    context,
                    user_id as *const tego_user_id,
                    file_transfer_id,
                    direction,
                    result,
                );

                get_object_map().remove(&user_id);
            }
            UserStatusChanged { service_id, status } => {
                let on_user_status_changed = self
                    .on_user_status_changed
                    .context("missing on_user_status_changed callback")?;
                log_trace!("invoke on_user_status_changed");

                let user = get_object_map().insert(TegoObject::UserId(service_id));

                on_user_status_changed(context, user as *const tego_user_id, status);

                get_object_map().remove(&user);
            }
        }
        Ok(())
    }
}
