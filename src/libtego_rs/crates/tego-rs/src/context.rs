// standard
use std::collections::BTreeMap;
use std::ffi::CString;
use std::path::PathBuf;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex, Weak};

// extern
use anyhow::Result;
use tor_interface::proxy::{ProxyConfig};
use tor_interface::legacy_tor_client::*;
use tor_interface::tor_crypto::{Ed25519PrivateKey, V3OnionServiceId};
use tor_interface::tor_provider::{OnionListener, TorEvent, TorProvider};

// internal crates
use crate::ffi::*;

#[derive(Default)]
pub(crate) struct Context {
    pub tego_key: TegoKey,
    pub callbacks: Arc<Mutex<Callbacks>>,
    // tor daemon data
    pub tor_data_directory: PathBuf,
    pub proxy_settings: Option<ProxyConfig>,
    pub allowed_ports: Option<Vec<u16>>,
    tor_client: Option<Arc<Mutex<LegacyTorClient>>>,
    pub tor_version: CString,
    pub tor_logs: Arc<Mutex<Vec<String>>>,
    connect_complete: Arc<AtomicBool>,
    // ricochet-refresh data
    pub private_key: Option<Ed25519PrivateKey>,
    pub users: Arc<Mutex<BTreeMap<V3OnionServiceId, UserData>>>,
}

impl Context {
    pub fn connect(&mut self) -> Result<()> {

        let tego_key = self.tego_key;
        let callbacks = Arc::downgrade(&self.callbacks);

        let config = LegacyTorClientConfig::BundledTor{
            tor_bin_path: Self::tor_bin_path()?,
            data_directory: self.tor_data_directory.clone(),
            proxy_settings: None,
            allowed_ports: None,
            pluggable_transports: None,
            bridge_lines: None,
        };

        let mut tor_client = LegacyTorClient::new(config)?;
        let tor_version = tor_client.version().to_string();
        let tor_version = CString::new(tor_version)?;
        self.tor_version = tor_version;

        let tor_client = Arc::new(Mutex::new(tor_client));
        let tor_client_weak = Arc::downgrade(&tor_client);

        self.tor_client = Some(tor_client);

        let tor_client = tor_client_weak;

        let tor_logs = Arc::downgrade(&self.tor_logs);

        let connect_complete = Arc::downgrade(&self.connect_complete);

        let private_key = self.private_key.as_ref().unwrap().clone();

        std::thread::Builder::new()
            .name("network-task".to_string())
            .spawn(move || {
                Self::network_task(
                    tego_key,
                    &callbacks,
                    &tor_client,
                    &tor_logs,
                    &connect_complete,
                    private_key)
            })?;

        Ok(())
    }

    pub fn connect_complete(&self) -> bool {
        self.connect_complete.load(Ordering::Relaxed)
    }

    fn tor_bin_path() -> Result<PathBuf> {
        let bin_name = format!("tor{}", std::env::consts::EXE_SUFFIX);

        // get the path of the current running exe
        let mut path = std::env::current_exe()?;
        // tor should live in the same directory
        path.pop();
        path.push(bin_name.as_str());

        if path.exists() {
            Ok(path)
        } else {
            path = which::which(bin_name)?;
            Ok(path)
        }
    }

    fn network_task(
        tego_key: TegoKey,
        callbacks: &Weak<Mutex<Callbacks>>,
        tor_client: &Weak<Mutex<LegacyTorClient>>,
        tor_logs: &Weak<Mutex<Vec<String>>>,
        connect_complete: &Weak<AtomicBool>,
        private_key: Ed25519PrivateKey) -> () {

        if let Some(tor_client) = tor_client.upgrade() {
            let _ = tor_client.lock().unwrap().bootstrap();
        } else {
            // drop everything?
            return;
        }

        let mut listener: Option<OnionListener> = None;

        loop {
            // get events
            let events = if let Some(tor_client) = tor_client.upgrade() {
                tor_client.lock().unwrap().update().unwrap()
            } else {
                // TODO: error callback?
                return;
            };

            if let Some(callbacks) = callbacks.upgrade() {
                let callbacks = callbacks.lock().unwrap();

                // handle events
                for e in events {
                    match e {
                        TorEvent::BootstrapStatus{progress, tag, summary} => {
                            if let Some(on_tor_bootstrap_status_changed) = callbacks.on_tor_bootstrap_status_changed {
                                on_tor_bootstrap_status_changed(tego_key as *mut tego_context, progress as i32, tag.as_str().into());
                            }
                        },
                        TorEvent::BootstrapComplete => {
                            if let Some(connect_complete) = connect_complete.upgrade() {
                                connect_complete.store(true, Ordering::Relaxed);
                            }

                            if let Some(on_tor_network_status_changed) = callbacks.on_tor_network_status_changed {
                                use tego_tor_network_status::tego_tor_network_status_ready;
                                on_tor_network_status_changed(tego_key as *mut tego_context, tego_tor_network_status_ready);
                            }

                            if let Some(on_host_onion_service_state_changed) = callbacks.on_host_onion_service_state_changed {
                                use tego_host_onion_service_state::tego_host_onion_service_state_service_added;
                                on_host_onion_service_state_changed(tego_key as *mut tego_context, tego_host_onion_service_state_service_added);
                            }

                            // start onion service
                            if let Some(tor_client) = tor_client.upgrade() {
                                listener = Some(tor_client.lock().unwrap().listener(&private_key, 9878u16, None).unwrap());
                            } else {
                                // TODO: error callback?
                                return;
                            };
                        },
                        TorEvent::LogReceived{line} => {
                            if let Some(on_tor_log_received) = callbacks.on_tor_log_received {
                                let line = CString::new(line.as_str()).unwrap();
                                let line_len = line.as_bytes().len();
                                on_tor_log_received(tego_key as *mut tego_context, line.as_c_str().as_ptr(), line_len);
                            }

                            if let Some(tor_logs) = tor_logs.upgrade() {
                                let mut tor_logs = tor_logs.lock().unwrap();
                                tor_logs.push(line);
                            }
                        },
                        TorEvent::OnionServicePublished{service_id : _} => {
                            if let Some(on_host_onion_service_state_changed) = callbacks.on_host_onion_service_state_changed {
                                use tego_host_onion_service_state::tego_host_onion_service_state_service_published;
                                on_host_onion_service_state_changed(tego_key as *mut tego_context, tego_host_onion_service_state_service_published);
                            }
                        },
                        _ => (),
                    }
                }
            }
        }
    }
}

#[derive(Default)]
pub(crate) struct Callbacks {
    pub on_tor_error_occurred: tego_tor_error_occurred_callback,
    pub on_update_tor_daemon_config_succeeded: tego_update_tor_daemon_config_succeeded_callback,
    pub on_tor_control_status_changed: tego_tor_control_status_changed_callback,
    pub on_tor_process_status_changed: tego_tor_process_status_changed_callback,
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
    pub on_file_transfer_request_response_received: tego_file_transfer_request_response_received_callback,
    pub on_file_transfer_progress: tego_file_transfer_progress_callback,
    pub on_file_transfer_complete: tego_file_transfer_complete_callback,
    pub on_user_status_changed: tego_user_status_changed_callback,
    pub on_new_identity_created: tego_new_identity_created_callback,
}

pub(crate) enum UserData {
    Allowed,
    Requesting,
    Blocked,
    Pending,
    Rejected,
}
