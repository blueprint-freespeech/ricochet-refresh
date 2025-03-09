// standard
use std::ffi::CString;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};

// extern
use anyhow::Result;
use tor_interface::proxy::{ProxyConfig};
use tor_interface::legacy_tor_client::*;
use tor_interface::tor_provider::{TorEvent, TorProvider};

// internal crates
use crate::ffi::*;

#[derive(Default)]
pub(crate) struct Context {
    pub tego_key: TegoKey,
    pub callbacks: Arc<Mutex<Callbacks>>,
    // daemon configuration data
    pub tor_data_directory: PathBuf,
    pub proxy_settings: Option<ProxyConfig>,
    pub allowed_ports: Option<Vec<u16>>,
    tor_client: Option<Arc<Mutex<LegacyTorClient>>>,
    pub tor_version: CString,
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

        std::thread::Builder::new()
            .name("network-task".to_string())
            .spawn(move || {
                Self::network_task(tego_key, &callbacks, &tor_client)
            })?;

        Ok(())
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
        tor_client: &Weak<Mutex<LegacyTorClient>>) -> () {

        println!("begin network_task");

        if let Some(tor_client) = tor_client.upgrade() {
            let _ = tor_client.lock().unwrap().bootstrap();
        } else {
            // drop everything?
            return;
        }

        loop {
            // get events
            let events = if let Some(tor_client) = tor_client.upgrade() {
                tor_client.lock().unwrap().update().unwrap()
            } else {
                // drop everything?
                return;
            };

            if let Some(callbacks) = callbacks.upgrade() {
                let callbacks = callbacks.lock().unwrap();

                // handle events
                for e in events {
                    match e {
                        TorEvent::BootstrapStatus{progress, tag, summary} => {
                            println!("progress: {progress}, tag: {tag}, summary: {summary}");
                            if let Some(on_tor_bootstrap_status_changed) = callbacks.on_tor_bootstrap_status_changed {
                                on_tor_bootstrap_status_changed(tego_key as *mut tego_context, progress as i32, tag.as_str().into());
                            }
                        },
                        TorEvent::BootstrapComplete => {

                        },
                        TorEvent::LogReceived{line} => {

                        },
                        TorEvent::OnionServicePublished{service_id} => {

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
