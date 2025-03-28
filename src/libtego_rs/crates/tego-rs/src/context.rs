// standard
use std::collections::{BTreeMap};
use std::ffi::CString;
use std::io::{ErrorKind, Read, Write};
use std::path::PathBuf;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Condvar, Mutex, Weak};

// extern
use anyhow::{Context as AnyhowContext ,Result};
use rico_protocol::v3::packet_handler::*;
use tor_interface::proxy::{ProxyConfig};
use tor_interface::legacy_tor_client::*;
use tor_interface::legacy_tor_version::LegacyTorVersion;
use tor_interface::tor_crypto::{Ed25519PrivateKey, V3OnionServiceId};
use tor_interface::tor_provider::{OnionListener, OnionStream, TorEvent, TorProvider};

// internal crates
use crate::ffi::*;

#[derive(Default)]
pub(crate) struct Context {
    pub tego_key: TegoKey,
    pub callbacks: Arc<Mutex<Callbacks>>,
    // tor config data
    pub tor_data_directory: PathBuf,
    pub proxy_settings: Option<ProxyConfig>,
    pub allowed_ports: Option<Vec<u16>>,
    // tor runtime data
    tor_version_cstring: Option<CString>,
    tor_version: Arc<Mutex<Option<LegacyTorVersion>>>,
    pub tor_logs: Arc<Mutex<Vec<String>>>,
    // flags
    connect_complete: Arc<AtomicBool>,
    event_loop_complete: Arc<(Mutex<bool>, Condvar)>,
    // command queue
    command_queue: Arc<Mutex<Vec<Command>>>,
    // ricochet-refresh data
    pub private_key: Option<Ed25519PrivateKey>,
    pub users: Arc<Mutex<BTreeMap<V3OnionServiceId, UserData>>>,
}

impl Context {
    pub fn tor_version_string(&mut self) -> Option<&CString> {
        if self.tor_version_cstring.is_none() {
            let tor_version = self.tor_version.lock().expect("tor_version mutex poisoned");
            if let Some(tor_version) = &*tor_version {
                let tor_version = tor_version.to_string();
                self.tor_version_cstring = Some(CString::new(tor_version).unwrap());
            }
        }
        self.tor_version_cstring.as_ref()
    }

    pub fn connect(&mut self) -> Result<()> {

        let tego_key = self.tego_key;
        let callbacks = Arc::downgrade(&self.callbacks);

        let tor_config = LegacyTorClientConfig::BundledTor{
            tor_bin_path: Self::tor_bin_path()?,
            data_directory: self.tor_data_directory.clone(),
            proxy_settings: None,
            allowed_ports: None,
            pluggable_transports: None,
            bridge_lines: None,
        };

        let tor_version = Arc::downgrade(&self.tor_version);
        let tor_logs = Arc::downgrade(&self.tor_logs);

        let connect_complete = Arc::downgrade(&self.connect_complete);
        let event_loop_complete = Arc::downgrade(&self.event_loop_complete);

        let private_key = self.private_key.as_ref().unwrap().clone();

        let command_queue = Arc::downgrade(&self.command_queue);

        std::thread::Builder::new()
            .name("event-loop".to_string())
            .spawn(move || {
                // start event loop
                let _ = Self::event_loop(
                    tego_key,
                    &callbacks,
                    tor_config,
                    &tor_version,
                    &tor_logs,
                    &connect_complete,
                    private_key,
                    &command_queue);

                // signal task completion
                if let Some(complete) = event_loop_complete.upgrade() {
                    let (complete, cvar) = &*complete;
                    let mut complete = complete.lock().unwrap();
                    *complete = true;
                    cvar.notify_one();
                }
            })?;

        Ok(())
    }

    pub fn connect_complete(&self) -> bool {
        self.connect_complete.load(Ordering::Relaxed)
    }

    fn push_command(&self, cmd: Command) -> () {
        let mut command_queue = self.command_queue.lock().expect("command_queue mutex poisoned");
        command_queue.push(cmd);
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

    fn event_loop(
        tego_key: TegoKey,
        callbacks: &Weak<Mutex<Callbacks>>,
        tor_config: LegacyTorClientConfig,
        tor_version: &Weak<Mutex<Option<LegacyTorVersion>>>,
        tor_logs: &Weak<Mutex<Vec<String>>>,
        connect_complete: &Weak<AtomicBool>,
        private_key: Ed25519PrivateKey,
        command_queue: &Weak<Mutex<Vec<Command>>>) -> Result<()> {

        // launch tor daemon
        let mut tor_client = LegacyTorClient::new(tor_config)?;

        // save off the tor daemon version
        {
            let mut tor_version = tor_version.upgrade().context("tor_version dropped")?;
            let mut tor_version = tor_version.lock().expect("tor_version mutex poisoned");
            *tor_version = Some(tor_client.version());
        }

        // bootstrap tor daemon
        tor_client.bootstrap()?;

        // our ricochet-refresh packet handler
        let mut packet_handler = PacketHandler::new(V3OnionServiceId::from_private_key(&private_key));
        // our current connections
        let mut connections: BTreeMap<ConnectionHandle, Connection> = Default::default();
        // byte read buffer
        const READ_BUFFER_SIZE: usize = 1024;
        let mut read_buffer: [u8; READ_BUFFER_SIZE] = [0u8; READ_BUFFER_SIZE];

        loop {
            // get events
            let events = tor_client.update()?;

            // handle callbacks
            let callbacks = callbacks.upgrade().context("callbacks dropped")?;
            let callbacks = callbacks.lock().expect("callbacks mutex poisoned");

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
                        let listener = tor_client.listener(&private_key, 9878u16, None)?;
                        std::thread::Builder::new()
                            .name("listener-loop".to_string())
                            .spawn({
                                let command_queue = command_queue.clone();
                                move || {
                                    let _ = Self::listener_loop(listener, &command_queue);
                            }})?;
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

            // get and handle pending commands
            let command_queue: Vec<Command> = {
                let command_queue = command_queue.upgrade().context("command_queue dropped")?;
                let mut command_queue = command_queue.lock().expect("command_queue mutex poisoned");
                std::mem::take(&mut command_queue)
            };

            for cmd in command_queue {
                match cmd {
                    Command::EndEventLoop => return Ok(()),
                    Command::BeginServerHandshake{stream} => {
                        let handle = packet_handler.new_incoming_connection();

                        let connection = Connection{
                            service_id: None,
                            stream,
                            read_bytes: Default::default(),
                        };

                        println!("begin server handshake: {connection:?}");

                        connections.insert(handle, connection);

                    },
                }
            }

            // read any pending bytes and update the packet handler
            connections.retain(|&handle, connection| -> bool {
                match connection.stream.read(&mut read_buffer) {
                    Err(err) => match err.kind() {
                        ErrorKind::WouldBlock | ErrorKind::TimedOut => true,
                        _ => false,
                    },
                    Ok(0) => false,
                    Ok(size) => {
                        let read_buffer = &read_buffer[..size];
                        connection.read_bytes.write(read_buffer);
                        let mut read_bytes = connection.read_bytes.as_slice();
                        // total handled bytes
                        let mut trim_count = 0usize;

                        let mut read_packets: Vec<Packet> = Default::default();

                        loop {
                            match packet_handler.try_parse_packet(handle, read_bytes) {
                                Ok((packet, size)) => {
                                    println!("read packet: {packet:?}");
                                    // move slice up by number of handled bytes
                                    read_bytes = &read_bytes[size..];
                                    trim_count += size;
                                    // save off read bytes for handling
                                    read_packets.push(packet);
                                },
                                Err(rico_protocol::v3::message::Error::NeedMoreBytes) => {
                                    break;
                                },
                                Err(err) => {
                                    // TODO: report error somewhere?
                                    println!("err: {err:?}");
                                    // drop connection
                                    return false;
                                },
                            }
                        }
                        // drop handled bytes off the front
                        connection.read_bytes.drain(0..trim_count);

                        // handle packets and queue responses
                        let mut write_packets: Vec<Packet> = Default::default();
                        for packet in read_packets.drain(..) {
                            match packet_handler.handle_packet(handle, packet) {
                                Ok(Some(Event::IntroductionReceived{reply})) => {
                                    println!("--- introduction received ---");
                                    write_packets.push(reply);
                                },
                                Ok(Some(Event::OpenChannelAuthHiddenServiceReceived{reply})) => {
                                    println!("--- open auth hidden service received ---");
                                    write_packets.push(reply);
                                },
                        Ok(Some(Event::ClientAuthenticated{service_id, reply})) => {
                            println!("--- client authorised: {service_id:?} ---");
                            connection.service_id = Some(service_id);
                                    write_packets.push(reply);
                                },
                                // errors
                                Ok(Some(Event::FatalProtocolFailure)) => {
                                    println!("fatal protocol error, removing connection");
                                    return false;
                                }
                                Err(err) => panic!("error: {err:?}"),
                                _ => (),
                            }
                        }

                        // write replies
                        if !write_packets.is_empty() {
                            // serialise out packets to bytes
                            let mut write_bytes: Vec<u8> = Default::default();
                            for packet in write_packets.drain(..) {
                                println!("write packet: {packet:?}");
                                packet.write_to_vec(&mut write_bytes);
                            }

                            // send bytes
                            if let Ok(_written) = connection.stream.write(write_bytes.as_slice()) {
                                true
                            } else {
                                // TODO: error reporting, remove user?
                                // drop connection
                                false
                            }
                        } else {
                            true
                        }
                    },
                }
            });
        }
    }

    // listen for connections to our onion service and request handshake begin
    fn listener_loop(
        listener: OnionListener,
        command_queue: &Weak<Mutex<Vec<Command>>>,
    ) -> Result<()> {
        listener.set_nonblocking(false);
        while let Ok(stream) = listener.accept() {
            if let Some(stream) = stream {
                stream.set_nonblocking(true)?;
                println!("stream: {stream:?}");
                let command_queue = command_queue.upgrade().context("command_queue dropped")?;
                let mut command_queue = command_queue.lock().expect("command_queue mutex poisoned");
                command_queue.push(Command::BeginServerHandshake{stream});
            }
        }

        Ok(())
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        self.push_command(Command::EndEventLoop);
        let (complete, cvar) = &*self.event_loop_complete;
        let mut complete = complete.lock().unwrap();
        while !*complete {
            complete = cvar.wait(complete).unwrap();
        }
    }
}

#[derive(Debug)]
struct Connection {
    pub service_id: Option<V3OnionServiceId>,
    pub stream: OnionStream,
    // buffer of unhandled read bytes
    pub read_bytes: Vec<u8>,
}

enum Command {
    // library is going away we need to cleanup
    EndEventLoop,
    // client connects to our listener triggering an incoming handshake
    BeginServerHandshake{
        stream: OnionStream
    },
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
