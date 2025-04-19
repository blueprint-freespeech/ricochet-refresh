// standard
use std::collections::{BTreeMap};
use std::ffi::CString;
use std::io::{ErrorKind, Read, Write};
use std::path::PathBuf;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex, Weak};

// extern
use anyhow::{Context as AnyhowContext, Result};
use rico_protocol::v3::packet_handler::*;
use tor_interface::proxy::{ProxyConfig};
use tor_interface::legacy_tor_client::*;
use tor_interface::legacy_tor_version::LegacyTorVersion;
use tor_interface::tor_crypto::{Ed25519PrivateKey, V3OnionServiceId};
use tor_interface::tor_provider::{OnionListener, OnionStream, TorEvent, TorProvider};

// internal crates
use crate::ffi::*;
use crate::user_id::UserId;
use crate::promise::Promise;

const RICOCHET_PORT: u16 = 9878u16;

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
    event_loop_complete: Promise<()>,
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
        let event_loop_complete = self.event_loop_complete.clone();

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
                event_loop_complete.resolve(());
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

    pub fn send_contact_request(
        &self,
        service_id: V3OnionServiceId,
        message: rico_protocol::v3::message::contact_request_channel::MessageText) -> () {
        self.push_command(Command::SendContactRequest{service_id, message});
    }

    pub fn acknowledge_contact_request(
        &self,
        service_id: V3OnionServiceId,
        response: tego_chat_acknowledge) -> () {
        self.push_command(Command::AcknowledgeContactRequest{service_id, response});
    }

    pub fn send_message(
        &self,
        service_id: V3OnionServiceId,
        message_text: rico_protocol::v3::message::chat_channel::MessageText) -> Result<tego_message_id> {

        let message_id: Promise<Result<tego_message_id>> = Default::default();
        let message_id_future = message_id.get_future();
        let cmd = Command::SendMessage{service_id, message_text, message_id};
        self.push_command(cmd);

        message_id_future.wait()
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
            let tor_version = tor_version.upgrade().context("tor_version dropped")?;
            let mut tor_version = tor_version.lock().expect("tor_version mutex poisoned");
            *tor_version = Some(tor_client.version());
        }

        // bootstrap tor daemon
        tor_client.bootstrap()?;

        // our ricochet-refresh packet handler
        let mut packet_handler = PacketHandler::new(private_key.clone());

        // our pending connections (outgoing)
        let mut pending_connections: BTreeMap<tor_interface::tor_provider::ConnectHandle, PendingConnection> = Default::default();

        // our current connections
        let mut connections: BTreeMap<ConnectionHandle, Connection> = Default::default();

        // queue of frontend callbacks
        let mut callback_queue: Vec<CallbackData> = Default::default();

        // byte read buffer
        const READ_BUFFER_SIZE: usize = 1024;
        let mut read_buffer: [u8; READ_BUFFER_SIZE] = [0u8; READ_BUFFER_SIZE];

        loop {
            // handle tor events
            for e in tor_client.update()? {
                match e {
                    TorEvent::BootstrapStatus{progress, tag, summary: _} => {
                        callback_queue.push(
                            CallbackData::TorBootstrapStatusChanged{progress, tag});
                    },
                    TorEvent::BootstrapComplete => {
                        if let Some(connect_complete) = connect_complete.upgrade() {
                            connect_complete.store(true, Ordering::Relaxed);
                        }

                        callback_queue.push(
                            CallbackData::TorNetworkStatusChanged{status: tego_tor_network_status::tego_tor_network_status_ready});

                        callback_queue.push(
                            CallbackData::HostOnionServiceStateChanged{state: tego_host_onion_service_state::tego_host_onion_service_state_service_added});

                        // start onion service
                        let listener = tor_client.listener(&private_key, RICOCHET_PORT, None)?;
                        std::thread::Builder::new()
                            .name("listener-loop".to_string())
                            .spawn({
                                let command_queue = command_queue.clone();
                                move || {
                                    let _ = Self::listener_loop(listener, &command_queue);
                            }})?;
                    },
                    TorEvent::LogReceived{line} => {
                        if let Some(tor_logs) = tor_logs.upgrade() {
                            let mut tor_logs = tor_logs.lock().expect("tor_logs mutex poisoned");
                            tor_logs.push(line.clone());
                        }
                        callback_queue.push(
                            CallbackData::TorLogReceived{line});
                    },
                    TorEvent::OnionServicePublished{service_id : _} => {
                        callback_queue.push(
                            CallbackData::HostOnionServiceStateChanged{state: tego_host_onion_service_state::tego_host_onion_service_state_service_published});
                    },
                    TorEvent::ConnectComplete{handle, stream} => {
                        if let Some(pending_connection) = pending_connections.remove(&handle) {

                            stream.set_nonblocking(true).expect("");

                            let service_id = pending_connection.service_id;
                            let message_text = pending_connection.message_text;

                            let mut replies: Vec<Packet> = Default::default();
                            let handle = packet_handler.new_outgoing_connection(service_id.clone(), message_text, &mut replies);

                            let connection = Connection{
                                service_id: Some(service_id.clone()),
                                stream: Some(stream),
                                read_bytes: Default::default(),
                                write_packets: replies,
                            };

                            connections.insert(handle, connection);
                        }
                    },
                    TorEvent::ConnectFailed{handle, error} => {
                        let pending_connection = pending_connections.remove(&handle);
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
                            stream: Some(stream),
                            read_bytes: Default::default(),
                            write_packets: Default::default(),
                        };

                        println!("begin server handshake: {connection:?}");

                        connections.insert(handle, connection);
                    },
                    Command::AcknowledgeContactRequest{service_id, response} => {
                        let mut replies: Vec<Packet> = Default::default();
                        use tego_chat_acknowledge::*;
                        let result = match response {
                            tego_chat_acknowledge_accept => packet_handler.accept_contact_request(service_id, &mut replies),
                            tego_chat_acknowledge_reject => todo!(),
                            tego_chat_acknowledge_block => todo!(),
                        };

                        match result {
                            Ok(connection_handle) => {
                                if let Some(connection) = connections.get_mut(&connection_handle) {
                                    connection.write_packets.append(&mut replies);
                                }
                            },
                            Err(_err) => todo!(),
                        }
                    },
                    Command::SendContactRequest{service_id, message} => {
                        let target_addr: tor_interface::tor_provider::TargetAddr = (service_id.clone(), RICOCHET_PORT).into();

                        let connect_handle = tor_client.connect_async(target_addr, None).unwrap();

                        let pending_connection = PendingConnection {service_id, message_text: Some(message) };
                        pending_connections.insert(connect_handle, pending_connection);
                    },
                    Command::SendMessage{service_id, message_text, message_id} => {
                        let mut replies: Vec<Packet> = Default::default();
                        let result = match packet_handler.send_message(service_id, message_text, &mut replies) {
                            Ok((connection_handle, message_id)) => {
                                if let Some(connection) = connections.get_mut(&connection_handle) {
                                    connection.write_packets.append(&mut replies);
                                }
                                Ok(message_id)
                            },
                            Err(err) => Err(err.into()),
                        };
                        message_id.resolve(result);
                    },
                }
            }

            // read any pending bytes and update the packet handler
            connections.retain(|&handle, connection| -> bool {

                let mut retain = true;

                // early exit if we don't have a stream yet
                let stream = if let Some(stream) = connection.stream.as_mut() {
                    stream
                } else {
                    return retain;
                };

                // handle reading
                match stream.read(&mut read_buffer) {
                    Err(err) => match err.kind() {
                        ErrorKind::WouldBlock | ErrorKind::TimedOut => (),
                        _ => {
                            println!("retain = false; err: {err:?}");
                            retain = false; // some error
                        },
                    },
                    Ok(0) => {
                        println!("retain = false; end of stream");
                        retain = false; // end of stream
                    },
                    Ok(size) => {
                        let read_buffer = &read_buffer[..size];
                        connection.read_bytes.write(read_buffer).expect("read_bytes write failed");
                    },
                }

                let mut read_bytes = connection.read_bytes.as_slice();
                // total handled bytes
                let mut trim_count = 0usize;

                let mut read_packets: Vec<Packet> = Default::default();

                // parse read bytes into packets
                loop {
                    match packet_handler.try_parse_packet(handle, read_bytes) {
                        Ok((packet, size)) => {
                            println!("<< read packet: {packet:?}");
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
                            println!("- error: {err:?}");
                            println!("read_bytes: {read_bytes:?}");
                            // drop connection
                            println!("retain = false; protobuf error");
                            retain = false;
                            break;
                        },
                    }
                }
                // drop handled bytes off the front
                connection.read_bytes.drain(0..trim_count);

                // handle packets and queue responses
                let write_packets = &mut connection.write_packets;
                for packet in read_packets.drain(..) {
                    match packet_handler.handle_packet(handle, packet, write_packets) {
                        Ok(Event::IntroductionReceived) => {
                            println!("--- introduction received ---");
                        },
                        Ok(Event::IntroductionResponseReceived) => {
                            println!("--- introduction response received ---");
                        },
                        Ok(Event::OpenChannelAuthHiddenServiceReceived) => {
                            println!("--- open auth hidden service received ---");
                        },
                        Ok(Event::ClientAuthenticated{service_id}) => {
                            println!("--- client authenticated: peer: {service_id:?} ---");
                            connection.service_id = Some(service_id);
                        },
                        Ok(Event::HostAuthenticated{service_id}) => {
                            println!("--- host authenticated: peer: {service_id:?} ---");
                        },
                        Ok(Event::ContactRequestReceived{service_id, nickname: _, message_text}) => {
                            println!("--- contact request received, peer: {service_id:?}, message_text: \"{message_text}\"");
                            callback_queue.push(CallbackData::ChatRequestReceived{service_id, message: message_text});
                        },
                        Ok(Event::ContactRequestResultPending{service_id}) => {
                            println!("--- contact request result pending, peer: {service_id:?}");
                        },
                        Ok(Event::ContactRequestResultAccepted{service_id}) => {
                            println!("--- contact request result accepted, peer: {service_id:?}");
                        },
                        Ok(Event::IncomingChatChannelOpened{service_id}) => {
                            println!(" --- incoming chat channel opened, peer: {service_id:?} ---");
                        },
                        Ok(Event::IncomingFileTransferChannelOpened{service_id}) => {
                            println!(" --- incoming file transfer channel opened, peer: {service_id:?} ---");
                        },
                        Ok(Event::OutgoingAuthHiddenServiceChannelOpened{service_id}) => {
                            println!(" --- outgoing auth hidden service channel opened, peer: {service_id:?} ---");
                        },
                        Ok(Event::OutgoingChatChannelOpened{service_id}) => {
                            println!(" --- outgoing chat channel opened, peer: {service_id:?} ---");
                            callback_queue.push(CallbackData::UserStatusChanged{service_id, status: tego_user_status::tego_user_status_online});
                        },
                        Ok(Event::OutgoingFileTransferChannelOpened{service_id}) => {
                            println!(" --- outgoing file transfer channel opened, peer: {service_id:?} ---");
                        },
                        Ok(Event::ChatMessageReceived{service_id, message_text, message_id, time_delta}) => {
                            println!(" --- chat message receved, peer: {service_id:?}, message: \"{message_text}");
                            let now = std::time::SystemTime::now();
                            let timestamp = now.checked_sub(time_delta).unwrap();
                            callback_queue.push(CallbackData::MessageReceived{service_id, timestamp, message_id, message: message_text});
                        },
                        Ok(Event::ChatAcknowledgeReceived{service_id, message_id, accepted}) => {
                            println!(" --- chat ack received, peer: {service_id:?}, message_id: {message_id}, accepted: {accepted}");
                            callback_queue.push(CallbackData::MessageAcknowledged{service_id, message_id, accepted});
                        },
                        Ok(Event::ChannelClosed{id, data}) => {
                            println!("--- channel closed: {id}, {data:?} ---");
                        },
                        // errors
                        Ok(Event::ProtocolFailure{message}) => {
                            println!("--- non-fatal protocol failure: {message} ---");
                        }
                        Ok(Event::FatalProtocolFailure) => {
                            println!("--- fatal protocol error, removing connection ---");
                            println!("retain = false; FatalProtocolError");
                            retain = false;
                        }
                        Err(err) => panic!("error: {err:?}"),
                    }
                }

                // write replies
                if !write_packets.is_empty() {
                    // serialise out packets to bytes
                    let mut write_bytes: Vec<u8> = Default::default();
                    for packet in write_packets.drain(..) {
                        println!(">> write packet: {packet:?}");
                        packet.write_to_vec(&mut write_bytes).expect("packet write failed");
                    }

                    // send bytes
                    if !stream.write(write_bytes.as_slice()).is_ok() {
                        println!("retain = false; write failed");
                        retain = false;
                    }
                }
                retain
            });

            // handle callbacks back to frontend
            let callbacks = callbacks.upgrade().context("callbacks dropped")?;
            let callbacks = callbacks.lock().expect("callbacks mutex poisoned");
            for callback_data in callback_queue.drain(..) {
                match callback_data {
                    CallbackData::TorNetworkStatusChanged{status} => {
                        if let Some(on_tor_network_status_changed) = callbacks.on_tor_network_status_changed {
                            on_tor_network_status_changed(tego_key as *mut tego_context, status);
                        }
                    },
                    CallbackData::TorBootstrapStatusChanged{progress, tag} => {
                        if let Some(on_tor_bootstrap_status_changed) = callbacks.on_tor_bootstrap_status_changed {
                            on_tor_bootstrap_status_changed(tego_key as *mut tego_context, progress as i32, tag.as_str().into());
                        }
                    },
                    CallbackData::TorLogReceived{line} => {
                        if let Some(on_tor_log_received) = callbacks.on_tor_log_received {
                            let line = CString::new(line.as_str()).unwrap();
                            let line_len = line.as_bytes().len();
                            on_tor_log_received(tego_key as *mut tego_context, line.as_c_str().as_ptr(), line_len);
                        }
                    },
                    CallbackData::HostOnionServiceStateChanged{state} => {
                        if let Some(on_host_onion_service_state_changed) = callbacks.on_host_onion_service_state_changed {
                            on_host_onion_service_state_changed(tego_key as *mut tego_context, state);
                        }
                    },
                    CallbackData::ChatRequestReceived{service_id, message} => {
                        if let Some(on_chat_request_received) = callbacks.on_chat_request_received {
                            let sender = get_object_map().insert(TegoObject::UserId(UserId{service_id}));
                            let message = CString::new(message.as_str()).unwrap();
                            let message_len = message.as_bytes().len();
                            on_chat_request_received(tego_key as *mut tego_context, sender as *const tego_user_id, message.as_c_str().as_ptr(), message_len);
                            get_object_map().remove(&sender);
                        }
                    },
                    CallbackData::UserStatusChanged{service_id, status} => {
                        if let Some(on_user_status_changed) = callbacks.on_user_status_changed {
                            let user = get_object_map().insert(TegoObject::UserId(UserId{service_id}));
                            on_user_status_changed(tego_key as *mut tego_context, user as *const tego_user_id, status);
                            get_object_map().remove(&user);
                        }
                    },
                    CallbackData::MessageReceived{service_id, timestamp, message_id, message} => {
                        if let Some(on_message_received) = callbacks.on_message_received {
                            let user = get_object_map().insert(TegoObject::UserId(UserId{service_id}));
                            let timestamp = timestamp.duration_since(std::time::UNIX_EPOCH).unwrap();
                            let timestamp = timestamp.as_millis() as tego_time;
                            assert!(timestamp > 0);

                            let message = CString::new(message.as_str()).unwrap();
                            let message_len = message.as_bytes().len();
                            on_message_received(tego_key as *mut tego_context, user as *const tego_user_id, timestamp, message_id, message.as_c_str().as_ptr(), message_len);

                            get_object_map().remove(&user);
                        }
                    },
                    CallbackData::MessageAcknowledged{service_id, message_id, accepted} => {
                        if let Some(on_message_acknowledged) = callbacks.on_message_acknowledged {
                            let user = get_object_map().insert(TegoObject::UserId(UserId{service_id}));
                            let accepted = if accepted {
                                TEGO_TRUE
                            } else {
                                TEGO_FALSE
                            };
                            on_message_acknowledged(tego_key as *mut tego_context, user as *const tego_user_id, message_id, accepted);
                            get_object_map().remove(&user);
                        }
                    },
                    _ => panic!("not implemented"),
                }
            }
        }
    }

    // listen for connections to our onion service and request handshake begin
    fn listener_loop(
        listener: OnionListener,
        command_queue: &Weak<Mutex<Vec<Command>>>,
    ) -> Result<()> {
        listener.set_nonblocking(false)?;
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
        let complete = self.event_loop_complete.get_future();
        complete.wait();
    }
}

#[derive(Debug)]
struct PendingConnection {
    pub service_id: V3OnionServiceId,
    pub message_text: Option<rico_protocol::v3::message::contact_request_channel::MessageText>,
}

#[derive(Debug)]
struct Connection {
    pub service_id: Option<V3OnionServiceId>,
    pub stream: Option<OnionStream>,
    // buffer of unhandled read bytes
    pub read_bytes: Vec<u8>,
    // buffer of packets to write
    pub write_packets: Vec<Packet>,
}

enum Command {
    // library is going away we need to cleanup
    EndEventLoop,
    // client connects to our listener triggering an incoming handshake
    BeginServerHandshake{
        stream: OnionStream
    },
    AcknowledgeContactRequest{
        service_id: V3OnionServiceId,
        response: tego_chat_acknowledge,
    },
    SendContactRequest{
        service_id: V3OnionServiceId,
        message: rico_protocol::v3::message::contact_request_channel::MessageText,
    },
    SendMessage{
        service_id: V3OnionServiceId,
        message_text: rico_protocol::v3::message::chat_channel::MessageText,
        message_id: Promise<Result<tego_message_id>>,
    },
}

enum CallbackData {
    TorErrorOccurred,
    UpdateTorDaemonConfigSucceeded,
    TorControlStatusChanged,
    TorProcessStatusChanged,
    TorNetworkStatusChanged{status: tego_tor_network_status},
    TorBootstrapStatusChanged{progress: u32, tag: String},
    TorLogReceived{line: String},
    HostOnionServiceStateChanged{state: tego_host_onion_service_state},
    ChatRequestReceived{service_id: V3OnionServiceId, message: String},
    ChatRequestResponseReceived,
    MessageReceived{service_id: V3OnionServiceId, timestamp: std::time::SystemTime, message_id: tego_message_id, message: String},
    MessageAcknowledged{service_id: V3OnionServiceId, message_id: tego_message_id, accepted: bool},
    FileTransferRequestReceived,
    FileTransferRequestAcknowledged,
    FileTransferRequestResponseReceived,
    FileTransferProgress,
    FileTransferComplete,
    UserStatusChanged{service_id: V3OnionServiceId, status: tego_user_status},
    NewIdentityCreated,
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
