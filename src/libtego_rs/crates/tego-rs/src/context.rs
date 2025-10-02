// standard
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{ErrorKind, Read, Seek, Write};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, Weak,
};
use std::time::{Duration, Instant};

// extern
use anyhow::{Context as AnyhowContext, Result};
use rico_protocol::v3::file_hasher::*;
use rico_protocol::v3::packet_handler::*;
use rico_protocol::v3::Error;
use tor_interface::legacy_tor_client::*;
use tor_interface::legacy_tor_version::LegacyTorVersion;
use tor_interface::proxy::ProxyConfig;
use tor_interface::tor_crypto::{Ed25519PrivateKey, V3OnionServiceId};
use tor_interface::tor_provider::{OnionListener, OnionStream, TorEvent, TorProvider};

// internal crates
use crate::command_queue::*;
use crate::ffi::*;
use crate::macros::*;
use crate::promise::Promise;
use crate::user_id::UserId;

const RICOCHET_PORT: u16 = 9878u16;

// TODO: replace println!s with a configurable logger

#[derive(Default)]
pub(crate) struct Context {
    tego_key: TegoKey,
    // todo: this should not exposed directly
    // callback setters in FFI should pass pointers
    // down here and set them via cmd to avoid
    // this lock
    pub callbacks: Arc<Mutex<Callbacks>>,
    // tor config data
    tor_data_directory: PathBuf,
    proxy_settings: Option<ProxyConfig>,
    allowed_ports: Option<Vec<u16>>,
    // tor runtime data
    tor_version_cstring: Option<CString>,
    // todo: arguably these should be accessed by a Command
    // as well though there would be more latency than acquire
    // lock
    tor_version: Arc<Mutex<Option<LegacyTorVersion>>>,
    tor_logs: Arc<Mutex<String>>,
    // flags
    connect_complete: Arc<AtomicBool>,
    event_loop_complete: Promise<()>,
    // command queue
    command_queue: CommandQueue,
    // ricochet-refresh data
    private_key: Option<Ed25519PrivateKey>,
    users: BTreeMap<V3OnionServiceId, tego_user_type>,
}

impl Context {
    pub fn set_tego_key(&mut self, tego_key: TegoKey) {
        self.tego_key = tego_key;
    }

    pub fn set_tor_data_directory(&mut self, tor_data_directory: PathBuf) {
        self.tor_data_directory = tor_data_directory;
    }

    // todo: this needs to support bridges and pluggable-transports
    pub fn set_tor_config(
        &mut self,
        proxy_settings: Option<ProxyConfig>,
        allowed_ports: Option<Vec<u16>>,
    ) {
        self.proxy_settings = proxy_settings;
        self.allowed_ports = allowed_ports;
    }

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

    pub fn tor_logs_size(&self) -> usize {
        let tor_logs = self.tor_logs.lock().expect("tor_logs mutex poisoned");
        tor_logs.len() + 1usize
    }

    pub fn tor_logs(&self) -> String {
        let tor_logs = self.tor_logs.lock().expect("tor_logs mutex poisoned");
        tor_logs.clone()
    }

    pub fn set_private_key(&mut self, private_key: Ed25519PrivateKey) {
        self.private_key = Some(private_key);
    }

    pub fn private_key(&self) -> Option<&Ed25519PrivateKey> {
        self.private_key.as_ref()
    }

    pub fn set_users(&mut self, users: BTreeMap<V3OnionServiceId, tego_user_type>) {
        self.users = users;
    }

    pub fn host_service_id(&self) -> Option<V3OnionServiceId> {
        self.private_key
            .as_ref()
            .map(V3OnionServiceId::from_private_key)
    }

    // todo: should take a tor config as an argument
    pub fn connect(&mut self) -> Result<()> {
        let tego_key = self.tego_key;
        let callbacks = Arc::downgrade(&self.callbacks);

        // todo: should read proxy, firewall, bridge and pt settings too
        let tor_config = LegacyTorClientConfig::BundledTor {
            tor_bin_path: Self::tor_bin_path()?,
            data_directory: self.tor_data_directory.clone(),
            proxy_settings: None,
            allowed_ports: None,
            pluggable_transports: None,
            bridge_lines: None,
        };
        let tor_client = LegacyTorClient::new(tor_config)?;

        let tor_version = Arc::downgrade(&self.tor_version);
        let tor_logs = Arc::downgrade(&self.tor_logs);

        let connect_complete = Arc::downgrade(&self.connect_complete);
        let event_loop_complete = self.event_loop_complete.clone();

        let private_key = self.private_key.as_ref().unwrap().clone();

        let command_queue = self.command_queue.downgrade();

        let task = EventLoopTask::new(
            tego_key,
            callbacks,
            tor_client,
            tor_version,
            tor_logs,
            connect_complete,
            private_key,
            std::mem::take(&mut self.users),
            command_queue,
            event_loop_complete,
        );

        std::thread::Builder::new()
            .name("event-loop".to_string())
            .spawn(move || {
                // start event loop
                let _ = task.run();
            })?;

        Ok(())
    }

    pub fn connect_complete(&self) -> bool {
        self.connect_complete.load(Ordering::Relaxed)
    }

    fn push_command(&self, data: CommandData) {
        self.push_command_ex(data, Duration::ZERO);
    }

    fn push_command_ex(&self, data: CommandData, delay: Duration) {
        self.command_queue.push(data, delay);
    }

    pub fn forget_user(&mut self, service_id: V3OnionServiceId) -> Result<()> {
        self.users.remove(&service_id);
        let result: Promise<Result<()>> = Default::default();
        let result_future = result.get_future();
        self.push_command(CommandData::ForgetUser { service_id, result });

        result_future.wait()
    }

    pub fn send_contact_request(
        &self,
        service_id: V3OnionServiceId,
        message: rico_protocol::v3::message::contact_request_channel::MessageText,
    ) {
        let contact_request_message = Some(message);
        self.push_command(CommandData::ConnectContact {
            service_id,
            failure_count: 0usize,
            contact_request_message,
        });
    }

    pub fn acknowledge_contact_request(
        &self,
        service_id: V3OnionServiceId,
        response: tego_chat_acknowledge,
    ) {
        self.push_command(CommandData::AcknowledgeContactRequest {
            service_id,
            response,
        });
    }

    pub fn send_message(
        &self,
        service_id: V3OnionServiceId,
        message_text: rico_protocol::v3::message::chat_channel::MessageText,
    ) -> Result<tego_message_id> {
        let message_id: Promise<Result<tego_message_id>> = Default::default();
        let message_id_future = message_id.get_future();
        let cmd = CommandData::SendMessage {
            service_id,
            message_text,
            message_id,
        };
        self.push_command(cmd);

        message_id_future.wait()
    }

    pub fn send_file_transfer_request(
        &self,
        service_id: V3OnionServiceId,
        file_path: PathBuf,
    ) -> Result<(tego_file_transfer_id, tego_file_size)> {
        let result: Promise<Result<(tego_file_transfer_id, tego_file_size)>> = Default::default();
        let result_future = result.get_future();
        let cmd = CommandData::SendFileTransferRequest {
            service_id,
            file_path,
            result,
        };
        self.push_command(cmd);

        result_future.wait()
    }

    pub fn accept_file_transfer_request(
        &self,
        service_id: V3OnionServiceId,
        file_transfer_id: tego_file_transfer_id,
        dest_path: PathBuf,
    ) -> Result<()> {
        println!("--- called accept_file_transfer_requesst");

        // verify absolute path
        bail_if!(!dest_path.is_absolute());

        // verify dest_path is NOT a directory
        bail_if!(dest_path.is_dir());

        // verify the parent directory exists
        let parent = dest_path.parent().context("dest_path has no parent")?;
        bail_if!(!parent.exists());

        let result: Promise<Result<()>> = Default::default();
        let result_future = result.get_future();

        let cmd = CommandData::AcceptFileTransferRequest {
            service_id,
            file_transfer_id,
            dest_path,
            result,
        };
        self.push_command(cmd);

        result_future.wait()
    }

    pub fn reject_file_transfer_request(
        &self,
        service_id: V3OnionServiceId,
        file_transfer_id: tego_file_transfer_id,
    ) -> Result<()> {
        println!("--- called reject_file_transfer_requesst");

        let result: Promise<Result<()>> = Default::default();
        let result_future = result.get_future();

        let cmd = CommandData::RejectFileTransferRequest {
            service_id,
            file_transfer_id,
            result,
        };
        self.push_command(cmd);

        result_future.wait()
    }

    pub fn cancel_file_transfer(
        &self,
        service_id: V3OnionServiceId,
        file_transfer_id: tego_file_transfer_id,
    ) -> Result<()> {
        println!("--- called cancel_file_transfer_requesst");

        let result: Promise<Result<()>> = Default::default();
        let result_future = result.get_future();

        let cmd = CommandData::CancelFileTransfer {
            service_id,
            file_transfer_id,
            result,
        };
        self.push_command(cmd);

        result_future.wait()
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
}

impl Drop for Context {
    fn drop(&mut self) {
        self.push_command(CommandData::EndEventLoop);
        let complete = self.event_loop_complete.get_future();
        complete.wait();
    }
}

struct UserData {
    user_type: tego_user_type,
    pending_connection_handle: Option<tor_interface::tor_provider::ConnectHandle>,
    connection_handle: Option<ConnectionHandle>,
    // todo: maybe we can queue messages here?
}

struct EventLoopTask {
    context: TegoKey,
    callbacks: Weak<Mutex<Callbacks>>,
    tor_client: LegacyTorClient,
    tor_version: Weak<Mutex<Option<LegacyTorVersion>>>,
    tor_logs: Weak<Mutex<String>>,
    connect_complete: Weak<AtomicBool>,
    private_key: Ed25519PrivateKey,
    command_queue: CommandQueue,
    read_buffer: [u8; Self::READ_BUFFER_SIZE],
    packet_handler: PacketHandler,
    pending_connections: BTreeMap<tor_interface::tor_provider::ConnectHandle, PendingConnection>,
    connections: BTreeMap<ConnectionHandle, Connection>,
    callback_queue: Vec<CallbackData>,
    task_complete: bool,
    event_loop_complete: Promise<()>,
    // file reader buffer for uploads
    file_read_buffer: [u8; Self::FILE_READ_BUFFER_SIZE],
    // todo: we need to keep track of numberr of authentication failures
    // and use this in place of the decentralised connection  failures
    // which are passed along through the relevant Connect command
    users: BTreeMap<V3OnionServiceId, UserData>,
}

impl EventLoopTask {
    const READ_BUFFER_SIZE: usize = 64 * 1024;
    const FILE_READ_BUFFER_SIZE: usize = rico_protocol::v3::MAX_FILE_CHUNK_SIZE;

    fn new(
        context: TegoKey,
        callbacks: Weak<Mutex<Callbacks>>,
        tor_client: LegacyTorClient,
        tor_version: Weak<Mutex<Option<LegacyTorVersion>>>,
        tor_logs: Weak<Mutex<String>>,
        connect_complete: Weak<AtomicBool>,
        private_key: Ed25519PrivateKey,
        users: BTreeMap<V3OnionServiceId, tego_user_type>,
        command_queue: CommandQueue,
        event_loop_complete: Promise<()>,
    ) -> Self {
        // create our list of known contacts from our users
        // and our UserData structs
        let mut known_contacts: BTreeSet<V3OnionServiceId> = Default::default();
        let mut user_data: BTreeMap<V3OnionServiceId, UserData> = Default::default();

        for (user_id, user_type) in users.iter() {
            use tego_user_type::*;
            match user_type {
                tego_user_type_allowed | tego_user_type_pending => {
                    known_contacts.insert(user_id.clone());
                }
                _ => (),
            }
            user_data.insert(
                user_id.clone(),
                UserData {
                    user_type: *user_type,
                    pending_connection_handle: None,
                    connection_handle: None,
                },
            );
        }

        Self {
            context,
            callbacks,
            tor_client,
            tor_version,
            tor_logs,
            connect_complete,
            private_key: private_key.clone(),
            command_queue,
            read_buffer: [0u8; Self::READ_BUFFER_SIZE],
            packet_handler: PacketHandler::new(private_key, known_contacts),
            pending_connections: Default::default(),
            connections: Default::default(),
            callback_queue: Default::default(),
            task_complete: false,
            event_loop_complete,
            file_read_buffer: [0u8; Self::FILE_READ_BUFFER_SIZE],
            users: user_data,
        }
    }

    fn run(mut self) -> Result<()> {
        // save off the tor daemon version
        {
            let tor_version = self.tor_version.upgrade().context("tor_version dropped")?;
            let mut tor_version = tor_version.lock().expect("tor_version mutex poisoned");
            *tor_version = Some(self.tor_client.version());
        }

        // begin connect to tor network
        self.tor_client.bootstrap()?;

        while !self.task_complete {
            // handle tor provider events
            self.handle_tor_events()?;

            // get and handle pending commands
            self.handle_commands()?;

            // read any pending bytes and update the packet handler
            self.handle_connections()?;

            // trigger callbacks for frontend
            self.handle_callbacks()?;
        }

        // signal task completion
        self.event_loop_complete.resolve(());

        Ok(())
    }

    fn handle_tor_events(&mut self) -> Result<()> {
        // handle tor events
        for e in self.tor_client.update()? {
            match e {
                TorEvent::BootstrapStatus {
                    progress,
                    tag,
                    summary: _,
                } => {
                    self.callback_queue
                        .push(CallbackData::TorBootstrapStatusChanged { progress, tag });
                }
                TorEvent::BootstrapComplete => {
                    if let Some(connect_complete) = self.connect_complete.upgrade() {
                        connect_complete.store(true, Ordering::Relaxed);
                    }

                    self.callback_queue
                        .push(CallbackData::TorNetworkStatusChanged {
                            status: tego_tor_network_status::tego_tor_network_status_ready,
                        });

                    self.callback_queue.push(
                        CallbackData::HostOnionServiceStateChanged{state: tego_host_onion_service_state::tego_host_onion_service_state_service_added});

                    // start onion service
                    let listener =
                        self.tor_client
                            .listener(&self.private_key, RICOCHET_PORT, None)?;
                    std::thread::Builder::new()
                        .name("listener-loop".to_string())
                        .spawn({
                            let command_queue = self.command_queue.downgrade();
                            move || {
                                let task = ListenerTask {
                                    listener,
                                    command_queue,
                                };
                                let _ = task.run();
                            }
                        })?;

                    // try to connect to contacts
                    for (user_id, user_data) in self.users.iter() {
                        use tego_user_type::*;
                        match user_data.user_type {
                            tego_user_type_allowed | tego_user_type_pending => {
                                self.command_queue.push(
                                    CommandData::ConnectContact {
                                        service_id: user_id.clone(),
                                        failure_count: 0usize,
                                        contact_request_message: None,
                                    },
                                    Duration::ZERO,
                                );
                            }
                            _ => (),
                        }
                    }
                }
                TorEvent::LogReceived { line } => {
                    if let Some(tor_logs) = self.tor_logs.upgrade() {
                        let mut tor_logs = tor_logs.lock().expect("tor_logs mutex poisoned");
                        if !tor_logs.is_empty() {
                            tor_logs.push('\n');
                        }
                        tor_logs.push_str(line.as_str());
                    }
                    self.callback_queue
                        .push(CallbackData::TorLogReceived { line });
                }
                TorEvent::OnionServicePublished { service_id: _ } => {
                    self.callback_queue.push(
                        CallbackData::HostOnionServiceStateChanged{state: tego_host_onion_service_state::tego_host_onion_service_state_service_published});
                }
                TorEvent::ConnectComplete { handle, stream } => {
                    let handle_connect_complete = || -> Result<()> {
                        if let Some(pending_connection) = self.pending_connections.remove(&handle) {
                            stream.set_nonblocking(true).unwrap();

                            let service_id = pending_connection.service_id;
                            let message_text = pending_connection.message_text;

                            if !self.packet_handler.has_verified_connection(&service_id) {
                                println!("--- connected to {service_id:?}");
                                let mut replies: Vec<Packet> = Default::default();
                                let handle = self.packet_handler.new_outgoing_connection(
                                    service_id.clone(),
                                    message_text,
                                    &mut replies,
                                )?;

                                let connection = Connection {
                                    service_id: Some(service_id),
                                    stream,
                                    read_bytes: Default::default(),
                                    read_packets: Default::default(),
                                    write_packets: replies,
                                    file_downloads: Default::default(),
                                    file_uploads: Default::default(),
                                    remove: false,
                                };

                                self.connections.insert(handle, connection);
                            } else {
                                println!("--- connected to {service_id:?} but verified connection already exists, dropping");
                            }
                        }
                        Ok(())
                    };
                    let _ = handle_connect_complete();
                }
                TorEvent::ConnectFailed { handle, error: _ } => {
                    if let Some(pending_connection) = self.pending_connections.remove(&handle) {
                        let service_id = pending_connection.service_id;
                        let failure_count = pending_connection.failure_count + 1;

                        // delay before trying to connect in seconds
                        let delay = match failure_count {
                            0..=10 => 30u64,
                            11..=15 => 60u64,
                            16..=20 => 120u64,
                            21.. => 600u64,
                        };

                        println!("--- connect attempt {failure_count} to {service_id:?} failed; try again in {delay} seconds");

                        let contact_request_message = pending_connection.message_text;
                        let command_data = CommandData::ConnectContact {
                            service_id,
                            failure_count,
                            contact_request_message,
                        };

                        self.command_queue
                            .push(command_data, Duration::from_secs(delay));
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_commands(&mut self) -> Result<()> {
        let mut command_queue = self.command_queue.take();

        while let Some(cmd) = command_queue.peek() {
            if *cmd.start_time() > Instant::now() {
                break;
            }

            let cmd = command_queue.pop().unwrap();
            match cmd.data() {
                CommandData::EndEventLoop => self.task_complete = true,
                CommandData::ForgetUser { service_id, result } => {
                    let mut handle_forget_user = || -> Result<()> {
                        // remove from our set of users
                        if let Some(user_data) = self.users.remove(&service_id) {
                            // ignore any pending connection
                            if let Some(pending_connection_handle) =
                                user_data.pending_connection_handle
                            {
                                self.pending_connections.remove(&pending_connection_handle);
                            }

                            // kill open connection
                            if let Some(connection_handle) = user_data.connection_handle {
                                self.connections.remove(&connection_handle);
                            }
                        }
                        // remove from packet handler
                        self.packet_handler.forget_user(&service_id);

                        Ok(())
                    };
                    result.resolve(handle_forget_user());
                }
                CommandData::BeginServerHandshake { stream } => {
                    let handle_begin_server_handshake = || -> Result<()> {
                        let handle = self.packet_handler.new_incoming_connection()?;

                        let connection = Connection {
                            service_id: None,
                            stream,
                            read_bytes: Default::default(),
                            read_packets: Default::default(),
                            write_packets: Default::default(),
                            file_downloads: Default::default(),
                            file_uploads: Default::default(),
                            remove: false,
                        };

                        println!("begin server handshake: {connection:?}");

                        self.connections.insert(handle, connection);
                        Ok(())
                    };
                    let _ = handle_begin_server_handshake();
                }
                CommandData::AcknowledgeContactRequest {
                    service_id,
                    response,
                } => {
                    let mut replies: Vec<Packet> = Default::default();
                    use tego_chat_acknowledge::*;
                    let (result, remove) = match response {
                        tego_chat_acknowledge_accept => (
                            self.packet_handler
                                .accept_contact_request(service_id, &mut replies),
                            false,
                        ),
                        // todo: add user to our user_data list
                        tego_chat_acknowledge_reject => (
                            self.packet_handler
                                .reject_contact_request(service_id, &mut replies),
                            true,
                        ),
                        tego_chat_acknowledge_block => todo!(),
                    };

                    match result {
                        Ok(connection_handle) => {
                            if let Some(connection) = self.connections.get_mut(&connection_handle) {
                                connection.write_packets.append(&mut replies);
                                connection.remove = remove;
                            }
                        }
                        Err(_err) => todo!(),
                    }
                }
                CommandData::ConnectContact {
                    service_id,
                    failure_count,
                    contact_request_message: message_text,
                } => {
                    // only open new connection if there is no existing verified
                    // connection already
                    if !self.packet_handler.has_verified_connection(&service_id) {
                        println!("--- connecting to {service_id}");
                        let target_addr: tor_interface::tor_provider::TargetAddr =
                            (service_id.clone(), RICOCHET_PORT).into();

                        let connect_handle =
                            self.tor_client.connect_async(target_addr, None).unwrap();

                        let pending_connection = PendingConnection {
                            service_id,
                            failure_count,
                            message_text,
                        };
                        self.pending_connections
                            .insert(connect_handle, pending_connection);
                    } else {
                        println!("--- skipping connection attempt, verified connection already exists to {service_id}");
                    }
                }
                CommandData::SendMessage {
                    service_id,
                    message_text,
                    message_id,
                } => {
                    let mut replies: Vec<Packet> = Default::default();
                    let result = match self.packet_handler.send_message(
                        service_id,
                        message_text,
                        &mut replies,
                    ) {
                        Ok((connection_handle, message_handle)) => {
                            if let Some(connection) = self.connections.get_mut(&connection_handle) {
                                connection.write_packets.append(&mut replies);
                            }
                            Ok(message_handle.into())
                        }
                        Err(err) => Err(err.into()),
                    };
                    message_id.resolve(result);
                }
                CommandData::SendFileTransferRequest {
                    service_id,
                    file_path,
                    result,
                } => {
                    let handle_send_file_transfer_request =
                        || -> Result<(tego_file_transfer_id, tego_file_size)> {
                            // we only deal in absolute paths
                            bail_if!(!file_path.is_absolute());

                            // get our filename
                            let file_name: String = file_path
                                .file_name()
                                .context("path contains no file name")?
                                .to_str()
                                .context("file name not valid utf8")?
                                .to_string();

                            let file_upload = FileUpload::new(file_path)?;
                            let file_size = file_upload.size();

                            let file_hash = file_upload.hash();

                            //construct reply packets
                            let mut replies: Vec<Packet> = Vec::with_capacity(1);
                            let (connection_handle, file_transfer_handle) =
                                self.packet_handler.send_file_transfer_request(
                                    service_id,
                                    file_name,
                                    file_size,
                                    file_hash,
                                    &mut replies,
                                )?;

                            let connection = self
                                .connections
                                .get_mut(&connection_handle)
                                .context("missing Connection struct")?;

                            // save of file upload record
                            connection
                                .file_uploads
                                .insert(file_transfer_handle, file_upload);

                            // queue packets for writing
                            connection.write_packets.append(&mut replies);

                            let file_transfer_id: tego_file_transfer_id =
                                file_transfer_handle.into();

                            Ok((file_transfer_id, file_size))
                        };

                    result.resolve(handle_send_file_transfer_request());
                }
                CommandData::AcceptFileTransferRequest {
                    service_id,
                    file_transfer_id,
                    dest_path,
                    result,
                } => {
                    let handle_accept_file_transfer_request = || -> Result<()> {
                        let file_transfer_handle: FileTransferHandle = file_transfer_id.into();

                        // construct reply packets
                        let mut replies: Vec<Packet> = Vec::with_capacity(1);
                        let connection_handle = self.packet_handler.accept_file_transfer_request(
                            &service_id,
                            file_transfer_handle,
                            &mut replies,
                        )?;

                        // setup file download
                        let connection = self
                            .connections
                            .get_mut(&connection_handle)
                            .context("missing Connection struct")?;

                        let file_download = connection
                            .file_downloads
                            .get_mut(&file_transfer_handle)
                            .context("missing FileDownload struct")?;
                        file_download.start(dest_path)?;

                        // queue packets for writing
                        connection.write_packets.append(&mut replies);

                        Ok(())
                    };

                    result.resolve(handle_accept_file_transfer_request());
                }
                CommandData::RejectFileTransferRequest {
                    service_id,
                    file_transfer_id,
                    result,
                } => {
                    let handle_reject_file_transfer_request = || -> Result<()> {
                        let file_transfer_handle: FileTransferHandle = file_transfer_id.into();

                        // construct reply packets
                        let mut replies: Vec<Packet> = Vec::with_capacity(1);
                        let connection_handle = self.packet_handler.reject_file_transfer_request(
                            &service_id,
                            file_transfer_handle,
                            &mut replies,
                        )?;

                        // remove our file download struct
                        let connection = self
                            .connections
                            .get_mut(&connection_handle)
                            .context("missing Connection struct")?;
                        connection
                            .file_downloads
                            .remove(&file_transfer_handle)
                            .context("missing FileDownload struct")?;

                        // queue packets for writing
                        connection.write_packets.append(&mut replies);

                        // fire callback
                        let direction =
                            tego_file_transfer_direction::tego_file_transfer_direction_receiving;
                        self.callback_queue
                            .push(CallbackData::FileTransferComplete {
                                user_id: service_id,
                                file_transfer_id,
                                direction,
                                result:
                                    tego_file_transfer_result::tego_file_transfer_result_rejected,
                            });

                        Ok(())
                    };

                    result.resolve(handle_reject_file_transfer_request());
                }
                CommandData::CancelFileTransfer {
                    service_id,
                    file_transfer_id,
                    result,
                } => {
                    let handle_cancel_file_transfer = || -> Result<()> {
                        let file_transfer_handle: FileTransferHandle = file_transfer_id.into();

                        // construct reply packets
                        let mut replies: Vec<Packet> = Vec::with_capacity(1);
                        let connection_handle = self.packet_handler.cancel_file_transfer(
                            &service_id,
                            file_transfer_handle,
                            &mut replies,
                        )?;

                        // remove our file download/upload struct
                        let connection = self
                            .connections
                            .get_mut(&connection_handle)
                            .context("missing Connection struct")?;

                        let direction = if connection
                            .file_downloads
                            .remove(&file_transfer_handle)
                            .is_some()
                        {
                            tego_file_transfer_direction::tego_file_transfer_direction_receiving
                        } else {
                            connection
                                .file_uploads
                                .remove(&file_transfer_handle)
                                .context("missing FileDownload or FileUpload struct")?;
                            tego_file_transfer_direction::tego_file_transfer_direction_sending
                        };

                        // queue packets for writing
                        connection.write_packets.append(&mut replies);

                        // fire callback
                        self.callback_queue
                            .push(CallbackData::FileTransferComplete {
                                user_id: service_id,
                                file_transfer_id,
                                direction,
                                result:
                                    tego_file_transfer_result::tego_file_transfer_result_cancelled,
                            });

                        Ok(())
                    };

                    result.resolve(handle_cancel_file_transfer());
                }
            }
        }

        // merge remainng commands
        if !command_queue.is_empty() {
            self.command_queue.append(command_queue);
        }

        Ok(())
    }

    fn handle_connections(&mut self) -> Result<()> {
        // connections to be removed
        let mut to_remove: BTreeSet<ConnectionHandle> = Default::default();
        // TODO: we need some kind of exponential backoff for repeated failures to connect+authenticate
        // blocked users will currently spam over and over again
        let to_retry: BTreeSet<V3OnionServiceId> = Default::default();

        // read bytes from each connection
        for (&handle, connection) in self.connections.iter_mut() {
            let stream = &mut connection.stream;

            // handle reading
            match stream.read(&mut self.read_buffer) {
                Err(err) => match err.kind() {
                    ErrorKind::WouldBlock | ErrorKind::TimedOut => (),
                    _ => {
                        // some error
                        println!("stream read err: {err:?}");
                        connection.remove = true;
                        // todo: we should only retry allowed or pending contacts
                        if let Some(_service_id) = &connection.service_id {
                            // to_retry.insert(service_id.clone());
                        }
                    }
                },
                Ok(0) => {
                    // end of stream
                    println!("stream read err: end of stream");
                    connection.remove = true;
                    // todo: we should only retry allowed or pending contacts
                    if let Some(_service_id) = &connection.service_id {
                        // to_retry.insert(service_id.clone());
                    }
                }
                Ok(size) => {
                    let read_buffer = &self.read_buffer[..size];
                    connection
                        .read_bytes
                        .write_all(read_buffer)
                        .expect("read_bytes write failed");
                }
            }

            // handle reading packets
            let mut read_bytes = connection.read_bytes.as_slice();
            let read_packets = &mut connection.read_packets;
            let write_packets = &mut connection.write_packets;

            if !read_bytes.is_empty() {
                // total handled bytes
                let mut trim_count = 0usize;

                // parse read bytes into packets
                'packet_parse: loop {
                    match self.packet_handler.try_parse_packet(handle, read_bytes) {
                        Ok((packet, size)) => {
                            println!("<< read packet: {packet:?}");
                            // move slice up by number of handled bytes
                            read_bytes = &read_bytes[size..];
                            trim_count += size;
                            // save off read bytes for handling
                            read_packets.push(packet);
                        }
                        Err(Error::NeedMoreBytes) => {
                            break 'packet_parse;
                        }
                        Err(err) => {
                            // TODO: report error somewhere?
                            println!("parse packet error: {err:?}");
                            println!("- read_bytes: {read_bytes:?}");
                            // drop connection
                            connection.remove = true;
                            break 'packet_parse;
                        }
                    }
                }

                // drop handled bytes off the front
                connection.read_bytes.drain(0..trim_count);

                // handle packets and queue responses
                'packet_handle: for packet in read_packets.drain(..) {
                    match self
                        .packet_handler
                        .handle_packet(handle, packet, write_packets)
                    {
                        Ok(Event::IntroductionReceived) => {
                            println!("--- introduction received ---");
                        }
                        Ok(Event::IntroductionResponseReceived) => {
                            println!("--- introduction response received ---");
                        }
                        Ok(Event::OpenChannelAuthHiddenServiceReceived) => {
                            println!("--- open auth hidden service received ---");
                        }
                        Ok(Event::ClientAuthenticated {
                            service_id,
                            duplicate_connection,
                        }) => {
                            // todo: handle closed connection
                            println!("--- client authenticated: peer: {service_id:?}, duplicate_connection: {duplicate_connection:?} ---");
                            connection.service_id = Some(service_id);
                            if duplicate_connection.is_some() {
                                connection.remove = true;
                            }
                        }
                        Ok(Event::BlockedClientAuthenticationAttempted { service_id }) => {
                            println!(
                                "--- blocked client attempted authentication, peer: {service_id}"
                            );
                            connection.remove = true;
                            break 'packet_handle;
                        }
                        Ok(Event::HostAuthenticated {
                            service_id,
                            duplicate_connection,
                        }) => {
                            // todo: handle closed connection
                            println!("--- host authenticated: peer: {service_id:?}, duplicate_connection: {duplicate_connection:?} ---");
                            if duplicate_connection.is_some() {
                                connection.remove = true;
                            }
                        }
                        Ok(Event::DuplicateConnectionDropped {
                            duplicate_connection,
                        }) => {
                            // todo: handle closed connection
                            println!("--- duplicate connection dropped: {duplicate_connection}");
                            connection.remove = true;
                        }
                        Ok(Event::ContactRequestReceived {
                            service_id,
                            nickname: _,
                            message_text,
                        }) => {
                            println!("--- contact request received, peer: {service_id:?}, message_text: \"{message_text}\"");
                            self.callback_queue.push(CallbackData::ChatRequestReceived {
                                service_id,
                                message: message_text,
                            });
                        }
                        Ok(Event::ContactRequestResultPending { service_id }) => {
                            println!("--- contact request result pending, peer: {service_id:?}");
                        }
                        Ok(Event::ContactRequestResultAccepted { service_id }) => {
                            println!("--- contact request result accepted, peer: {service_id:?}");
                            self.callback_queue
                                .push(CallbackData::ChatRequestResponseReceived {
                                    service_id,
                                    accepted_request: true,
                                });
                        }
                        Ok(Event::ContactRequestResultRejected { service_id }) => {
                            println!("--- contact request result rejected, peer: {service_id:?}");
                            connection.remove = true;
                            self.callback_queue
                                .push(CallbackData::ChatRequestResponseReceived {
                                    service_id,
                                    accepted_request: false,
                                });
                        }
                        Ok(Event::IncomingChatChannelOpened { service_id }) => {
                            println!("--- incoming chat channel opened, peer: {service_id:?} ---");
                        }
                        Ok(Event::IncomingFileTransferChannelOpened { service_id }) => {
                            println!("--- incoming file transfer channel opened, peer: {service_id:?} ---");
                        }
                        Ok(Event::OutgoingAuthHiddenServiceChannelOpened { service_id }) => {
                            println!("--- outgoing auth hidden service channel opened, peer: {service_id:?} ---");
                        }
                        Ok(Event::OutgoingChatChannelOpened { service_id }) => {
                            println!("--- outgoing chat channel opened, peer: {service_id:?} ---");
                            self.callback_queue.push(CallbackData::UserStatusChanged {
                                service_id,
                                status: tego_user_status::tego_user_status_online,
                            });
                        }
                        Ok(Event::OutgoingFileTransferChannelOpened { service_id }) => {
                            println!("--- outgoing file transfer channel opened, peer: {service_id:?} ---");
                        }
                        Ok(Event::ChatMessageReceived {
                            service_id,
                            message_text,
                            message_handle,
                            time_delta,
                        }) => {
                            println!("--- chat message receved, peer: {service_id:?}, message: \"{message_text}, message_handle: {message_handle:?}, time_delta: {time_delta:?}");
                            let now = std::time::SystemTime::now();
                            let timestamp = now.checked_sub(time_delta).unwrap();
                            let message_id: tego_message_id = message_handle.into();
                            let message = message_text;
                            self.callback_queue.push(CallbackData::MessageReceived {
                                service_id,
                                timestamp,
                                message_id,
                                message,
                            });
                        }
                        Ok(Event::ChatAcknowledgeReceived {
                            service_id,
                            message_handle,
                            accepted,
                        }) => {
                            println!("--- chat ack received, peer: {service_id:?}, message_handle: {message_handle:?}, accepted: {accepted}");
                            let message_id: tego_message_id = message_handle.into();
                            self.callback_queue.push(CallbackData::MessageAcknowledged {
                                service_id,
                                message_id,
                                accepted,
                            });
                        }
                        Ok(Event::FileTransferRequestReceived {
                            service_id,
                            file_transfer_handle,
                            file_name,
                            file_size,
                        }) => {
                            println!("--- file transfer request received, peer: {service_id:?}, file_transfer_handle: {file_transfer_handle:?}, file_name: {file_name}, file_size: {file_size}");

                            // the protocol handler *shouldn't* be returning duplicate handles but we get them
                            // from the other party so really we have no control here :(
                            let file_transfer_id: tego_file_transfer_id =
                                file_transfer_handle.into();
                            if connection
                                .file_downloads
                                .contains_key(&file_transfer_handle)
                            {
                                // if we have a collision, just cancel the old one
                                self.callback_queue.push(CallbackData::FileTransferComplete{
                                    user_id: service_id.clone(),
                                    file_transfer_id,
                                    direction: tego_file_transfer_direction::tego_file_transfer_direction_receiving,
                                    result: tego_file_transfer_result::tego_file_transfer_result_cancelled
                                });
                            }

                            let file_download: FileDownload = FileDownload::new(file_size);
                            connection
                                .file_downloads
                                .insert(file_transfer_handle, file_download);

                            self.callback_queue
                                .push(CallbackData::FileTransferRequestReceived {
                                    sender: service_id,
                                    file_transfer_id,
                                    file_name,
                                    file_size,
                                });
                        }
                        Ok(Event::FileTransferRequestAcknowledgeReceived {
                            service_id,
                            file_transfer_handle,
                            accepted,
                        }) => {
                            println!("--- file transfer request ack received, peer: {service_id:?}, file_transfer_handle: {file_transfer_handle:?}, accepted: {accepted}");
                            self.callback_queue.push(
                                CallbackData::FileTransferRequestAcknowledged {
                                    service_id,
                                    file_transfer_id: file_transfer_handle.into(),
                                    accepted,
                                },
                            );
                        }
                        Ok(Event::FileTransferRequestAccepted {
                            service_id,
                            file_transfer_handle,
                        }) => {
                            println!("--- file transfer request accepted, peer: {service_id:?}, file_transfer_handle: {file_transfer_handle:?}");

                            let file_transfer_id: tego_file_transfer_id =
                                file_transfer_handle.into();

                            let file_upload = connection
                                .file_uploads
                                .get_mut(&file_transfer_handle)
                                .unwrap();

                            // begin sending chunks
                            let bytes_read = match file_upload.read(&mut self.file_read_buffer) {
                                Ok(bytes_read) => bytes_read,
                                Err(_) => todo!(),
                            };
                            let chunk_data: Vec<u8> = self.file_read_buffer[..bytes_read].to_vec();

                            self.packet_handler
                                .send_file_chunk(
                                    &service_id,
                                    file_transfer_handle,
                                    chunk_data,
                                    write_packets,
                                )
                                .unwrap();

                            // trigger callbacks
                            self.callback_queue
                                .push(CallbackData::FileTransferRequestResponseReceived {
                                service_id: service_id.clone(),
                                file_transfer_id,
                                response:
                                    tego_file_transfer_response::tego_file_transfer_response_accept,
                            });
                            self.callback_queue.push(CallbackData::FileTransferProgress{
                                user_id: service_id,
                                file_transfer_id,
                                direction: tego_file_transfer_direction::tego_file_transfer_direction_sending,
                                bytes_complete: file_upload.bytes_sent,
                                bytes_total: file_upload.size,
                            });

                            file_upload.bytes_sent += bytes_read as u64;
                        }
                        Ok(Event::FileTransferRequestRejected {
                            service_id,
                            file_transfer_handle,
                        }) => {
                            println!("--- file transfer request rejected, peer: {service_id:?}, file_transfer_handle: {file_transfer_handle:?}");

                            let file_transfer_id: tego_file_transfer_id =
                                file_transfer_handle.into();
                            self.callback_queue
                                .push(CallbackData::FileTransferRequestResponseReceived {
                                service_id,
                                file_transfer_id,
                                response:
                                    tego_file_transfer_response::tego_file_transfer_response_reject,
                            });
                        }
                        Ok(Event::FileChunkReceived {
                            service_id,
                            file_transfer_handle,
                            data,
                            last_chunk,
                            hash_matches,
                        }) => {
                            println!("--- file chunk received, peer: {service_id:?}, file_transfer_handle: {file_transfer_handle:?}, data: [u8; {}], last_chunk: {last_chunk}, hash_matches: {hash_matches:?}", data.len());

                            let file_transfer_id: tego_file_transfer_id =
                                file_transfer_handle.into();

                            // these two last_chunk checks get us a Option<FileDownload&>
                            // in both cases where we need to remove it and where we need to modify
                            // it in-place
                            let mut file_download = if last_chunk {
                                connection.file_downloads.remove(&file_transfer_handle)
                            } else {
                                None
                            };
                            let file_download = if last_chunk {
                                file_download.as_mut()
                            } else {
                                connection.file_downloads.get_mut(&file_transfer_handle)
                            };
                            let file_download = file_download.unwrap();

                            // write chunk to disk
                            match file_download.write(&data) {
                                Ok(()) => {
                                    self.callback_queue.push(CallbackData::FileTransferProgress{
                                        user_id: service_id.clone(),
                                        file_transfer_id,
                                        direction: tego_file_transfer_direction::tego_file_transfer_direction_receiving,
                                        bytes_complete: file_download.bytes_written,
                                        bytes_total: file_download.expected_size,
                                    });
                                }
                                Err(_) => {
                                    self.callback_queue.push(CallbackData::FileTransferComplete{
                                        user_id: service_id,
                                        file_transfer_id,
                                        direction: tego_file_transfer_direction::tego_file_transfer_direction_receiving,
                                        result: tego_file_transfer_result::tego_file_transfer_result_filesystem_error,
                                    });
                                    continue 'packet_handle;
                                }
                            }

                            // handle completed download
                            match (last_chunk, hash_matches) {
                                // download complete, hashes match
                                (true, Some(true)) => {
                                    let result = match file_download.finalize() {
                                        Ok(()) => tego_file_transfer_result::tego_file_transfer_result_success,
                                        Err(_) => tego_file_transfer_result::tego_file_transfer_result_filesystem_error,
                                    };

                                    self.callback_queue.push(CallbackData::FileTransferComplete{
                                        user_id: service_id,
                                        file_transfer_id,
                                        direction: tego_file_transfer_direction::tego_file_transfer_direction_receiving,
                                        result,
                                    });
                                }
                                // download complete, hashes do not match
                                (true, Some(false)) => {
                                    self.callback_queue.push(CallbackData::FileTransferComplete{
                                        user_id: service_id,
                                        file_transfer_id,
                                        direction: tego_file_transfer_direction::tego_file_transfer_direction_receiving,
                                        result: tego_file_transfer_result::tego_file_transfer_result_bad_hash,
                                    });
                                }
                                // download not complete, no hash to check
                                (false, None) => (),
                                // remaining states are not possible
                                _ => unreachable!(),
                            }
                        }
                        Ok(Event::FileChunkAckReceived {
                            service_id,
                            file_transfer_handle,
                            offset,
                        }) => {
                            println!("--- file chunk ack received, peer: {service_id:?}, file_transfer_handle: {file_transfer_handle:?}, offset: {offset}");

                            let file_transfer_id: tego_file_transfer_id =
                                file_transfer_handle.into();
                            let file_upload = connection
                                .file_uploads
                                .get_mut(&file_transfer_handle)
                                .unwrap();

                            self.callback_queue.push(CallbackData::FileTransferProgress{
                                user_id: service_id.clone(),
                                file_transfer_id,
                                direction: tego_file_transfer_direction::tego_file_transfer_direction_sending,
                                bytes_complete: file_upload.bytes_sent,
                                bytes_total: file_upload.size,
                            });

                            // todo: better error handling
                            assert_eq!(file_upload.bytes_sent, offset);

                            if file_upload.bytes_sent < file_upload.size {
                                // send next chunk if there is more data to sesnd
                                let bytes_read = match file_upload.read(&mut self.file_read_buffer)
                                {
                                    Ok(bytes_read) => bytes_read,
                                    Err(_) => todo!(),
                                };
                                let chunk_data: Vec<u8> =
                                    self.file_read_buffer[..bytes_read].to_vec();

                                self.packet_handler
                                    .send_file_chunk(
                                        &service_id,
                                        file_transfer_handle,
                                        chunk_data,
                                        write_packets,
                                    )
                                    .unwrap();

                                file_upload.bytes_sent += bytes_read as u64;
                            }
                        }
                        Ok(Event::FileTransferSucceeded {
                            service_id,
                            file_transfer_handle,
                        }) => {
                            println!("--- file transfer succeeded, peer: {service_id}, file_transfer_handle: {file_transfer_handle:?}");

                            let file_transfer_id: tego_file_transfer_id =
                                file_transfer_handle.into();
                            self.callback_queue.push(CallbackData::FileTransferComplete{
                                user_id: service_id,
                                file_transfer_id,
                                direction: tego_file_transfer_direction::tego_file_transfer_direction_sending,
                                result: tego_file_transfer_result::tego_file_transfer_result_success
                            });
                        }
                        Ok(Event::FileTransferFailed {
                            service_id,
                            file_transfer_handle,
                        }) => {
                            println!("--- file transfer failed, peer: {service_id}, file_transfer_handle: {file_transfer_handle:?}");

                            let file_transfer_id: tego_file_transfer_id =
                                file_transfer_handle.into();
                            self.callback_queue.push(CallbackData::FileTransferComplete{
                                user_id: service_id,
                                file_transfer_id,
                                direction: tego_file_transfer_direction::tego_file_transfer_direction_sending,
                                result: tego_file_transfer_result::tego_file_transfer_result_failure
                            });
                        }
                        Ok(Event::FileTransferCancelled {
                            service_id,
                            file_transfer_handle,
                        }) => {
                            println!("--- file transfer cancelled, peer: {service_id}, file_transfer_handle: {file_transfer_handle:?}");

                            let file_transfer_id: tego_file_transfer_id =
                                file_transfer_handle.into();
                            self.callback_queue.push(CallbackData::FileTransferComplete{
                                user_id: service_id,
                                file_transfer_id,
                                direction: tego_file_transfer_direction::tego_file_transfer_direction_sending,
                                result: tego_file_transfer_result::tego_file_transfer_result_cancelled
                            });
                        }
                        Ok(Event::ChannelClosed { id }) => {
                            println!("--- channel closed: {id} ---");
                        }
                        // errors
                        Ok(Event::ProtocolFailure { message }) => {
                            println!("--- non-fatal protocol failure: {message} ---");
                        }
                        Ok(Event::FatalProtocolFailure) => {
                            println!("--- fatal protocol error, removing connection ---");
                            connection.remove = true;
                            break 'packet_handle;
                        }
                        Err(err) => panic!("error: {err:?}"),
                    }
                }
            }

            // write packets to stream
            if !write_packets.is_empty() {
                // serialise out packets to bytes
                let mut write_bytes: Vec<u8> = Default::default();
                for packet in write_packets.drain(..) {
                    println!(">> write packet: {packet:?}");
                    packet
                        .write_to_vec(&mut write_bytes)
                        .expect("packet write failed");
                }

                // send bytes
                let stream = &mut connection.stream;
                if stream.write(write_bytes.as_slice()).is_err() {
                    connection.remove = true;
                    if let Some(_service_id) = &connection.service_id {
                        // todo: only retry known +  pending contacts
                        // to_retry.insert(service_id.clone());
                    }
                }
            }

            // handle connection flagged for removal
            if connection.remove {
                to_remove.insert(handle);
            }
        }

        // drop our dead connections
        for &handle in to_remove.iter() {
            self.packet_handler.remove_connection(&handle);
            let connection = self
                .connections
                .remove(&handle)
                .expect("removed non-existing connection");
            // signal user ofline status to frontend
            if let Some(service_id) = connection.service_id {
                println!("--- dropping connection; handle: {handle}, service_id: {service_id}");
                // signal user offline status if there is not another connection
                // todo: only signal for allowed users
                if !self.packet_handler.has_verified_connection(&service_id) {
                    use crate::ffi::tego_user_status::tego_user_status_offline;
                    let status = tego_user_status_offline;
                    self.callback_queue
                        .push(CallbackData::UserStatusChanged { service_id, status });
                }
            } else {
                println!("--- dropping connection; handle: {handle}");
            }
        }

        // initiate connection retries for connections which had IO failures
        for service_id in to_retry.iter() {
            // todo: check if user is allowed or pending or requesting
            let service_id = service_id.clone();

            let command_data = CommandData::ConnectContact {
                service_id,
                failure_count: 0,
                contact_request_message: None,
            };

            self.command_queue
                .push(command_data, Duration::from_secs(0));
        }

        Ok(())
    }

    fn handle_callbacks(&mut self) -> Result<()> {
        let context = self.context as *mut tego_context;

        let callbacks = self.callbacks.upgrade().context("callbacks dropped")?;
        let callbacks = callbacks.lock().expect("callbacks mutex poisoned");

        for cd in self.callback_queue.drain(..) {
            match cd {
                CallbackData::TorNetworkStatusChanged { status } => {
                    if let Some(on_tor_network_status_changed) =
                        callbacks.on_tor_network_status_changed
                    {
                        println!("-- invoke on_tor_network_status_changed");
                        on_tor_network_status_changed(context, status);
                    }
                }
                CallbackData::TorBootstrapStatusChanged { progress, tag } => {
                    if let Some(on_tor_bootstrap_status_changed) =
                        callbacks.on_tor_bootstrap_status_changed
                    {
                        println!("-- invoke on_tor_bootstrap_status_changed");
                        on_tor_bootstrap_status_changed(
                            context,
                            progress as i32,
                            tag.as_str().into(),
                        );
                    }
                }
                CallbackData::TorLogReceived { line } => {
                    if let Some(on_tor_log_received) = callbacks.on_tor_log_received {
                        println!("-- invoke on_tor_log_received");
                        let line = CString::new(line.as_str()).unwrap();
                        let line_len = line.as_bytes().len();
                        on_tor_log_received(context, line.as_c_str().as_ptr(), line_len);
                    }
                }
                CallbackData::HostOnionServiceStateChanged { state } => {
                    if let Some(on_host_onion_service_state_changed) =
                        callbacks.on_host_onion_service_state_changed
                    {
                        println!("-- invoke on_host_onion_service_state_changed");
                        on_host_onion_service_state_changed(context, state);
                    }
                }
                CallbackData::ChatRequestReceived {
                    service_id,
                    message,
                } => {
                    if let Some(on_chat_request_received) = callbacks.on_chat_request_received {
                        println!("-- invoke on_chat_request_received");
                        let sender =
                            get_object_map().insert(TegoObject::UserId(UserId { service_id }));
                        let message = CString::new(message.as_str()).unwrap();
                        let message_len = message.as_bytes().len();
                        on_chat_request_received(
                            context,
                            sender as *const tego_user_id,
                            message.as_c_str().as_ptr(),
                            message_len,
                        );
                        get_object_map().remove(&sender);
                    }
                }
                CallbackData::ChatRequestResponseReceived {
                    service_id,
                    accepted_request,
                } => {
                    if let Some(on_chat_request_response_received) =
                        callbacks.on_chat_request_response_received
                    {
                        println!("-- invoke on_chat_request_response_received");
                        let sender =
                            get_object_map().insert(TegoObject::UserId(UserId { service_id }));
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
                }
                CallbackData::UserStatusChanged { service_id, status } => {
                    if let Some(on_user_status_changed) = callbacks.on_user_status_changed {
                        println!("-- invoke on_user_status_changed");
                        let user =
                            get_object_map().insert(TegoObject::UserId(UserId { service_id }));
                        on_user_status_changed(context, user as *const tego_user_id, status);
                        get_object_map().remove(&user);
                    }
                }
                CallbackData::MessageReceived {
                    service_id,
                    timestamp,
                    message_id,
                    message,
                } => {
                    if let Some(on_message_received) = callbacks.on_message_received {
                        println!("-- invoke on_message_received");
                        let user =
                            get_object_map().insert(TegoObject::UserId(UserId { service_id }));
                        let timestamp = timestamp.duration_since(std::time::UNIX_EPOCH).unwrap();
                        let timestamp = timestamp.as_millis() as tego_time;
                        assert!(timestamp > 0);

                        let message = CString::new(message.as_str()).unwrap();
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
                }
                CallbackData::MessageAcknowledged {
                    service_id,
                    message_id,
                    accepted,
                } => {
                    if let Some(on_message_acknowledged) = callbacks.on_message_acknowledged {
                        println!("-- invoke on_message_acknowledged");
                        let user =
                            get_object_map().insert(TegoObject::UserId(UserId { service_id }));
                        let accepted = if accepted { TEGO_TRUE } else { TEGO_FALSE };
                        on_message_acknowledged(
                            context,
                            user as *const tego_user_id,
                            message_id,
                            accepted,
                        );
                        get_object_map().remove(&user);
                    }
                }
                CallbackData::FileTransferRequestReceived {
                    sender,
                    file_transfer_id,
                    file_name,
                    file_size,
                } => {
                    if let Some(on_file_transfer_request_received) =
                        callbacks.on_file_transfer_request_received
                    {
                        println!("-- invoke on_file_transfer_request_received");

                        let sender = get_object_map()
                            .insert(TegoObject::UserId(UserId { service_id: sender }));
                        let file_name = CString::new(file_name.as_str()).unwrap();
                        let file_name_length = file_name.as_bytes().len();

                        on_file_transfer_request_received(
                            context,
                            sender as *const tego_user_id,
                            file_transfer_id,
                            file_name.as_c_str().as_ptr(),
                            file_name_length,
                            file_size,
                        );

                        get_object_map().remove(&sender);
                    }
                }
                CallbackData::FileTransferRequestAcknowledged {
                    service_id,
                    file_transfer_id,
                    accepted,
                } => {
                    if let Some(on_file_transfer_request_acknowledged) =
                        callbacks.on_file_transfer_request_acknowledged
                    {
                        println!("-- invoke on_file_transfer_request_acknowledged");
                        let user =
                            get_object_map().insert(TegoObject::UserId(UserId { service_id }));
                        let accepted = if accepted { TEGO_TRUE } else { TEGO_FALSE };
                        on_file_transfer_request_acknowledged(
                            context,
                            user as *const tego_user_id,
                            file_transfer_id,
                            accepted,
                        );
                        get_object_map().remove(&user);
                    }
                }
                CallbackData::FileTransferRequestResponseReceived {
                    service_id,
                    file_transfer_id,
                    response,
                } => {
                    if let Some(on_file_transfer_request_response_received) =
                        callbacks.on_file_transfer_request_response_received
                    {
                        println!("-- invoke on_file_transfer_request_response_received");
                        let user =
                            get_object_map().insert(TegoObject::UserId(UserId { service_id }));

                        on_file_transfer_request_response_received(
                            context,
                            user as *const tego_user_id,
                            file_transfer_id,
                            response,
                        );
                        get_object_map().remove(&user);
                    }
                }
                CallbackData::FileTransferProgress {
                    user_id,
                    file_transfer_id,
                    direction,
                    bytes_complete,
                    bytes_total,
                } => {
                    if let Some(on_file_transfer_progress) = callbacks.on_file_transfer_progress {
                        println!("-- invoke on_file_transfer_progress");
                        let user_id = get_object_map().insert(TegoObject::UserId(UserId {
                            service_id: user_id,
                        }));

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
                }
                CallbackData::FileTransferComplete {
                    user_id,
                    file_transfer_id,
                    direction,
                    result,
                } => {
                    if let Some(on_file_transfer_complete) = callbacks.on_file_transfer_complete {
                        println!("-- invoke on_file_transfer_complete");
                        let user_id = get_object_map().insert(TegoObject::UserId(UserId {
                            service_id: user_id,
                        }));

                        on_file_transfer_complete(
                            context,
                            user_id as *const tego_user_id,
                            file_transfer_id,
                            direction,
                            result,
                        );

                        get_object_map().remove(&user_id);
                    }
                }
                _ => panic!("not implemented"),
            }
        }
        Ok(())
    }
}

struct ListenerTask {
    listener: OnionListener,
    command_queue: CommandQueue,
}

impl ListenerTask {
    fn run(self) -> Result<()> {
        // todo: try to open a new listener in the event of failure
        let listener = self.listener;
        let command_queue = self.command_queue;

        listener.set_nonblocking(false)?;
        while let Ok(stream) = listener.accept() {
            if let Some(stream) = stream {
                stream.set_nonblocking(true)?;
                println!("stream: {stream:?}");
                command_queue.push(CommandData::BeginServerHandshake { stream }, Duration::ZERO);
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
struct PendingConnection {
    pub service_id: V3OnionServiceId,
    pub failure_count: usize,
    pub message_text: Option<rico_protocol::v3::message::contact_request_channel::MessageText>,
}

#[derive(Debug)]
struct Connection {
    pub service_id: Option<V3OnionServiceId>,
    pub stream: OnionStream,
    // buffer of unhandled read bytes
    pub read_bytes: Vec<u8>,
    // buffer of read Packets to handle
    pub read_packets: Vec<Packet>,
    // buffer of packets to write
    pub write_packets: Vec<Packet>,
    // todo: maybe these should also just be a single FileTransfer
    // pending and in-progress file downloads
    pub file_downloads:
        BTreeMap<rico_protocol::v3::packet_handler::FileTransferHandle, FileDownload>,
    // pending and in-process file uploads
    pub file_uploads: BTreeMap<rico_protocol::v3::packet_handler::FileTransferHandle, FileUpload>,
    // whether this connection should be removed after sending queued packets
    pub remove: bool,
}

#[derive(Debug)]
struct FileDownload {
    // number of bytes written
    bytes_written: u64,
    // total expected file-size
    expected_size: u64,
    // final destination for the in-progress file transfer
    final_destination: PathBuf,
    // the temporary destination we will write the file to before renaming
    temp_destination: PathBuf,
    // destination to write the received data
    file: Option<File>,
}

impl FileDownload {
    pub fn new(expected_size: u64) -> Self {
        Self {
            bytes_written: 0u64,
            expected_size,
            final_destination: Default::default(),
            temp_destination: Default::default(),
            file: None,
        }
    }

    // start the download
    pub fn start(&mut self, final_destination: PathBuf) -> Result<()> {
        bail_if!(!final_destination.is_absolute());

        // create a temporary file location of the form ".filename.part"
        let mut temp_destination_filename = OsString::from(".");
        temp_destination_filename.push(
            final_destination
                .file_name()
                .context("final_destination has no filename")?,
        );
        temp_destination_filename.push(".part");

        let mut temp_destination = final_destination.clone();
        bail_if!(!temp_destination.pop());
        temp_destination.push(temp_destination_filename);

        // create our file
        let file = Some(File::create(&temp_destination)?);

        self.final_destination = final_destination;
        self.temp_destination = temp_destination;
        self.file = file;

        Ok(())
    }

    // returns true when we're done writing, false if we need more bytes
    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        let file = self.file.as_mut().context("file is None")?;
        file.write_all(bytes)?;
        self.bytes_written += bytes.len() as u64;

        Ok(())
    }

    pub fn finalize(&mut self) -> Result<()> {
        // close the temporary file
        self.file = None;

        // move temp file to final destination
        std::fs::rename(&self.temp_destination, &self.final_destination)?;

        Ok(())
    }
}

#[derive(Debug)]
struct FileUpload {
    file: File,
    // the numebr of bytes we have uploaded
    bytes_sent: u64,
    // the size of the file
    size: u64,
    // the hash of the file
    hash: rico_protocol::v3::file_hasher::FileHash,
}

impl FileUpload {
    pub fn new(file_path: PathBuf) -> Result<Self> {
        // open file for reading
        let mut file = std::fs::OpenOptions::new().read(true).open(file_path)?;

        let bytes_sent = 0u64;

        // get our file's size
        let size = file.metadata()?.len();

        // calculate the file's hash
        let mut hasher: FileHasher = Default::default();
        const HASH_BUFFER_SIZE: usize = 64usize * 1024usize;
        let mut buffer = [0u8; HASH_BUFFER_SIZE];

        let mut bytes_read = 0u64;
        while bytes_read != size {
            let n = file.read(&mut buffer)?;
            hasher.update(&buffer[..n]);
            bytes_read += n as u64;
        }
        let hash = hasher.finalize();

        // reset the file read stream to beginning
        file.rewind()?;

        Ok(Self {
            file,
            bytes_sent,
            size,
            hash,
        })
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.file.read(buf)?)
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn hash(&self) -> rico_protocol::v3::file_hasher::FileHash {
        self.hash
    }
}

// todo: remove unused callbacks
#[allow(dead_code)]
enum CallbackData {
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
    pub on_file_transfer_request_response_received:
        tego_file_transfer_request_response_received_callback,
    pub on_file_transfer_progress: tego_file_transfer_progress_callback,
    pub on_file_transfer_complete: tego_file_transfer_complete_callback,
    pub on_user_status_changed: tego_user_status_changed_callback,
    pub on_new_identity_created: tego_new_identity_created_callback,
}
