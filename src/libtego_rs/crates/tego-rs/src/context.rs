// standard
use std::collections::BTreeMap;
use std::ffi::CString;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

// extern
use anyhow::{Context as AnyhowContext, Result};
use tor_interface::legacy_tor_client::LegacyTorClientConfig;
use tor_interface::legacy_tor_version::LegacyTorVersion;
use tor_interface::tor_crypto::{Ed25519PrivateKey, V3OnionServiceId};

// internal crates
use crate::callbacks::*;
use crate::command_queue::*;
use crate::event_loop_task::*;
use crate::ffi::*;
use crate::macros::*;
use crate::promise::Promise;

pub(crate) const RICOCHET_PORT: u16 = 9878u16;

#[derive(Default)]
pub(crate) struct Context {
    tego_key: TegoKey,
    // callback struct
    pub callbacks: Arc<Mutex<Callbacks>>,
    // tor runtime data
    tor_version_cstring: Option<CString>,
    // todo: arguably these should be accessed by a Command
    // as well though there would be more latency than acquire
    // lock
    tor_version: Arc<Mutex<Option<LegacyTorVersion>>>,
    tor_logs: Arc<Mutex<String>>,
    // flags
    connect_complete: Arc<AtomicBool>,
    // command queue
    command_queue: CommandQueue,
    // event loop thread handle
    event_loop_thread_handle: Option<std::thread::JoinHandle<()>>,
    // ricochet-refresh data
    private_key: Option<Ed25519PrivateKey>,
    users: BTreeMap<V3OnionServiceId, tego_user_type>,
}

impl Context {
    pub fn set_tego_key(&mut self, tego_key: TegoKey) {
        log_trace!();

        self.tego_key = tego_key;
    }

    pub fn tor_version_string(&mut self) -> Option<&CString> {
        log_trace!();

        if self.tor_version_cstring.is_none() {
            let tor_version = self.tor_version.lock().expect("tor_version mutex poisoned");
            if let Some(tor_version) = &*tor_version {
                let tor_version = tor_version.to_string();
                self.tor_version_cstring = Some(
                    CString::new(tor_version.replace("\0", ""))
                        .expect("tor_version conntains null-byte"),
                );
            }
        }
        self.tor_version_cstring.as_ref()
    }

    pub fn tor_logs_size(&self) -> usize {
        log_trace!();

        let tor_logs = self.tor_logs.lock().expect("tor_logs mutex poisoned");
        tor_logs.len() + 1usize
    }

    pub fn tor_logs(&self) -> String {
        log_trace!();

        let tor_logs = self.tor_logs.lock().expect("tor_logs mutex poisoned");
        tor_logs.clone()
    }

    pub fn host_service_id(&self) -> Option<V3OnionServiceId> {
        log_trace!();

        self.private_key
            .as_ref()
            .map(V3OnionServiceId::from_private_key)
    }

    pub fn begin(
        &mut self,
        tor_config: LegacyTorClientConfig,
        private_key: Ed25519PrivateKey,
        users: BTreeMap<V3OnionServiceId, tego_user_type>,
    ) -> Result<()> {
        log_trace!();

        self.private_key = Some(private_key.clone());
        let tego_key = self.tego_key;
        let callbacks = Arc::downgrade(&self.callbacks);
        let tor_version = Arc::downgrade(&self.tor_version);
        let tor_logs = Arc::downgrade(&self.tor_logs);

        let connect_complete = Arc::downgrade(&self.connect_complete);

        let command_queue = self.command_queue.downgrade();

        let task = EventLoopTask::new(
            tego_key,
            callbacks,
            tor_version,
            tor_logs,
            connect_complete,
            private_key,
            users,
            command_queue,
        );

        self.event_loop_thread_handle = Some(
            std::thread::Builder::new()
                .name("event-loop".to_string())
                .spawn(move || {
                    // start event loop
                    if let Err(_err) = task.run(tor_config) {
                        log_error!("{_err:?}");
                        panic!();
                    }
                })?,
        );

        Ok(())
    }

    pub fn end(&mut self) {
        log_trace!();

        if let Some(join_handle) = std::mem::take(&mut self.event_loop_thread_handle) {
            self.push_command(CommandData::EndEventLoop);
            let _ = join_handle.join();
        }

        self.tor_version_cstring = Default::default();
        self.tor_version = Default::default();
        self.tor_logs = Default::default();
        self.connect_complete = Default::default();
        self.command_queue = Default::default();
        self.event_loop_thread_handle = Default::default();
        self.private_key = Default::default();
        self.users = Default::default();
    }

    // todo: remove need for this
    pub fn connect_complete(&self) -> bool {
        log_trace!();

        self.connect_complete.load(Ordering::Relaxed)
    }

    fn push_command(&self, data: CommandData) {
        self.push_command_ex(data, Duration::ZERO);
    }

    fn push_command_ex(&self, data: CommandData, delay: Duration) {
        self.command_queue.push(data, delay);
    }

    pub fn forget_user(&mut self, service_id: V3OnionServiceId) -> Result<()> {
        log_trace!();

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
        log_trace!();

        let contact_request_message = Some(message);
        self.push_command(CommandData::ConnectContact {
            service_id,
            contact_request_message,
        });
    }

    pub fn acknowledge_contact_request(
        &self,
        service_id: V3OnionServiceId,
        response: tego_chat_acknowledge,
    ) {
        log_trace!();

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
        log_trace!();

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
        log_trace!();

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
        log_trace!();

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
        log_trace!();

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
        log_trace!();

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

    pub fn tor_bin_path() -> Result<PathBuf> {
        log_trace!();

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
        self.end();
    }
}
