// std
use std::time::Duration;

// extern
use anyhow::Result;
use tor_interface::tor_provider::OnionListener;

// internal
use crate::command_queue::*;
use crate::macros::*;

pub(crate) struct ListenerTask {
    listener: OnionListener,
    command_queue: CommandQueue,
}

impl ListenerTask {
    pub fn new(listener: OnionListener, command_queue: CommandQueue) -> Self {
        Self {
            listener,
            command_queue,
        }
    }

    pub fn run(self) -> Result<()> {
        // todo: try to open a new listener in the event of failure
        let listener = self.listener;
        let command_queue = self.command_queue;

        listener.set_nonblocking(false)?;
        while let Ok(stream) = listener.accept() {
            if let Some(stream) = stream {
                stream.set_nonblocking(true)?;
                log_info!("new stream accepted: {stream:?}");
                command_queue.push(CommandData::BeginServerHandshake { stream }, Duration::ZERO);
            }
        }

        Ok(())
    }
}
