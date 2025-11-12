// standard
use std::convert::TryFrom;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

// extern
use time::UtcDateTime;

const LOG_LEVEL_NONE: u32 = 0u32;
const LOG_LEVEL_ERROR: u32 = 1u32;
const LOG_LEVEL_INFO: u32 = 2u32;
const LOG_LEVEL_TRACE: u32 = 4u32;
const LOG_LEVEL_PACKET: u32 = 8u32;
const LOG_LEVEL_ALL: u32 = u32::MAX;

#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub(crate) enum LogLevel {
    None,
    Error,
    Info,
    Trace,
    Packet,
    All,
}

impl TryFrom<&str> for LogLevel {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, <Self as TryFrom<&str>>::Error> {
        Ok(match value {
            "None" => LogLevel::None,
            "Error" => LogLevel::Error,
            "Info" => LogLevel::Info,
            "Trace" => LogLevel::Trace,
            "Packet" => LogLevel::Packet,
            "All" => LogLevel::All,

            value => anyhow::bail!("{value} is not a valid LogLevel"),
        })
    }
}

impl From<LogLevel> for u32 {
    fn from(value: LogLevel) -> u32 {
        match value {
            LogLevel::None => LOG_LEVEL_NONE,
            LogLevel::Error => LOG_LEVEL_ERROR,
            LogLevel::Info => LOG_LEVEL_INFO,
            LogLevel::Trace => LOG_LEVEL_TRACE,
            LogLevel::Packet => LOG_LEVEL_PACKET,
            LogLevel::All => LOG_LEVEL_ALL,
        }
    }
}

struct Message {
    log_level: u32,
    timestamp: UtcDateTime,
    text: String,
}

pub(crate) struct Logger {
    queue: Arc<(Mutex<Vec<Message>>, Condvar)>,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();
fn init_logger() -> Logger {
    Logger::new()
}

impl Logger {
    fn new() -> Self {
        let logger = Self {
            queue: Default::default(),
        };

        // get log level from env variable
        let log_level: u32 = {
            match std::env::var("RICOCHET_REFRESH_LOG_LEVEL") {
                Ok(val) => val
                    .split(",")
                    .map(|val| {
                        LogLevel::try_from(val.trim())
                            .unwrap_or(LogLevel::None)
                            .into()
                    })
                    .fold(0u32, |acc, x: u32| acc | x),
                _ => LogLevel::Error.into(),
            }
        };

        // create logging thread
        let queue = Arc::downgrade(&logger.queue);
        let _ = std::thread::Builder::new()
            .name("logging-thread".to_string())
            .spawn(move || {
                let mut local_queue: Vec<Message> = Default::default();
                let format = time::macros::format_description!(
                    "[year]-[month]-[day] [hour]:[minute]:[second]"
                );
                let mut stderr = std::io::stderr();
                let mut stdout = std::io::stdout();

                while let Some(queue) = queue.upgrade() {
                    {
                        let (queue, cvar) = &*queue;
                        let queue = queue.lock().expect("LOGGER queue mutex poisoned");
                        let mut queue = if queue.is_empty() {
                            // wait for a message to get added
                            cvar.wait(queue).unwrap()
                        } else {
                            // handle messages
                            queue
                        };
                        // take the queued messages and re-lock the shared
                        // queue
                        std::mem::swap(&mut *queue, &mut local_queue);
                    }

                    // print all our messages
                    for msg in local_queue.drain(..) {
                        if msg.log_level <= log_level {
                            let timestamp = msg.timestamp.format(&format).unwrap();
                            let text = msg.text;
                            match msg.log_level & log_level {
                                LOG_LEVEL_NONE => (),
                                LOG_LEVEL_ERROR => {
                                    let _ = writeln!(stderr, "[ERROR][{timestamp}] {text}");
                                }
                                LOG_LEVEL_INFO => {
                                    let _ = writeln!(stdout, "[INFO][{timestamp}] {text}");
                                }
                                LOG_LEVEL_TRACE => {
                                    let _ = writeln!(stdout, "[TRACE][{timestamp}] {text}");
                                }
                                LOG_LEVEL_PACKET => {
                                    let _ = writeln!(stdout, "[PACKET][{timestamp}] {text}");
                                }
                                _ => (),
                            }
                        }
                    }
                }
            });
        logger
    }

    pub fn log(log_level: LogLevel, text: String) {
        let message = Message {
            log_level: log_level.into(),
            timestamp: UtcDateTime::now(),
            text,
        };
        let logger = LOGGER.get_or_init(init_logger);
        let (queue, cvar) = &*logger.queue;
        let mut queue = queue.lock().expect("LOGGER queue mutex poisoned");
        // append message
        queue.push(message);
        // signal thread new message is available
        cvar.notify_one();
    }
}
