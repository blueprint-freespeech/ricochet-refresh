// standard
use std::path::PathBuf;

#[derive(Default)]
pub(crate) struct TorLaunchConfig {
    pub data_directory: PathBuf,
}
