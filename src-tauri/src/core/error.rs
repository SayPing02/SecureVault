// Error types for the core modules
// Using thiserror to avoid writing Display/Error boilerplate manually

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("shamir error: {0}")]
    Shamir(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("invalid fragment: {0}")]
    InvalidFragment(String),

    #[error("integrity check failed: the file may be corrupted")]
    ChecksumMismatch,

    #[error("operation cancelled")]
    Cancelled,

    #[error("storage error: {0}")]
    Storage(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("archive error: {0}")]
    Archive(String),
}

pub type CoreResult<T> = Result<T, CoreError>;

// Need this so tauri commands can return our errors as strings
impl From<CoreError> for String {
    fn from(err: CoreError) -> Self {
        err.to_string()
    }
}
