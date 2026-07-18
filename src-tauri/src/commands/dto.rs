// Request/response types for the tauri commands
// Fields are camelCase on the JS side

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitRequest {
    pub file_path: String,
    // User-editable display name to store the file under — defaults to the
    // source file's own name when absent/blank.
    #[serde(default)]
    pub filename: Option<String>,
    pub total_fragments: u8,
    pub threshold: u8,
    pub password: Option<String>,
    #[serde(default)]
    pub compress: bool,
    #[serde(default = "default_cipher")]
    pub cipher: String,
    #[serde(default = "default_kdf")]
    pub kdf: String,
    #[serde(default)]
    pub padding_pct: u8,
}

fn default_cipher() -> String { "aes256gcm".to_string() }
fn default_kdf()    -> String { "standard".to_string() }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultFileDto {
    pub file_id: String,
    pub filename: String,
    pub size: u64,
    pub total_fragments: u8,
    pub threshold: u8,
    pub password_protected: bool,
    pub created_at: u64,
    pub is_large: bool,
    pub fragment_labels: HashMap<u8, String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationResult {
    pub success: bool,
    pub message: String,
    pub output_path: Option<String>,
}

impl OperationResult {
    pub fn ok(message: impl Into<String>, path: Option<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            output_path: path,
        }
    }
}
