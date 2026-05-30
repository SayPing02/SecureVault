// Request/response types for the tauri commands
// Fields are camelCase on the JS side

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitRequest {
    pub file_path: String,
    pub total_fragments: u8,
    pub threshold: u8,
    pub password: Option<String>,
}

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
