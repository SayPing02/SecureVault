// Data models for fragments, vault entries, and the manifest
// These all need Serialize/Deserialize because they get saved as JSON

use serde::{Deserialize, Serialize};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

pub const FRAGMENT_FORMAT_VERSION: &str = "2.0";

// A single .svf fragment file
// Contains one shamir share of the AES key + a copy of the encrypted file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fragment {
    pub version: String,
    pub file_id: String,
    pub index: u8,
    pub total: u8,      // n in k-of-n
    pub threshold: u8,  // k in k-of-n
    pub original_filename: String,
    pub original_size: u64,
    pub password_protected: bool,
    pub salt_b64: String,  // salt, only used if password_protected
    pub share_x: u8,
    pub share_y_b64: String,
    pub nonce_b64: String,
    pub checksum: String, // sha256 of the original file
    pub ciphertext_b64: String, // the entire encrypted file
}

impl Fragment {
    // encode fragment into opaque .svf format (not human readable)
    // the entire JSON is base64 encoded so opening the file shows gibberish
    pub fn to_opaque_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let json = serde_json::to_vec(self)?;
        let encoded = B64.encode(&json);
        Ok(encoded.into_bytes())
    }

    // decode a fragment from the opaque .svf format
    pub fn from_opaque_bytes(data: &[u8]) -> Result<Self, String> {
        // try to decode as base64 first (opaque format)
        let data_str = std::str::from_utf8(data)
            .map_err(|e| format!("invalid fragment file: {e}"))?;

        let json_bytes = B64.decode(data_str.trim())
            .map_err(|e| format!("could not decode fragment: {e}"))?;

        serde_json::from_slice(&json_bytes)
            .map_err(|e| format!("could not parse fragment: {e}"))
    }
}

// What the user picks on the split screen
#[derive(Debug, Clone, Deserialize)]
pub struct SplitParams {
    pub total_fragments: u8,
    pub threshold: u8,
    pub password: Option<String>,
}

// One entry in the vault list (metadata only, no key material)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub file_id: String,
    pub filename: String,
    pub size: u64,
    pub total_fragments: u8,
    pub threshold: u8,
    pub password_protected: bool,
    pub created_at: u64,
}

// The manifest stores all vault entries
// Saved as manifest.json (encrypted) in the vault folder
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub entries: Vec<VaultEntry>,
}

impl Manifest {
    // add or update an entry
    pub fn upsert(&mut self, entry: VaultEntry) {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.file_id == entry.file_id)
        {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }

    // remove an entry, returns true if something was actually removed
    pub fn remove(&mut self, file_id: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.file_id != file_id);
        self.entries.len() != before
    }
}
