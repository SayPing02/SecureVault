// Data models for fragments, vault entries, and the manifest
// These all need Serialize/Deserialize because they get saved as JSON

use serde::{Deserialize, Serialize};

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
    pub salt_b64: String,  // PBKDF2 salt, only if password protected
    pub share_x: u8,
    pub share_y_b64: String,
    pub nonce_b64: String,
    pub checksum: String, // sha256 of the original file
    pub ciphertext_b64: String, // the entire encrypted file
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
