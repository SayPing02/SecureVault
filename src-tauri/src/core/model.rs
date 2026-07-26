// Data models for fragments, vault entries, and the manifest
// These all need Serialize/Deserialize because they get saved as JSON

use serde::{Deserialize, Serialize};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
<<<<<<< HEAD

pub const FRAGMENT_FORMAT_VERSION: &str = "2.0";

=======
use std::collections::HashMap;

pub const FRAGMENT_FORMAT_VERSION: &str = "2.0";

fn default_cipher()  -> String { "aes256gcm".to_string() }
fn default_kdf()     -> String { "standard".to_string() }
fn default_padding() -> u8    { 0 }

>>>>>>> origin/felix
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
<<<<<<< HEAD
    pub salt_b64: String,  // salt, only used if password_protected
    pub share_x: u8,
    pub share_y_b64: String,
    pub nonce_b64: String,
    pub checksum: String, // sha256 of the original file
    pub ciphertext_b64: String, // the entire encrypted file
=======
    #[serde(default)]
    pub compressed: bool,
    pub salt_b64: String,
    pub share_x: u8,
    pub share_y_b64: String,
    pub nonce_b64: String,
    pub checksum: String,
    pub ciphertext_b64: String,
    // User-chosen cipher: "aes256gcm" (default) or "chacha20"
    // #[serde(default)] keeps old fragments readable (they used AES-256-GCM)
    #[serde(default = "default_cipher")]
    pub cipher: String,
    // KDF preset used for password wrapping: "fast"/"standard"/"strong"/"argon2id"
    #[serde(default = "default_kdf")]
    pub kdf: String,
    // Random padding added before encrypt to obscure true file size (0–100 %)
    #[serde(default = "default_padding")]
    pub padding_pct: u8,
>>>>>>> origin/felix
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
<<<<<<< HEAD
=======
    #[serde(default)]
    pub compress: bool,
    #[serde(default = "default_cipher")]
    pub cipher: String,  // "aes256gcm" | "chacha20"
    #[serde(default = "default_kdf")]
    pub kdf: String,     // "fast" | "standard" | "strong" | "argon2id"
    #[serde(default)]
    pub padding_pct: u8, // 0 = none, 10/25/50 = % of file size added as random noise
>>>>>>> origin/felix
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
<<<<<<< HEAD
=======
    #[serde(default)]
    pub is_large: bool,  // true → stored as RS shards (.svf3), false → legacy .svf.enc
    // User-assigned notes on where each fragment/shard was sent (e.g. index 1
    // -> "Mom's laptop"), purely informational — never affects reconstruction.
    #[serde(default)]
    pub fragment_labels: HashMap<u8, String>,
    // Kept at the top of "My Files" — purely a display preference.
    #[serde(default)]
    pub pinned: bool,
    // Unix seconds of the last rotation (fresh Shamir polynomial + fresh
    // fragments), or the same as created_at if never rotated. 0 for entries
    // saved before this field existed — treat that as "use created_at" when
    // computing staleness, rather than as an actual timestamp.
    #[serde(default)]
    pub last_rotated_at: u64,
>>>>>>> origin/felix
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
<<<<<<< HEAD
=======

// A single line in the activity log — "added / downloaded / shared / deleted
// / reconstructed <filename> at <timestamp>". Purely a local history for the
// user's own reference, same as fragment labels; never read by any
// crypto/reconstruction path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEntry {
    pub timestamp: u64,
    pub action: String, // "added" | "downloaded" | "shared" | "deleted" | "reconstructed"
    pub filename: String,
}

// Saved as activity_log.json (encrypted) in the vault folder, same as the manifest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActivityLog {
    pub entries: Vec<ActivityEntry>,
}

impl ActivityLog {
    // Newest first; capped so the log can't grow forever.
    pub const MAX_ENTRIES: usize = 200;

    pub fn record(&mut self, action: impl Into<String>, filename: impl Into<String>, timestamp: u64) {
        self.entries.insert(0, ActivityEntry {
            timestamp,
            action: action.into(),
            filename: filename.into(),
        });
        self.entries.truncate(Self::MAX_ENTRIES);
    }
}
>>>>>>> origin/felix
