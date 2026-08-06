// Vault storage layer
//
// Handles reading/writing fragment files and the manifest to disk.
// Everything written to the vault folder is encrypted with a key derived
// from a machine-local secret (app.secret file). This way even if someone
// finds the folder, the files look like random noise.
//
// Folder layout:
//   <app-data>/vault/
//     manifest.json.enc
//     <file_id>/
//       fragment_1.svf.enc
//       fragment_2.svf.enc
//       ...
//
// Thread-safety:
//   Fragment writes are fully concurrent — each file has a unique name so there
//   are no write conflicts. The manifest is protected by an internal Mutex so
//   concurrent load+save pairs are always atomic. Because all methods take &self,
//   Storage can be wrapped in Arc and shared across threads without an outer Mutex.

use crate::core::crypto;
use crate::core::error::{CoreError, CoreResult};
use crate::core::model::{ActivityLog, Fragment, Manifest};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const VAULT_DIR_NAME: &str = "vault";
const MANIFEST_NAME: &str = "manifest.json.enc";
const APP_SECRET_NAME: &str = "app.secret";
const ACTIVITY_LOG_NAME: &str = "activity_log.json.enc";

pub struct Storage {
    vault_dir: PathBuf,
    at_rest_key: [u8; crypto::KEY_LEN],
    // Serialises concurrent manifest read+write pairs; fragment writes need no lock.
    manifest_lock: Mutex<()>,
    // Same, for the activity log.
    activity_lock: Mutex<()>,
}

impl Storage {
    pub fn new(app_data_dir: &Path) -> CoreResult<Self> {
        let secret_path = app_data_dir.join(APP_SECRET_NAME);
        let app_secret = load_or_create_app_secret(&secret_path)?;
        Self::from_secret(app_data_dir, app_secret)
    }

    /// Same as `new`, but the secret is already known (e.g. just retrieved
    /// from the OS keychain via biometric auth) instead of being read from
    /// the plaintext `app.secret` file. Derives the exact same key for the
    /// exact same secret bytes, so switching between the two never requires
    /// re-encrypting anything already in the vault.
    pub fn from_secret(app_data_dir: &Path, mut secret: [u8; 32]) -> CoreResult<Self> {
        let vault_dir = app_data_dir.join(VAULT_DIR_NAME);
        fs::create_dir_all(&vault_dir)?;

        let mut secret_hex = hex(&secret);
        let at_rest_key =
            crypto::derive_key_from_password(&secret_hex, b"securevault-at-rest");
        secret.zeroize();
        secret_hex.zeroize();

        Ok(Self {
            vault_dir,
            at_rest_key,
            manifest_lock: Mutex::new(()),
            activity_lock: Mutex::new(()),
        })
    }

    pub fn load_manifest(&self) -> CoreResult<Manifest> {
        let _guard = self.manifest_lock.lock().unwrap_or_else(|e| e.into_inner());
        let path = self.vault_dir.join(MANIFEST_NAME);
        if !path.exists() {
            return Ok(Manifest::default());
        }
        let plaintext = self.read_encrypted(&path)?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    pub fn save_manifest(&self, manifest: &Manifest) -> CoreResult<()> {
        let _guard = self.manifest_lock.lock().unwrap_or_else(|e| e.into_inner());
        let path = self.vault_dir.join(MANIFEST_NAME);
        let json = serde_json::to_vec_pretty(manifest)?;
        self.write_encrypted(&path, &json)
    }

    pub fn load_activity_log(&self) -> CoreResult<ActivityLog> {
        let _guard = self.activity_lock.lock().unwrap_or_else(|e| e.into_inner());
        let path = self.vault_dir.join(ACTIVITY_LOG_NAME);
        if !path.exists() {
            return Ok(ActivityLog::default());
        }
        let plaintext = self.read_encrypted(&path)?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    pub fn save_activity_log(&self, log: &ActivityLog) -> CoreResult<()> {
        let _guard = self.activity_lock.lock().unwrap_or_else(|e| e.into_inner());
        let path = self.vault_dir.join(ACTIVITY_LOG_NAME);
        let json = serde_json::to_vec_pretty(log)?;
        self.write_encrypted(&path, &json)
    }

    /// Best-effort: append one line to the activity log. Never propagates a
    /// failure to the caller — a logging hiccup shouldn't fail the actual
    /// operation (add/download/share/delete) that triggered it.
    pub fn log_activity(&self, action: &str, filename: &str) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut log = match self.load_activity_log() {
            Ok(l) => l,
            Err(e) => {
                eprintln!("SecureVault: could not load activity log: {e}");
                return;
            }
        };
        log.record(action, filename, timestamp);
        if let Err(e) = self.save_activity_log(&log) {
            eprintln!("SecureVault: could not save activity log: {e}");
        }
    }

    // Each fragment file has a unique name so this is safe to call concurrently
    // from multiple threads for the same file_id.
    pub fn store_fragments(&self, file_id: &str, fragments: &[Fragment]) -> CoreResult<()> {
        let dir = self.vault_dir.join(file_id);
        fs::create_dir_all(&dir)?;

        for frag in fragments {
            let name = format!("fragment_{}.svf.enc", frag.index);
            let json = serde_json::to_vec(frag)?;
            self.write_encrypted(&dir.join(name), &json)?;
        }
        Ok(())
    }

    pub fn load_fragments(&self, file_id: &str) -> CoreResult<Vec<Fragment>> {
        self.load_fragments_limited(file_id, usize::MAX)
    }

    /// Load at most `limit` fragments for `file_id`, decrypting only as many
    /// as needed. Each fragment also carries a full copy of the file's
    /// ciphertext, so this matters: reading all N of them (as `load_fragments`
    /// does) costs N times the file size even when only `threshold` fragments'
    /// key-share data is actually needed, e.g. for a quick password check.
    pub fn load_fragments_limited(&self, file_id: &str, limit: usize) -> CoreResult<Vec<Fragment>> {
        let dir = self.vault_dir.join(file_id);
        if !dir.exists() {
            return Err(CoreError::Storage(format!("no fragments found for {file_id}")));
        }

        let mut fragments = Vec::new();
        for entry in fs::read_dir(&dir)? {
            if fragments.len() >= limit { break; }

            let path = entry?.path();
            let is_frag = path.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(".svf.enc"))
                .unwrap_or(false);
            if !is_frag { continue; }

            // A damaged fragment is skipped, not fatal. The whole point of a
            // K-of-N split is that losing some is survivable — aborting the
            // load here would make one corrupt file byte destroy a file that
            // still has more than `threshold` healthy fragments left.
            // Callers get however many are readable; `reconstruct_file`
            // already refuses clearly if that's fewer than the threshold, and
            // `check_vault_file_integrity` is what reports *which* are bad.
            let data = match self.read_encrypted(&path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!(
                        "SecureVault: skipping unreadable fragment {}: {e}",
                        path.display()
                    );
                    continue;
                }
            };
            let frag: Fragment = match serde_json::from_slice(&data) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!(
                        "SecureVault: skipping malformed fragment {}: {e}",
                        path.display()
                    );
                    continue;
                }
            };
            fragments.push(frag);
        }

        fragments.sort_by_key(|f| f.index);
        Ok(fragments)
    }

    /// Whether the stored fragment at `index` can still be read and
    /// decrypted intact. Fragments are written with authenticated encryption
    /// (`write_encrypted`), so any on-disk corruption or tampering makes
    /// decryption fail — this is a real check, not a placeholder. Doesn't
    /// parse the decrypted bytes any further: AES-GCM's auth tag already
    /// guarantees the plaintext is byte-for-byte what was written, so
    /// re-parsing it into a `Fragment` here would just burn time re-copying
    /// the full embedded ciphertext (each fragment carries a complete copy
    /// of the original file) without checking anything the tag didn't already.
    pub fn check_fragment_intact(&self, file_id: &str, index: u8) -> bool {
        let path = self.vault_dir.join(file_id).join(format!("fragment_{index}.svf.enc"));
        self.read_encrypted(&path).is_ok()
    }

    /// The at-rest encryption key — passed to `large_fragment` functions.
    pub fn at_rest_key(&self) -> &[u8; crypto::KEY_LEN] {
        &self.at_rest_key
    }

    /// Directory where shard files for a large file are stored.
    pub fn frag_dir(&self, file_id: &str) -> PathBuf {
        self.vault_dir.join(file_id)
    }

    pub fn delete_fragments(&self, file_id: &str) -> CoreResult<()> {
        let dir = self.vault_dir.join(file_id);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        Ok(())
    }

    /// Remove any vault folder not referenced by the manifest. An add-file
    /// operation writes fragments/shards to disk before updating the
    /// manifest at the very end — if the app is killed or crashes in
    /// between (e.g. a forced quit mid-split), those fragments are orphaned:
    /// never visible in the vault, but still taking up disk space forever.
    /// Called once at startup so this can't silently accumulate.
    /// Returns the number of orphaned folders removed.
    pub fn cleanup_orphaned_fragments(&self) -> CoreResult<usize> {
        if !self.vault_dir.exists() {
            return Ok(0);
        }

        let manifest = self.load_manifest()?;
        let mut removed = 0;

        for entry in fs::read_dir(&self.vault_dir)? {
            let path = entry?.path();
            if !path.is_dir() { continue; }

            let id = match path.file_name().and_then(|n| n.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };

            if !manifest.entries.iter().any(|e| e.file_id == id) {
                fs::remove_dir_all(&path)?;
                removed += 1;
            }
        }

        Ok(removed)
    }

    // format: [12-byte nonce][ciphertext...]
    fn write_encrypted(&self, path: &Path, data: &[u8]) -> CoreResult<()> {
        let enc = crypto::encrypt(&self.at_rest_key, data)?;
        let mut file = fs::File::create(path)?;
        file.write_all(&enc.nonce)?;
        file.write_all(&enc.ciphertext)?;
        Ok(())
    }

    fn read_encrypted(&self, path: &Path) -> CoreResult<Vec<u8>> {
        let mut file = fs::File::open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        if buf.len() <= crypto::NONCE_LEN {
            return Err(CoreError::Storage(
                format!("file is truncated: {}", path.display()),
            ));
        }

        let (nonce_part, cipher_part) = buf.split_at(crypto::NONCE_LEN);
        let mut nonce = [0u8; crypto::NONCE_LEN];
        nonce.copy_from_slice(nonce_part);

        crypto::decrypt(&self.at_rest_key, &nonce, cipher_part)
    }
}

impl Drop for Storage {
    fn drop(&mut self) {
        self.at_rest_key.zeroize();
    }
}

fn load_or_create_app_secret(path: &Path) -> CoreResult<[u8; 32]> {
    if path.exists() {
        let mut file = fs::File::open(path)?;
        let mut buf = [0u8; 32];
        file.read_exact(&mut buf)
            .map_err(|_| CoreError::Storage("app secret file is corrupt".into()))?;
        Ok(buf)
    } else {
        let secret = crypto::generate_key();
        fs::write(path, secret)?;
        Ok(secret)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{SplitParams, VaultEntry};
    use crate::core::fragmenter;

    fn temp_storage() -> (Storage, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::new(dir.path()).unwrap();
        (s, dir)
    }

    #[test]
    fn test_manifest() {
        let (storage, _dir) = temp_storage();

        let mut manifest = Manifest::default();
        manifest.upsert(VaultEntry {
            file_id: "abc".into(),
            filename: "report.pdf".into(),
            size: 1234,
            total_fragments: 5,
            threshold: 3,
            password_protected: false,
            created_at: 0,
            is_large: false,
            fragment_labels: Default::default(),
            pinned: Default::default(),
            last_rotated_at: Default::default(),
        });
        storage.save_manifest(&manifest).unwrap();

        let loaded = storage.load_manifest().unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].filename, "report.pdf");
    }

    #[test]
    fn test_fragment_storage() {
        let (storage, _dir) = temp_storage();

        let params = SplitParams { total_fragments: 4, threshold: 2, password: None, compress: false, cipher: "aes256gcm".to_string(), kdf: "standard".to_string(), padding_pct: 0 };
        let frags = fragmenter::split_file(b"hello vault", "h.txt", &params).unwrap();
        let file_id = frags[0].file_id.clone();

        storage.store_fragments(&file_id, &frags).unwrap();
        let loaded = storage.load_fragments(&file_id).unwrap();
        assert_eq!(loaded.len(), 4);

        let recovered = fragmenter::reconstruct_file(&loaded[0..2], None).unwrap();
        assert_eq!(recovered, b"hello vault");
    }

    #[test]
    fn test_delete() {
        let (storage, _dir) = temp_storage();
        let params = SplitParams { total_fragments: 3, threshold: 2, password: None, compress: false, cipher: "aes256gcm".to_string(), kdf: "standard".to_string(), padding_pct: 0 };
        let frags = fragmenter::split_file(b"data", "d.txt", &params).unwrap();
        let id = frags[0].file_id.clone();

        storage.store_fragments(&id, &frags).unwrap();
        storage.delete_fragments(&id).unwrap();
        assert!(storage.load_fragments(&id).is_err());
    }

    #[test]
    fn test_cleanup_orphaned_fragments() {
        let (storage, _dir) = temp_storage();

        // a legitimate file, properly recorded in the manifest
        let params = SplitParams { total_fragments: 3, threshold: 2, password: None, compress: false, cipher: "aes256gcm".to_string(), kdf: "standard".to_string(), padding_pct: 0 };
        let frags = fragmenter::split_file(b"kept data", "keep.txt", &params).unwrap();
        let kept_id = frags[0].file_id.clone();
        storage.store_fragments(&kept_id, &frags).unwrap();

        let mut manifest = Manifest::default();
        manifest.upsert(VaultEntry {
            file_id: kept_id.clone(),
            filename: "keep.txt".into(),
            size: 9,
            total_fragments: 3,
            threshold: 2,
            password_protected: false,
            created_at: 0,
            is_large: false,
            fragment_labels: Default::default(),
            pinned: Default::default(),
            last_rotated_at: Default::default(),
        });
        storage.save_manifest(&manifest).unwrap();

        // an orphan: fragments on disk from a split that never finished,
        // so it was never added to the manifest
        let orphan_frags = fragmenter::split_file(b"orphaned data", "orphan.txt", &params).unwrap();
        let orphan_id = orphan_frags[0].file_id.clone();
        storage.store_fragments(&orphan_id, &orphan_frags).unwrap();

        let removed = storage.cleanup_orphaned_fragments().unwrap();
        assert_eq!(removed, 1);

        // the legitimate file survives...
        assert_eq!(storage.load_fragments(&kept_id).unwrap().len(), 3);
        // ...but the orphan is gone
        assert!(storage.load_fragments(&orphan_id).is_err());

        // running it again finds nothing left to clean up
        assert_eq!(storage.cleanup_orphaned_fragments().unwrap(), 0);
    }

    #[test]
    fn test_load_fragments_limited() {
        let (storage, _dir) = temp_storage();
        let params = SplitParams { total_fragments: 5, threshold: 3, password: None, compress: false, cipher: "aes256gcm".to_string(), kdf: "standard".to_string(), padding_pct: 0 };
        let frags = fragmenter::split_file(b"limited load test", "l.txt", &params).unwrap();
        let file_id = frags[0].file_id.clone();
        storage.store_fragments(&file_id, &frags).unwrap();

        let limited = storage.load_fragments_limited(&file_id, 3).unwrap();
        assert_eq!(limited.len(), 3);

        // still enough to reconstruct (threshold is 3)
        let recovered = fragmenter::reconstruct_file(&limited, None).unwrap();
        assert_eq!(recovered, b"limited load test");

        // a limit at or above the total just returns everything
        let all = storage.load_fragments_limited(&file_id, 100).unwrap();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn a_corrupt_fragment_is_skipped_rather_than_failing_the_whole_load() {
        // The K-of-N promise: with 5 fragments and a threshold of 3, one
        // damaged fragment must still leave the file fully recoverable —
        // downloadable, rotatable, shareable. Before this was handled, a
        // single bad byte made all four of those operations fail outright.
        let (storage, _dir) = temp_storage();
        let params = SplitParams {
            total_fragments: 5, threshold: 3, password: None, compress: false,
            cipher: "aes256gcm".to_string(), kdf: "standard".to_string(), padding_pct: 0,
        };
        let data = b"survives a damaged fragment".to_vec();
        let frags = fragmenter::split_file(&data, "c.txt", &params).unwrap();
        let file_id = frags[0].file_id.clone();
        storage.store_fragments(&file_id, &frags).unwrap();

        // Flip a byte in the middle of one stored fragment, the way real
        // disk corruption (or a user experimenting) would.
        let victim = storage.frag_dir(&file_id).join("fragment_1.svf.enc");
        let mut bytes = std::fs::read(&victim).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        std::fs::write(&victim, &bytes).unwrap();

        // The damaged one is dropped; the other four still load.
        let loaded = storage.load_fragments(&file_id).unwrap();
        assert_eq!(loaded.len(), 4, "only the corrupt fragment should be skipped");
        assert!(!loaded.iter().any(|f| f.index == 1), "the corrupt one must not appear");

        // And 4 healthy fragments still rebuild the file exactly.
        assert_eq!(fragmenter::reconstruct_file(&loaded, None).unwrap(), data);

        // The integrity checker is still what reports the damage.
        assert!(!storage.check_fragment_intact(&file_id, 1));
        assert!(storage.check_fragment_intact(&file_id, 2));
    }

    #[test]
    fn test_parallel_fragment_writes() {
        use std::sync::Arc;
        use rayon::prelude::*;

        let (storage, _dir) = temp_storage();
        let storage = Arc::new(storage);

        let params = SplitParams { total_fragments: 5, threshold: 3, password: None, compress: false, cipher: "aes256gcm".to_string(), kdf: "standard".to_string(), padding_pct: 0 };
        let frags = fragmenter::split_file(b"parallel write test data", "p.txt", &params).unwrap();
        let file_id = frags[0].file_id.clone();

        // Write all fragments in parallel
        frags.par_iter().for_each(|frag| {
            storage.store_fragments(&file_id, std::slice::from_ref(frag)).unwrap();
        });

        let loaded = storage.load_fragments(&file_id).unwrap();
        assert_eq!(loaded.len(), 5);
        let recovered = fragmenter::reconstruct_file(&loaded[0..3], None).unwrap();
        assert_eq!(recovered, b"parallel write test data");
    }
}
