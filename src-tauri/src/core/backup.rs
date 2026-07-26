// Vault backup / restore — disaster recovery for the whole local vault.
//
// The manifest and every fragment/shard on disk are encrypted at rest with
// a key derived from *this installation's* secret (see core/storage.rs).
// That's exactly right for local storage, but it means a raw copy of the
// vault folder is useless on another machine (or a fresh install after a
// disk failure) — nothing there can derive the same key.
//
// So a backup re-wraps everything under a password the user chooses at
// export time (Argon2id, same KDF preset used for PIN lock), independent of
// any device secret. Restoring decrypts with that password, then re-writes
// every fragment/shard under the *destination* machine's own at-rest key —
// reusing `to_portable_bytes`/`portable_bytes_to_vault`, the same conversion
// the fragment-sharing path already implements for exactly this
// "move encrypted data between machines" problem.

use crate::core::crypto;
use crate::core::error::{CoreError, CoreResult};
use crate::core::large_fragment;
use crate::core::model::{ActivityLog, Fragment, Manifest};
use crate::core::storage::Storage;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MAGIC: &[u8; 8] = b"SVVAULTB";
const VERSION: u8 = 1;
const BACKUP_KDF: &str = crypto::KDF_ARGON2ID;
pub const MIN_BACKUP_PASSWORD_LENGTH: usize = 8;

#[derive(Serialize, Deserialize)]
struct LargeShardEntry {
    index: u8,
    portable_b64: String,
}

#[derive(Serialize, Deserialize)]
struct BackupPayload {
    manifest: Manifest,
    activity_log: ActivityLog,
    // file_id -> fragments, for entries where `is_large` is false.
    small_fragments: HashMap<String, Vec<Fragment>>,
    // file_id -> shards, for entries where `is_large` is true.
    large_shards: HashMap<String, Vec<LargeShardEntry>>,
}

/// Bundle everything in `storage`'s vault into one password-encrypted blob.
pub fn export_bytes(storage: &Storage, password: &str) -> CoreResult<Vec<u8>> {
    let manifest = storage.load_manifest()?;
    let activity_log = storage.load_activity_log()?;

    let mut small_fragments = HashMap::new();
    let mut large_shards = HashMap::new();

    for entry in &manifest.entries {
        if entry.is_large {
            let frag_dir = storage.frag_dir(&entry.file_id);
            let shard_files = large_fragment::find_shard_files(&frag_dir)?;
            let mut shards = Vec::with_capacity(shard_files.len());
            for (index, path) in shard_files {
                let portable = large_fragment::to_portable_bytes(&path, storage.at_rest_key())?;
                shards.push(LargeShardEntry { index, portable_b64: B64.encode(portable) });
            }
            large_shards.insert(entry.file_id.clone(), shards);
        } else {
            let fragments = storage.load_fragments(&entry.file_id)?;
            small_fragments.insert(entry.file_id.clone(), fragments);
        }
    }

    let payload = BackupPayload { manifest, activity_log, small_fragments, large_shards };
    let json = serde_json::to_vec(&payload)?;

    let salt = crypto::generate_salt();
    let key = crypto::derive_key_kdf(BACKUP_KDF, password, &salt)?;
    let encrypted = crypto::encrypt(&key, &json)?;

    let mut out = Vec::with_capacity(8 + 1 + salt.len() + encrypted.nonce.len() + encrypted.ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&encrypted.nonce);
    out.extend_from_slice(&encrypted.ciphertext);
    Ok(out)
}

/// Decrypt a backup blob and write everything into `storage`. The caller is
/// responsible for only doing this into an empty vault. Returns the number
/// of files restored.
pub fn import_bytes(storage: &Storage, password: &str, bytes: &[u8]) -> CoreResult<u32> {
    if bytes.len() < 8 + 1 + crypto::SALT_LEN + crypto::NONCE_LEN || &bytes[..8] != MAGIC {
        return Err(CoreError::InvalidFragment("not a SecureVault backup file".into()));
    }
    if bytes[8] != VERSION {
        return Err(CoreError::InvalidFragment(
            "backup was made by an incompatible version of SecureVault".into(),
        ));
    }

    let mut offset = 9;
    let salt = &bytes[offset..offset + crypto::SALT_LEN];
    offset += crypto::SALT_LEN;
    let nonce_slice = &bytes[offset..offset + crypto::NONCE_LEN];
    offset += crypto::NONCE_LEN;
    let ciphertext = &bytes[offset..];

    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(nonce_slice);

    let key = crypto::derive_key_kdf(BACKUP_KDF, password, salt)?;
    let json = crypto::decrypt(&key, &nonce, ciphertext)
        .map_err(|_| CoreError::Decryption("incorrect backup password".into()))?;
    let payload: BackupPayload = serde_json::from_slice(&json)
        .map_err(|_| CoreError::InvalidFragment("backup file is corrupt".into()))?;

    for (file_id, fragments) in &payload.small_fragments {
        storage.store_fragments(file_id, fragments)?;
    }
    for (file_id, shards) in &payload.large_shards {
        let frag_dir = storage.frag_dir(file_id);
        let portable: Vec<(u8, Vec<u8>)> = shards
            .iter()
            .map(|s| {
                B64.decode(&s.portable_b64)
                    .map(|d| (s.index, d))
                    .map_err(|e| CoreError::InvalidFragment(format!("bad shard data: {e}")))
            })
            .collect::<CoreResult<_>>()?;
        large_fragment::import_portable_shards(&portable, &frag_dir, storage.at_rest_key())?;
    }

    let files_restored = payload.manifest.entries.len() as u32;
    storage.save_manifest(&payload.manifest)?;
    storage.save_activity_log(&payload.activity_log)?;
    storage.log_activity("restore", &format!("{files_restored} file(s) from backup"));

    Ok(files_restored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{SplitParams, VaultEntry};
    use crate::core::{fragmenter, large_fragment, op_control::OpControl};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_storage(tag: &str) -> Storage {
        let dir = std::env::temp_dir().join(format!("svtest_backup_{tag}_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Storage::new(&dir).unwrap()
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    #[test]
    fn round_trip_restores_small_and_large_files_on_a_fresh_vault() {
        let source = make_storage("source");
        let mut manifest = Manifest::default();

        // A small file, password-protected.
        let small_params = SplitParams {
            total_fragments: 5,
            threshold: 3,
            password: Some("filepassword".to_string()),
            compress: false,
            cipher: "aes256gcm".to_string(),
            kdf: "standard".to_string(),
            padding_pct: 0,
        };
        let small_data = b"disaster recovery test payload".to_vec();
        let small_fragments = fragmenter::split_file(&small_data, "small.txt", &small_params).unwrap();
        let small_id = small_fragments[0].file_id.clone();
        source.store_fragments(&small_id, &small_fragments).unwrap();
        manifest.upsert(VaultEntry {
            file_id: small_id.clone(),
            filename: "small.txt".to_string(),
            size: small_data.len() as u64,
            total_fragments: 5,
            threshold: 3,
            password_protected: true,
            created_at: now(),
            is_large: false,
            fragment_labels: Default::default(),
            pinned: false,
            last_rotated_at: now(),
        });

        // A large file, no password.
        let big_path = std::env::temp_dir().join(format!("svtest_backup_big_{}", uuid::Uuid::new_v4()));
        {
            use rand::RngCore;
            let mut f = std::fs::File::create(&big_path).unwrap();
            let mut buf = vec![0u8; 8 * 1024 * 1024];
            for _ in 0..9 {
                rand::thread_rng().fill_bytes(&mut buf);
                std::io::Write::write_all(&mut f, &buf).unwrap();
            }
        }
        let big_data = std::fs::read(&big_path).unwrap();
        let large_params = SplitParams {
            total_fragments: 5,
            threshold: 3,
            password: None,
            compress: false,
            cipher: "aes256gcm".to_string(),
            kdf: "standard".to_string(),
            padding_pct: 0,
        };
        let large_id = uuid::Uuid::new_v4().to_string();
        let frag_dir = source.frag_dir(&large_id);
        large_fragment::split_large_file(
            &big_path, "big.bin", &large_params, source.at_rest_key(), &frag_dir, &large_id, &OpControl::new(), |_, _| {},
        ).unwrap();
        manifest.upsert(VaultEntry {
            file_id: large_id.clone(),
            filename: "big.bin".to_string(),
            size: big_data.len() as u64,
            total_fragments: 5,
            threshold: 3,
            password_protected: false,
            created_at: now(),
            is_large: true,
            fragment_labels: Default::default(),
            pinned: false,
            last_rotated_at: now(),
        });

        source.save_manifest(&manifest).unwrap();
        source.log_activity("add", "small.txt");
        source.log_activity("add", "big.bin");

        // Export, then restore into a completely separate, empty vault.
        let bundle = export_bytes(&source, "backuppassword").unwrap();

        // Wrong password must fail cleanly, not silently produce garbage.
        let dest_wrong = make_storage("dest_wrong");
        assert!(import_bytes(&dest_wrong, "notthepassword", &bundle).is_err());

        let dest = make_storage("dest");
        let restored_count = import_bytes(&dest, "backuppassword", &bundle).unwrap();
        assert_eq!(restored_count, 2);

        let restored_manifest = dest.load_manifest().unwrap();
        assert_eq!(restored_manifest.entries.len(), 2);
        // The 2 restored entries, plus the "restore" event itself that
        // `import_bytes` logs after writing them back.
        let restored_log = dest.load_activity_log().unwrap();
        assert_eq!(restored_log.entries.len(), 3);

        // Small file: fragments decrypt under the *destination* vault's own
        // at-rest key and the original file password still round-trips.
        let restored_small = dest.load_fragments(&small_id).unwrap();
        assert_eq!(
            fragmenter::reconstruct_file(&restored_small, Some("filepassword")).unwrap(),
            small_data
        );

        // Large file: shards decrypt under the destination's at-rest key too.
        let restored_frag_dir = dest.frag_dir(&large_id);
        let shard_files = large_fragment::find_shard_files(&restored_frag_dir).unwrap();
        let out_path = std::env::temp_dir().join(format!("svtest_backup_restored_{}.bin", uuid::Uuid::new_v4()));
        large_fragment::reconstruct_large_file(&shard_files, None, dest.at_rest_key(), &out_path).unwrap();
        assert_eq!(std::fs::read(&out_path).unwrap(), big_data);
    }
}
