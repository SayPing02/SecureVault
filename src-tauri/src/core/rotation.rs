// Fragment rotation — re-split a vault file with a brand-new random Shamir
// polynomial (or fresh Reed-Solomon shards, for large files).
//
// Old fragments still out there (a USB drive, a friend's laptop, wherever)
// become useless against the new set immediately: they're not part of the
// same random polynomial anymore, so mixing an old fragment with new ones
// fails to decrypt rather than quietly reconstructing anything. This is the
// real substitute for "expiring" a fragment — instant, deliberate, and not
// dependent on trusting a clock (see the in-app discussion this came from:
// offline expiry can't be enforced, since a local clock can always be
// turned back).
//
// New fragments are written to a `{file_id}.rotating` directory first, and
// the old ones are only deleted once that succeeds — so a failure partway
// through (disk full, crash) leaves the original, working fragments
// untouched instead of a mix of old and new. Any `.rotating` leftover from
// an interrupted run is swept up by the same orphaned-fragment cleanup that
// already runs at startup, since it isn't referenced by any manifest entry.

use crate::core::error::CoreResult;
use crate::core::model::{SplitParams, VaultEntry};
use crate::core::storage::Storage;
use crate::core::{fragmenter, large_fragment, op_control::OpControl};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Rotates `entry`'s fragments in place. Returns the manifest entry to save
/// back (password_protected reflects whichever password was actually used;
/// fragment_labels and last_rotated_at are reset/updated).
pub fn rotate(storage: &Storage, entry: &VaultEntry, password: Option<&str>) -> CoreResult<VaultEntry> {
    let file_id = entry.file_id.as_str();
    let frag_dir = storage.frag_dir(file_id);
    let temp_id = format!("{file_id}.rotating");
    let shard_files = large_fragment::find_shard_files(&frag_dir).unwrap_or_default();

    let new_password_protected = if !shard_files.is_empty() {
        rotate_large(storage, file_id, &frag_dir, &temp_id, &shard_files, password)?
    } else {
        rotate_small(storage, file_id, &frag_dir, &temp_id, entry, password)?
    };

    let mut updated = entry.clone();
    updated.password_protected = new_password_protected;
    updated.last_rotated_at = now_unix();
    // Old labels described where the *old* fragments went — meaningless
    // once the fragments themselves have changed.
    updated.fragment_labels = Default::default();
    Ok(updated)
}

fn rotate_large(
    storage: &Storage,
    file_id: &str,
    frag_dir: &std::path::Path,
    temp_id: &str,
    shard_files: &[(u8, std::path::PathBuf)],
    password: Option<&str>,
) -> CoreResult<bool> {
    let meta = large_fragment::read_meta(&shard_files[0].1, storage.at_rest_key())?;
    let tmp_plaintext = std::env::temp_dir().join(format!("securevault_rotate_{file_id}.tmp"));

    let reconstruct_result = large_fragment::reconstruct_large_file(
        shard_files, password, storage.at_rest_key(), &tmp_plaintext,
    );
    if let Err(e) = reconstruct_result {
        let _ = fs::remove_file(&tmp_plaintext);
        return Err(e);
    }

    let params = SplitParams {
        total_fragments: meta.total,
        threshold: meta.threshold,
        password: password.map(|p| p.to_string()),
        compress: meta.compressed,
        cipher: meta.cipher.clone(),
        kdf: meta.kdf.clone(),
        padding_pct: meta.padding_pct,
    };
    let new_dir = storage.frag_dir(temp_id);
    let split_result = large_fragment::split_large_file(
        &tmp_plaintext, &meta.original_filename, &params, storage.at_rest_key(),
        &new_dir, file_id, &OpControl::new(), |_, _| {},
    );
    let _ = fs::remove_file(&tmp_plaintext);
    let metas = match split_result {
        Ok(m) => m,
        Err(e) => { let _ = fs::remove_dir_all(&new_dir); return Err(e); }
    };

    storage.delete_fragments(file_id)?;
    fs::rename(&new_dir, frag_dir)?;
    Ok(metas[0].password_protected)
}

fn rotate_small(
    storage: &Storage,
    file_id: &str,
    frag_dir: &std::path::Path,
    temp_id: &str,
    entry: &VaultEntry,
    password: Option<&str>,
) -> CoreResult<bool> {
    let fragments = storage.load_fragments(file_id)?;
    let mut file_bytes = fragmenter::reconstruct_file(&fragments, password)?;

    let params = SplitParams {
        total_fragments: fragments[0].total,
        threshold: fragments[0].threshold,
        password: password.map(|p| p.to_string()),
        compress: fragments[0].compressed,
        cipher: fragments[0].cipher.clone(),
        kdf: fragments[0].kdf.clone(),
        padding_pct: fragments[0].padding_pct,
    };
    let split_result = fragmenter::split_file(&file_bytes, &entry.filename, &params);
    file_bytes.zeroize();
    let mut new_fragments = split_result?;
    // split_file always mints a fresh uuid — override it so the rotated
    // fragments keep the same manifest identity.
    for f in &mut new_fragments {
        f.file_id = file_id.to_string();
    }

    storage.store_fragments(temp_id, &new_fragments)?;
    storage.delete_fragments(file_id)?;
    let new_dir = storage.frag_dir(temp_id);
    fs::rename(&new_dir, frag_dir)?;
    Ok(new_fragments[0].password_protected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::Manifest;

    fn make_storage(tag: &str) -> Storage {
        let dir = std::env::temp_dir().join(format!("svtest_rotation_{tag}_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Storage::new(&dir).unwrap()
    }

    #[test]
    fn rotation_reconstructs_correctly_and_invalidates_old_fragments() {
        let storage = make_storage("small");
        let data = b"top secret, before rotation".to_vec();
        let params = SplitParams {
            total_fragments: 5,
            threshold: 3,
            password: Some("hunter2".to_string()),
            compress: false,
            cipher: "aes256gcm".to_string(),
            kdf: "standard".to_string(),
            padding_pct: 0,
        };
        let old_fragments = fragmenter::split_file(&data, "secret.txt", &params).unwrap();
        let file_id = old_fragments[0].file_id.clone();
        storage.store_fragments(&file_id, &old_fragments).unwrap();

        let entry = VaultEntry {
            file_id: file_id.clone(),
            filename: "secret.txt".to_string(),
            size: data.len() as u64,
            total_fragments: 5,
            threshold: 3,
            password_protected: true,
            created_at: 1000,
            is_large: false,
            fragment_labels: [(1u8, "USB drive".to_string())].into_iter().collect(),
            pinned: true,
            last_rotated_at: 1000,
        };

        let updated = rotate(&storage, &entry, Some("hunter2")).unwrap();

        // Identity and unrelated fields survive; labels/rotation timestamp don't.
        assert_eq!(updated.file_id, file_id);
        assert_eq!(updated.filename, "secret.txt");
        assert!(updated.pinned);
        assert!(updated.fragment_labels.is_empty());
        assert!(updated.last_rotated_at > entry.last_rotated_at);
        assert!(updated.password_protected);

        // New fragments reconstruct the same content correctly.
        let new_fragments = storage.load_fragments(&file_id).unwrap();
        let recovered = fragmenter::reconstruct_file(&new_fragments[0..3], Some("hunter2")).unwrap();
        assert_eq!(recovered, data);

        // The new share values are actually different (fresh polynomial),
        // not just re-saved copies of the old ones.
        assert_ne!(new_fragments[0].share_y_b64, old_fragments[0].share_y_b64);

        // Mixing old + new fragments must NOT reconstruct — this is the
        // actual revocation guarantee rotation is supposed to provide.
        let mixed = vec![new_fragments[0].clone(), new_fragments[1].clone(), old_fragments[2].clone()];
        assert!(fragmenter::reconstruct_file(&mixed, Some("hunter2")).is_err());

        // A full set of *old* fragments on their own still reconstructs —
        // rotation revokes trust going forward, it doesn't retroactively
        // erase copies someone already has. Confirms the guarantee is
        // "old+new don't mix", not an overclaimed "old fragments now do
        // nothing at all".
        let recovered_old = fragmenter::reconstruct_file(&old_fragments[0..3], Some("hunter2")).unwrap();
        assert_eq!(recovered_old, data);
    }

    #[test]
    fn rotating_past_a_corrupt_fragment_repairs_the_set() {
        // The scenario that exposed the bug: a fragment gets damaged, and
        // rotating is exactly what you'd reach for to get a clean set back.
        // It used to fail with "wrong password or corrupted data", because
        // loading aborted on the bad fragment instead of skipping it —
        // leaving the file stuck in a damaged state with no way out.
        let storage = make_storage("corrupt");
        let params = SplitParams {
            total_fragments: 5,
            threshold: 3,
            password: Some("hunter2".to_string()),
            compress: false,
            cipher: "aes256gcm".to_string(),
            kdf: "standard".to_string(),
            padding_pct: 0,
        };
        let data = b"rotation should heal this".to_vec();
        let frags = fragmenter::split_file(&data, "damaged.txt", &params).unwrap();
        let file_id = frags[0].file_id.clone();
        storage.store_fragments(&file_id, &frags).unwrap();

        // Damage one fragment on disk.
        let victim = storage.frag_dir(&file_id).join("fragment_2.svf.enc");
        let mut bytes = std::fs::read(&victim).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        std::fs::write(&victim, &bytes).unwrap();
        assert!(!storage.check_fragment_intact(&file_id, 2), "setup: should be damaged");

        let entry = VaultEntry {
            file_id: file_id.clone(),
            filename: "damaged.txt".to_string(),
            size: data.len() as u64,
            total_fragments: 5,
            threshold: 3,
            password_protected: true,
            created_at: 1000,
            is_large: false,
            fragment_labels: Default::default(),
            pinned: false,
            last_rotated_at: 1000,
        };

        // Rotation now succeeds despite the damage.
        let updated = rotate(&storage, &entry, Some("hunter2")).unwrap();
        assert!(updated.last_rotated_at > 1000);

        // And it *heals*: a full set of 5, every one of them intact.
        let fresh = storage.load_fragments(&file_id).unwrap();
        assert_eq!(fresh.len(), 5, "should end up with a complete healthy set");
        for i in 1..=5u8 {
            assert!(storage.check_fragment_intact(&file_id, i), "fragment {i} still damaged");
        }

        // The file itself is unchanged.
        assert_eq!(
            fragmenter::reconstruct_file(&fresh[0..3], Some("hunter2")).unwrap(),
            data
        );
    }

    #[test]
    fn rotation_round_trips_a_large_file() {
        let storage = make_storage("large");
        let big_path = std::env::temp_dir().join(format!("svtest_rotation_big_{}", uuid::Uuid::new_v4()));
        {
            use rand::RngCore;
            let mut f = std::fs::File::create(&big_path).unwrap();
            let mut buf = vec![0u8; 8 * 1024 * 1024];
            for _ in 0..9 { // ~72 MB, above the 64MB LARGE_FILE_THRESHOLD
                rand::thread_rng().fill_bytes(&mut buf);
                std::io::Write::write_all(&mut f, &buf).unwrap();
            }
        }
        let original = std::fs::read(&big_path).unwrap();

        let params = SplitParams {
            total_fragments: 5,
            threshold: 3,
            password: None,
            compress: false,
            cipher: "aes256gcm".to_string(),
            kdf: "standard".to_string(),
            padding_pct: 0,
        };
        let file_id = uuid::Uuid::new_v4().to_string();
        let frag_dir = storage.frag_dir(&file_id);
        large_fragment::split_large_file(
            &big_path, "big.bin", &params, storage.at_rest_key(), &frag_dir, &file_id, &OpControl::new(), |_, _| {},
        ).unwrap();

        let mut manifest = Manifest::default();
        let entry = VaultEntry {
            file_id: file_id.clone(),
            filename: "big.bin".to_string(),
            size: original.len() as u64,
            total_fragments: 5,
            threshold: 3,
            password_protected: false,
            created_at: 1000,
            is_large: true,
            fragment_labels: Default::default(),
            pinned: false,
            last_rotated_at: 1000,
        };
        manifest.upsert(entry.clone());

        let updated = rotate(&storage, &entry, None).unwrap();
        assert!(updated.last_rotated_at > 1000);

        let shard_files = large_fragment::find_shard_files(&storage.frag_dir(&file_id)).unwrap();
        let out_path = std::env::temp_dir().join(format!("svtest_rotation_out_{}.bin", uuid::Uuid::new_v4()));
        large_fragment::reconstruct_large_file(&shard_files, None, storage.at_rest_key(), &out_path).unwrap();
        assert_eq!(std::fs::read(&out_path).unwrap(), original);
    }
}
