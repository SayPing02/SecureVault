// Commands for vault operations: split, list, download, delete

use crate::commands::dto::{ActivityEntryDto, CipherRecommendationDto, OperationResult, SplitRequest, VaultFileDto};
use crate::core::crypto;
use crate::core::fragmenter;
use crate::core::large_fragment::{self, LARGE_FILE_THRESHOLD};
use crate::core::model::{SplitParams, VaultEntry};
use crate::core::op_control::OpControl;
use crate::state::AppState;
use rayon::prelude::*;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri::async_runtime::spawn_blocking;
use zeroize::Zeroize;

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SplitProgress {
    percent: u8,
    message: String,
    stage: &'static str,
}

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct DownloadProgress {
    percent: u8,
    message: String,
}

// Matches the frontend's MIN_PASSWORD_LENGTH — enforced here too so the
// requirement can't be bypassed by calling the command directly.
const MIN_PASSWORD_LENGTH: usize = 8;

/// Returns the byte size of a file without reading it into memory.
#[tauri::command]
pub fn get_file_size(file_path: String) -> Result<u64, String> {
    let meta = std::fs::metadata(&file_path)
        .map_err(|e| format!("cannot stat file: {e}"))?;
    if !meta.is_file() {
        return Err("that's a folder (or an app bundle), not a single file — please pick a regular file".into());
    }
    Ok(meta.len())
}

/// Suggests a cipher for the frontend to pre-select, based on the file's
/// size and whether this CPU has AES hardware acceleration. Purely advisory
/// — every cipher works regardless, so this only affects the default the
/// user sees, not correctness.
#[tauri::command]
pub fn recommend_cipher(file_size: u64) -> CipherRecommendationDto {
    if file_size >= LARGE_FILE_THRESHOLD {
        return CipherRecommendationDto {
            cipher: crypto::CIPHER_XCHACHA20POLY.to_string(),
            reason: "Best fit for large files — no speed cost, and safe even after generating many nonces.".to_string(),
        };
    }
    if crypto::has_hardware_aes() {
        CipherRecommendationDto {
            cipher: crypto::CIPHER_AES256GCM.to_string(),
            reason: "Your device has AES hardware acceleration.".to_string(),
        }
    } else {
        CipherRecommendationDto {
            cipher: crypto::CIPHER_CHACHA20POLY.to_string(),
            reason: "Faster than AES on this device.".to_string(),
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tauri::command]
pub async fn split_and_store(
    request: SplitRequest,
    operation_id: String,
    _state: State<'_, AppState>,
    app: AppHandle,
) -> Result<OperationResult, String> {
    if let Some(pw) = &request.password {
        if !pw.is_empty() && pw.chars().count() < MIN_PASSWORD_LENGTH {
            return Err(format!("password must be at least {MIN_PASSWORD_LENGTH} characters"));
        }
    }

    spawn_blocking(move || {
        let ctl = OpControl::new();
        app.state::<AppState>().operations.lock().unwrap().insert(operation_id.clone(), ctl.clone());

        // Set as soon as a vault-side file_id exists, so a cancellation can
        // clean up whatever partial fragments/shards were already written.
        let mut created_file_id: Option<String> = None;

        let result = (|| -> Result<OperationResult, String> {
            let storage: Arc<_> = app.state::<AppState>().storage()?;
            macro_rules! emit {
                ($pct:expr, $stage:expr, $msg:expr) => {
                    let _ = app.emit("split-progress", SplitProgress {
                        percent: $pct,
                        stage: $stage,
                        message: String::from($msg),
                    });
                };
            }

            let file_meta = fs::metadata(&request.file_path)
                .map_err(|e| format!("cannot stat file: {e}"))?;
            if !file_meta.is_file() {
                return Err("that's a folder (or an app bundle), not a single file — please pick a regular file".to_string());
            }
            let file_size = file_meta.len();

            let source_filename = std::path::Path::new(&request.file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unnamed")
                .to_string();
            let filename = sanitize_filename(request.filename.as_deref(), &source_filename);

            let mut params = SplitParams {
                total_fragments: request.total_fragments,
                threshold:       request.threshold,
                password:        request.password,
                compress:        request.compress,
                cipher:          request.cipher,
                kdf:             request.kdf,
                padding_pct:     request.padding_pct,
            };

            if file_size >= LARGE_FILE_THRESHOLD {
                // ── Large-file path: streaming Reed-Solomon shards ──────────────────
                emit!(3, "preparing", "Preparing large-file split…");

                let file_path = std::path::PathBuf::from(&request.file_path);
                let file_id   = uuid::Uuid::new_v4().to_string();
                created_file_id = Some(file_id.clone());
                let frag_dir  = storage.frag_dir(&file_id);
                let at_rest   = *storage.at_rest_key();

                let app2 = app.clone();
                let metas = large_fragment::split_large_file(
                    &file_path,
                    &filename,
                    &params,
                    &at_rest,
                    &frag_dir,
                    &file_id,
                    &ctl,
                    move |pct, msg| {
                        let _ = app2.emit("split-progress", SplitProgress {
                            percent: pct,
                            stage: "processing",
                            message: msg.to_string(),
                        });
                    },
                )?;
                params.password.zeroize();

                emit!(98, "manifest", "Updating manifest…");
                let mut manifest = storage.load_manifest()?;
                let meta = &metas[0];
                manifest.upsert(VaultEntry {
                    file_id: file_id.clone(),
                    filename: filename.clone(),
                    size: file_size,
                    total_fragments: meta.total,
                    threshold: meta.threshold,
                    password_protected: meta.password_protected,
                    created_at: now_unix(),
                    is_large: true,
                    fragment_labels: Default::default(),
                    pinned: Default::default(),
                    last_rotated_at: now_unix(),
                });
                storage.save_manifest(&manifest)?;
                storage.log_activity("added", &filename);

                emit!(100, "done", "Done!");
                Ok(OperationResult::ok(
                    format!(
                        "'{}' split into {} RS shards (threshold {})",
                        filename, meta.total, meta.threshold,
                    ),
                    None,
                ))
            } else {
                // ── Small-file path: in-memory, full copy per fragment ──────────────
                emit!(5, "reading", "Reading file from disk…");
                let file_bytes = fs::read(&request.file_path)
                    .map_err(|e| format!("could not read file: {e}"))?;

                // Map fragmenter's 0-100 into overall 10-65%
                let app2 = app.clone();
                let fragments = fragmenter::split_file_with_progress(
                    &file_bytes,
                    &filename,
                    &params,
                    move |frag_pct, msg| {
                        let overall = 10u8 + (frag_pct as u32 * 55 / 100) as u8;
                        let _ = app2.emit("split-progress", SplitProgress {
                            percent: overall,
                            stage: "processing",
                            message: msg.to_string(),
                        });
                    },
                )?;
                params.password.zeroize();

                let file_id  = fragments[0].file_id.clone();
                created_file_id = Some(file_id.clone());
                let total    = fragments[0].total;
                let threshold = fragments[0].threshold;
                let compressed = fragments[0].compressed;
                let n = fragments.len();

                emit!(65, "writing", format!("Writing {} fragments in parallel…", n));
                let done         = AtomicUsize::new(0);
                let storage_ref  = &*storage;
                let file_id_ref  = &file_id;
                let app_ref      = &app;
                let ctl_ref      = &ctl;

                fragments.par_iter().try_for_each(|frag| -> Result<(), String> {
                    ctl_ref.checkpoint()?;
                    storage_ref.store_fragments(file_id_ref, std::slice::from_ref(frag))?;
                    let i   = done.fetch_add(1, Ordering::Relaxed) + 1;
                    let pct = 65u8 + (i * 28 / n) as u8;
                    let _ = app_ref.emit("split-progress", SplitProgress {
                        percent: pct,
                        stage: "writing",
                        message: format!("Wrote fragment {} of {}…", i, n),
                    });
                    Ok(())
                })?;

                emit!(95, "manifest", "Updating manifest…");
                let mut manifest = storage.load_manifest()?;

                let size_info = if compressed {
                    let ratio = file_bytes.len();
                    let compressed_size = fragments[0].ciphertext_b64.len() * 3 / 4;
                    let enc_pct = (compressed_size * 100).checked_div(ratio).unwrap_or(100);
                    let savings = 100_usize.saturating_sub(enc_pct);
                    format!(" (compressed ~{}%)", savings)
                } else {
                    String::new()
                };

                manifest.upsert(VaultEntry {
                    file_id: file_id.clone(),
                    filename: filename.clone(),
                    size: fragments[0].original_size,
                    total_fragments: total,
                    threshold,
                    password_protected: fragments[0].password_protected,
                    created_at: now_unix(),
                    is_large: false,
                    fragment_labels: Default::default(),
                    pinned: Default::default(),
                    last_rotated_at: now_unix(),
                });
                storage.save_manifest(&manifest)?;
                storage.log_activity("added", &filename);

                emit!(100, "done", "Done!");
                Ok(OperationResult::ok(
                    format!(
                        "'{}' split into {} fragments (threshold {}){size_info}",
                        filename, total, threshold
                    ),
                    None,
                ))
            }
        })();

        if let Err(ref e) = result {
            if e == "operation cancelled" {
                if let Some(ref fid) = created_file_id {
                    if let Ok(storage) = app.state::<AppState>().storage() {
                        let _ = storage.delete_fragments(fid);
                    }
                }
            }
        }

        app.state::<AppState>().operations.lock().unwrap().remove(&operation_id);
        result
    })
    .await
    .map_err(|e| format!("background task failed: {e}"))?
}

/// Re-split a vault file with a brand-new random Shamir polynomial (or fresh
/// Reed-Solomon shards, for large files) — the "rotate" action. Old fragments
/// still out there (a USB drive, a friend's laptop, wherever) become useless
/// against the new set immediately, since mixing them with new fragments
/// fails to decrypt rather than quietly reconstructing anything. See
/// core::rotation for the actual logic and its safety guarantees.
#[tauri::command]
pub async fn rotate_vault_file(
    file_id: String,
    mut password: Option<String>,
    _state: State<'_, AppState>,
    app: AppHandle,
) -> Result<OperationResult, String> {
    spawn_blocking(move || -> Result<OperationResult, String> {
        let storage: Arc<_> = app.state::<AppState>().storage()?;
        let pw = password.as_deref().filter(|p| !p.is_empty());

        let mut manifest = storage.load_manifest()?;
        let entry = manifest.entries.iter().find(|e| e.file_id == file_id).cloned()
            .ok_or_else(|| "file not found in vault".to_string())?;

        let updated = crate::core::rotation::rotate(&storage, &entry, pw)?;
        password.zeroize();

        let filename = updated.filename.clone();
        manifest.upsert(updated);
        storage.save_manifest(&manifest)?;
        storage.log_activity("rotated", &filename);

        Ok(OperationResult::ok(
            format!("'{filename}' rotated — old fragments are no longer valid"),
            None,
        ))
    })
    .await
    .map_err(|e| format!("background task failed: {e}"))?
}

#[tauri::command]
pub fn list_vault_files(
    state: State<'_, AppState>,
) -> Result<Vec<VaultFileDto>, String> {
    let storage = state.storage()?;
    let manifest = storage.load_manifest()?;

    let files = manifest.entries.into_iter().map(|e| VaultFileDto {
        file_id: e.file_id,
        filename: e.filename,
        size: e.size,
        total_fragments: e.total_fragments,
        threshold: e.threshold,
        password_protected: e.password_protected,
        created_at: e.created_at,
        is_large: e.is_large,
        fragment_labels: e.fragment_labels,
        pinned: e.pinned,
        // 0 means "never rotated" (entry predates this field) — fall back
        // to created_at so staleness can still be computed sensibly.
        last_rotated_at: if e.last_rotated_at == 0 { e.created_at } else { e.last_rotated_at },
    }).collect();

    Ok(files)
}

// History of add/download/share/delete/reconstruct events, newest first.
// Purely a local record for the user's own reference — same status as
// fragment labels, never read by any crypto or reconstruction path.
#[tauri::command]
pub fn get_activity_log(state: State<'_, AppState>) -> Result<Vec<ActivityEntryDto>, String> {
    let storage = state.storage()?;
    let log = storage.load_activity_log()?;
    Ok(log.entries.into_iter().map(|e| ActivityEntryDto {
        timestamp: e.timestamp,
        action: e.action,
        filename: e.filename,
    }).collect())
}

#[tauri::command]
pub fn clear_activity_log(state: State<'_, AppState>) -> Result<(), String> {
    let storage = state.storage()?;
    storage.save_activity_log(&crate::core::model::ActivityLog::default())?;
    Ok(())
}

// Checks whether each stored fragment/shard for a vault file can still be
// read and decrypted intact, for the "Fragment Preview" card. Returns one
// bool per fragment in display order (index 0 = fragment/shard #1, etc.) —
// a real corruption/tamper check, not a placeholder "Valid" label.
#[tauri::command]
pub fn check_vault_file_integrity(
    file_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<bool>, String> {
    let storage = state.storage()?;
    let manifest = storage.load_manifest()?;
    let entry = manifest.entries.iter()
        .find(|e| e.file_id == file_id)
        .ok_or_else(|| "file not found in vault".to_string())?;

    // Each check decrypts its own fragment/shard independently, and for
    // small files that means decrypting a full copy of the original file
    // per fragment — run them in parallel so N fragments don't serialize
    // into N times the wait.
    let results = if entry.is_large {
        // Shard files are named shard_0.svf3 .. shard_{N-1}.svf3
        let frag_dir = storage.frag_dir(&file_id);
        let shard_files = large_fragment::find_shard_files(&frag_dir).unwrap_or_default();
        let indices: Vec<u8> = (0..entry.total_fragments).collect();
        indices.par_iter()
            .map(|idx| {
                shard_files.iter()
                    .find(|(shard_idx, _)| shard_idx == idx)
                    .map(|(_, path)| large_fragment::read_meta(path, storage.at_rest_key()).is_ok())
                    .unwrap_or(false)
            })
            .collect()
    } else {
        // Fragment files are named fragment_1.svf.enc .. fragment_N.svf.enc
        let indices: Vec<u8> = (1..=entry.total_fragments).collect();
        indices.par_iter()
            .map(|&idx| storage.check_fragment_intact(&file_id, idx))
            .collect()
    };

    Ok(results)
}

// Quick check for whether `password` unlocks a vault file, without doing the
// full reconstruction. Lets the UI reject a wrong password immediately.
#[tauri::command]
pub fn verify_file_password(
    file_id: String,
    mut password: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let storage = state.storage()?;
    let frag_dir = storage.frag_dir(&file_id);
    let pw = Some(password.as_str()).filter(|p| !p.is_empty());

    let shard_files = large_fragment::find_shard_files(&frag_dir).unwrap_or_default();

    let result = if !shard_files.is_empty() {
        large_fragment::verify_password(&shard_files, pw, storage.at_rest_key())
    } else {
        // Only decrypt `threshold` fragments, not all N — each fragment also
        // carries a full copy of the file's ciphertext, so loading every one
        // just to check a password would cost N times the file size.
        let manifest = storage.load_manifest()?;
        let limit = manifest.entries.iter()
            .find(|e| e.file_id == file_id)
            .map(|e| e.threshold as usize)
            .unwrap_or(usize::MAX);
        let fragments = storage.load_fragments_limited(&file_id, limit)?;
        fragmenter::verify_password(&fragments, pw)
    };

    password.zeroize();
    Ok(result.is_ok())
}

// Reconstruct a file and save to Downloads.
// File type (large RS shards vs small fragments) is detected from disk,
// not from the manifest — this avoids any manifest format-version issues.
#[tauri::command]
pub async fn download_vault_file(
    file_id: String,
    mut password: Option<String>,
    operation_id: String,
    _state: State<'_, AppState>,
    app: AppHandle,
) -> Result<OperationResult, String> {
    spawn_blocking(move || {
        let ctl = OpControl::new();
        app.state::<AppState>().operations.lock().unwrap().insert(operation_id.clone(), ctl.clone());

        // Only the large-file streaming path can leave a partial output file
        // behind (it writes incrementally); set once that path starts writing.
        let mut created_out_path: Option<std::path::PathBuf> = None;

        let result = (|| -> Result<OperationResult, String> {
            let storage: Arc<_> = app.state::<AppState>().storage()?;
            let frag_dir = storage.frag_dir(&file_id);
            let pw       = password.as_deref().filter(|p| !p.is_empty());
            let downloads = get_downloads_dir()?;

            macro_rules! emit {
                ($pct:expr, $msg:expr) => {
                    let _ = app.emit("download-progress", DownloadProgress {
                        percent: $pct,
                        message: String::from($msg),
                    });
                };
            }

            emit!(2, "Reading vault metadata…");

            // Detect file type by checking which files exist on disk.
            let shard_files = large_fragment::find_shard_files(&frag_dir)
                .unwrap_or_default();

            if !shard_files.is_empty() {
                // ── Large-file path (Reed-Solomon shards) ─────────────────────────
                let meta = large_fragment::read_meta(
                    &shard_files[0].1,
                    storage.at_rest_key(),
                )?;
                let out_path = unique_path(&downloads, &meta.original_filename);
                created_out_path = Some(out_path.clone());

                let app2 = app.clone();
                large_fragment::reconstruct_large_file_with_progress(
                    &shard_files,
                    pw,
                    storage.at_rest_key(),
                    &out_path,
                    &ctl,
                    move |pct, msg| {
                        let _ = app2.emit("download-progress", DownloadProgress {
                            percent: pct,
                            message: msg.to_string(),
                        });
                    },
                )?;
                password.zeroize();
                storage.log_activity("downloaded", &meta.original_filename);
                emit!(100, "Done");
                Ok(OperationResult::ok(
                    format!("'{}' saved to Downloads", meta.original_filename),
                    Some(out_path.to_string_lossy().to_string()),
                ))
            } else {
                // ── Small-file path (encrypted fragment copies) ────────────────────
                let fragments  = storage.load_fragments(&file_id)?;

                let app2 = app.clone();
                let file_bytes = fragmenter::reconstruct_file_with_progress(
                    &fragments,
                    pw,
                    move |pct, msg| {
                        // Map fragmenter's 0-100 into overall 5-90%
                        let overall = 5u8 + (pct as u32 * 85 / 100) as u8;
                        let _ = app2.emit("download-progress", DownloadProgress {
                            percent: overall,
                            message: msg.to_string(),
                        });
                    },
                )?;
                password.zeroize();
                let filename   = &fragments[0].original_filename;
                let out_path   = unique_path(&downloads, filename);

                // Only checkpoint here — nothing has been written to disk yet, so
                // a cancel that fires before this point leaves nothing to clean up.
                ctl.checkpoint()?;

                emit!(95, "Writing file to Downloads…");
                fs::write(&out_path, &file_bytes)
                    .map_err(|e| format!("could not save file: {e}"))?;

                storage.log_activity("downloaded", filename);
                emit!(100, "Done");
                Ok(OperationResult::ok(
                    format!("'{}' saved to Downloads", filename),
                    Some(out_path.to_string_lossy().to_string()),
                ))
            }
        })();

        if let Err(ref e) = result {
            if e == "operation cancelled" {
                if let Some(ref p) = created_out_path {
                    let _ = std::fs::remove_file(p);
                }
            }
        }

        app.state::<AppState>().operations.lock().unwrap().remove(&operation_id);
        result
    })
    .await
    .map_err(|e| format!("background task failed: {e}"))?
}

#[tauri::command]
pub fn delete_vault_file(
    file_id: String,
    state: State<'_, AppState>,
) -> Result<OperationResult, String> {
    let storage = state.storage()?;

    storage.delete_fragments(&file_id)?;
    let mut manifest = storage.load_manifest()?;
    let filename = manifest.entries.iter()
        .find(|e| e.file_id == file_id)
        .map(|e| e.filename.clone())
        .unwrap_or_else(|| file_id.clone());
    manifest.remove(&file_id);
    storage.save_manifest(&manifest)?;
    storage.log_activity("deleted", &filename);

    Ok(OperationResult::ok("File removed from vault", None))
}

// Replace the full set of fragment destination labels for a vault entry.
// Purely a note to self for the user (e.g. "Fragment 1 -> Mom's laptop") —
// never read by reconstruction, so this can't corrupt or lock out a file.
#[tauri::command]
pub fn update_fragment_labels(
    file_id: String,
    labels: std::collections::HashMap<u8, String>,
    state: State<'_, AppState>,
) -> Result<OperationResult, String> {
    let storage = state.storage()?;
    let mut manifest = storage.load_manifest()?;

    let entry = manifest.entries.iter_mut()
        .find(|e| e.file_id == file_id)
        .ok_or_else(|| "file not found in vault".to_string())?;

    entry.fragment_labels = labels.into_iter()
        .filter(|(_, label)| !label.trim().is_empty())
        .collect();

    storage.save_manifest(&manifest)?;
    Ok(OperationResult::ok("Fragment labels updated", None))
}

// Keep a file pinned to the top of "My Files" — purely a display
// preference, doesn't touch fragments or the encryption key in any way.
#[tauri::command]
pub fn set_file_pinned(
    file_id: String,
    pinned: bool,
    state: State<'_, AppState>,
) -> Result<OperationResult, String> {
    let storage = state.storage()?;
    let mut manifest = storage.load_manifest()?;

    let entry = manifest.entries.iter_mut()
        .find(|e| e.file_id == file_id)
        .ok_or_else(|| "file not found in vault".to_string())?;

    entry.pinned = pinned;

    storage.save_manifest(&manifest)?;
    Ok(OperationResult::ok(
        if pinned { "File pinned" } else { "File unpinned" },
        None,
    ))
}

// Turn a user-supplied display name into a safe single-component filename:
// strip any path components (so it can't be used to escape the intended
// output directory later, e.g. on download) and drop characters that are
// invalid/awkward in filenames. Falls back to `source_name` if nothing
// usable is left after cleaning.
fn sanitize_filename(requested: Option<&str>, source_name: &str) -> String {
    let cleaned: String = requested
        .and_then(|s| std::path::Path::new(s.trim()).file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .chars()
        .filter(|c| !matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        .collect::<String>()
        .trim()
        .to_string();

    if cleaned.is_empty() {
        source_name.to_string()
    } else {
        cleaned
    }
}

fn get_downloads_dir() -> Result<std::path::PathBuf, String> {
    dirs::download_dir().ok_or_else(|| "could not find Downloads folder".to_string())
}

// if a file with the same name already exists, add (1), (2), etc
pub(crate) fn unique_path(dir: &std::path::Path, filename: &str) -> std::path::PathBuf {
    let candidate = dir.join(filename);
    if !candidate.exists() {
        return candidate;
    }

    let p    = std::path::Path::new(filename);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext  = p.extension().and_then(|e| e.to_str());

    for i in 1.. {
        let name = match ext {
            Some(e) => format!("{stem} ({i}).{e}"),
            None    => format!("{stem} ({i})"),
        };
        let path = dir.join(name);
        if !path.exists() {
            return path;
        }
    }
    unreachable!()
}
