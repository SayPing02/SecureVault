// Commands for sharing and reconstructing from individual fragments
//
// Share: load fragments from vault, package as opaque .svf files in a zip
// Reconstruct: user selects individual .svf files, app decodes and reconstructs
// The .svf files are base64-encoded so they're not human readable,
// but they don't use any machine-specific key so they work on any machine

use crate::commands::dto::OperationResult;
use crate::commands::vault::unique_path;
use crate::core::model::{Fragment, SplitParams, VaultEntry};
use crate::core::op_control::OpControl;
use crate::core::{crypto, fragmenter, large_fragment, sharing};
use crate::state::AppState;
use std::fs;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri::async_runtime::spawn_blocking;
use uuid::Uuid;
use zeroize::Zeroize;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// Turn a user-supplied name into a safe zip filename: strip any path
// components (so it can't be used to write outside Downloads), drop
// characters that are invalid/awkward in filenames, and make sure it ends
// in ".zip". Falls back to `default_name` if nothing usable is left.
fn sanitize_zip_name(requested: Option<&str>, default_name: &str) -> String {
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
        return default_name.to_string();
    }

    if cleaned.to_lowercase().ends_with(".zip") {
        cleaned
    } else {
        format!("{cleaned}.zip")
    }
}

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ShareProgress {
    percent: u8,
    message: String,
}

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportProgress {
    percent: u8,
    message: String,
}

// Export all N fragments as opaque .svf files in a zip to Downloads.
// If the file is password-protected, the correct password must be supplied
// or the export is refused — sharing exposes every fragment (not just the
// threshold), so re-confirming the password before export is required, not
// just gated in the UI.
#[tauri::command]
pub async fn share_vault_file(
    file_id: String,
    mut password: Option<String>,
    zip_name: Option<String>,
    operation_id: String,
    _state: State<'_, AppState>,
    app: AppHandle,
) -> Result<OperationResult, String> {
    spawn_blocking(move || {
        let ctl = OpControl::new();
        app.state::<AppState>().operations.lock().unwrap().insert(operation_id.clone(), ctl.clone());

        // Sharing never writes anything until the very last step (the share
        // zip itself), and every checkpoint below runs before that write, so
        // a cancellation never needs to clean anything up.
        let result = (|| -> Result<OperationResult, String> {
            let storage: Arc<_> = app.state::<AppState>().storage()?;
            macro_rules! emit {
                ($pct:expr, $msg:expr) => {
                    let _ = app.emit("share-progress", ShareProgress {
                        percent: $pct,
                        message: String::from($msg),
                    });
                };
            }

            emit!(2, "Checking password…");

            let manifest = storage.load_manifest()?;
            let (password_protected, threshold, fragment_labels) = manifest.entries.iter()
                .find(|e| e.file_id == file_id)
                .map(|e| (e.password_protected, e.threshold, e.fragment_labels.clone()))
                .ok_or_else(|| "file not found in vault".to_string())?;

            if password_protected {
                let pw = password.as_deref().filter(|p| !p.is_empty());
                let frag_dir = storage.frag_dir(&file_id);
                let shard_files = large_fragment::find_shard_files(&frag_dir).unwrap_or_default();

                let verified = if !shard_files.is_empty() {
                    large_fragment::verify_password(&shard_files, pw, storage.at_rest_key()).is_ok()
                } else {
                    let sample = storage.load_fragments_limited(&file_id, threshold as usize)?;
                    fragmenter::verify_password(&sample, pw).is_ok()
                };

                if !verified {
                    password.zeroize();
                    return Err("incorrect password".to_string());
                }
            }
            password.zeroize();

            ctl.checkpoint()?;
            emit!(10, "Reading vault fragments…");

            let fragments = storage.load_fragments(&file_id)?;

            let (mut zip_bytes, filename, count) = if fragments.is_empty() {
                // Large file — package portable shards
                let frag_dir = storage.frag_dir(&file_id);
                let app2 = app.clone();
                large_fragment::package_shards_for_sharing_with_progress(
                    &frag_dir,
                    storage.at_rest_key(),
                    &ctl,
                    move |pct, msg| {
                        // Map packaging's 0-100 into overall 15-90%
                        let overall = 15u8 + (pct as u32 * 75 / 100) as u8;
                        let _ = app2.emit("share-progress", ShareProgress {
                            percent: overall,
                            message: msg.to_string(),
                        });
                    },
                )
                .map_err(|e| format!("could not package shards: {e}"))?
            } else {
                // Small file — package opaque .svf fragments
                emit!(50, "Packaging fragments…");
                let name = fragments[0].original_filename.clone();
                let n = fragments.len();
                let zip = sharing::package_all_fragments(&fragments, &ctl)
                    .map_err(|e| format!("could not package fragments: {e}"))?;
                (zip, name, n)
            };

            if !fragment_labels.is_empty() {
                zip_bytes = sharing::append_labels_file(zip_bytes, &fragment_labels)
                    .map_err(|e| format!("could not add fragment labels: {e}"))?;
            }

            emit!(92, "Writing share bundle…");

            let downloads = dirs::download_dir()
                .ok_or_else(|| "could not find Downloads".to_string())?;
            let stem = std::path::Path::new(&filename)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(&filename);
            let default_name = format!("{stem}-share.zip");
            let zip_name = sanitize_zip_name(zip_name.as_deref(), &default_name);
            let out_path = unique_path(&downloads, &zip_name);

            fs::write(&out_path, &zip_bytes)
                .map_err(|e| format!("could not write share file: {e}"))?;

            storage.log_activity("shared", &filename);
            emit!(100, "Done");
            Ok(OperationResult::ok(
                format!("Share bundle for '{}' saved to Downloads ({} fragments)", filename, count),
                Some(out_path.to_string_lossy().to_string()),
            ))
        })();

        app.state::<AppState>().operations.lock().unwrap().remove(&operation_id);
        result
    })
    .await
    .map_err(|e| format!("background task failed: {e}"))?
}

// Reconstruct a file from individual .svf / .svf3 fragment files
#[tauri::command]
pub async fn reconstruct_from_fragments(
    fragment_paths: Vec<String>,
    mut password: Option<String>,
    operation_id: String,
    _state: State<'_, AppState>,
    app: AppHandle,
) -> Result<OperationResult, String> {
    if fragment_paths.is_empty() {
        return Err("no fragment files selected".to_string());
    }

    spawn_blocking(move || {
        let ctl = OpControl::new();
        app.state::<AppState>().operations.lock().unwrap().insert(operation_id.clone(), ctl.clone());

        // Set as soon as a new vault entry's id is known, so a cancellation
        // that fires after fragments/shards were written can clean them up.
        let mut created_id: Option<String> = None;

        let result = (|| -> Result<OperationResult, String> {
            let storage: Arc<_> = app.state::<AppState>().storage()?;
            let pw = password.as_deref().filter(|p| !p.is_empty());

            macro_rules! emit {
                ($pct:expr, $msg:expr) => {
                    let _ = app.emit("import-progress", ImportProgress {
                        percent: $pct,
                        message: String::from($msg),
                    });
                };
            }

            emit!(2, "Reading fragment files…");

            // Detect format from first file
            let first_data = fs::read(&fragment_paths[0])
                .map_err(|e| format!("could not read {}: {e}", fragment_paths[0]))?;

            if first_data.starts_with(large_fragment::MAGIC_PORTABLE) {
                // ── Large-file portable shards (.svf3) ──────────────────────────────
                let n = fragment_paths.len();
                let mut portable_shards: Vec<(u8, Vec<u8>)> = Vec::new();
                for (i, path_str) in fragment_paths.iter().enumerate() {
                    ctl.checkpoint()?;
                    let data = fs::read(path_str)
                        .map_err(|e| format!("could not read {}: {e}", path_str))?;
                    let meta = large_fragment::meta_from_portable_bytes(&data)
                        .map_err(|e| format!("bad shard file {}: {e}", path_str))?;
                    portable_shards.push((meta.shard_index, data));
                    emit!(2 + (((i + 1) * 40 / n.max(1)) as u8), format!("Read shard {} of {}…", i + 1, n));
                }

                let meta = large_fragment::meta_from_portable_bytes(&portable_shards[0].1)
                    .map_err(|e| e.to_string())?;

                if portable_shards.len() < meta.threshold as usize {
                    return Err(format!(
                        "need at least {} shards, but only {} selected",
                        meta.threshold, portable_shards.len()
                    ));
                }

                let new_id = Uuid::new_v4().to_string();
                created_id = Some(new_id.clone());
                let frag_dir = storage.frag_dir(&new_id);

                emit!(50, "Importing shards into vault…");

                // Import: re-encrypt headers with this machine's at-rest key, write shards
                large_fragment::import_portable_shards(&portable_shards, &frag_dir, storage.at_rest_key())
                    .map_err(|e| format!("import failed: {e}"))?;

                emit!(90, "Updating manifest…");

                let mut manifest = storage.load_manifest()?;
                manifest.upsert(VaultEntry {
                    file_id: new_id.clone(),
                    filename: meta.original_filename.clone(),
                    size: meta.original_size,
                    total_fragments: meta.total,
                    threshold: meta.threshold,
                    password_protected: meta.password_protected,
                    created_at: now_unix(),
                    is_large: true,
                    fragment_labels: Default::default(),
                    pinned: Default::default(),
                    last_rotated_at: Default::default(),
                });
                storage.save_manifest(&manifest)?;
                storage.log_activity("reconstructed", &meta.original_filename);

                password.zeroize();
                emit!(100, "Done");
                return Ok(OperationResult::ok(
                    format!("Imported '{}' and stored in vault ({} shards)", meta.original_filename, portable_shards.len()),
                    None,
                ));
            }

            // ── Small-file opaque fragments (.svf) ───────────────────────────────────
            let n = fragment_paths.len();
            let mut fragments: Vec<Fragment> = Vec::new();
            for (i, path_str) in fragment_paths.iter().enumerate() {
                ctl.checkpoint()?;
                let data = fs::read(path_str)
                    .map_err(|e| format!("could not read {}: {e}", path_str))?;
                let frag = sharing::read_opaque_fragment(&data)?;
                fragments.push(frag);
                emit!(2 + (((i + 1) * 18 / n.max(1)) as u8), format!("Read fragment {} of {}…", i + 1, n));
            }

            let first = &fragments[0];
            let filename = first.original_filename.clone();
            if fragments.len() < first.threshold as usize {
                return Err(format!(
                    "need at least {} fragments to reconstruct '{}', but only {} selected",
                    first.threshold, filename, fragments.len()
                ));
            }

            let app2 = app.clone();
            let file_bytes = fragmenter::reconstruct_file_with_progress(
                &fragments,
                pw,
                move |pct, msg| {
                    // Map reconstruct's 0-100 into overall 20-55%
                    let overall = 20u8 + (pct as u32 * 35 / 100) as u8;
                    let _ = app2.emit("import-progress", ImportProgress {
                        percent: overall,
                        message: msg.to_string(),
                    });
                },
            )?;

            let params_password = if first.password_protected { password.take() } else { None };
            password.zeroize();

            let mut params = SplitParams {
                total_fragments: first.total,
                threshold:       first.threshold,
                password:        params_password,
                compress:        first.compressed,
                cipher:          first.cipher.clone(),
                kdf:             first.kdf.clone(),
                padding_pct:     first.padding_pct,
            };

            let app3 = app.clone();
            let new_frags = fragmenter::split_file_with_progress(
                &file_bytes,
                &filename,
                &params,
                move |pct, msg| {
                    // Map split's 0-100 into overall 55-90%
                    let overall = 55u8 + (pct as u32 * 35 / 100) as u8;
                    let _ = app3.emit("import-progress", ImportProgress {
                        percent: overall,
                        message: msg.to_string(),
                    });
                },
            )?;
            params.password.zeroize();
            let new_id = new_frags[0].file_id.clone();
            created_id = Some(new_id.clone());
            storage.store_fragments(&new_id, &new_frags)?;

            emit!(95, "Updating manifest…");

            let mut manifest = storage.load_manifest()?;
            manifest.upsert(VaultEntry {
                file_id: new_id,
                filename: filename.clone(),
                size: first.original_size,
                total_fragments: first.total,
                threshold: first.threshold,
                password_protected: first.password_protected,
                created_at: now_unix(),
                is_large: false,
                fragment_labels: Default::default(),
                pinned: Default::default(),
                last_rotated_at: Default::default(),
            });
            storage.save_manifest(&manifest)?;
            storage.log_activity("reconstructed", &filename);

            emit!(100, "Done");
            Ok(OperationResult::ok(
                format!("Reconstructed '{}' and stored in vault", filename),
                None,
            ))
        })();

        if let Err(ref e) = result {
            if e == "operation cancelled" {
                if let Some(ref id) = created_id {
                    if let Ok(storage) = app.state::<AppState>().storage() {
                        let _ = storage.delete_fragments(id);
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

// Quick check for whether `password` unlocks a selected set of fragment/shard
// files, without doing the full reconstruction. Lets the UI reject a wrong
// password immediately instead of running the whole import first.
#[tauri::command]
pub fn verify_fragment_password(
    fragment_paths: Vec<String>,
    mut password: String,
) -> Result<bool, String> {
    if fragment_paths.is_empty() {
        return Err("no fragment files selected".to_string());
    }
    let pw = Some(password.as_str()).filter(|p| !p.is_empty());

    let first_data = fs::read(&fragment_paths[0])
        .map_err(|e| format!("could not read {}: {e}", fragment_paths[0]))?;

    if first_data.starts_with(large_fragment::MAGIC_PORTABLE) {
        // Large-file portable shards (.svf3) — read_meta handles the portable
        // format directly, so any placeholder at-rest key works here.
        let dummy_key = [0u8; crypto::KEY_LEN];
        let shard_files: Vec<(u8, std::path::PathBuf)> = fragment_paths.iter()
            .map(|p| {
                let path = std::path::PathBuf::from(p);
                let meta = large_fragment::read_meta(&path, &dummy_key)
                    .map_err(|e| format!("bad shard file {p}: {e}"))?;
                Ok((meta.shard_index, path))
            })
            .collect::<Result<_, String>>()?;
        let result = large_fragment::verify_password(&shard_files, pw, &dummy_key).is_ok();
        password.zeroize();
        return Ok(result);
    }

    // Small-file opaque fragments (.svf) — each one also carries a full copy
    // of the file's ciphertext, so stop as soon as we have `threshold` of
    // them rather than decoding every selected file.
    let mut fragments: Vec<Fragment> = Vec::new();
    for path_str in &fragment_paths {
        if let Some(first) = fragments.first() {
            let first: &Fragment = first;
            if fragments.len() >= first.threshold as usize { break; }
        }
        let data = fs::read(path_str)
            .map_err(|e| format!("could not read {}: {e}", path_str))?;
        fragments.push(sharing::read_opaque_fragment(&data)?);
    }
    let result = fragmenter::verify_password(&fragments, pw).is_ok();
    password.zeroize();
    Ok(result)
}

// Inspect selected .svf / .svf3 files to show details before reconstruction
#[tauri::command]
pub fn inspect_fragments(
    fragment_paths: Vec<String>,
) -> Result<FragmentSetInfo, String> {
    if fragment_paths.is_empty() {
        return Err("no fragment files selected".to_string());
    }

    let first_data = fs::read(&fragment_paths[0])
        .map_err(|e| format!("could not read {}: {e}", fragment_paths[0]))?;

    if first_data.starts_with(large_fragment::MAGIC_PORTABLE) {
        // Large-file portable shards (.svf3)
        let meta = large_fragment::meta_from_portable_bytes(&first_data)
            .map_err(|e| format!("bad shard file: {e}"))?;
        let count = fragment_paths.len();
        return Ok(FragmentSetInfo {
            filename: meta.original_filename.clone(),
            size: meta.original_size,
            fragments_loaded: count,
            threshold: meta.threshold,
            total: meta.total,
            password_protected: meta.password_protected,
            enough_to_reconstruct: count >= meta.threshold as usize,
        });
    }

    // Small-file opaque fragments (.svf)
    let mut fragments: Vec<Fragment> = Vec::new();
    for path_str in &fragment_paths {
        let data = fs::read(path_str)
            .map_err(|e| format!("could not read {}: {e}", path_str))?;
        let frag = sharing::read_opaque_fragment(&data)?;
        fragments.push(frag);
    }

    let first = &fragments[0];
    let enough = fragments.len() >= first.threshold as usize;

    Ok(FragmentSetInfo {
        filename: first.original_filename.clone(),
        size: first.original_size,
        fragments_loaded: fragments.len(),
        threshold: first.threshold,
        total: first.total,
        password_protected: first.password_protected,
        enough_to_reconstruct: enough,
    })
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FragmentSetInfo {
    pub filename: String,
    pub size: u64,
    pub fragments_loaded: usize,
    pub threshold: u8,
    pub total: u8,
    pub password_protected: bool,
    pub enough_to_reconstruct: bool,
}
