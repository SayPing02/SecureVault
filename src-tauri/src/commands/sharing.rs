// Commands for sharing files between users
// Export: zip up k fragments and save to Downloads
// Import: load a shared zip, reconstruct, re-fragment into our vault

use crate::commands::dto::OperationResult;
use crate::core::model::{SplitParams, VaultEntry};
use crate::core::{fragmenter, sharing};
use crate::state::AppState;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tauri::command]
pub fn share_vault_file(
    file_id: String,
    state: State<'_, AppState>,
) -> Result<OperationResult, String> {
    let storage = state.storage.lock().map_err(|_| "storage lock poisoned")?;

    let fragments = storage.load_fragments(&file_id)?;
    let filename = fragments[0].original_filename.clone();
    let threshold = fragments[0].threshold;

    let zip_bytes = sharing::package_for_sharing(&fragments)?;

    // save to Downloads as "filename-share.zip" (without the file extension)
    let downloads = dirs::download_dir()
        .ok_or_else(|| "could not find Downloads".to_string())?;
    let stem = std::path::Path::new(&filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&filename);
    let zip_name = format!("{stem}-share.zip");
    let out_path = downloads.join(&zip_name);

    fs::write(&out_path, &zip_bytes)
        .map_err(|e| format!("could not write share file: {e}"))?;

    Ok(OperationResult::ok(
        format!("Share bundle for '{}' saved to Downloads ({} fragments)", filename, threshold),
        Some(out_path.to_string_lossy().to_string()),
    ))
}

// Import a shared zip: reconstruct the file, then re-fragment it
// into our own vault using the original parameters
#[tauri::command]
pub fn import_shared_file(
    zip_path: String,
    password: Option<String>,
    state: State<'_, AppState>,
) -> Result<OperationResult, String> {
    let zip_bytes = fs::read(&zip_path)
        .map_err(|e| format!("could not read share file: {e}"))?;
    let incoming = sharing::import_shared_bundle(&zip_bytes)?;

    let first = &incoming[0];
    let pw = password.as_deref().filter(|p| !p.is_empty());

    // reconstruct the original file
    let file_bytes = fragmenter::reconstruct_file(&incoming, pw)?;
    let filename = first.original_filename.clone();

    // re-fragment with the same n/k/password as the original
    let params = SplitParams {
        total_fragments: first.total,
        threshold: first.threshold,
        password: if first.password_protected { password } else { None },
    };
    let new_frags = fragmenter::split_file(&file_bytes, &filename, &params)?;
    let new_id = new_frags[0].file_id.clone();

    // store in our vault
    let storage = state.storage.lock().map_err(|_| "storage lock poisoned")?;
    storage.store_fragments(&new_id, &new_frags)?;

    let mut manifest = storage.load_manifest()?;
    manifest.upsert(VaultEntry {
        file_id: new_id,
        filename: filename.clone(),
        size: first.original_size,
        total_fragments: first.total,
        threshold: first.threshold,
        password_protected: first.password_protected,
        created_at: now_unix(),
    });
    storage.save_manifest(&manifest)?;

    Ok(OperationResult::ok(
        format!("Imported '{}' into your vault", filename),
        None,
    ))
}

// Peek at a shared zip to see whats inside (filename, size, needs password?)
// Frontend calls this before import so it can prompt for password if needed
#[tauri::command]
pub fn inspect_shared_file(zip_path: String) -> Result<SharedFileInfo, String> {
    let zip_bytes = fs::read(&zip_path)
        .map_err(|e| format!("could not read share file: {e}"))?;
    let fragments = sharing::import_shared_bundle(&zip_bytes)?;
    let first = &fragments[0];

    Ok(SharedFileInfo {
        filename: first.original_filename.clone(),
        size: first.original_size,
        fragment_count: fragments.len(),
        threshold: first.threshold,
        password_protected: first.password_protected,
    })
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedFileInfo {
    pub filename: String,
    pub size: u64,
    pub fragment_count: usize,
    pub threshold: u8,
    pub password_protected: bool,
}
