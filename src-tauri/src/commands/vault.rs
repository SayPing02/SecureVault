// Commands for vault operations: split, list, download, delete

use crate::commands::dto::{OperationResult, SplitRequest, VaultFileDto};
use crate::core::fragmenter;
use crate::core::model::{SplitParams, VaultEntry};
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
pub fn split_and_store(
    request: SplitRequest,
    state: State<'_, AppState>,
) -> Result<OperationResult, String> {
    let file_bytes = fs::read(&request.file_path)
        .map_err(|e| format!("could not read file: {e}"))?;

    // grab just the filename without the directory path
    let filename = std::path::Path::new(&request.file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed")
        .to_string();

    let params = SplitParams {
        total_fragments: request.total_fragments,
        threshold: request.threshold,
        password: request.password,
    };

    let fragments = fragmenter::split_file(&file_bytes, &filename, &params)?;
    let file_id = fragments[0].file_id.clone();
    let total = fragments[0].total;
    let threshold = fragments[0].threshold;

    let storage = state.storage.lock().map_err(|_| "storage lock poisoned")?;
    storage.store_fragments(&file_id, &fragments)?;

    let mut manifest = storage.load_manifest()?;
    manifest.upsert(VaultEntry {
        file_id,
        filename: filename.clone(),
        size: fragments[0].original_size,
        total_fragments: total,
        threshold,
        password_protected: fragments[0].password_protected,
        created_at: now_unix(),
    });
    storage.save_manifest(&manifest)?;

    Ok(OperationResult::ok(
        format!("'{}' split into {} fragments (threshold {})", filename, total, threshold),
        None,
    ))
}

#[tauri::command]
pub fn list_vault_files(
    state: State<'_, AppState>,
) -> Result<Vec<VaultFileDto>, String> {
    let storage = state.storage.lock().map_err(|_| "storage lock poisoned")?;
    let manifest = storage.load_manifest()?;

    let files = manifest.entries.into_iter().map(|e| VaultFileDto {
        file_id: e.file_id,
        filename: e.filename,
        size: e.size,
        total_fragments: e.total_fragments,
        threshold: e.threshold,
        password_protected: e.password_protected,
        created_at: e.created_at,
    }).collect();

    Ok(files)
}

// Reconstruct a file and save to Downloads
#[tauri::command]
pub fn download_vault_file(
    file_id: String,
    password: Option<String>,
    state: State<'_, AppState>,
) -> Result<OperationResult, String> {
    let storage = state.storage.lock().map_err(|_| "storage lock poisoned")?;
    let fragments = storage.load_fragments(&file_id)?;

    let pw = password.as_deref().filter(|p| !p.is_empty());
    let file_bytes = fragmenter::reconstruct_file(&fragments, pw)?;
    let filename = fragments[0].original_filename.clone();

    let downloads = get_downloads_dir()?;
    let out_path = unique_path(&downloads, &filename);
    fs::write(&out_path, &file_bytes)
        .map_err(|e| format!("could not save file: {e}"))?;

    Ok(OperationResult::ok(
        format!("Reconstructed '{}' to Downloads", filename),
        Some(out_path.to_string_lossy().to_string()),
    ))
}

#[tauri::command]
pub fn delete_vault_file(
    file_id: String,
    state: State<'_, AppState>,
) -> Result<OperationResult, String> {
    let storage = state.storage.lock().map_err(|_| "storage lock poisoned")?;

    storage.delete_fragments(&file_id)?;
    let mut manifest = storage.load_manifest()?;
    manifest.remove(&file_id);
    storage.save_manifest(&manifest)?;

    Ok(OperationResult::ok("File removed from vault", None))
}

fn get_downloads_dir() -> Result<std::path::PathBuf, String> {
    dirs::download_dir().ok_or_else(|| "could not find Downloads folder".to_string())
}

// if a file with the same name already exists, add (1), (2), etc
fn unique_path(dir: &std::path::Path, filename: &str) -> std::path::PathBuf {
    let candidate = dir.join(filename);
    if !candidate.exists() {
        return candidate;
    }

    let p = std::path::Path::new(filename);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = p.extension().and_then(|e| e.to_str());

    for i in 1.. {
        let name = match ext {
            Some(e) => format!("{stem} ({i}).{e}"),
            None => format!("{stem} ({i})"),
        };
        let path = dir.join(name);
        if !path.exists() {
            return path;
        }
    }
    unreachable!()
}
