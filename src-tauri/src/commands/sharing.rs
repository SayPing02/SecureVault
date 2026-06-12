// Commands for sharing and reconstructing from individual fragments
//
// Share: load fragments from vault, package as opaque .svf files in a zip
// Reconstruct: user selects individual .svf files, app decodes and reconstructs
// The .svf files are base64-encoded so they're not human readable,
// but they don't use any machine-specific key so they work on any machine

use crate::commands::dto::OperationResult;
use crate::core::model::{Fragment, SplitParams, VaultEntry};
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

// Export all N fragments as opaque .svf files in a zip to Downloads
#[tauri::command]
pub fn share_vault_file(
    file_id: String,
    state: State<'_, AppState>,
) -> Result<OperationResult, String> {
    let storage = state.storage.lock().map_err(|_| "storage lock poisoned")?;

    // load and decrypt fragments from vault (at-rest decryption)
    let fragments = storage.load_fragments(&file_id)?;
    let filename = fragments[0].original_filename.clone();
    let count = fragments.len();

    // package them as opaque .svf files (portable, no machine-specific key)
    let zip_bytes = sharing::package_all_fragments(&fragments)?;

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
        format!("Share bundle for '{}' saved to Downloads ({} fragments)", filename, count),
        Some(out_path.to_string_lossy().to_string()),
    ))
}

// Reconstruct a file from individual .svf fragment files
// The .svf files use opaque encoding so they work from any machine
#[tauri::command]
pub fn reconstruct_from_fragments(
    fragment_paths: Vec<String>,
    password: Option<String>,
    state: State<'_, AppState>,
) -> Result<OperationResult, String> {
    if fragment_paths.is_empty() {
        return Err("no fragment files selected".to_string());
    }

    // read and decode each .svf file
    let mut fragments = Vec::new();
    for path_str in &fragment_paths {
        let data = fs::read(path_str)
            .map_err(|e| format!("could not read {}: {e}", path_str))?;
        let frag = sharing::read_opaque_fragment(&data)?;
        fragments.push(frag);
    }

    let first = &fragments[0];
    let filename = first.original_filename.clone();
    let threshold = first.threshold;

    if fragments.len() < threshold as usize {
        return Err(format!(
            "need at least {} fragments to reconstruct '{}', but only {} selected",
            threshold, filename, fragments.len()
        ));
    }

    let pw = password.as_deref().filter(|p| !p.is_empty());

    // reconstruct the original file
    let file_bytes = fragmenter::reconstruct_file(&fragments, pw)?;

    // re-fragment and store in this vault
    let params = SplitParams {
        total_fragments: first.total,
        threshold: first.threshold,
        password: if first.password_protected { password } else { None },
    };
    let new_frags = fragmenter::split_file(&file_bytes, &filename, &params)?;
    let new_id = new_frags[0].file_id.clone();

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
        format!("Reconstructed '{}' and stored in vault", filename),
        None,
    ))
}

// Inspect selected .svf files to show details before reconstruction
#[tauri::command]
pub fn inspect_fragments(
    fragment_paths: Vec<String>,
) -> Result<FragmentSetInfo, String> {
    if fragment_paths.is_empty() {
        return Err("no fragment files selected".to_string());
    }

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
