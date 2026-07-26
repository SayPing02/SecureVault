// Tauri glue for vault backup/restore — the actual format and crypto live
// in core::backup so they can be unit-tested without a running app.

use crate::commands::dto::BackupImportResultDto;
use crate::core::backup;
use crate::state::AppState;
use tauri::async_runtime::spawn_blocking;
use tauri::{AppHandle, Manager, State};

#[tauri::command]
pub async fn export_vault_backup(
    password: String,
    destination_path: String,
    _state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    if password.chars().count() < backup::MIN_BACKUP_PASSWORD_LENGTH {
        return Err(format!(
            "backup password must be at least {} characters",
            backup::MIN_BACKUP_PASSWORD_LENGTH
        ));
    }

    spawn_blocking(move || -> Result<(), String> {
        let storage = app.state::<AppState>().storage()?;
        let bytes = backup::export_bytes(&storage, &password)?;
        std::fs::write(&destination_path, bytes)
            .map_err(|e| format!("could not write backup file: {e}"))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn import_vault_backup(
    password: String,
    source_path: String,
    _state: State<'_, AppState>,
    app: AppHandle,
) -> Result<BackupImportResultDto, String> {
    spawn_blocking(move || -> Result<BackupImportResultDto, String> {
        let storage = app.state::<AppState>().storage()?;

        let existing = storage.load_manifest()?;
        if !existing.entries.is_empty() {
            return Err(
                "this vault already has files in it — restoring a backup only works into an \
                 empty vault, to avoid silently overwriting anything. Start with a fresh \
                 install (or an empty vault) and try again."
                    .to_string(),
            );
        }

        let bytes = std::fs::read(&source_path).map_err(|e| format!("could not read backup file: {e}"))?;
        let files_restored = backup::import_bytes(&storage, &password, &bytes)?;
        Ok(BackupImportResultDto { files_restored })
    })
    .await
    .map_err(|e| e.to_string())?
}
