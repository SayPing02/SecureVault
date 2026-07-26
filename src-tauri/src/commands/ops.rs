// Commands for pausing/resuming/cancelling an in-flight vault operation.
// The frontend generates the operation_id up front and passes it into the
// initiating command (split_and_store, download_vault_file, etc.), so it's
// always known before there's anything to control.

use crate::state::AppState;
use tauri::State;

#[tauri::command]
pub fn pause_operation(operation_id: String, state: State<'_, AppState>) -> Result<(), String> {
    if let Some(ctl) = state.operations.lock().unwrap().get(&operation_id) {
        ctl.pause();
    }
    // Silently no-op if not found — the operation already finished, which
    // isn't an error condition worth surfacing to the user.
    Ok(())
}

#[tauri::command]
pub fn resume_operation(operation_id: String, state: State<'_, AppState>) -> Result<(), String> {
    if let Some(ctl) = state.operations.lock().unwrap().get(&operation_id) {
        ctl.resume();
    }
    Ok(())
}

#[tauri::command]
pub fn cancel_operation(operation_id: String, state: State<'_, AppState>) -> Result<(), String> {
    if let Some(ctl) = state.operations.lock().unwrap().get(&operation_id) {
        ctl.cancel();
    }
    Ok(())
}
