// Main entry point for the Tauri app
// Sets up the storage backend and registers all the commands
// that the frontend can call

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod core;
mod state;

use crate::core::storage::Storage;
use crate::state::AppState;
use tauri::Manager;
use tauri_plugin_dialog::{DialogExt, MessageDialogKind};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_biometry::init())
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir().unwrap_or_else(|e| {
                fatal_startup_error(
                    app,
                    &format!("SecureVault could not determine where to store its data.\n\n{e}"),
                )
            });

            if let Err(e) = std::fs::create_dir_all(&app_data_dir) {
                fatal_startup_error(
                    app,
                    &format!(
                        "SecureVault could not create its data folder:\n{}\n\n{e}",
                        app_data_dir.display()
                    ),
                );
            }

            // When biometric lock is enabled, the vault's secret lives in the
            // OS keychain, not on disk — there's no window yet to prompt
            // Touch ID through, so storage stays unset until the frontend
            // calls `unlock_vault_with_biometric`. Everyone who hasn't
            // opted into the feature gets the exact behavior this app has
            // always had: storage is ready immediately, no lock screen.
            if commands::security::is_locked(&app_data_dir) {
                app.manage(AppState::new(None));
            } else {
                let storage = Storage::new(&app_data_dir).unwrap_or_else(|e| {
                    fatal_startup_error(
                        app,
                        &format!(
                            "SecureVault could not open its vault storage.\n\n{e}\n\n\
                            If this vault belongs to a different machine or user account, \
                            it cannot be opened here."
                        ),
                    )
                });

                match storage.cleanup_orphaned_fragments() {
                    Ok(0) => {}
                    Ok(n) => eprintln!(
                        "SecureVault: removed {n} orphaned fragment folder(s) left over from an interrupted add-file operation"
                    ),
                    Err(e) => eprintln!("SecureVault: could not check for orphaned fragments: {e}"),
                }

                app.manage(AppState::new(Some(storage)));
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault::get_file_size,
            commands::vault::recommend_cipher,
            commands::vault::split_and_store,
            commands::vault::rotate_vault_file,
            commands::vault::list_vault_files,
            commands::vault::get_activity_log,
            commands::vault::clear_activity_log,
            commands::vault::check_vault_file_integrity,
            commands::vault::verify_file_password,
            commands::vault::download_vault_file,
            commands::vault::delete_vault_file,
            commands::vault::update_fragment_labels,
            commands::vault::set_file_pinned,
            commands::sharing::share_vault_file,
            commands::sharing::reconstruct_from_fragments,
            commands::sharing::verify_fragment_password,
            commands::sharing::inspect_fragments,
            commands::ops::pause_operation,
            commands::ops::resume_operation,
            commands::ops::cancel_operation,
            commands::security::security_status,
            commands::security::enable_biometric_lock,
            commands::security::disable_biometric_lock,
            commands::security::unlock_vault_with_biometric,
            commands::security::enable_pin_lock,
            commands::security::disable_pin_lock,
            commands::security::unlock_vault_with_pin,
            commands::security::recover_with_code,
            commands::security::regenerate_recovery_code,
            commands::security::regenerate_recovery_code_biometric,
            commands::security::lock_vault,
            commands::security::set_auto_lock_minutes,
            commands::backup::export_vault_backup,
            commands::backup::import_vault_backup,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            // No window exists yet if the runtime itself failed to start, so this
            // uses a standalone native dialog instead of the app's dialog plugin.
            rfd::MessageDialog::new()
                .set_title("SecureVault failed to start")
                .set_description(format!("{e}"))
                .set_level(rfd::MessageLevel::Error)
                .show();
            std::process::exit(1);
        });
}

// Show a blocking native error dialog, then exit — used in place of a panic
// so a startup failure is visible to the user instead of a silent crash.
fn fatal_startup_error(app: &tauri::App, message: &str) -> ! {
    app.dialog()
        .message(message)
        .title("SecureVault failed to start")
        .kind(MessageDialogKind::Error)
        .blocking_show();
    std::process::exit(1);
}
