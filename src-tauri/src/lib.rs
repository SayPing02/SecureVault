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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let app_data_dir = app
                .path()
                .app_data_dir()
                .expect("should have an app data directory");

            std::fs::create_dir_all(&app_data_dir)
                .expect("failed to create app data dir");

            let storage = Storage::new(&app_data_dir)
                .expect("failed to init storage");

            app.manage(AppState::new(storage));

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault::split_and_store,
            commands::vault::list_vault_files,
            commands::vault::download_vault_file,
            commands::vault::delete_vault_file,
            commands::sharing::share_vault_file,
            commands::sharing::reconstruct_from_fragments,
            commands::sharing::inspect_fragments,
        ])
        .run(tauri::generate_context!())
        .expect("error while running SecureVault");
}
