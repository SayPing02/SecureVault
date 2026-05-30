// App state that gets shared between all tauri commands
// Wrapping Storage in a Mutex so it can be safely used from different threads

use crate::core::storage::Storage;
use std::sync::Mutex;

pub struct AppState {
    pub storage: Mutex<Storage>,
}

impl AppState {
    pub fn new(storage: Storage) -> Self {
        Self {
            storage: Mutex::new(storage),
        }
    }
}
