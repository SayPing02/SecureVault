// App state shared between all Tauri commands.
// Storage is Arc-wrapped so commands can clone a reference and run concurrent
// operations (e.g. parallel fragment writes). Storage handles its own internal
// locking where needed (manifest reads/writes use an internal Mutex).
//
// `storage` is optional: when biometric lock is enabled, the vault's secret
// lives in the OS keychain rather than on disk, so `Storage` can't be built
// until the frontend has loaded and the user has authenticated via
// `unlock_vault_with_biometric`. Until then every command that needs storage
// gets a "vault is locked" error instead of panicking or blocking.

use crate::core::op_control::OpControl;
use crate::core::storage::Storage;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct AppState {
    storage: Mutex<Option<Arc<Storage>>>,
    // In-flight pause/resume/cancel controls, keyed by a client-generated operation id.
    pub operations: Mutex<HashMap<String, Arc<OpControl>>>,
}

impl AppState {
    pub fn new(storage: Option<Storage>) -> Self {
        Self {
            storage: Mutex::new(storage.map(Arc::new)),
            operations: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the storage handle, or an error if the vault hasn't been
    /// unlocked yet (biometric lock enabled, authentication not yet done).
    pub fn storage(&self) -> Result<Arc<Storage>, String> {
        self.storage
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "vault is locked".to_string())
    }

    /// Whether storage has been unlocked yet.
    pub fn is_unlocked(&self) -> bool {
        self.storage.lock().unwrap().is_some()
    }

    /// Populate storage after a successful unlock (biometric or startup).
    pub fn set_storage(&self, storage: Storage) {
        *self.storage.lock().unwrap() = Some(Arc::new(storage));
    }

    /// Drop the in-memory storage handle, e.g. for the auto-lock timer.
    /// Any operation already running keeps its own `Arc<Storage>` clone
    /// (captured before this runs) and finishes normally — only *new*
    /// commands see the vault as locked afterward.
    pub fn clear_storage(&self) {
        *self.storage.lock().unwrap() = None;
    }
}
