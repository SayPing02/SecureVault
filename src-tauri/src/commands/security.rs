// Optional app lock: Touch ID / Windows Hello, or a PIN — either way, the
// vault's actual secret bytes (the ones `at_rest_key` is derived from) are
// *relocated*, never re-derived. When no lock is set, `app.secret` is a
// plain file on disk exactly like before this feature existed. When one is
// on, those same bytes are moved somewhere gated instead — the OS
// keychain/credential store for biometric, or a PIN-encrypted blob for PIN
// — so turning either on or off never requires re-encrypting anything
// already in the vault; only where the secret bytes are read from changes.
//
// The two methods are mutually exclusive: the secret only ever lives in one
// place at a time, so enabling one requires the other to be off first.

use crate::core::crypto;
use crate::core::storage::Storage;
use crate::state::AppState;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_biometry::{AuthOptions, BiometryExt, DataOptions, GetDataOptions, SetDataOptions};

const SECURITY_FLAG_NAME: &str = "security.json";
const APP_SECRET_NAME: &str = "app.secret";
const KEYCHAIN_DOMAIN: &str = "com.securevault.app";
const KEYCHAIN_NAME: &str = "vault-secret";
const PIN_KDF: &str = crypto::KDF_ARGON2ID;
const MIN_PIN_LENGTH: usize = 4;

// PIN lockout: Argon2id already makes each guess slow, but that alone isn't
// a real limit on total guesses over time. The first few wrong attempts are
// free (typos happen); past that, lockout duration doubles each additional
// failure, capped at an hour. This state lives on disk in the same flag
// file as the PIN itself, not in memory, specifically so restarting the app
// doesn't reset the counter.
const PIN_LOCKOUT_FREE_ATTEMPTS: u32 = 5;
const PIN_LOCKOUT_BASE_SECS: u64 = 30;
const PIN_LOCKOUT_MAX_SECS: u64 = 3600;

#[derive(Debug, Default, Serialize, Deserialize)]
struct SecurityFlag {
    #[serde(default)]
    biometric_enabled: bool,
    #[serde(default)]
    pin_enabled: bool,
    // Only present while pin_enabled is true.
    #[serde(default)]
    pin_salt_b64: Option<String>,
    #[serde(default)]
    pin_nonce_b64: Option<String>,
    #[serde(default)]
    pin_wrapped_secret_b64: Option<String>,
    // Minutes of inactivity before auto re-lock; 0 = never. Independent of
    // which lock method is active, so it survives toggling between them.
    #[serde(default)]
    auto_lock_minutes: u32,
    // Consecutive wrong-PIN guesses since the last success, and the Unix-ms
    // timestamp until which further attempts are refused. Reset on success
    // or whenever the PIN is (re-)enabled.
    #[serde(default)]
    failed_pin_attempts: u32,
    #[serde(default)]
    pin_locked_until_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityStatusDto {
    pub biometric_available: bool,
    // "Touch ID" / "Face ID" / "Windows Hello" — for UI copy only.
    pub biometry_label: String,
    pub biometric_enabled: bool,
    pub pin_enabled: bool,
    pub vault_locked: bool,
    pub auto_lock_minutes: u32,
}

fn flag_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app.path().app_data_dir().map_err(|e| e.to_string())?.join(SECURITY_FLAG_NAME))
}

fn read_flag(app: &AppHandle) -> SecurityFlag {
    flag_path(app).ok()
        .and_then(|p| fs::read(p).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write_flag(app: &AppHandle, flag: &SecurityFlag) -> Result<(), String> {
    let path = flag_path(app)?;
    let json = serde_json::to_vec_pretty(flag).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| e.to_string())
}

/// Read directly from the app data dir, for use at startup in `lib.rs`
/// before any Tauri command/AppHandle machinery is available.
pub fn is_locked(app_data_dir: &std::path::Path) -> bool {
    fs::read(app_data_dir.join(SECURITY_FLAG_NAME)).ok()
        .and_then(|bytes| serde_json::from_slice::<SecurityFlag>(&bytes).ok())
        .map(|f| f.biometric_enabled || f.pin_enabled)
        .unwrap_or(false)
}

/// Decrypt the PIN-wrapped secret with a candidate PIN. A wrong PIN fails
/// here (AES-GCM auth tag mismatch) rather than silently returning garbage.
fn unwrap_secret_with_pin(flag: &SecurityFlag, pin: &str) -> Result<[u8; 32], String> {
    let salt = B64.decode(flag.pin_salt_b64.as_deref().unwrap_or(""))
        .map_err(|_| "PIN data is corrupt".to_string())?;
    let nonce_vec = B64.decode(flag.pin_nonce_b64.as_deref().unwrap_or(""))
        .map_err(|_| "PIN data is corrupt".to_string())?;
    let ciphertext = B64.decode(flag.pin_wrapped_secret_b64.as_deref().unwrap_or(""))
        .map_err(|_| "PIN data is corrupt".to_string())?;
    if nonce_vec.len() != crypto::NONCE_LEN {
        return Err("PIN data is corrupt".to_string());
    }
    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(&nonce_vec);

    let key = crypto::derive_key_kdf(PIN_KDF, pin, &salt).map_err(|e| e.to_string())?;
    let secret_vec = crypto::decrypt(&key, &nonce, &ciphertext)
        .map_err(|_| "incorrect PIN".to_string())?;
    if secret_vec.len() != 32 {
        return Err("PIN data is corrupt".to_string());
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_vec);
    Ok(secret)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `unwrap_secret_with_pin`, but backed by a persisted attempt counter and
/// exponential-backoff lockout — see `PIN_LOCKOUT_*` above. Every PIN-gated
/// command (unlock, disable) should go through this, not the raw unwrap.
fn unlock_with_pin_guarded(app: &AppHandle, pin: &str) -> Result<[u8; 32], String> {
    let mut flag = read_flag(app);

    if let Some(until) = flag.pin_locked_until_ms {
        let now = now_ms();
        if now < until {
            let remaining = (until - now).div_ceil(1000);
            return Err(format!(
                "too many incorrect attempts — try again in {remaining}s"
            ));
        }
    }

    match unwrap_secret_with_pin(&flag, pin) {
        Ok(secret) => {
            if flag.failed_pin_attempts != 0 || flag.pin_locked_until_ms.is_some() {
                flag.failed_pin_attempts = 0;
                flag.pin_locked_until_ms = None;
                let _ = write_flag(app, &flag);
            }
            Ok(secret)
        }
        Err(e) => {
            flag.failed_pin_attempts += 1;
            if flag.failed_pin_attempts >= PIN_LOCKOUT_FREE_ATTEMPTS {
                let extra = (flag.failed_pin_attempts - PIN_LOCKOUT_FREE_ATTEMPTS).min(7);
                let secs = (PIN_LOCKOUT_BASE_SECS << extra).min(PIN_LOCKOUT_MAX_SECS);
                flag.pin_locked_until_ms = Some(now_ms() + secs * 1000);
            }
            let _ = write_flag(app, &flag);
            Err(e)
        }
    }
}

fn biometry_label(app: &AppHandle) -> String {
    if cfg!(target_os = "macos") {
        match app.biometry().status() {
            Ok(s) if matches!(s.biometry_type, tauri_plugin_biometry::BiometryType::FaceID) => "Face ID",
            _ => "Touch ID",
        }.to_string()
    } else if cfg!(target_os = "windows") {
        "Windows Hello".to_string()
    } else {
        "biometric authentication".to_string()
    }
}

#[tauri::command]
pub fn security_status(state: State<'_, AppState>, app: AppHandle) -> Result<SecurityStatusDto, String> {
    let flag = read_flag(&app);
    let available = app.biometry().status().map(|s| s.is_available).unwrap_or(false);

    Ok(SecurityStatusDto {
        biometric_available: available,
        biometry_label: biometry_label(&app),
        biometric_enabled: flag.biometric_enabled,
        pin_enabled: flag.pin_enabled,
        vault_locked: !state.is_unlocked(),
        auto_lock_minutes: flag.auto_lock_minutes,
    })
}

/// Re-lock the vault immediately — drops the in-memory key (see
/// `AppState::clear_storage`) so it's a real lock, not a UI overlay. Refuses
/// if no lock method is set up, since that would leave no way back in.
#[tauri::command]
pub fn lock_vault(state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    let flag = read_flag(&app);
    if !flag.biometric_enabled && !flag.pin_enabled {
        return Err("no lock method is set up".to_string());
    }
    state.clear_storage();
    Ok(())
}

/// Persist how long the app can sit idle before auto-locking. 0 = never.
#[tauri::command]
pub fn set_auto_lock_minutes(minutes: u32, app: AppHandle) -> Result<(), String> {
    let mut flag = read_flag(&app);
    flag.auto_lock_minutes = minutes;
    write_flag(&app, &flag)
}

#[tauri::command]
pub async fn enable_biometric_lock(app: AppHandle) -> Result<(), String> {
    if read_flag(&app).pin_enabled {
        return Err("PIN lock is already on — turn it off before enabling Touch ID".to_string());
    }

    let status = app.biometry().status().map_err(|e| e.to_string())?;
    if !status.is_available {
        return Err("biometric authentication is not available on this device".to_string());
    }

    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let secret_path = app_data_dir.join(APP_SECRET_NAME);
    let secret_bytes = fs::read(&secret_path)
        .map_err(|e| format!("could not read the vault secret: {e}"))?;
    if secret_bytes.len() != 32 {
        return Err("vault secret file is corrupt".to_string());
    }

    // Require a fresh, explicit confirmation before handing the secret over
    // to the OS-gated store — set_data itself doesn't require auth to write,
    // only later reads do, so this is what actually stops someone from
    // silently flipping the toggle on an already-unlocked session.
    app.biometry()
        .authenticate(
            "Confirm to enable Touch ID protection for SecureVault".to_string(),
            AuthOptions::default(),
        )
        .map_err(|e| e.to_string())?;

    app.biometry()
        .set_data(SetDataOptions {
            domain: KEYCHAIN_DOMAIN.to_string(),
            name: KEYCHAIN_NAME.to_string(),
            data: B64.encode(&secret_bytes),
        })
        .map_err(|e| e.to_string())?;

    fs::remove_file(&secret_path).map_err(|e| {
        format!("the secret was copied to the keychain, but the old plaintext copy on disk could not be removed: {e}")
    })?;

    let mut flag = read_flag(&app);
    flag.biometric_enabled = true;
    flag.pin_enabled = false;
    flag.pin_salt_b64 = None;
    flag.pin_nonce_b64 = None;
    flag.pin_wrapped_secret_b64 = None;
    write_flag(&app, &flag)
}

#[tauri::command]
pub async fn disable_biometric_lock(state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    if !state.operations.lock().unwrap().is_empty() {
        return Err("an operation is still running — wait for it to finish before disabling Touch ID".to_string());
    }

    let response = app.biometry()
        .get_data(GetDataOptions {
            domain: KEYCHAIN_DOMAIN.to_string(),
            name: KEYCHAIN_NAME.to_string(),
            reason: "Confirm to disable Touch ID protection for SecureVault".to_string(),
            cancel_title: None,
        })
        .map_err(|e| e.to_string())?;

    let secret_bytes = B64.decode(&response.data)
        .map_err(|_| "could not decode the stored vault secret".to_string())?;
    if secret_bytes.len() != 32 {
        return Err("stored vault secret is corrupt".to_string());
    }

    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    fs::write(app_data_dir.join(APP_SECRET_NAME), &secret_bytes)
        .map_err(|e| format!("could not restore the plaintext secret file: {e}"))?;

    app.biometry()
        .remove_data(DataOptions { domain: KEYCHAIN_DOMAIN.to_string(), name: KEYCHAIN_NAME.to_string() })
        .map_err(|e| e.to_string())?;

    let mut flag = read_flag(&app);
    flag.biometric_enabled = false;
    write_flag(&app, &flag)
}

// --- PIN lock ---
// Same relocation idea as biometric, but the gate is a PIN-derived key
// (Argon2id, the strongest KDF preset already used for per-file passwords)
// instead of an OS API. No platform APIs, no code signing, no entitlements
// — this works identically on every OS the app runs on.

#[tauri::command]
pub fn enable_pin_lock(pin: String, app: AppHandle) -> Result<(), String> {
    if read_flag(&app).biometric_enabled {
        return Err("Touch ID lock is already on — turn it off before enabling a PIN".to_string());
    }
    if pin.chars().count() < MIN_PIN_LENGTH {
        return Err(format!("PIN must be at least {MIN_PIN_LENGTH} characters"));
    }

    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let secret_path = app_data_dir.join(APP_SECRET_NAME);
    let secret_bytes = fs::read(&secret_path)
        .map_err(|e| format!("could not read the vault secret: {e}"))?;
    if secret_bytes.len() != 32 {
        return Err("vault secret file is corrupt".to_string());
    }

    let salt = crypto::generate_salt();
    let key = crypto::derive_key_kdf(PIN_KDF, &pin, &salt).map_err(|e| e.to_string())?;
    let encrypted = crypto::encrypt(&key, &secret_bytes).map_err(|e| e.to_string())?;

    fs::remove_file(&secret_path)
        .map_err(|e| format!("could not remove the old plaintext secret file: {e}"))?;

    let mut flag = read_flag(&app);
    flag.pin_enabled = true;
    flag.biometric_enabled = false;
    flag.pin_salt_b64 = Some(B64.encode(salt));
    flag.pin_nonce_b64 = Some(B64.encode(encrypted.nonce));
    flag.pin_wrapped_secret_b64 = Some(B64.encode(&encrypted.ciphertext));
    flag.failed_pin_attempts = 0;
    flag.pin_locked_until_ms = None;
    write_flag(&app, &flag)
}

#[tauri::command]
pub fn disable_pin_lock(pin: String, state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    if !state.operations.lock().unwrap().is_empty() {
        return Err("an operation is still running — wait for it to finish before disabling the PIN".to_string());
    }

    let secret = unlock_with_pin_guarded(&app, &pin)?;

    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    fs::write(app_data_dir.join(APP_SECRET_NAME), &secret)
        .map_err(|e| format!("could not restore the plaintext secret file: {e}"))?;

    let mut new_flag = read_flag(&app);
    new_flag.pin_enabled = false;
    new_flag.pin_salt_b64 = None;
    new_flag.pin_nonce_b64 = None;
    new_flag.pin_wrapped_secret_b64 = None;
    new_flag.failed_pin_attempts = 0;
    new_flag.pin_locked_until_ms = None;
    write_flag(&app, &new_flag)
}

/// Same role as `unlock_vault_with_biometric`, gated by a PIN instead.
#[tauri::command]
pub fn unlock_vault_with_pin(pin: String, state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    if state.is_unlocked() {
        return Ok(());
    }

    let secret = unlock_with_pin_guarded(&app, &pin)?;

    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let storage = Storage::from_secret(&app_data_dir, secret).map_err(|e| e.to_string())?;

    match storage.cleanup_orphaned_fragments() {
        Ok(0) => {}
        Ok(n) => eprintln!(
            "SecureVault: removed {n} orphaned fragment folder(s) left over from an interrupted add-file operation"
        ),
        Err(e) => eprintln!("SecureVault: could not check for orphaned fragments: {e}"),
    }

    state.set_storage(storage);
    Ok(())
}

/// Called from the frontend once it has loaded, when `security_status` (or
/// the startup flag check in `lib.rs`) says the vault is locked. Prompts
/// Touch ID / Windows Hello, then builds `Storage` from the retrieved
/// secret and populates `AppState` — the same thing `lib.rs`'s `.setup()`
/// does eagerly for the non-biometric path.
#[tauri::command]
pub async fn unlock_vault_with_biometric(state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    if state.is_unlocked() {
        return Ok(());
    }

    let response = app.biometry()
        .get_data(GetDataOptions {
            domain: KEYCHAIN_DOMAIN.to_string(),
            name: KEYCHAIN_NAME.to_string(),
            reason: "Unlock SecureVault".to_string(),
            cancel_title: None,
        })
        .map_err(|e| e.to_string())?;

    let secret_vec = B64.decode(&response.data)
        .map_err(|_| "could not decode the stored vault secret".to_string())?;
    if secret_vec.len() != 32 {
        return Err("stored vault secret is corrupt".to_string());
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_vec);

    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let storage = Storage::from_secret(&app_data_dir, secret).map_err(|e| e.to_string())?;

    match storage.cleanup_orphaned_fragments() {
        Ok(0) => {}
        Ok(n) => eprintln!(
            "SecureVault: removed {n} orphaned fragment folder(s) left over from an interrupted add-file operation"
        ),
        Err(e) => eprintln!("SecureVault: could not check for orphaned fragments: {e}"),
    }

    state.set_storage(storage);
    Ok(())
}
