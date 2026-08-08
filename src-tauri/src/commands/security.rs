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

// Recovery code: a second, independent way to unwrap the vault secret, for
// when the PIN is forgotten. Argon2id makes a forgotten PIN genuinely
// unrecoverable by design, so without this there is no path back at all —
// the vault is simply gone. Same model as FileVault/BitLocker recovery keys:
// the code is generated on-device, shown exactly once, and never stored
// anywhere — only a copy of the secret wrapped under a key derived from it.
// This is not a backdoor: nobody but whoever holds the code can use it.
//
// Crockford Base32 — the output alphabet omits I, L, O and U so there is
// nothing ambiguous to transcribe, and `normalize_recovery_code` folds the
// classic look-alikes back on input, so a mis-read character still works.
// 256 is an exact multiple of 32, so sampling a byte modulo the alphabet
// length is unbiased.
const RECOVERY_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const RECOVERY_CHARS: usize = 25; // 25 x 5 bits = 125 bits of entropy
const RECOVERY_GROUP: usize = 5;

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
    // A second wrapped copy of the *same* secret, keyed by the recovery code
    // instead of the PIN. Present whenever pin_enabled is true.
    #[serde(default)]
    recovery_salt_b64: Option<String>,
    #[serde(default)]
    recovery_nonce_b64: Option<String>,
    #[serde(default)]
    recovery_wrapped_secret_b64: Option<String>,
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
    // The recovery path gets its *own* counter rather than sharing the PIN's.
    // Sharing would mean the lockout from failed PIN guesses also blocks the
    // recovery code — which is exactly the moment someone reaches for it.
    #[serde(default)]
    failed_recovery_attempts: u32,
    #[serde(default)]
    recovery_locked_until_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityStatusDto {
    pub biometric_available: bool,
    // "Touch ID" / "Face ID" / "Windows Hello" — for UI copy only.
    pub biometry_label: String,
    pub biometric_enabled: bool,
    pub pin_enabled: bool,
    pub recovery_code_set: bool,
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

/// Decrypt one wrapped copy of the vault secret with a candidate passphrase.
/// A wrong passphrase fails here (AES-GCM auth tag mismatch) rather than
/// silently returning garbage. Shared by the PIN and recovery-code paths —
/// both wrap the *same* 32 secret bytes, just under different keys.
fn unwrap_secret_blob(
    salt_b64: Option<&str>,
    nonce_b64: Option<&str>,
    wrapped_b64: Option<&str>,
    passphrase: &str,
    corrupt_msg: &str,
    wrong_msg: &str,
) -> Result<[u8; 32], String> {
    let salt = B64.decode(salt_b64.unwrap_or(""))
        .map_err(|_| corrupt_msg.to_string())?;
    let nonce = B64.decode(nonce_b64.unwrap_or(""))
        .map_err(|_| corrupt_msg.to_string())?;
    let ciphertext = B64.decode(wrapped_b64.unwrap_or(""))
        .map_err(|_| corrupt_msg.to_string())?;
    if nonce.len() != crypto::NONCE_LEN {
        return Err(corrupt_msg.to_string());
    }

    let key = crypto::derive_key_kdf(PIN_KDF, passphrase, &salt).map_err(|e| e.to_string())?;
    let secret_vec = crypto::decrypt(&key, &nonce, &ciphertext)
        .map_err(|_| wrong_msg.to_string())?;
    if secret_vec.len() != 32 {
        return Err(corrupt_msg.to_string());
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_vec);
    Ok(secret)
}

fn unwrap_secret_with_pin(flag: &SecurityFlag, pin: &str) -> Result<[u8; 32], String> {
    unwrap_secret_blob(
        flag.pin_salt_b64.as_deref(),
        flag.pin_nonce_b64.as_deref(),
        flag.pin_wrapped_secret_b64.as_deref(),
        pin,
        "PIN data is corrupt",
        "incorrect PIN",
    )
}

fn unwrap_secret_with_recovery_code(flag: &SecurityFlag, code: &str) -> Result<[u8; 32], String> {
    if flag.recovery_wrapped_secret_b64.is_none() {
        return Err("no recovery code is set up for this vault".to_string());
    }
    unwrap_secret_blob(
        flag.recovery_salt_b64.as_deref(),
        flag.recovery_nonce_b64.as_deref(),
        flag.recovery_wrapped_secret_b64.as_deref(),
        &normalize_recovery_code(code),
        "recovery data is corrupt",
        "incorrect recovery code",
    )
}

/// A fresh, random recovery code in `XXXXX-XXXXX-…` form. Never persisted —
/// the caller shows it to the user once and then it exists only wherever
/// they chose to write it down.
fn generate_recovery_code() -> String {
    let bytes = crypto::random_bytes(RECOVERY_CHARS);
    let mut out = String::with_capacity(RECOVERY_CHARS + RECOVERY_CHARS / RECOVERY_GROUP);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && i % RECOVERY_GROUP == 0 {
            out.push('-');
        }
        out.push(RECOVERY_ALPHABET[*b as usize % RECOVERY_ALPHABET.len()] as char);
    }
    out
}

/// Fold typed input back to canonical form: drop separators, uppercase, and
/// correct the look-alikes the output alphabet deliberately avoids.
fn normalize_recovery_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            'U' => 'V',
            other => other,
        })
        .collect()
}

/// Wrap `secret` under a key derived from `code`, storing the result in the
/// flag's recovery fields. Replaces any previous recovery copy.
fn set_recovery_wrapping(
    flag: &mut SecurityFlag,
    secret: &[u8; 32],
    code: &str,
) -> Result<(), String> {
    let salt = crypto::generate_salt();
    let key = crypto::derive_key_kdf(PIN_KDF, &normalize_recovery_code(code), &salt)
        .map_err(|e| e.to_string())?;
    let encrypted = crypto::encrypt(&key, secret).map_err(|e| e.to_string())?;
    flag.recovery_salt_b64 = Some(B64.encode(salt));
    flag.recovery_nonce_b64 = Some(B64.encode(&encrypted.nonce));
    flag.recovery_wrapped_secret_b64 = Some(B64.encode(&encrypted.ciphertext));
    flag.failed_recovery_attempts = 0;
    flag.recovery_locked_until_ms = None;
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Refuse the attempt outright while a backoff window is still open.
fn check_lockout(locked_until_ms: Option<u64>) -> Result<(), String> {
    if let Some(until) = locked_until_ms {
        let now = now_ms();
        if now < until {
            let remaining = (until - now).div_ceil(1000);
            return Err(format!(
                "too many incorrect attempts — try again in {remaining}s"
            ));
        }
    }
    Ok(())
}

/// Bump the failure counter and, past the free-attempt allowance, open a
/// backoff window that doubles with each further failure.
fn record_failure(attempts: &mut u32, locked_until_ms: &mut Option<u64>) {
    *attempts += 1;
    if *attempts >= PIN_LOCKOUT_FREE_ATTEMPTS {
        let extra = (*attempts - PIN_LOCKOUT_FREE_ATTEMPTS).min(7);
        let secs = (PIN_LOCKOUT_BASE_SECS << extra).min(PIN_LOCKOUT_MAX_SECS);
        *locked_until_ms = Some(now_ms() + secs * 1000);
    }
}

/// `unwrap_secret_with_pin`, but backed by a persisted attempt counter and
/// exponential-backoff lockout — see `PIN_LOCKOUT_*` above. Every PIN-gated
/// command (unlock, disable) should go through this, not the raw unwrap.
fn unlock_with_pin_guarded(app: &AppHandle, pin: &str) -> Result<[u8; 32], String> {
    let mut flag = read_flag(app);
    check_lockout(flag.pin_locked_until_ms)?;

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
            record_failure(&mut flag.failed_pin_attempts, &mut flag.pin_locked_until_ms);
            let _ = write_flag(app, &flag);
            Err(e)
        }
    }
}

/// Same guarding for the recovery code, on its own independent counter.
fn unlock_with_recovery_guarded(app: &AppHandle, code: &str) -> Result<[u8; 32], String> {
    let mut flag = read_flag(app);
    check_lockout(flag.recovery_locked_until_ms)?;

    match unwrap_secret_with_recovery_code(&flag, code) {
        Ok(secret) => {
            if flag.failed_recovery_attempts != 0 || flag.recovery_locked_until_ms.is_some() {
                flag.failed_recovery_attempts = 0;
                flag.recovery_locked_until_ms = None;
                let _ = write_flag(app, &flag);
            }
            Ok(secret)
        }
        Err(e) => {
            record_failure(
                &mut flag.failed_recovery_attempts,
                &mut flag.recovery_locked_until_ms,
            );
            let _ = write_flag(app, &flag);
            Err(e)
        }
    }
}

/// Best-effort sweep of fragment folders left behind by an interrupted
/// add-file operation. Deferred to unlock time on the locked path, since
/// `lib.rs`'s startup hook has no storage to sweep with yet.
fn cleanup_orphans(storage: &Storage) {
    match storage.cleanup_orphaned_fragments() {
        Ok(0) => {}
        Ok(n) => eprintln!(
            "SecureVault: removed {n} orphaned fragment folder(s) left over from an interrupted add-file operation"
        ),
        Err(e) => eprintln!("SecureVault: could not check for orphaned fragments: {e}"),
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
        recovery_code_set: flag.recovery_wrapped_secret_b64.is_some(),
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
pub async fn enable_biometric_lock(app: AppHandle) -> Result<String, String> {
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

    // Issue a fresh recovery code for the biometric lock, replacing any the
    // PIN had. Biometric arguably needs this *more* than a PIN does: the
    // keychain entry can be lost outright — new machine, keychain reset,
    // sensor failure — and unlike a forgotten PIN there's nothing the user
    // could even try to remember. Written before the plaintext file is
    // removed, so a failure here leaves the original state intact.
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);
    let recovery_code = generate_recovery_code();
    let mut flag = read_flag(&app);
    set_recovery_wrapping(&mut flag, &secret, &recovery_code)?;

    fs::remove_file(&secret_path).map_err(|e| {
        format!("the secret was copied to the keychain, but the old plaintext copy on disk could not be removed: {e}")
    })?;

    flag.biometric_enabled = true;
    flag.pin_enabled = false;
    flag.pin_salt_b64 = None;
    flag.pin_nonce_b64 = None;
    flag.pin_wrapped_secret_b64 = None;
    write_flag(&app, &flag)?;

    Ok(recovery_code)
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

    // The secret is back in its plaintext file, so the recovery wrapping is
    // meaningless now and must not linger as a second live door.
    let mut flag = read_flag(&app);
    flag.biometric_enabled = false;
    flag.recovery_salt_b64 = None;
    flag.recovery_nonce_b64 = None;
    flag.recovery_wrapped_secret_b64 = None;
    flag.failed_recovery_attempts = 0;
    flag.recovery_locked_until_ms = None;
    write_flag(&app, &flag)
}

/// Replace the recovery code for a biometric-locked vault. The PIN variant
/// can't serve here — there is no PIN — so ownership is proven by the
/// Touch ID / Windows Hello prompt that `get_data` raises.
#[tauri::command]
pub async fn regenerate_recovery_code_biometric(app: AppHandle) -> Result<String, String> {
    let response = app.biometry()
        .get_data(GetDataOptions {
            domain: KEYCHAIN_DOMAIN.to_string(),
            name: KEYCHAIN_NAME.to_string(),
            reason: "Confirm to issue a new SecureVault recovery code".to_string(),
            cancel_title: None,
        })
        .map_err(|e| e.to_string())?;

    let secret_bytes = B64.decode(&response.data)
        .map_err(|_| "could not decode the stored vault secret".to_string())?;
    if secret_bytes.len() != 32 {
        return Err("stored vault secret is corrupt".to_string());
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);

    let code = generate_recovery_code();
    let mut flag = read_flag(&app);
    set_recovery_wrapping(&mut flag, &secret, &code)?;
    write_flag(&app, &flag)?;

    Ok(code)
}

// --- PIN lock ---
// Same relocation idea as biometric, but the gate is a PIN-derived key
// (Argon2id, the strongest KDF preset already used for per-file passwords)
// instead of an OS API. No platform APIs, no code signing, no entitlements
// — this works identically on every OS the app runs on.

/// Returns the one-time recovery code. The caller MUST show it to the user
/// immediately — it is never written down anywhere else, and there is no way
/// to retrieve it again afterwards (only to replace it, which needs the PIN).
#[tauri::command]
pub fn enable_pin_lock(pin: String, app: AppHandle) -> Result<String, String> {
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
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);

    let salt = crypto::generate_salt();
    let key = crypto::derive_key_kdf(PIN_KDF, &pin, &salt).map_err(|e| e.to_string())?;
    let encrypted = crypto::encrypt(&key, &secret_bytes).map_err(|e| e.to_string())?;

    // Wrap the same secret a second time under a fresh recovery code, so a
    // forgotten PIN isn't the end of the vault. Built before the plaintext
    // file is removed, so a failure here leaves the original state intact.
    let recovery_code = generate_recovery_code();
    let mut flag = read_flag(&app);
    set_recovery_wrapping(&mut flag, &secret, &recovery_code)?;

    fs::remove_file(&secret_path)
        .map_err(|e| format!("could not remove the old plaintext secret file: {e}"))?;

    flag.pin_enabled = true;
    flag.biometric_enabled = false;
    flag.pin_salt_b64 = Some(B64.encode(salt));
    flag.pin_nonce_b64 = Some(B64.encode(&encrypted.nonce));
    flag.pin_wrapped_secret_b64 = Some(B64.encode(&encrypted.ciphertext));
    flag.failed_pin_attempts = 0;
    flag.pin_locked_until_ms = None;
    write_flag(&app, &flag)?;

    Ok(recovery_code)
}

#[tauri::command]
pub fn disable_pin_lock(pin: String, state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    if !state.operations.lock().unwrap().is_empty() {
        return Err("an operation is still running — wait for it to finish before disabling the PIN".to_string());
    }

    let secret = unlock_with_pin_guarded(&app, &pin)?;

    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    fs::write(app_data_dir.join(APP_SECRET_NAME), secret)
        .map_err(|e| format!("could not restore the plaintext secret file: {e}"))?;

    // The secret is back in its plaintext file, so both wrapped copies —
    // PIN and recovery — are now meaningless and must not linger.
    let mut new_flag = read_flag(&app);
    new_flag.pin_enabled = false;
    new_flag.pin_salt_b64 = None;
    new_flag.pin_nonce_b64 = None;
    new_flag.pin_wrapped_secret_b64 = None;
    new_flag.recovery_salt_b64 = None;
    new_flag.recovery_nonce_b64 = None;
    new_flag.recovery_wrapped_secret_b64 = None;
    new_flag.failed_pin_attempts = 0;
    new_flag.pin_locked_until_ms = None;
    new_flag.failed_recovery_attempts = 0;
    new_flag.recovery_locked_until_ms = None;
    write_flag(&app, &new_flag)
}

/// The way back in after a forgotten PIN, or a Touch ID / Windows Hello that
/// can no longer be used: unwrap the secret with the recovery code, re-wrap
/// it under a new PIN, and issue a fresh recovery code (the old one is
/// consumed — reusing it would mean a code that stays valid forever after
/// being written on a piece of paper somewhere). Unlocks the vault on success
/// and returns the new recovery code.
///
/// Recovery always lands in PIN mode, whichever lock was in use before. For a
/// biometric vault that's the point: the reason you're here is that the
/// keychain entry is gone, so re-arming the same broken door would be no help.
/// Touch ID can be switched back on from Settings once you're in.
#[tauri::command]
pub fn recover_with_code(
    recovery_code: String,
    new_pin: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<String, String> {
    if new_pin.chars().count() < MIN_PIN_LENGTH {
        return Err(format!("PIN must be at least {MIN_PIN_LENGTH} characters"));
    }

    let secret = unlock_with_recovery_guarded(&app, &recovery_code)?;

    let salt = crypto::generate_salt();
    let key = crypto::derive_key_kdf(PIN_KDF, &new_pin, &salt).map_err(|e| e.to_string())?;
    let encrypted = crypto::encrypt(&key, &secret).map_err(|e| e.to_string())?;

    let next_code = generate_recovery_code();
    let mut flag = read_flag(&app);
    let was_biometric = flag.biometric_enabled;
    set_recovery_wrapping(&mut flag, &secret, &next_code)?;
    flag.pin_enabled = true;
    flag.biometric_enabled = false;
    flag.pin_salt_b64 = Some(B64.encode(salt));
    flag.pin_nonce_b64 = Some(B64.encode(&encrypted.nonce));
    flag.pin_wrapped_secret_b64 = Some(B64.encode(&encrypted.ciphertext));
    flag.failed_pin_attempts = 0;
    flag.pin_locked_until_ms = None;
    write_flag(&app, &flag)?;

    // Best-effort tidy-up of the now-unused keychain copy. Deliberately
    // ignores failure: an unreachable keychain is the likeliest reason for
    // being in this function at all, and it must not fail the recovery.
    if was_biometric {
        let _ = app.biometry().remove_data(DataOptions {
            domain: KEYCHAIN_DOMAIN.to_string(),
            name: KEYCHAIN_NAME.to_string(),
        });
    }

    if !state.is_unlocked() {
        let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
        let storage = Storage::from_secret(&app_data_dir, secret).map_err(|e| e.to_string())?;
        cleanup_orphans(&storage);
        state.set_storage(storage);
    }

    Ok(next_code)
}

/// Replace the recovery code with a fresh one — for when the old code is
/// lost, or was written somewhere the user no longer trusts. Requires the
/// current PIN, which is what proves this is the vault's owner.
#[tauri::command]
pub fn regenerate_recovery_code(pin: String, app: AppHandle) -> Result<String, String> {
    let secret = unlock_with_pin_guarded(&app, &pin)?;

    let code = generate_recovery_code();
    let mut flag = read_flag(&app);
    set_recovery_wrapping(&mut flag, &secret, &code)?;
    write_flag(&app, &flag)?;

    Ok(code)
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

    cleanup_orphans(&storage);
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

    cleanup_orphans(&storage);
    state.set_storage(storage);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrapped_flag(secret: &[u8; 32], code: &str) -> SecurityFlag {
        let mut flag = SecurityFlag::default();
        set_recovery_wrapping(&mut flag, secret, code).unwrap();
        flag
    }

    #[test]
    fn generated_code_is_well_formed_and_unique() {
        let a = generate_recovery_code();
        let b = generate_recovery_code();

        // 25 characters in 5 dash-separated groups of 5.
        assert_eq!(a.len(), RECOVERY_CHARS + RECOVERY_CHARS / RECOVERY_GROUP - 1);
        let groups: Vec<&str> = a.split('-').collect();
        assert_eq!(groups.len(), RECOVERY_CHARS / RECOVERY_GROUP);
        assert!(groups.iter().all(|g| g.len() == RECOVERY_GROUP));

        // Only characters from the unambiguous alphabet — nothing a user
        // could misread as something else.
        assert!(a
            .chars()
            .filter(|c| *c != '-')
            .all(|c| RECOVERY_ALPHABET.contains(&(c as u8))));
        assert!(!a.contains('I') && !a.contains('L') && !a.contains('O') && !a.contains('U'));

        assert_ne!(a, b, "two generated codes must not collide");
    }

    #[test]
    fn recovery_code_round_trips_and_rejects_a_wrong_code() {
        let secret = [7u8; 32];
        let code = "ABCDE-12345-VWXYZ-67890-JKMNP";
        let flag = wrapped_flag(&secret, code);

        assert_eq!(unwrap_secret_with_recovery_code(&flag, code).unwrap(), secret);
        assert!(unwrap_secret_with_recovery_code(&flag, "ABCDE-12345-VWXYZ-67890-JKMNQ").is_err());
    }

    #[test]
    fn recovery_code_tolerates_realistic_transcription_slips() {
        let secret = [3u8; 32];
        let code = "ABCDE-12345-VWXYZ-67890-JKMNP";
        let flag = wrapped_flag(&secret, code);

        // Lowercase, spaces instead of dashes, no separators at all.
        assert_eq!(
            unwrap_secret_with_recovery_code(&flag, "abcde 12345 vwxyz 67890 jkmnp").unwrap(),
            secret
        );
        assert_eq!(
            unwrap_secret_with_recovery_code(&flag, "ABCDE12345VWXYZ67890JKMNP").unwrap(),
            secret
        );
        // The look-alikes the output alphabet deliberately avoids: someone
        // reading handwriting types I for 1, O for 0, U for V.
        assert_eq!(
            unwrap_secret_with_recovery_code(&flag, "ABCDE-I2345-UWXYZ-6789O-JKMNP").unwrap(),
            secret
        );
    }

    #[test]
    fn pin_and_recovery_code_unwrap_the_same_secret() {
        // The whole point: two independent doors to one vault, not two
        // different vaults.
        let secret = [42u8; 32];
        let pin = "1234";
        let code = "ABCDE-12345-VWXYZ-67890-JKMNP";

        let salt = crypto::generate_salt();
        let key = crypto::derive_key_kdf(PIN_KDF, pin, &salt).unwrap();
        let encrypted = crypto::encrypt(&key, &secret).unwrap();

        let mut flag = wrapped_flag(&secret, code);
        flag.pin_enabled = true;
        flag.pin_salt_b64 = Some(B64.encode(salt));
        flag.pin_nonce_b64 = Some(B64.encode(&encrypted.nonce));
        flag.pin_wrapped_secret_b64 = Some(B64.encode(&encrypted.ciphertext));

        assert_eq!(unwrap_secret_with_pin(&flag, pin).unwrap(), secret);
        assert_eq!(unwrap_secret_with_recovery_code(&flag, code).unwrap(), secret);
    }

    #[test]
    fn a_reissued_code_replaces_the_previous_one() {
        // Both the PIN and biometric "replace code" paths call
        // set_recovery_wrapping again over the top. The old code must stop
        // working — otherwise every code ever issued stays valid forever,
        // and "replace" would be a lie.
        let secret = [11u8; 32];
        let first = "ABCDE-12345-VWXYZ-67890-JKMNP";
        let second = "22222-33333-44444-55555-66666";

        let mut flag = wrapped_flag(&secret, first);
        assert_eq!(unwrap_secret_with_recovery_code(&flag, first).unwrap(), secret);

        set_recovery_wrapping(&mut flag, &secret, second).unwrap();
        assert_eq!(unwrap_secret_with_recovery_code(&flag, second).unwrap(), secret);
        assert!(
            unwrap_secret_with_recovery_code(&flag, first).is_err(),
            "the superseded code must no longer open the vault"
        );
    }

    #[test]
    fn reissuing_clears_any_open_recovery_lockout() {
        // Otherwise someone who locked themselves out guessing, then issued a
        // fresh code, would still be stuck behind the old backoff window.
        let secret = [5u8; 32];
        let mut flag = SecurityFlag {
            failed_recovery_attempts: 9,
            recovery_locked_until_ms: Some(now_ms() + 60_000),
            ..Default::default()
        };

        set_recovery_wrapping(&mut flag, &secret, "ABCDE-12345-VWXYZ-67890-JKMNP").unwrap();

        assert_eq!(flag.failed_recovery_attempts, 0);
        assert!(flag.recovery_locked_until_ms.is_none());
        assert!(check_lockout(flag.recovery_locked_until_ms).is_ok());
    }

    #[test]
    fn recovery_is_refused_when_no_code_was_ever_set_up() {
        let flag = SecurityFlag::default();
        let err = unwrap_secret_with_recovery_code(&flag, "ABCDE-12345-VWXYZ-67890-JKMNP")
            .unwrap_err();
        assert!(err.contains("no recovery code"), "unexpected error: {err}");
    }

    #[test]
    fn lockout_opens_only_after_the_free_attempts_and_backs_off() {
        let mut attempts = 0u32;
        let mut until = None;

        for _ in 0..(PIN_LOCKOUT_FREE_ATTEMPTS - 1) {
            record_failure(&mut attempts, &mut until);
        }
        assert!(until.is_none(), "typos inside the free allowance must not lock");
        assert!(check_lockout(until).is_ok());

        record_failure(&mut attempts, &mut until);
        let first = until.expect("lockout should open at the threshold");
        assert!(check_lockout(until).is_err());

        record_failure(&mut attempts, &mut until);
        let second = until.expect("still locked");
        assert!(second > first, "each further failure must extend the backoff");
    }
}
