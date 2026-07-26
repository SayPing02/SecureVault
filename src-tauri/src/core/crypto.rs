// Cryptographic primitives for SecureVault
//
// At-rest vault encryption always uses AES-256-GCM (the encrypt/decrypt fns below).
// User-visible file content uses whichever cipher the user chose (encrypt_file /
// decrypt_file). Both ciphers produce identically-shaped Encrypted structs so the
// rest of the codebase doesn't need to know which one is active.
//
// KDF presets for password-protected keys:
//   "fast"     – PBKDF2-SHA256  10 000 iter  (~10 ms)  — quick sharing
//   "standard" – PBKDF2-SHA256 100 000 iter (~100 ms)  — default
//   "strong"   – PBKDF2-SHA256   1 000 000  (~1 s)     — sensitive files
//   "argon2id" – Argon2id m=64MB, t=3, p=4            — best password resistance

use crate::core::error::{CoreError, CoreResult};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

pub const KEY_LEN:   usize = 32;
pub const NONCE_LEN: usize = 12;
// XChaCha20's extended nonce. At 12 bytes, a randomly generated nonce is only
// safe up to ~2^32 uses of the same key (NIST's bound before collision risk
// becomes non-negligible) — fine for a single file, but the vault's at-rest
// key is reused for the life of the install. 24 bytes pushes that bound out
// far enough that it stops being a practical concern at all.
pub const XNONCE_LEN: usize = 24;
pub const SALT_LEN:  usize = 16;

// Canonical cipher name constants (stored in fragment metadata)
pub const CIPHER_AES256GCM:     &str = "aes256gcm";
pub const CIPHER_CHACHA20POLY:  &str = "chacha20";
pub const CIPHER_XCHACHA20POLY: &str = "xchacha20";
pub const CIPHER_AES256GCM_SIV: &str = "aesgcmsiv";

// Canonical KDF preset name constants
pub const KDF_FAST:     &str = "fast";
pub const KDF_STANDARD: &str = "standard";
pub const KDF_STRONG:   &str = "strong";
pub const KDF_ARGON2ID: &str = "argon2id";

/// Nonce length in bytes for a given file-content cipher name. Every cipher
/// but XChaCha20 uses the standard 12-byte nonce; only XChaCha20 needs the
/// wider 24-byte one. Callers that frame nonces on disk per-chunk (the large
/// file streaming path) need this to know how many bytes to read back.
pub fn nonce_len_for_cipher(cipher_name: &str) -> usize {
    match cipher_name {
        CIPHER_XCHACHA20POLY => XNONCE_LEN,
        _ => NONCE_LEN,
    }
}

#[derive(Debug, Clone)]
pub struct Encrypted {
    pub ciphertext: Vec<u8>,
    // Always NONCE_LEN bytes, except XChaCha20 output (XNONCE_LEN).
    pub nonce: Vec<u8>,
}

pub fn generate_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// Whether this CPU has hardware-accelerated AES — AES-NI on x86_64, or the
/// ARMv8-A crypto extensions on aarch64 (near-universal on modern aarch64
/// desktops/laptops, including Apple Silicon, so treated as always-on rather
/// than runtime-detected there). Used to pick a sensible default cipher;
/// never affects correctness, since every cipher works regardless.
pub fn has_hardware_aes() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("aes")
    }
    #[cfg(target_arch = "aarch64")]
    {
        true
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

// ── At-rest vault encryption (always AES-256-GCM, not user-configurable) ─────

pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> CoreResult<Encrypted> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CoreError::Encryption("AES-GCM encryption failed".into()))?;
    Ok(Encrypted { ciphertext, nonce: nonce_bytes.to_vec() })
}

pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
) -> CoreResult<Vec<u8>> {
    if nonce.len() != NONCE_LEN {
        return Err(CoreError::Decryption("nonce wrong length".into()));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CoreError::Decryption("wrong password or corrupted data".into()))
}

// ── User-chosen cipher for file content ──────────────────────────────────────

pub fn encrypt_file(cipher_name: &str, key: &[u8; KEY_LEN], plaintext: &[u8]) -> CoreResult<Encrypted> {
    match cipher_name {
        CIPHER_AES256GCM | "" => encrypt(key, plaintext),
        CIPHER_CHACHA20POLY    => encrypt_chacha20(key, plaintext),
        CIPHER_XCHACHA20POLY   => encrypt_xchacha20(key, plaintext),
        CIPHER_AES256GCM_SIV   => encrypt_aes_gcm_siv(key, plaintext),
        other => Err(CoreError::Encryption(format!("unknown cipher: {other}"))),
    }
}

pub fn decrypt_file(
    cipher_name: &str,
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
) -> CoreResult<Vec<u8>> {
    match cipher_name {
        CIPHER_AES256GCM | "" => decrypt(key, nonce, ciphertext),
        CIPHER_CHACHA20POLY    => decrypt_chacha20(key, nonce, ciphertext),
        CIPHER_XCHACHA20POLY   => decrypt_xchacha20(key, nonce, ciphertext),
        CIPHER_AES256GCM_SIV   => decrypt_aes_gcm_siv(key, nonce, ciphertext),
        other => Err(CoreError::Decryption(format!("unknown cipher: {other}"))),
    }
}

fn encrypt_chacha20(key: &[u8; KEY_LEN], plaintext: &[u8]) -> CoreResult<Encrypted> {
    use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce, aead::{Aead as ChaAead, KeyInit as ChaKeyInit}};
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CoreError::Encryption("invalid ChaCha20 key".into()))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = ChaNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CoreError::Encryption("ChaCha20-Poly1305 encryption failed".into()))?;
    Ok(Encrypted { ciphertext, nonce: nonce_bytes.to_vec() })
}

fn decrypt_chacha20(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
) -> CoreResult<Vec<u8>> {
    use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce, aead::{Aead as ChaAead, KeyInit as ChaKeyInit}};
    if nonce.len() != NONCE_LEN {
        return Err(CoreError::Decryption("nonce wrong length".into()));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CoreError::Decryption("invalid ChaCha20 key".into()))?;
    let nonce = ChaNonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CoreError::Decryption("ChaCha20-Poly1305 decryption failed".into()))
}

fn encrypt_xchacha20(key: &[u8; KEY_LEN], plaintext: &[u8]) -> CoreResult<Encrypted> {
    use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::{Aead as ChaAead, KeyInit as ChaKeyInit}};
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CoreError::Encryption("invalid XChaCha20 key".into()))?;
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CoreError::Encryption("XChaCha20-Poly1305 encryption failed".into()))?;
    Ok(Encrypted { ciphertext, nonce: nonce_bytes.to_vec() })
}

fn decrypt_xchacha20(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
) -> CoreResult<Vec<u8>> {
    use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::{Aead as ChaAead, KeyInit as ChaKeyInit}};
    if nonce.len() != XNONCE_LEN {
        return Err(CoreError::Decryption("nonce wrong length".into()));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CoreError::Decryption("invalid XChaCha20 key".into()))?;
    let nonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CoreError::Decryption("XChaCha20-Poly1305 decryption failed".into()))
}

fn encrypt_aes_gcm_siv(key: &[u8; KEY_LEN], plaintext: &[u8]) -> CoreResult<Encrypted> {
    use aes_gcm_siv::{Aes256GcmSiv, Nonce as SivNonce, Key as SivKey, aead::{Aead as SivAead, KeyInit as SivKeyInit}};
    let cipher = Aes256GcmSiv::new(SivKey::<Aes256GcmSiv>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = SivNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CoreError::Encryption("AES-256-GCM-SIV encryption failed".into()))?;
    Ok(Encrypted { ciphertext, nonce: nonce_bytes.to_vec() })
}

fn decrypt_aes_gcm_siv(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
) -> CoreResult<Vec<u8>> {
    use aes_gcm_siv::{Aes256GcmSiv, Nonce as SivNonce, Key as SivKey, aead::{Aead as SivAead, KeyInit as SivKeyInit}};
    if nonce.len() != NONCE_LEN {
        return Err(CoreError::Decryption("nonce wrong length".into()));
    }
    let cipher = Aes256GcmSiv::new(SivKey::<Aes256GcmSiv>::from_slice(key));
    let nonce = SivNonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CoreError::Decryption("AES-256-GCM-SIV decryption failed".into()))
}

// ── Key derivation ────────────────────────────────────────────────────────────

/// Derive a 32-byte key from a password using the named KDF preset.
/// The preset name is stored in the fragment so reconstruction uses the same KDF.
pub fn derive_key_kdf(kdf: &str, password: &str, salt: &[u8]) -> CoreResult<[u8; KEY_LEN]> {
    match kdf {
        KDF_FAST              => Ok(derive_pbkdf2(password, salt, 10_000)),
        KDF_STANDARD | ""     => Ok(derive_pbkdf2(password, salt, 100_000)),
        KDF_STRONG            => Ok(derive_pbkdf2(password, salt, 1_000_000)),
        KDF_ARGON2ID          => derive_argon2id(password, salt),
        other => Err(CoreError::Storage(format!("unknown KDF: {other}"))),
    }
}

// Keep old name as a wrapper for storage.rs (always standard-strength)
pub fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    derive_pbkdf2(password, salt, 100_000)
}

fn derive_pbkdf2(password: &str, salt: &[u8], iterations: u32) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
    key
}

fn derive_argon2id(password: &str, salt: &[u8]) -> CoreResult<[u8; KEY_LEN]> {
    use argon2::{Argon2, Algorithm, Params, Version};
    // m=65536 KiB (64 MB RAM), t=3 passes, p=4 threads — OWASP minimum for Argon2id
    let params = Params::new(65_536, 3, 4, Some(KEY_LEN))
        .map_err(|e| CoreError::Storage(format!("argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| CoreError::Encryption(format!("argon2id: {e}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = generate_key();
        let msg = b"the quick brown fox jumps over the lazy dog";
        let enc = encrypt(&key, msg).unwrap();
        let dec = decrypt(&key, &enc.nonce, &enc.ciphertext).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = generate_key();
        let wrong = generate_key();
        let enc = encrypt(&key, b"secret stuff").unwrap();
        assert!(decrypt(&wrong, &enc.nonce, &enc.ciphertext).is_err());
    }

    #[test]
    fn test_tampered_data_fails() {
        let key = generate_key();
        let mut enc = encrypt(&key, b"dont tamper").unwrap();
        enc.ciphertext[0] ^= 0x01;
        assert!(decrypt(&key, &enc.nonce, &enc.ciphertext).is_err());
    }

    #[test]
    fn test_nonce_is_random() {
        let key = generate_key();
        let a = encrypt(&key, b"same message").unwrap();
        let b = encrypt(&key, b"same message").unwrap();
        assert_ne!(a.nonce, b.nonce);
    }

    #[test]
    fn test_password_derivation() {
        let salt = [7u8; SALT_LEN];
        let a = derive_key_from_password("hunter2", &salt);
        let b = derive_key_from_password("hunter2", &salt);
        assert_eq!(a, b);
        let c = derive_key_from_password("hunter3", &salt);
        assert_ne!(a, c);
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key = generate_key();
        let msg = b"chacha20 test message";
        let enc = encrypt_file(CIPHER_CHACHA20POLY, &key, msg).unwrap();
        let dec = decrypt_file(CIPHER_CHACHA20POLY, &key, &enc.nonce, &enc.ciphertext).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn test_xchacha20_roundtrip() {
        let key = generate_key();
        let msg = b"xchacha20 test message, extended nonce";
        let enc = encrypt_file(CIPHER_XCHACHA20POLY, &key, msg).unwrap();
        assert_eq!(enc.nonce.len(), XNONCE_LEN);
        let dec = decrypt_file(CIPHER_XCHACHA20POLY, &key, &enc.nonce, &enc.ciphertext).unwrap();
        assert_eq!(dec, msg);

        let wrong = generate_key();
        assert!(decrypt_file(CIPHER_XCHACHA20POLY, &wrong, &enc.nonce, &enc.ciphertext).is_err());
    }

    #[test]
    fn test_aes_gcm_siv_roundtrip() {
        let key = generate_key();
        let msg = b"aes-256-gcm-siv test message";
        let enc = encrypt_file(CIPHER_AES256GCM_SIV, &key, msg).unwrap();
        assert_eq!(enc.nonce.len(), NONCE_LEN);
        let dec = decrypt_file(CIPHER_AES256GCM_SIV, &key, &enc.nonce, &enc.ciphertext).unwrap();
        assert_eq!(dec, msg);

        let wrong = generate_key();
        assert!(decrypt_file(CIPHER_AES256GCM_SIV, &wrong, &enc.nonce, &enc.ciphertext).is_err());
    }

    #[test]
    fn test_has_hardware_aes_does_not_panic() {
        // Result depends on the machine running the test — just confirm the
        // feature-detection call itself is safe to make.
        let _ = has_hardware_aes();
    }

    #[test]
    fn test_nonce_len_for_cipher() {
        assert_eq!(nonce_len_for_cipher(CIPHER_AES256GCM), NONCE_LEN);
        assert_eq!(nonce_len_for_cipher(CIPHER_CHACHA20POLY), NONCE_LEN);
        assert_eq!(nonce_len_for_cipher(CIPHER_AES256GCM_SIV), NONCE_LEN);
        assert_eq!(nonce_len_for_cipher(CIPHER_XCHACHA20POLY), XNONCE_LEN);
    }

    #[test]
    fn test_kdf_presets_deterministic() {
        let salt = [1u8; SALT_LEN];
        let k1 = derive_key_kdf(KDF_FAST, "pw", &salt).unwrap();
        let k2 = derive_key_kdf(KDF_FAST, "pw", &salt).unwrap();
        assert_eq!(k1, k2);
        let k3 = derive_key_kdf(KDF_STANDARD, "pw", &salt).unwrap();
        assert_ne!(k1, k3); // different iterations → different key
    }

    #[test]
    fn test_argon2id_roundtrip() {
        let salt = [2u8; SALT_LEN];
        let k = derive_key_kdf(KDF_ARGON2ID, "password", &salt).unwrap();
        assert_eq!(k.len(), KEY_LEN);
        let k2 = derive_key_kdf(KDF_ARGON2ID, "password", &salt).unwrap();
        assert_eq!(k, k2);
    }
}
