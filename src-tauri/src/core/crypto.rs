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
pub const SALT_LEN:  usize = 16;

// Canonical cipher name constants (stored in fragment metadata)
pub const CIPHER_AES256GCM:    &str = "aes256gcm";
pub const CIPHER_CHACHA20POLY: &str = "chacha20";

// Canonical KDF preset name constants
pub const KDF_FAST:     &str = "fast";
pub const KDF_STANDARD: &str = "standard";
pub const KDF_STRONG:   &str = "strong";
pub const KDF_ARGON2ID: &str = "argon2id";

#[derive(Debug, Clone)]
pub struct Encrypted {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
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

// ── At-rest vault encryption (always AES-256-GCM, not user-configurable) ─────

pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> CoreResult<Encrypted> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CoreError::Encryption("AES-GCM encryption failed".into()))?;
    Ok(Encrypted { ciphertext, nonce: nonce_bytes })
}

pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> CoreResult<Vec<u8>> {
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
        other => Err(CoreError::Encryption(format!("unknown cipher: {other}"))),
    }
}

pub fn decrypt_file(
    cipher_name: &str,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> CoreResult<Vec<u8>> {
    match cipher_name {
        CIPHER_AES256GCM | "" => decrypt(key, nonce, ciphertext),
        CIPHER_CHACHA20POLY    => decrypt_chacha20(key, nonce, ciphertext),
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
    Ok(Encrypted { ciphertext, nonce: nonce_bytes })
}

fn decrypt_chacha20(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> CoreResult<Vec<u8>> {
    use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce, aead::{Aead as ChaAead, KeyInit as ChaKeyInit}};
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CoreError::Decryption("invalid ChaCha20 key".into()))?;
    let nonce = ChaNonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CoreError::Decryption("ChaCha20-Poly1305 decryption failed".into()))
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
