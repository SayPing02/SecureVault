// AES-256-GCM encryption and key derivation
// GCM gives us both encryption AND integrity checking - if someone
// tampers with the ciphertext or uses the wrong key, decryption will
// fail with an error instead of giving back garbage data.

use crate::core::error::{CoreError, CoreResult};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;

pub const KEY_LEN: usize = 32; // AES-256 = 32 bytes
pub const NONCE_LEN: usize = 12; // 96 bit nonce recommended for GCM
pub const SALT_LEN: usize = 16;
pub const PBKDF2_ITERATIONS: u32 = 100_000;

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

// derive a key from a password using PBKDF2
// this makes brute-force attacks slow since each guess costs 100k iterations
pub fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> CoreResult<Encrypted> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    // always use a fresh random nonce - reusing one would be a security disaster
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CoreError::Encryption("AES-GCM encryption failed".into()))?;

    Ok(Encrypted {
        ciphertext,
        nonce: nonce_bytes,
    })
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
        enc.ciphertext[0] ^= 0x01; // flip one bit
        assert!(decrypt(&key, &enc.nonce, &enc.ciphertext).is_err());
    }

    #[test]
    fn test_password_derivation() {
        let salt = [7u8; SALT_LEN];
        let a = derive_key_from_password("hunter2", &salt);
        let b = derive_key_from_password("hunter2", &salt);
        assert_eq!(a, b); // same password + salt = same key

        let c = derive_key_from_password("hunter3", &salt);
        assert_ne!(a, c); // different password = different key
    }

    #[test]
    fn test_nonce_is_random() {
        let key = generate_key();
        let a = encrypt(&key, b"same message").unwrap();
        let b = encrypt(&key, b"same message").unwrap();
        assert_ne!(a.nonce, b.nonce); // nonces must never repeat!
    }
}
