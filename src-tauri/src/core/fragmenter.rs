// File fragmentation and reconstruction
//
// How splitting works:
// 1. generate random AES key
// 2. if user set a password, wrap the key with password-derived encryption
// 3. encrypt the file with the AES key
// 4. shamir-split the key into n shares
// 5. package each share + ciphertext into a Fragment
//
// Reconstruction is the reverse

use crate::core::crypto;
use crate::core::error::{CoreError, CoreResult};
use crate::core::model::{Fragment, SplitParams, FRAGMENT_FORMAT_VERSION};
use crate::core::shamir::{self, Share};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use uuid::Uuid;
use zeroize::Zeroize;

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

fn zlib_compress(data: &[u8]) -> CoreResult<Vec<u8>> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data)
        .map_err(|e| CoreError::Storage(format!("compression error: {e}")))?;
    enc.finish()
        .map_err(|e| CoreError::Storage(format!("compression error: {e}")))
}

fn zlib_decompress(data: &[u8]) -> CoreResult<Vec<u8>> {
    let mut dec = ZlibDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| CoreError::Storage(format!("decompression error: {e}")))?;
    Ok(out)
}

pub fn split_file(
    file_bytes: &[u8],
    original_filename: &str,
    params: &SplitParams,
) -> CoreResult<Vec<Fragment>> {
    split_file_with_progress(file_bytes, original_filename, params, |_, _| {})
}

// Same as split_file but calls on_progress(percent 0-100, message) at key stages.
// Percentages emitted: 10 (key gen), 55 (after AES encrypt), 70 (after shamir), 100 (done).
pub fn split_file_with_progress<F: FnMut(u8, &str)>(
    file_bytes: &[u8],
    original_filename: &str,
    params: &SplitParams,
    mut on_progress: F,
) -> CoreResult<Vec<Fragment>> {
    if file_bytes.is_empty() {
        return Err(CoreError::Storage("file is empty".into()));
    }

    let password = params.password.as_deref().filter(|p| !p.is_empty());
    let password_protected = password.is_some();

    on_progress(10, "Generating encryption key…");
    let mut file_key = crypto::generate_key();

    // Optionally pad the plaintext with random bytes to obscure the true file size.
    // Checksum is always of the original unpadded bytes; original_size lets reconstruct strip padding.
    let padded: Vec<u8>;
    let after_pad: &[u8] = if params.padding_pct > 0 {
        let pad_len = (file_bytes.len() * params.padding_pct as usize) / 100;
        let mut v = file_bytes.to_vec();
        v.extend(crypto::random_bytes(pad_len));
        padded = v;
        &padded
    } else {
        file_bytes
    };

    // Optionally compress before encryption. Checksum is always of the original
    // uncompressed bytes so we can verify after decompression on reconstruct.
    let payload: Vec<u8>;
    let to_encrypt: &[u8] = if params.compress {
        on_progress(18, "Compressing…");
        payload = zlib_compress(after_pad)?;
        &payload
    } else {
        after_pad
    };

    on_progress(20, "Encrypting file…");
    let encrypted_file = crypto::encrypt_file(&params.cipher, &file_key, to_encrypt)?;

    on_progress(55, "Applying password protection…");
    let salt = crypto::generate_salt();
    let (mut key_to_share, salt_b64): (Vec<u8>, String) = match password {
        Some(pw) => {
            let mut pw_key = crypto::derive_key_kdf(&params.kdf, pw, &salt)?;
            let wrapped = crypto::encrypt(&pw_key, &file_key)?;
            pw_key.zeroize();
            let mut blob = wrapped.nonce.to_vec();
            blob.extend_from_slice(&wrapped.ciphertext);
            (blob, B64.encode(salt))
        }
        None => (file_key.to_vec(), String::new()),
    };

    on_progress(65, "Splitting encryption key…");
    let shares = shamir::split(&key_to_share, params.total_fragments, params.threshold)?;
    file_key.zeroize();
    key_to_share.zeroize();

    on_progress(80, "Packaging fragments…");
    let file_id = Uuid::new_v4().to_string();
    let checksum = sha256_hex(file_bytes);
    let ct_b64 = B64.encode(&encrypted_file.ciphertext);
    let nonce_b64 = B64.encode(encrypted_file.nonce);

    let fragments = shares
        .into_iter()
        .map(|share| Fragment {
            version: FRAGMENT_FORMAT_VERSION.to_string(),
            file_id: file_id.clone(),
            index: share.x,
            total: params.total_fragments,
            threshold: params.threshold,
            original_filename: original_filename.to_string(),
            original_size: file_bytes.len() as u64,
            password_protected,
            compressed: params.compress,
            salt_b64: salt_b64.clone(),
            share_x: share.x,
            share_y_b64: B64.encode(&share.y),
            nonce_b64: nonce_b64.clone(),
            checksum: checksum.clone(),
            ciphertext_b64: ct_b64.clone(),
            cipher: params.cipher.clone(),
            kdf: params.kdf.clone(),
            padding_pct: params.padding_pct,
        })
        .collect();

    on_progress(100, "Fragments ready");
    Ok(fragments)
}

pub fn reconstruct_file(
    fragments: &[Fragment],
    password: Option<&str>,
) -> CoreResult<Vec<u8>> {
    reconstruct_file_with_progress(fragments, password, |_, _| {})
}

// Same as reconstruct_file but calls on_progress(percent 0-100, message) at key stages.
pub fn reconstruct_file_with_progress<F: FnMut(u8, &str)>(
    fragments: &[Fragment],
    password: Option<&str>,
    mut on_progress: F,
) -> CoreResult<Vec<u8>> {
    let first = fragments
        .first()
        .ok_or_else(|| CoreError::InvalidFragment("no fragments provided".into()))?;

    // basic checks
    if fragments.len() < first.threshold as usize {
        return Err(CoreError::InvalidFragment(format!(
            "need {} fragments but only got {}",
            first.threshold, fragments.len()
        )));
    }
    if fragments.iter().any(|f| f.file_id != first.file_id) {
        return Err(CoreError::InvalidFragment(
            "fragments are from different files".into(),
        ));
    }

    on_progress(10, "Combining key shares…");

    // step 1: combine shamir shares to get the key back
    let mut shares = Vec::new();
    for frag in fragments.iter().take(first.threshold as usize) {
        let y = B64.decode(&frag.share_y_b64)
            .map_err(|e| CoreError::InvalidFragment(format!("bad share data: {e}")))?;
        shares.push(Share { x: frag.share_x, y });
    }
    let recovered_key_data = shamir::combine(&shares)?;
    for share in shares.iter_mut() { share.y.zeroize(); }

    on_progress(30, "Unlocking encryption key…");

    // step 2: if password protected, unwrap the key
    let mut file_key = unwrap_file_key(
        recovered_key_data,
        first.password_protected,
        password,
        &first.kdf,
        &first.salt_b64,
    )?;

    on_progress(50, "Decrypting file…");

    // step 3: decrypt the actual file — nonce length depends on the cipher
    // (XChaCha20 uses a wider nonce than the others), so let decrypt_file
    // validate it rather than assuming a fixed size here.
    let nonce_bytes = B64.decode(&first.nonce_b64)
        .map_err(|e| CoreError::InvalidFragment(format!("bad nonce: {e}")))?;

    let ciphertext = B64.decode(&first.ciphertext_b64)
        .map_err(|e| CoreError::InvalidFragment(format!("bad ciphertext: {e}")))?;

    let decrypted = crypto::decrypt_file(&first.cipher, &file_key, &nonce_bytes, &ciphertext)?;
    file_key.zeroize();

    on_progress(80, "Decompressing…");

    // step 4: decompress if needed, strip padding, then verify checksum of original bytes
    let mut plaintext = if first.compressed {
        zlib_decompress(&decrypted)?
    } else {
        decrypted
    };

    // strip random padding (if any was added at split time)
    let orig = first.original_size as usize;
    if plaintext.len() > orig {
        plaintext.truncate(orig);
    }

    on_progress(95, "Verifying checksum…");

    if sha256_hex(&plaintext) != first.checksum {
        return Err(CoreError::ChecksumMismatch);
    }

    on_progress(100, "Done");

    Ok(plaintext)
}

/// Check whether `password` unlocks this fragment set, without decrypting the
/// (potentially large) file content. Lets the UI reject a wrong password
/// immediately instead of running the full reconstruction first.
pub fn verify_password(fragments: &[Fragment], password: Option<&str>) -> CoreResult<()> {
    let first = fragments
        .first()
        .ok_or_else(|| CoreError::InvalidFragment("no fragments provided".into()))?;

    if fragments.len() < first.threshold as usize {
        return Err(CoreError::InvalidFragment(format!(
            "need {} fragments but only got {}",
            first.threshold, fragments.len()
        )));
    }

    let mut shares = Vec::new();
    for frag in fragments.iter().take(first.threshold as usize) {
        let y = B64.decode(&frag.share_y_b64)
            .map_err(|e| CoreError::InvalidFragment(format!("bad share data: {e}")))?;
        shares.push(Share { x: frag.share_x, y });
    }
    let recovered_key_data = shamir::combine(&shares)?;
    for share in shares.iter_mut() { share.y.zeroize(); }

    let mut key = unwrap_file_key(
        recovered_key_data,
        first.password_protected,
        password,
        &first.kdf,
        &first.salt_b64,
    )?;
    key.zeroize();
    Ok(())
}

// Combine the Shamir-recovered key material with the password (if the file is
// password-protected) to recover the actual file encryption key.
fn unwrap_file_key(
    mut recovered_key_data: Vec<u8>,
    password_protected: bool,
    password: Option<&str>,
    kdf: &str,
    salt_b64: &str,
) -> CoreResult<[u8; crypto::KEY_LEN]> {
    if !password_protected {
        let key = to_key_array(&recovered_key_data);
        recovered_key_data.zeroize();
        return key;
    }

    let pw = password.ok_or_else(|| {
        CoreError::Decryption("this file needs a password".into())
    })?;

    let salt = B64.decode(salt_b64)
        .map_err(|e| CoreError::InvalidFragment(format!("bad salt: {e}")))?;
    let mut pw_key = crypto::derive_key_kdf(kdf, pw, &salt)?;

    // wrapped format is: nonce (12 bytes) + ciphertext
    if recovered_key_data.len() <= crypto::NONCE_LEN {
        recovered_key_data.zeroize();
        return Err(CoreError::InvalidFragment("wrapped key too short".into()));
    }
    let (nonce_part, cipher_part) = recovered_key_data.split_at(crypto::NONCE_LEN);
    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(nonce_part);

    let mut unwrapped = crypto::decrypt(&pw_key, &nonce, cipher_part)?;
    pw_key.zeroize();
    recovered_key_data.zeroize();
    let key = to_key_array(&unwrapped);
    unwrapped.zeroize();
    key
}

fn to_key_array(bytes: &[u8]) -> CoreResult<[u8; crypto::KEY_LEN]> {
    if bytes.len() != crypto::KEY_LEN {
        return Err(CoreError::InvalidFragment(format!(
            "key has wrong length: expected {} got {}",
            crypto::KEY_LEN, bytes.len()
        )));
    }
    let mut arr = [0u8; crypto::KEY_LEN];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_params(n: u8, k: u8, pw: Option<&str>) -> SplitParams {
        make_params_cipher(n, k, pw, "aes256gcm")
    }

    fn make_params_cipher(n: u8, k: u8, pw: Option<&str>, cipher: &str) -> SplitParams {
        SplitParams {
            total_fragments: n,
            threshold:       k,
            password:        pw.map(|s| s.to_string()),
            compress:        false,
            cipher:          cipher.to_string(),
            kdf:             "standard".to_string(),
            padding_pct:     0,
        }
    }

    #[test]
    fn test_split_reconstruct() {
        let data = b"Top secret document contents. Do not share!";
        let frags = split_file(data, "secret.txt", &make_params(5, 3, None)).unwrap();
        assert_eq!(frags.len(), 5);

        let recovered = reconstruct_file(&frags[0..3], None).unwrap();
        assert_eq!(recovered, data);
    }

    // XChaCha20's 24-byte nonce is wider than every other cipher's — this
    // exercises the base64 round trip through Fragment.nonce_b64 without the
    // fixed-12-byte assumption the small-file decrypt path used to have.
    #[test]
    fn test_split_reconstruct_xchacha20() {
        let data = b"wide-nonce cipher payload, must not get truncated";
        let frags = split_file(data, "wide.bin", &make_params_cipher(5, 3, Some("hunter2"), "xchacha20")).unwrap();
        assert_eq!(frags[0].cipher, "xchacha20");
        let recovered = reconstruct_file(&frags[0..3], Some("hunter2")).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_split_reconstruct_aes_gcm_siv() {
        let data = b"nonce-misuse-resistant cipher payload";
        let frags = split_file(data, "siv.bin", &make_params_cipher(5, 3, None, "aesgcmsiv")).unwrap();
        let recovered = reconstruct_file(&frags[0..3], None).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_with_password() {
        let data = b"Password-locked payload bytes here.";
        let frags = split_file(data, "locked.bin", &make_params(4, 2, Some("hunter2"))).unwrap();
        let recovered = reconstruct_file(&frags[0..2], Some("hunter2")).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_verify_password() {
        let data = b"verify me without reconstructing".to_vec();
        let frags = split_file(&data, "x.bin", &make_params(4, 2, Some("hunter2"))).unwrap();

        assert!(verify_password(&frags[0..2], Some("hunter2")).is_ok());
        assert!(verify_password(&frags[0..2], Some("wrong")).is_err());
        assert!(verify_password(&frags[0..2], None).is_err());
    }

    #[test]
    fn test_verify_password_no_protection() {
        let data = b"no password on this one".to_vec();
        let frags = split_file(&data, "x.bin", &make_params(4, 2, None)).unwrap();

        assert!(verify_password(&frags[0..2], None).is_ok());
        // a password is simply ignored when the file isn't protected
        assert!(verify_password(&frags[0..2], Some("anything")).is_ok());
    }

    #[test]
    fn test_wrong_password() {
        let data = b"cannot read this without the password";
        let frags = split_file(data, "x.bin", &make_params(3, 2, Some("correct"))).unwrap();
        assert!(reconstruct_file(&frags[0..2], Some("wrong")).is_err());
    }

    #[test]
    fn test_missing_password() {
        let data = b"needs a password";
        let frags = split_file(data, "x.bin", &make_params(3, 2, Some("secret"))).unwrap();
        assert!(reconstruct_file(&frags[0..2], None).is_err());
    }

    #[test]
    fn test_not_enough_fragments() {
        let data = b"need three fragments minimum";
        let frags = split_file(data, "x.bin", &make_params(5, 3, None)).unwrap();
        assert!(reconstruct_file(&frags[0..2], None).is_err());
    }

    #[test]
    fn test_any_k_subset() {
        let data = b"choose any k of the n fragments";
        let frags = split_file(data, "x.bin", &make_params(5, 3, None)).unwrap();
        let subset = vec![frags[1].clone(), frags[3].clone(), frags[4].clone()];
        assert_eq!(reconstruct_file(&subset, None).unwrap(), data);
    }
}

#[test]
fn test_padding_split_reconstruct() {
    let data = b"Secret file content for padding test!";
    let params = crate::core::model::SplitParams {
        total_fragments: 5,
        threshold:       3,
        password:        None,
        compress:        false,
        cipher:          "aes256gcm".to_string(),
        kdf:             "standard".to_string(),
        padding_pct:     25,
    };
    let frags = split_file(data, "pad_test.txt", &params).unwrap();
    let recovered = reconstruct_file(&frags[0..3], None).unwrap();
    assert_eq!(recovered, data);
}

#[test]
fn test_padding_with_compress() {
    let data = b"Compressible content that repeats repeats repeats repeats repeats.";
    let params = crate::core::model::SplitParams {
        total_fragments: 3,
        threshold:       2,
        password:        None,
        compress:        true,
        cipher:          "aes256gcm".to_string(),
        kdf:             "standard".to_string(),
        padding_pct:     50,
    };
    let frags = split_file(data, "pad_compress.txt", &params).unwrap();
    let recovered = reconstruct_file(&frags[0..2], None).unwrap();
    assert_eq!(recovered, data);
}
