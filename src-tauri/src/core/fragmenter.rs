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
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn split_file(
    file_bytes: &[u8],
    original_filename: &str,
    params: &SplitParams,
) -> CoreResult<Vec<Fragment>> {
    if file_bytes.is_empty() {
        return Err(CoreError::Storage("file is empty".into()));
    }

    // treat empty string same as no password
    let password = params.password.as_deref().filter(|p| !p.is_empty());
    let password_protected = password.is_some();

    // step 1: generate key and encrypt the file
    let file_key = crypto::generate_key();
    let encrypted_file = crypto::encrypt(&file_key, file_bytes)?;

    // step 2: optionally wrap the key behind a password
    // if password protected, we encrypt the AES key AGAIN with a password-derived key
    // so even having k fragments isnt enough without the password
    let salt = crypto::generate_salt();
    let (key_to_share, salt_b64): (Vec<u8>, String) = match password {
        Some(pw) => {
            let pw_key = crypto::derive_key_from_password(pw, &salt);
            let wrapped = crypto::encrypt(&pw_key, &file_key)?;
            // prepend nonce so we can find it during unwrap
            let mut blob = wrapped.nonce.to_vec();
            blob.extend_from_slice(&wrapped.ciphertext);
            (blob, B64.encode(salt))
        }
        None => (file_key.to_vec(), String::new()),
    };

    // step 3: split the key with shamir
    let shares = shamir::split(&key_to_share, params.total_fragments, params.threshold)?;

    // step 4: build the fragment structs
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
            salt_b64: salt_b64.clone(),
            share_x: share.x,
            share_y_b64: B64.encode(&share.y),
            nonce_b64: nonce_b64.clone(),
            checksum: checksum.clone(),
            ciphertext_b64: ct_b64.clone(),
        })
        .collect();

    Ok(fragments)
}

pub fn reconstruct_file(
    fragments: &[Fragment],
    password: Option<&str>,
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

    // step 1: combine shamir shares to get the key back
    let mut shares = Vec::new();
    for frag in fragments.iter().take(first.threshold as usize) {
        let y = B64.decode(&frag.share_y_b64)
            .map_err(|e| CoreError::InvalidFragment(format!("bad share data: {e}")))?;
        shares.push(Share { x: frag.share_x, y });
    }
    let recovered_key_data = shamir::combine(&shares)?;

    // step 2: if password protected, unwrap the key
    let file_key: [u8; crypto::KEY_LEN] = if first.password_protected {
        let pw = password.ok_or_else(|| {
            CoreError::Decryption("this file needs a password".into())
        })?;

        let salt = B64.decode(&first.salt_b64)
            .map_err(|e| CoreError::InvalidFragment(format!("bad salt: {e}")))?;
        let pw_key = crypto::derive_key_from_password(pw, &salt);

        // wrapped format is: nonce (12 bytes) + ciphertext
        if recovered_key_data.len() <= crypto::NONCE_LEN {
            return Err(CoreError::InvalidFragment("wrapped key too short".into()));
        }
        let (nonce_part, cipher_part) = recovered_key_data.split_at(crypto::NONCE_LEN);
        let mut nonce = [0u8; crypto::NONCE_LEN];
        nonce.copy_from_slice(nonce_part);

        let unwrapped = crypto::decrypt(&pw_key, &nonce, cipher_part)?;
        to_key_array(&unwrapped)?
    } else {
        to_key_array(&recovered_key_data)?
    };

    // step 3: decrypt the actual file
    let nonce_bytes = B64.decode(&first.nonce_b64)
        .map_err(|e| CoreError::InvalidFragment(format!("bad nonce: {e}")))?;
    if nonce_bytes.len() != crypto::NONCE_LEN {
        return Err(CoreError::InvalidFragment("nonce wrong length".into()));
    }
    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(&nonce_bytes);

    let ciphertext = B64.decode(&first.ciphertext_b64)
        .map_err(|e| CoreError::InvalidFragment(format!("bad ciphertext: {e}")))?;

    let plaintext = crypto::decrypt(&file_key, &nonce, &ciphertext)?;

    // step 4: verify checksum
    if sha256_hex(&plaintext) != first.checksum {
        return Err(CoreError::ChecksumMismatch);
    }

    Ok(plaintext)
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
        SplitParams {
            total_fragments: n,
            threshold: k,
            password: pw.map(|s| s.to_string()),
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

    #[test]
    fn test_with_password() {
        let data = b"Password-locked payload bytes here.";
        let frags = split_file(data, "locked.bin", &make_params(4, 2, Some("hunter2"))).unwrap();
        let recovered = reconstruct_file(&frags[0..2], Some("hunter2")).unwrap();
        assert_eq!(recovered, data);
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
