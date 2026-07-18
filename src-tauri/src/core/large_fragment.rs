// Large-file streaming split/reconstruct using Reed-Solomon erasure coding.
//
// Why this module exists
// ----------------------
// The small-file path (fragmenter.rs) loads the whole file into RAM, encrypts it,
// then stores a FULL encrypted copy inside every fragment. For a 10 GB file with
// N=5 fragments that means ~70 GB of disk writes and ~30 GB of peak RAM – impossible.
//
// This module does it properly:
//   1. Read the file in 8 MB chunks.
//   2. Optionally zlib-compress each chunk.
//   3. AES-256-GCM-encrypt each chunk (random nonce per chunk).
//   4. Reed-Solomon encode the encrypted chunk into N shards where any K reconstruct.
//      Each shard is 1/K of the chunk, so each fragment file ends up ~file_size/K.
//   5. Write one shard per fragment file as a binary stream.
//      Total disk usage ≈ (N/K) × file_size  vs  N × file_size before.
//
// Fragment shard file layout (.svf3)
// ------------------------------------
//   [ 8 ]  Magic "SVAULT3\0"
//   [12 ]  Header nonce (AES-GCM)
//   [ 4 ]  Header ciphertext length  (u32 LE)
//   [ ? ]  Header ciphertext  (at-rest encrypted JSON of LargeFragmentMeta)
//   Then for each of chunk_count chunks:
//     [12]  Chunk AES-GCM nonce
//     [ 4]  actual_enc_len (u32 LE) – length of AES-GCM output before RS padding
//     [ ?]  RS shard bytes  (shard_size = ceil(actual_enc_len / threshold))
//   [32 ]  SHA-256 of original plaintext (integrity trailer)

use crate::core::{crypto, error::{CoreError, CoreResult}, op_control::OpControl, shamir};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Files larger than this use the streaming RS path instead of the in-memory path.
pub const LARGE_FILE_THRESHOLD: u64 = 64 * 1024 * 1024; // 64 MB

/// Each chunk processed at a time. 8 MB keeps RAM usage low while amortising
/// per-chunk overhead. Peak RAM ≈ N × CHUNK_SIZE (40 MB for N=5).
const CHUNK_SIZE: usize = 8 * 1024 * 1024;

const MAGIC: &[u8; 8] = b"SVAULT3\0";
/// Portable shard format — header is plain JSON (no at-rest encryption), safe to share cross-machine.
pub const MAGIC_PORTABLE: &[u8; 8] = b"SVAULT3P";

// ── Metadata stored in the encrypted header of each shard file ────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeFragmentMeta {
    pub file_id:            String,
    pub shard_index:        u8,
    pub total:              u8,
    pub threshold:          u8,
    pub original_filename:  String,
    pub original_size:      u64,
    pub compressed:         bool,
    pub password_protected: bool,
    #[serde(default)]
    pub salt_b64:           String,
    pub share_x:            u8,
    pub share_y_b64:        String,
    pub chunk_count:        u64,
    // User-chosen cipher and KDF preset (default to old behaviour when absent)
    #[serde(default = "default_cipher_str")]
    pub cipher:             String,
    #[serde(default = "default_kdf_str")]
    pub kdf:                String,
    // Percentage of random padding added to obscure file size (0 = none)
    #[serde(default)]
    pub padding_pct:        u8,
}

fn default_cipher_str() -> String { "aes256gcm".to_string() }
fn default_kdf_str()    -> String { "standard".to_string() }

// ── Public API ────────────────────────────────────────────────────────────────

/// Stream-split a large file into N shard files under `frag_dir/<file_id>/`.
/// `at_rest_key` is used to encrypt each shard file's metadata header.
/// Returns one `LargeFragmentMeta` per shard (useful for building the vault manifest).
pub fn split_large_file<F: FnMut(u8, &str)>(
    file_path: &Path,
    filename:  &str,
    params:    &crate::core::model::SplitParams,
    at_rest_key: &[u8; crypto::KEY_LEN],
    frag_dir:  &Path,   // vault/<file_id>/
    file_id:   &str,
    ctl: &OpControl,
    mut on_progress: F,
) -> CoreResult<Vec<LargeFragmentMeta>> {
    let n = params.total_fragments as usize;
    let k = params.threshold   as usize;

    if k >= n {
        return Err(CoreError::Storage(format!(
            "threshold ({k}) must be less than total fragments ({n})"
        )));
    }

    let rs = ReedSolomon::new(k, n - k)
        .map_err(|e| CoreError::Storage(format!("RS init: {e:?}")))?;

    on_progress(3, "Generating encryption key…");
    let mut file_key = crypto::generate_key();

    // Optional password wrapping (same scheme as small files)
    let password = params.password.as_deref().filter(|p| !p.is_empty());
    let salt     = crypto::generate_salt();
    let (mut key_to_share, salt_b64) = if let Some(pw) = password {
        let mut pw_key = crypto::derive_key_kdf(&params.kdf, pw, &salt)?;
        let wrapped = crypto::encrypt(&pw_key, &file_key)?;
        pw_key.zeroize();
        let mut blob = wrapped.nonce.to_vec();
        blob.extend_from_slice(&wrapped.ciphertext);
        (blob, B64.encode(salt))
    } else {
        (file_key.to_vec(), String::new())
    };

    let shares = shamir::split(&key_to_share, params.total_fragments, params.threshold)?;
    key_to_share.zeroize();

    // chunk_count is known upfront from file size; add one extra chunk if padding is requested
    let file_size        = std::fs::metadata(file_path)?.len();
    let real_chunk_count = ((file_size as usize + CHUNK_SIZE - 1) / CHUNK_SIZE) as u64;
    let chunk_count      = real_chunk_count + if params.padding_pct > 0 { 1 } else { 0 };

    std::fs::create_dir_all(frag_dir)?;

    // Open one buffered writer per shard
    let mut writers: Vec<BufWriter<std::fs::File>> = (0..n)
        .map(|i| {
            std::fs::File::create(shard_path(frag_dir, i as u8))
                .map(|f| BufWriter::new(f))
                .map_err(CoreError::Io)
        })
        .collect::<CoreResult<_>>()?;

    // Write magic to every shard file
    for w in &mut writers {
        w.write_all(MAGIC)?;
    }

    // Encrypt and write header for each shard
    for (shard_idx, w) in writers.iter_mut().enumerate() {
        let share = &shares[shard_idx];
        let meta  = LargeFragmentMeta {
            file_id:           file_id.to_string(),
            shard_index:       shard_idx as u8,
            total:             params.total_fragments,
            threshold:         params.threshold,
            original_filename: filename.to_string(),
            original_size:     file_size,
            compressed:        params.compress,
            password_protected: password.is_some(),
            salt_b64:          salt_b64.clone(),
            share_x:           share.x,
            share_y_b64:       B64.encode(&share.y),
            chunk_count,
            cipher:            params.cipher.clone(),
            kdf:               params.kdf.clone(),
            padding_pct:       params.padding_pct,
        };
        let json = serde_json::to_vec(&meta)?;
        let enc  = crypto::encrypt(at_rest_key, &json)?;
        w.write_all(&enc.nonce)?;
        w.write_all(&(enc.ciphertext.len() as u32).to_le_bytes())?;
        w.write_all(&enc.ciphertext)?;
    }

    on_progress(8, "Streaming and encoding file…");

    // Stream through the file one chunk at a time
    let mut reader  = BufReader::with_capacity(CHUNK_SIZE, std::fs::File::open(file_path)?);
    let mut hasher  = Sha256::new();
    let mut buf     = vec![0u8; CHUNK_SIZE];
    let mut chunks_done = 0u64;

    loop {
        let n_read = read_chunk(&mut reader, &mut buf)?;
        if n_read == 0 { break; }
        ctl.checkpoint()?;
        let chunk = &buf[..n_read];

        hasher.update(chunk);

        // Optional compression
        let compressed_buf: Vec<u8>;
        let to_encrypt: &[u8] = if params.compress {
            compressed_buf = zlib_compress(chunk)?;
            &compressed_buf
        } else {
            chunk
        };

        // Encrypt the chunk with the user-chosen cipher.
        let enc = crypto::encrypt_file(&params.cipher, &file_key, to_encrypt)?;
        let actual_enc_len = enc.ciphertext.len(); // payload + 16-byte tag

        // RS encode: pad ciphertext to a multiple of K, then split into K data
        // shards + (N-K) parity shards.
        let shard_size = (actual_enc_len + k - 1) / k;
        let mut padded = enc.ciphertext;
        padded.resize(shard_size * k, 0);

        let mut shards: Vec<Vec<u8>> = (0..n)
            .map(|i| {
                if i < k {
                    padded[i * shard_size..(i + 1) * shard_size].to_vec()
                } else {
                    vec![0u8; shard_size]
                }
            })
            .collect();
        rs.encode(&mut shards)
            .map_err(|e| CoreError::Storage(format!("RS encode: {e:?}")))?;

        // Write one chunk record per shard file:
        //   [nonce: 12][actual_enc_len: 4][shard: shard_size]
        for (i, w) in writers.iter_mut().enumerate() {
            w.write_all(&enc.nonce)?;
            w.write_all(&(actual_enc_len as u32).to_le_bytes())?;
            w.write_all(&shards[i])?;
        }

        chunks_done += 1;
        // Map chunk progress to 8–95%
        let pct = 8 + ((chunks_done * 87) / chunk_count.max(1)) as u8;
        on_progress(pct.min(95), "Encoding chunks…");
    }

    // Optional padding chunk — random bytes to obscure true file size
    if params.padding_pct > 0 {
        let pad_len = ((file_size as usize) * params.padding_pct as usize) / 100;
        let pad_data = crypto::random_bytes(pad_len.max(1));
        hasher.update(&pad_data);

        let compressed_pad: Vec<u8>;
        let to_enc: &[u8] = if params.compress {
            compressed_pad = zlib_compress(&pad_data)?;
            &compressed_pad
        } else {
            &pad_data
        };
        let enc = crypto::encrypt_file(&params.cipher, &file_key, to_enc)?;
        let actual_enc_len = enc.ciphertext.len();
        let shard_size = (actual_enc_len + k - 1) / k;
        let mut padded_rs = enc.ciphertext;
        padded_rs.resize(shard_size * k, 0);
        let mut shards: Vec<Vec<u8>> = (0..n)
            .map(|i| if i < k { padded_rs[i * shard_size..(i + 1) * shard_size].to_vec() } else { vec![0u8; shard_size] })
            .collect();
        rs.encode(&mut shards).map_err(|e| CoreError::Storage(format!("RS encode pad: {e:?}")))?;
        for (i, w) in writers.iter_mut().enumerate() {
            w.write_all(&enc.nonce)?;
            w.write_all(&(actual_enc_len as u32).to_le_bytes())?;
            w.write_all(&shards[i])?;
        }
    }

    // SHA-256 integrity trailer (same in every shard file)
    let checksum: [u8; 32] = hasher.finalize().into();
    for w in &mut writers {
        w.write_all(&checksum)?;
        w.flush()?;
    }

    on_progress(100, "Done");

    // Return metadata for each shard (caller uses this to update the vault manifest)
    let metas = (0..n)
        .zip(shares.iter())
        .map(|(i, share)| LargeFragmentMeta {
            file_id:            file_id.to_string(),
            shard_index:        i as u8,
            total:              params.total_fragments,
            threshold:          params.threshold,
            original_filename:  filename.to_string(),
            original_size:      file_size,
            compressed:         params.compress,
            password_protected: password.is_some(),
            salt_b64:           salt_b64.clone(),
            share_x:            share.x,
            share_y_b64:        B64.encode(&share.y),
            chunk_count,
            cipher:             params.cipher.clone(),
            kdf:                params.kdf.clone(),
            padding_pct:        params.padding_pct,
        })
        .collect();

    file_key.zeroize();
    Ok(metas)
}

/// Reconstruct the original file from K or more shard files, writing directly to
/// `out_path`. The reconstructed file is never fully held in RAM.
pub fn reconstruct_large_file(
    shard_files: &[(u8, PathBuf)],  // (shard_index, path) for each available shard
    password:    Option<&str>,
    at_rest_key: &[u8; crypto::KEY_LEN],
    out_path:    &Path,
) -> CoreResult<()> {
    reconstruct_large_file_with_progress(shard_files, password, at_rest_key, out_path, &OpControl::new(), |_, _| {})
}

// Same as reconstruct_large_file but calls on_progress(percent 0-100, message) as chunks decode.
pub fn reconstruct_large_file_with_progress<F: FnMut(u8, &str)>(
    shard_files: &[(u8, PathBuf)],  // (shard_index, path) for each available shard
    password:    Option<&str>,
    at_rest_key: &[u8; crypto::KEY_LEN],
    out_path:    &Path,
    ctl: &OpControl,
    mut on_progress: F,
) -> CoreResult<()> {
    if shard_files.is_empty() {
        return Err(CoreError::InvalidFragment("no shard files provided".into()));
    }

    let meta = read_meta(&shard_files[0].1, at_rest_key)?;
    let n = meta.total    as usize;
    let k = meta.threshold as usize;

    if k >= n {
        return Err(CoreError::InvalidFragment(format!(
            "corrupt metadata: threshold ({k}) >= total ({n})"
        )));
    }
    if shard_files.len() < k {
        return Err(CoreError::InvalidFragment(format!(
            "need {} shards, have {}", k, shard_files.len()
        )));
    }

    let rs = ReedSolomon::new(k, n - k)
        .map_err(|e| CoreError::Storage(format!("RS init: {e:?}")))?;

    // Recover AES key via Shamir (use exactly K shares)
    let mut shares: Vec<shamir::Share> = shard_files.iter().take(k)
        .map(|(_, path)| {
            let m = read_meta(path, at_rest_key)?;
            let y = B64.decode(&m.share_y_b64)
                .map_err(|e| CoreError::InvalidFragment(format!("bad share: {e}")))?;
            Ok(shamir::Share { x: m.share_x, y })
        })
        .collect::<CoreResult<_>>()?;

    let recovered_key_data = shamir::combine(&shares)?;
    for share in shares.iter_mut() { share.y.zeroize(); }

    on_progress(3, "Unlocking encryption key…");

    let mut file_key = unwrap_file_key(
        recovered_key_data,
        meta.password_protected,
        password,
        &meta.kdf,
        &meta.salt_b64,
    )?;

    // Open each shard file positioned right after its header
    let mut readers: Vec<(u8, std::fs::File)> = shard_files.iter()
        .map(|(shard_idx, path)| {
            let hdr = header_end_offset(path)?;
            let mut f = std::fs::File::open(path)?;
            f.seek(SeekFrom::Start(hdr as u64))?;
            Ok((*shard_idx, f))
        })
        .collect::<CoreResult<_>>()?;

    let mut out     = BufWriter::new(std::fs::File::create(out_path)?);
    let mut hasher  = Sha256::new();

    on_progress(6, "Decoding chunks…");

    for chunk_idx in 0..meta.chunk_count {
        ctl.checkpoint()?;
        // Read the chunk record from the first reader to learn nonce + shard_size
        let mut nonce = [0u8; crypto::NONCE_LEN];
        let mut enc_len_buf = [0u8; 4];
        readers[0].1.read_exact(&mut nonce)?;
        readers[0].1.read_exact(&mut enc_len_buf)?;
        let actual_enc_len = u32::from_le_bytes(enc_len_buf) as usize;
        let shard_size = (actual_enc_len + k - 1) / k;

        let mut first_shard = vec![0u8; shard_size];
        readers[0].1.read_exact(&mut first_shard)?;

        // Build the option-shard array (None for missing shards)
        let mut option_shards: Vec<Option<Vec<u8>>> = vec![None; n];
        option_shards[readers[0].0 as usize] = Some(first_shard);

        for r in readers.iter_mut().skip(1) {
            // Skip duplicate nonce + enc_len (same for every fragment of this chunk)
            let mut _nonce2   = [0u8; crypto::NONCE_LEN];
            let mut _enc_len2 = [0u8; 4];
            r.1.read_exact(&mut _nonce2)?;
            r.1.read_exact(&mut _enc_len2)?;

            let mut shard = vec![0u8; shard_size];
            r.1.read_exact(&mut shard)?;
            option_shards[r.0 as usize] = Some(shard);
        }

        // Reconstruct missing data shards (first K shards are the data shards)
        rs.reconstruct_data(&mut option_shards)
            .map_err(|e| CoreError::Storage(format!("RS decode: {e:?}")))?;

        // Re-assemble the encrypted chunk from the K data shards
        let mut enc_chunk = Vec::with_capacity(shard_size * k);
        for i in 0..k {
            enc_chunk.extend_from_slice(option_shards[i].as_ref().unwrap());
        }
        enc_chunk.truncate(actual_enc_len); // strip RS padding

        // Decrypt with the cipher stored in the shard header
        let decrypted = crypto::decrypt_file(&meta.cipher, &file_key, &nonce, &enc_chunk)?;

        // Decompress if needed
        let plain = if meta.compressed {
            zlib_decompress(&decrypted)?
        } else {
            decrypted
        };

        hasher.update(&plain);
        out.write_all(&plain)?;

        // Map chunk progress to 6-90%
        let pct = 6 + (((chunk_idx + 1) * 84) / meta.chunk_count.max(1)) as u8;
        on_progress(pct.min(90), "Decoding chunks…");
    }

    out.flush()?;
    drop(out);
    file_key.zeroize();

    on_progress(93, "Finalizing…");

    // Strip the padding chunk from the output (truncate to real file size)
    if meta.padding_pct > 0 {
        let f = std::fs::OpenOptions::new().write(true).open(out_path)?;
        f.set_len(meta.original_size)?;
    }

    on_progress(96, "Verifying checksum…");

    // Verify the SHA-256 trailer (next 32 bytes in the first reader)
    let mut stored = [0u8; 32];
    readers[0].1.read_exact(&mut stored)?;
    if stored != <[u8; 32]>::from(hasher.finalize()) {
        return Err(CoreError::ChecksumMismatch);
    }

    on_progress(100, "Done");

    Ok(())
}

/// Read `LargeFragmentMeta` from a shard file — handles both at-rest and portable formats.
pub fn read_meta(path: &Path, at_rest_key: &[u8; crypto::KEY_LEN]) -> CoreResult<LargeFragmentMeta> {
    let mut f = std::fs::File::open(path)?;

    let mut magic = [0u8; 8];
    f.read_exact(&mut magic)?;

    if &magic == MAGIC_PORTABLE {
        // Portable format: plain JSON header, no at-rest encryption
        let mut len_buf = [0u8; 4];
        f.read_exact(&mut len_buf)?;
        let json_len = u32::from_le_bytes(len_buf) as usize;
        let mut json_bytes = vec![0u8; json_len];
        f.read_exact(&mut json_bytes)?;
        return Ok(serde_json::from_slice(&json_bytes)
            .map_err(|e| CoreError::InvalidFragment(format!("bad portable header: {e}")))?);
    }

    if &magic != MAGIC {
        return Err(CoreError::InvalidFragment(
            format!("not a large fragment file: {}", path.display())
        ));
    }

    // At-rest encrypted header
    let mut nonce = [0u8; crypto::NONCE_LEN];
    f.read_exact(&mut nonce)?;
    let mut len_buf = [0u8; 4];
    f.read_exact(&mut len_buf)?;
    let enc_len = u32::from_le_bytes(len_buf) as usize;
    let mut enc_data = vec![0u8; enc_len];
    f.read_exact(&mut enc_data)?;
    let json = crypto::decrypt(at_rest_key, &nonce, &enc_data)?;
    Ok(serde_json::from_slice(&json)?)
}

/// Byte offset where the chunk data starts — handles both formats.
fn header_end_offset(path: &Path) -> CoreResult<usize> {
    let mut f = std::fs::File::open(path)?;
    let mut magic = [0u8; 8];
    f.read_exact(&mut magic)?;

    if &magic == MAGIC_PORTABLE {
        // magic(8) + json_len(4) + json(json_len)
        let mut len_buf = [0u8; 4];
        f.read_exact(&mut len_buf)?;
        let json_len = u32::from_le_bytes(len_buf) as usize;
        return Ok(8 + 4 + json_len);
    }

    // magic(8) + nonce(12) + enc_len(4) + enc_data(enc_len)
    f.seek(SeekFrom::Current(12))?; // skip nonce
    let mut len_buf = [0u8; 4];
    f.read_exact(&mut len_buf)?;
    let enc_len = u32::from_le_bytes(len_buf) as usize;
    Ok(8 + 12 + 4 + enc_len)
}

/// Convert a vault shard (at-rest encrypted header) to portable bytes (plain JSON header).
/// The chunk data and SHA-256 trailer are copied verbatim — they use the file key, not at-rest key.
pub fn to_portable_bytes(path: &Path, at_rest_key: &[u8; crypto::KEY_LEN]) -> CoreResult<Vec<u8>> {
    let meta = read_meta(path, at_rest_key)?;
    let header_end = header_end_offset(path)?;
    let file_data = std::fs::read(path)?;
    let chunk_data = &file_data[header_end..];

    let json = serde_json::to_vec(&meta)?;
    let mut out = Vec::with_capacity(8 + 4 + json.len() + chunk_data.len());
    out.extend_from_slice(MAGIC_PORTABLE);
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(&json);
    out.extend_from_slice(chunk_data);
    Ok(out)
}

/// Convert a portable shard (plain JSON header) to vault shard (at-rest encrypted header).
/// Used when importing shared shards back into the vault on a (possibly different) machine.
pub fn portable_bytes_to_vault(data: &[u8], at_rest_key: &[u8; crypto::KEY_LEN]) -> CoreResult<Vec<u8>> {
    if data.len() < 12 || &data[..8] != MAGIC_PORTABLE {
        return Err(CoreError::InvalidFragment("not a portable shard".into()));
    }
    let json_len = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    let header_end = 8 + 4 + json_len;
    if data.len() < header_end {
        return Err(CoreError::InvalidFragment("portable shard truncated".into()));
    }
    let json_bytes = &data[12..header_end];
    let chunk_data = &data[header_end..];

    // Re-encrypt header with at-rest key
    let enc = crypto::encrypt(at_rest_key, json_bytes)?;
    let mut out = Vec::with_capacity(8 + 12 + 4 + enc.ciphertext.len() + chunk_data.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&enc.nonce);
    out.extend_from_slice(&(enc.ciphertext.len() as u32).to_le_bytes());
    out.extend_from_slice(&enc.ciphertext);
    out.extend_from_slice(chunk_data);
    Ok(out)
}

/// Read `LargeFragmentMeta` from raw portable shard bytes (without opening a file).
pub fn meta_from_portable_bytes(data: &[u8]) -> CoreResult<LargeFragmentMeta> {
    if data.len() < 12 || &data[..8] != MAGIC_PORTABLE {
        return Err(CoreError::InvalidFragment("not a portable shard".into()));
    }
    let json_len = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    if data.len() < 12 + json_len {
        return Err(CoreError::InvalidFragment("portable shard truncated".into()));
    }
    serde_json::from_slice(&data[12..12 + json_len])
        .map_err(|e| CoreError::InvalidFragment(format!("bad portable header: {e}")))
}

/// Package all vault shards as portable .svf3 files in a zip.
/// Returns (zip_bytes, original_filename, shard_count).
pub fn package_shards_for_sharing(
    frag_dir: &Path,
    at_rest_key: &[u8; crypto::KEY_LEN],
) -> CoreResult<(Vec<u8>, String, usize)> {
    package_shards_for_sharing_with_progress(frag_dir, at_rest_key, &OpControl::new(), |_, _| {})
}

// Same as package_shards_for_sharing but calls on_progress(percent 0-100, message) per shard.
pub fn package_shards_for_sharing_with_progress<F: FnMut(u8, &str)>(
    frag_dir: &Path,
    at_rest_key: &[u8; crypto::KEY_LEN],
    ctl: &OpControl,
    mut on_progress: F,
) -> CoreResult<(Vec<u8>, String, usize)> {
    let shards = find_shard_files(frag_dir)?;
    if shards.is_empty() {
        return Err(CoreError::Storage("no shard files found".into()));
    }
    let meta = read_meta(&shards[0].1, at_rest_key)?;
    let filename = meta.original_filename.clone();
    let count = shards.len();

    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (i, (idx, path)) in shards.iter().enumerate() {
            ctl.checkpoint()?;
            let portable = to_portable_bytes(path, at_rest_key)?;
            zip.start_file(format!("shard_{idx}.svf3"), opts)
                .map_err(|e| CoreError::Archive(e.to_string()))?;
            std::io::Write::write_all(&mut zip, &portable)?;

            let pct = ((i + 1) * 95 / count.max(1)) as u8;
            on_progress(pct.min(95), &format!("Packaging shard {} of {}…", i + 1, count));
        }
        zip.finish().map_err(|e| CoreError::Archive(e.to_string()))?;
    }
    on_progress(100, "Done");
    Ok((buffer.into_inner(), filename, count))
}

/// Import portable shard bytes into the vault — re-encrypts headers with at-rest key,
/// writes shard files under `frag_dir`, and returns the parsed metadata.
pub fn import_portable_shards(
    portable_shards: &[(u8, Vec<u8>)], // (shard_index, portable_bytes)
    frag_dir: &Path,
    at_rest_key: &[u8; crypto::KEY_LEN],
) -> CoreResult<LargeFragmentMeta> {
    std::fs::create_dir_all(frag_dir)?;
    let meta = meta_from_portable_bytes(&portable_shards[0].1)?;
    for (idx, data) in portable_shards {
        let vault_bytes = portable_bytes_to_vault(data, at_rest_key)?;
        std::fs::write(shard_path(frag_dir, *idx), vault_bytes)?;
    }
    Ok(meta)
}

/// Return the path for shard `index` inside `frag_dir`.
pub fn shard_path(frag_dir: &Path, index: u8) -> PathBuf {
    frag_dir.join(format!("shard_{index}.svf3"))
}

/// Return all shard files present for a given fragment directory,
/// sorted by shard index. Returns (shard_index, path) pairs.
pub fn find_shard_files(frag_dir: &Path) -> CoreResult<Vec<(u8, PathBuf)>> {
    let mut shards = Vec::new();
    for entry in std::fs::read_dir(frag_dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if let Some(rest) = name.strip_prefix("shard_") {
            if let Some(idx_str) = rest.strip_suffix(".svf3") {
                if let Ok(idx) = idx_str.parse::<u8>() {
                    shards.push((idx, path));
                }
            }
        }
    }
    shards.sort_by_key(|(idx, _)| *idx);
    Ok(shards)
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Read up to `buf.len()` bytes; returns 0 only at EOF.
fn read_chunk<R: Read>(r: &mut R, buf: &mut [u8]) -> CoreResult<usize> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

fn zlib_compress(data: &[u8]) -> CoreResult<Vec<u8>> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).map_err(|e| CoreError::Storage(format!("compress: {e}")))?;
    enc.finish().map_err(|e| CoreError::Storage(format!("compress: {e}")))
}

fn zlib_decompress(data: &[u8]) -> CoreResult<Vec<u8>> {
    let mut dec = ZlibDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).map_err(|e| CoreError::Storage(format!("decompress: {e}")))?;
    Ok(out)
}

/// Check whether `password` unlocks this shard set, without decoding any
/// chunk data. `at_rest_key` is only used for vault-local (non-portable)
/// shard headers — pass any key when checking portable (.svf3) shards.
pub fn verify_password(
    shard_files: &[(u8, PathBuf)],
    password: Option<&str>,
    at_rest_key: &[u8; crypto::KEY_LEN],
) -> CoreResult<()> {
    if shard_files.is_empty() {
        return Err(CoreError::InvalidFragment("no shard files provided".into()));
    }

    let meta = read_meta(&shard_files[0].1, at_rest_key)?;
    let k = meta.threshold as usize;

    if shard_files.len() < k {
        return Err(CoreError::InvalidFragment(format!(
            "need {} shards, have {}", k, shard_files.len()
        )));
    }

    let mut shares: Vec<shamir::Share> = shard_files.iter().take(k)
        .map(|(_, path)| {
            let m = read_meta(path, at_rest_key)?;
            let y = B64.decode(&m.share_y_b64)
                .map_err(|e| CoreError::InvalidFragment(format!("bad share: {e}")))?;
            Ok(shamir::Share { x: m.share_x, y })
        })
        .collect::<CoreResult<_>>()?;
    let recovered_key_data = shamir::combine(&shares)?;
    for share in shares.iter_mut() { share.y.zeroize(); }

    let mut key = unwrap_file_key(
        recovered_key_data,
        meta.password_protected,
        password,
        &meta.kdf,
        &meta.salt_b64,
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

    let pw = password.ok_or_else(|| CoreError::Decryption("password required".into()))?;
    let salt = B64.decode(salt_b64)
        .map_err(|e| CoreError::InvalidFragment(format!("bad salt: {e}")))?;
    let mut pw_key = crypto::derive_key_kdf(kdf, pw, &salt)?;

    if recovered_key_data.len() <= crypto::NONCE_LEN {
        recovered_key_data.zeroize();
        return Err(CoreError::InvalidFragment("wrapped key too short".into()));
    }
    let (np, cp) = recovered_key_data.split_at(crypto::NONCE_LEN);
    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(np);
    let mut unwrapped = crypto::decrypt(&pw_key, &nonce, cp)?;
    pw_key.zeroize();
    recovered_key_data.zeroize();
    let key = to_key_array(&unwrapped);
    unwrapped.zeroize();
    key
}

fn to_key_array(bytes: &[u8]) -> CoreResult<[u8; crypto::KEY_LEN]> {
    if bytes.len() != crypto::KEY_LEN {
        return Err(CoreError::InvalidFragment(format!(
            "key wrong length: {} vs {}", bytes.len(), crypto::KEY_LEN
        )));
    }
    let mut arr = [0u8; crypto::KEY_LEN];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::SplitParams;
    use rand::RngCore;

    fn make_file(path: &Path, size: usize) {
        let mut data = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut data);
        std::fs::write(path, &data).unwrap();
    }

    fn roundtrip(size: usize, padding_pct: u8, compress: bool, password: Option<&str>) {
        let dir = std::env::temp_dir().join(format!("svtest_{}_{}_{}", size, padding_pct, compress));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let in_path = dir.join("in.bin");
        make_file(&in_path, size);
        let orig = std::fs::read(&in_path).unwrap();

        let params = SplitParams {
            total_fragments: 5,
            threshold: 3,
            password: password.map(|s| s.to_string()),
            compress,
            cipher: "aes256gcm".to_string(),
            kdf: "standard".to_string(),
            padding_pct,
        };
        let at_rest_key = crypto::generate_key();
        let frag_dir = dir.join("frags");
        let file_id = "test-file-id".to_string();
        let metas = split_large_file(&in_path, "in.bin", &params, &at_rest_key, &frag_dir, &file_id, &OpControl::new(), |_, _| {}).unwrap();
        assert_eq!(metas.len(), 5);

        let shard_files = find_shard_files(&frag_dir).unwrap();
        let out_path = dir.join("out.bin");
        reconstruct_large_file(&shard_files[0..3], password, &at_rest_key, &out_path).unwrap();

        let recon = std::fs::read(&out_path).unwrap();
        assert_eq!(recon.len(), orig.len(), "size mismatch: size={} padding={} compress={}", size, padding_pct, compress);
        assert_eq!(recon, orig, "content mismatch: size={} padding={} compress={}", size, padding_pct, compress);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_exact_multiple_of_chunk() {
        roundtrip(CHUNK_SIZE * 2, 0, false, None);
    }

    #[test]
    fn test_not_multiple_of_chunk() {
        roundtrip(CHUNK_SIZE * 2 + 12345, 0, false, None);
    }

    #[test]
    fn test_small_one_chunk() {
        roundtrip(1000, 0, false, None);
    }

    #[test]
    fn test_with_padding() {
        roundtrip(CHUNK_SIZE + 500, 20, false, None);
    }

    #[test]
    fn test_with_compress() {
        roundtrip(CHUNK_SIZE + 500, 0, true, None);
    }

    #[test]
    fn test_with_password() {
        roundtrip(CHUNK_SIZE + 500, 0, false, Some("hunter2"));
    }

    #[test]
    fn test_all_options() {
        roundtrip(CHUNK_SIZE * 3 + 777, 15, true, Some("pw"));
    }

    #[test]
    fn test_verify_password() {
        let dir = std::env::temp_dir().join(format!("svtest_verify_pw_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let in_path = dir.join("in.bin");
        make_file(&in_path, CHUNK_SIZE + 500);

        let params = SplitParams {
            total_fragments: 5,
            threshold: 3,
            password: Some("hunter2".to_string()),
            compress: false,
            cipher: "aes256gcm".to_string(),
            kdf: "standard".to_string(),
            padding_pct: 0,
        };
        let at_rest_key = crypto::generate_key();
        let frag_dir = dir.join("frags");
        split_large_file(&in_path, "in.bin", &params, &at_rest_key, &frag_dir, "id", &OpControl::new(), |_, _| {}).unwrap();
        let shard_files = find_shard_files(&frag_dir).unwrap();

        assert!(verify_password(&shard_files[0..3], Some("hunter2"), &at_rest_key).is_ok());
        assert!(verify_password(&shard_files[0..3], Some("wrong"), &at_rest_key).is_err());
        assert!(verify_password(&shard_files[0..3], None, &at_rest_key).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
