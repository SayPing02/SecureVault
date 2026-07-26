// Full split -> share -> import -> download round trip, for both small and
// large files, verifying password protection survives crossing into a
// separate vault (as happens when a shared bundle is imported elsewhere).

use crate::core::{fragmenter, large_fragment, model::SplitParams, op_control::OpControl, sharing, storage::Storage};

fn make_storage(tag: &str) -> Storage {
    let dir = std::env::temp_dir().join(format!("svtest_{tag}_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    Storage::new(&dir).unwrap()
}

fn unzip_to(zip_bytes: Vec<u8>, dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::create_dir_all(dir).unwrap();
    let cursor = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor).unwrap();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).unwrap();
        let name = entry.name().to_string();
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut buf).unwrap();
        std::fs::write(dir.join(&name), &buf).unwrap();
    }
    std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect()
}

#[test]
fn small_file_password_survives_share_and_import() {
    let sender = make_storage("sender_small");
    let data = b"top secret payload, small file".to_vec();
    let params = SplitParams {
        total_fragments: 5,
        threshold: 3,
        password: Some("correcthorse".to_string()),
        compress: false,
        cipher: "aes256gcm".to_string(),
        kdf: "standard".to_string(),
        padding_pct: 0,
    };
    let fragments = fragmenter::split_file(&data, "secret.txt", &params).unwrap();
    assert!(fragments[0].password_protected);
    sender.store_fragments(&fragments[0].file_id, &fragments).unwrap();

    let loaded = sender.load_fragments(&fragments[0].file_id).unwrap();
    let zip_bytes = sharing::package_all_fragments(&loaded, &OpControl::new()).unwrap();

    let recipient_dir = std::env::temp_dir().join(format!("svtest_recipient_svf_{}", uuid::Uuid::new_v4()));
    let fragment_paths = unzip_to(zip_bytes, &recipient_dir);

    let recipient_frags: Vec<_> = fragment_paths.iter()
        .map(|p| sharing::read_opaque_fragment(&std::fs::read(p).unwrap()).unwrap())
        .collect();
    assert!(recipient_frags[0].password_protected);

    assert!(fragmenter::reconstruct_file(&recipient_frags, None).is_err());
    assert!(fragmenter::reconstruct_file(&recipient_frags, Some("wrongpassword")).is_err());
    assert_eq!(fragmenter::reconstruct_file(&recipient_frags, Some("correcthorse")).unwrap(), data);
}

#[test]
fn large_file_password_survives_share_and_import() {
    let sender = make_storage("sender_large");
    let big_path = std::env::temp_dir().join(format!("svtest_bigfile_{}", uuid::Uuid::new_v4()));
    {
        use rand::RngCore;
        let mut f = std::fs::File::create(&big_path).unwrap();
        let mut buf = vec![0u8; 8 * 1024 * 1024];
        for _ in 0..9 { // ~72 MB, above the 64MB LARGE_FILE_THRESHOLD
            rand::thread_rng().fill_bytes(&mut buf);
            std::io::Write::write_all(&mut f, &buf).unwrap();
        }
    }
    let original_bytes = std::fs::read(&big_path).unwrap();
    let params = SplitParams {
        total_fragments: 5,
        threshold: 3,
        password: Some("correcthorse".to_string()),
        compress: false,
        cipher: "aes256gcm".to_string(),
        kdf: "standard".to_string(),
        padding_pct: 0,
    };
    let file_id = uuid::Uuid::new_v4().to_string();
    let frag_dir = sender.frag_dir(&file_id);
    let metas = large_fragment::split_large_file(
        &big_path, "bigfile.bin", &params, sender.at_rest_key(), &frag_dir, &file_id, &OpControl::new(), |_, _| {}
    ).unwrap();
    assert!(metas[0].password_protected);

    let (zip_bytes, _filename, _count) = large_fragment::package_shards_for_sharing(&frag_dir, sender.at_rest_key()).unwrap();

    let recipient_dir = std::env::temp_dir().join(format!("svtest_recipient_svf3_{}", uuid::Uuid::new_v4()));
    let shard_paths = unzip_to(zip_bytes, &recipient_dir);

    let portable_shards: Vec<_> = shard_paths.iter()
        .map(|p| {
            let d = std::fs::read(p).unwrap();
            let meta = large_fragment::meta_from_portable_bytes(&d).unwrap();
            (meta.shard_index, d)
        })
        .collect();
    let meta0 = large_fragment::meta_from_portable_bytes(&portable_shards[0].1).unwrap();
    assert!(meta0.password_protected);

    // import into a *new* recipient vault (this is reconstruct_from_fragments's large-file branch)
    let recipient = make_storage("recipient_large");
    let new_id = uuid::Uuid::new_v4().to_string();
    let new_frag_dir = recipient.frag_dir(&new_id);
    large_fragment::import_portable_shards(&portable_shards, &new_frag_dir, recipient.at_rest_key()).unwrap();

    let shard_files = large_fragment::find_shard_files(&new_frag_dir).unwrap();

    let out_no_pw = std::env::temp_dir().join(format!("svtest_out_nopw_{}.bin", uuid::Uuid::new_v4()));
    assert!(large_fragment::reconstruct_large_file(&shard_files, None, recipient.at_rest_key(), &out_no_pw).is_err());

    let out_wrong_pw = std::env::temp_dir().join(format!("svtest_out_wrongpw_{}.bin", uuid::Uuid::new_v4()));
    assert!(large_fragment::reconstruct_large_file(&shard_files, Some("wrongpassword"), recipient.at_rest_key(), &out_wrong_pw).is_err());

    let out_ok = std::env::temp_dir().join(format!("svtest_out_ok_{}.bin", uuid::Uuid::new_v4()));
    large_fragment::reconstruct_large_file(&shard_files, Some("correcthorse"), recipient.at_rest_key(), &out_ok).unwrap();
    assert_eq!(std::fs::read(&out_ok).unwrap(), original_bytes);
}
