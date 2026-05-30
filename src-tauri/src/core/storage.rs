// Vault storage layer
//
// Handles reading/writing fragment files and the manifest to disk.
// Everything written to the vault folder is encrypted with a key derived
// from a machine-local secret (app.secret file). This way even if someone
// finds the folder, the files look like random noise.
//
// Folder layout:
//   <app-data>/vault/
//     manifest.json.enc
//     <file_id>/
//       fragment_1.svf.enc
//       fragment_2.svf.enc
//       ...

use crate::core::crypto;
use crate::core::error::{CoreError, CoreResult};
use crate::core::model::{Fragment, Manifest};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const VAULT_DIR_NAME: &str = "vault";
const MANIFEST_NAME: &str = "manifest.json.enc";
const APP_SECRET_NAME: &str = "app.secret";

pub struct Storage {
    vault_dir: PathBuf,
    at_rest_key: [u8; crypto::KEY_LEN],
}

impl Storage {
    pub fn new(app_data_dir: &Path) -> CoreResult<Self> {
        let vault_dir = app_data_dir.join(VAULT_DIR_NAME);
        fs::create_dir_all(&vault_dir)?;

        // load or create the app secret on first run
        let secret_path = app_data_dir.join(APP_SECRET_NAME);
        let app_secret = load_or_create_app_secret(&secret_path)?;

        // derive the at-rest encryption key from the app secret
        let at_rest_key =
            crypto::derive_key_from_password(&hex(&app_secret), b"securevault-at-rest");

        Ok(Self { vault_dir, at_rest_key })
    }

    pub fn load_manifest(&self) -> CoreResult<Manifest> {
        let path = self.vault_dir.join(MANIFEST_NAME);
        if !path.exists() {
            return Ok(Manifest::default());
        }
        let plaintext = self.read_encrypted(&path)?;
        let manifest = serde_json::from_slice(&plaintext)?;
        Ok(manifest)
    }

    pub fn save_manifest(&self, manifest: &Manifest) -> CoreResult<()> {
        let path = self.vault_dir.join(MANIFEST_NAME);
        let json = serde_json::to_vec_pretty(manifest)?;
        self.write_encrypted(&path, &json)
    }

    pub fn store_fragments(&self, file_id: &str, fragments: &[Fragment]) -> CoreResult<()> {
        let dir = self.vault_dir.join(file_id);
        fs::create_dir_all(&dir)?;

        for frag in fragments {
            let name = format!("fragment_{}.svf.enc", frag.index);
            let json = serde_json::to_vec(frag)?;
            self.write_encrypted(&dir.join(name), &json)?;
        }
        Ok(())
    }

    pub fn load_fragments(&self, file_id: &str) -> CoreResult<Vec<Fragment>> {
        let dir = self.vault_dir.join(file_id);
        if !dir.exists() {
            return Err(CoreError::Storage(
                format!("no fragments found for {file_id}")
            ));
        }

        let mut fragments = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            // only read .svf.enc files, skip anything else
            let is_frag = path.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(".svf.enc"))
                .unwrap_or(false);
            if !is_frag { continue; }

            let data = self.read_encrypted(&path)?;
            let frag: Fragment = serde_json::from_slice(&data)?;
            fragments.push(frag);
        }

        fragments.sort_by_key(|f| f.index);
        Ok(fragments)
    }

    pub fn delete_fragments(&self, file_id: &str) -> CoreResult<()> {
        let dir = self.vault_dir.join(file_id);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        Ok(())
    }

    // encrypt data and write to disk
    // format: [12 byte nonce][ciphertext...]
    fn write_encrypted(&self, path: &Path, data: &[u8]) -> CoreResult<()> {
        let enc = crypto::encrypt(&self.at_rest_key, data)?;
        let mut file = fs::File::create(path)?;
        file.write_all(&enc.nonce)?;
        file.write_all(&enc.ciphertext)?;
        Ok(())
    }

    // read and decrypt a file written by write_encrypted
    fn read_encrypted(&self, path: &Path) -> CoreResult<Vec<u8>> {
        let mut file = fs::File::open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        if buf.len() <= crypto::NONCE_LEN {
            return Err(CoreError::Storage(
                format!("file is truncated: {}", path.display())
            ));
        }

        let (nonce_part, cipher_part) = buf.split_at(crypto::NONCE_LEN);
        let mut nonce = [0u8; crypto::NONCE_LEN];
        nonce.copy_from_slice(nonce_part);

        crypto::decrypt(&self.at_rest_key, &nonce, cipher_part)
    }
}

fn load_or_create_app_secret(path: &Path) -> CoreResult<[u8; 32]> {
    if path.exists() {
        let mut file = fs::File::open(path)?;
        let mut buf = [0u8; 32];
        file.read_exact(&mut buf)
            .map_err(|_| CoreError::Storage("app secret file is corrupt".into()))?;
        Ok(buf)
    } else {
        // first run - generate a new random secret
        let secret = crypto::generate_key();
        fs::write(path, secret)?;
        Ok(secret)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{SplitParams, VaultEntry};
    use crate::core::fragmenter;

    fn temp_storage() -> (Storage, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::new(dir.path()).unwrap();
        (s, dir) // need to keep TempDir alive or the dir gets deleted
    }

    #[test]
    fn test_manifest() {
        let (storage, _dir) = temp_storage();

        let mut manifest = Manifest::default();
        manifest.upsert(VaultEntry {
            file_id: "abc".into(),
            filename: "report.pdf".into(),
            size: 1234,
            total_fragments: 5,
            threshold: 3,
            password_protected: false,
            created_at: 0,
        });
        storage.save_manifest(&manifest).unwrap();

        let loaded = storage.load_manifest().unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].filename, "report.pdf");
    }

    #[test]
    fn test_fragment_storage() {
        let (storage, _dir) = temp_storage();

        let params = SplitParams {
            total_fragments: 4,
            threshold: 2,
            password: None,
        };
        let frags = fragmenter::split_file(b"hello vault", "h.txt", &params).unwrap();
        let file_id = frags[0].file_id.clone();

        storage.store_fragments(&file_id, &frags).unwrap();
        let loaded = storage.load_fragments(&file_id).unwrap();
        assert_eq!(loaded.len(), 4);

        // make sure we can still reconstruct after going through storage
        let recovered = fragmenter::reconstruct_file(&loaded[0..2], None).unwrap();
        assert_eq!(recovered, b"hello vault");
    }

    #[test]
    fn test_delete() {
        let (storage, _dir) = temp_storage();
        let params = SplitParams {
            total_fragments: 3,
            threshold: 2,
            password: None,
        };
        let frags = fragmenter::split_file(b"data", "d.txt", &params).unwrap();
        let id = frags[0].file_id.clone();

        storage.store_fragments(&id, &frags).unwrap();
        storage.delete_fragments(&id).unwrap();
        assert!(storage.load_fragments(&id).is_err());
    }
}
