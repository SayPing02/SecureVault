// ZIP packaging for sharing fragments
//
// Fragments are exported as .svf files in opaque format (base64 encoded)
// so the contents are not human readable, but any machine can decode
// them without needing the sender's app secret.

use crate::core::error::{CoreError, CoreResult};
use crate::core::model::Fragment;
use crate::core::op_control::OpControl;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

// Build a zip containing all N fragments as opaque .svf files
pub fn package_all_fragments(fragments: &[Fragment], ctl: &OpControl) -> CoreResult<Vec<u8>> {
    if fragments.is_empty() {
        return Err(CoreError::Archive("no fragments to package".into()));
    }

    let mut buffer = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut buffer);
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        for frag in fragments {
            ctl.checkpoint()?;
            let name = format!("fragment_{}.svf", frag.index);
            let opaque = frag.to_opaque_bytes()
                .map_err(|e| CoreError::Archive(format!("could not encode fragment: {e}")))?;
            zip.start_file(name, opts)
                .map_err(|e| CoreError::Archive(e.to_string()))?;
            zip.write_all(&opaque)?;
        }

        zip.finish().map_err(|e| CoreError::Archive(e.to_string()))?;
    }

    Ok(buffer.into_inner())
}

// Parse a .svf file from its opaque bytes into a Fragment
pub fn read_opaque_fragment(data: &[u8]) -> CoreResult<Fragment> {
    Fragment::from_opaque_bytes(data)
        .map_err(CoreError::InvalidFragment)
}

/// Pull the fragment entries (.svf / .svf3) out of a share zip into `dest`,
/// which must already exist. Lets the app read back the very bundles it
/// produces, instead of making the user unzip them by hand first.
///
/// Entry names are reduced to their final path component before being used,
/// so an archive containing `../../something` can't write outside `dest`
/// ("zip slip"). Anything that isn't a fragment — the labels.txt note,
/// directory records — is skipped rather than treated as an error.
/// Returns the written paths sorted, so ordering doesn't depend on however
/// the archive happened to be built.
pub fn extract_fragments_from_zip(zip_bytes: &[u8], dest: &Path) -> CoreResult<Vec<PathBuf>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes))
        .map_err(|e| CoreError::Archive(format!("not a readable zip: {e}")))?;

    let mut written = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| CoreError::Archive(e.to_string()))?;
        if entry.is_dir() {
            continue;
        }

        // Deliberately discard any directory part the archive claims.
        let name = match Path::new(entry.name()).file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let lower = name.to_ascii_lowercase();
        if !(lower.ends_with(".svf") || lower.ends_with(".svf3")) {
            continue;
        }

        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        let out_path = dest.join(&name);
        std::fs::write(&out_path, &buf)?;
        written.push(out_path);
    }

    if written.is_empty() {
        return Err(CoreError::Archive(
            "that zip doesn't contain any .svf or .svf3 fragment files".into(),
        ));
    }
    written.sort();
    Ok(written)
}

// Re-open an already-built share zip and add a "labels.txt" listing which
// fragment/shard index went where, purely as a note for whoever opens the
// zip later — the labels are never read back by reconstruction. No-op if
// `labels` is empty so an unlabelled share stays exactly as it was.
pub fn append_labels_file(zip_bytes: Vec<u8>, labels: &HashMap<u8, String>) -> CoreResult<Vec<u8>> {
    if labels.is_empty() {
        return Ok(zip_bytes);
    }

    let mut sorted: Vec<(&u8, &String)> = labels.iter().collect();
    sorted.sort_by_key(|(idx, _)| **idx);

    let mut text = String::from("Fragment destinations (for your own reference only):\n\n");
    for (idx, label) in sorted {
        text.push_str(&format!("Fragment {idx}: {label}\n"));
    }

    let cursor = Cursor::new(zip_bytes);
    let mut zip = ZipWriter::new_append(cursor)
        .map_err(|e| CoreError::Archive(e.to_string()))?;
    let opts = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("labels.txt", opts)
        .map_err(|e| CoreError::Archive(e.to_string()))?;
    zip.write_all(text.as_bytes())?;

    let cursor = zip.finish().map_err(|e| CoreError::Archive(e.to_string()))?;
    Ok(cursor.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::fragmenter;
    use crate::core::model::SplitParams;

    #[test]
    fn test_package_and_read_back() {
        let params = SplitParams {
            total_fragments: 5,
            threshold:       3,
            password:        None,
            compress:        false,
            cipher:          "aes256gcm".to_string(),
            kdf:             "standard".to_string(),
            padding_pct:     0,
        };
        let frags = fragmenter::split_file(
            b"shareable content", "share.txt", &params
        ).unwrap();

        // package all 5
        let zip = package_all_fragments(&frags, &OpControl::new()).unwrap();
        assert!(!zip.is_empty());

        // verify we can read fragments back from zip
        let cursor = std::io::Cursor::new(zip);
        let mut archive = zip::ZipArchive::new(cursor).unwrap();
        assert_eq!(archive.len(), 5);

        // read one fragment and verify it decodes
        let mut entry = archive.by_index(0).unwrap();
        let mut contents = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut contents).unwrap();
        let recovered = read_opaque_fragment(&contents).unwrap();
        assert_eq!(recovered.original_filename, "share.txt");
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("svtest_unzip_{tag}_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn extracts_fragments_from_a_share_zip_the_app_produced() {
        let params = SplitParams {
            total_fragments: 5,
            threshold:       3,
            password:        None,
            compress:        false,
            cipher:          "aes256gcm".to_string(),
            kdf:             "standard".to_string(),
            padding_pct:     0,
        };
        let data = b"round trip through a share zip".to_vec();
        let frags = fragmenter::split_file(&data, "share.txt", &params).unwrap();
        // A real share zip also carries a labels.txt note, which must be
        // skipped rather than mistaken for a fragment.
        let zip = append_labels_file(
            package_all_fragments(&frags, &OpControl::new()).unwrap(),
            &HashMap::from([(1u8, "USB drive".to_string())]),
        )
        .unwrap();

        let dest = temp_dir("roundtrip");
        let extracted = extract_fragments_from_zip(&zip, &dest).unwrap();

        assert_eq!(extracted.len(), 5, "labels.txt must not be counted");
        assert!(extracted.iter().all(|p| p.exists()));

        // The extracted files really do reconstruct the original.
        let recovered: Vec<_> = extracted[0..3]
            .iter()
            .map(|p| read_opaque_fragment(&std::fs::read(p).unwrap()).unwrap())
            .collect();
        assert_eq!(fragmenter::reconstruct_file(&recovered, None).unwrap(), data);

        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn traversal_entry_names_cannot_escape_the_destination() {
        // "Zip slip": an archive whose entry name climbs out of the target
        // directory. The extractor must keep only the final component.
        let mut buffer = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut buffer);
            let opts = SimpleFileOptions::default();
            zip.start_file("../../escaped.svf", opts).unwrap();
            zip.write_all(b"payload").unwrap();
            zip.finish().unwrap();
        }
        let bytes = buffer.into_inner();

        let dest = temp_dir("slip");
        let extracted = extract_fragments_from_zip(&bytes, &dest).unwrap();

        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0], dest.join("escaped.svf"));
        assert!(extracted[0].starts_with(&dest), "must stay inside dest");
        assert!(
            !dest.parent().unwrap().join("escaped.svf").exists(),
            "nothing may be written outside dest"
        );

        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn a_zip_with_no_fragments_is_rejected() {
        let mut buffer = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut buffer);
            zip.start_file("readme.txt", SimpleFileOptions::default()).unwrap();
            zip.write_all(b"not a fragment").unwrap();
            zip.finish().unwrap();
        }
        let bytes = buffer.into_inner();

        let dest = temp_dir("empty");
        let err = extract_fragments_from_zip(&bytes, &dest).unwrap_err();
        assert!(err.to_string().contains("fragment"), "unexpected error: {err}");

        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn test_opaque_is_not_readable() {
        let params = SplitParams {
            total_fragments: 3,
            threshold:       2,
            password:        None,
            compress:        false,
            cipher:          "aes256gcm".to_string(),
            kdf:             "standard".to_string(),
            padding_pct:     0,
        };
        let frags = fragmenter::split_file(b"secret", "s.txt", &params).unwrap();
        let opaque = frags[0].to_opaque_bytes().unwrap();

        // the opaque bytes should NOT contain the filename in plain text
        let as_str = String::from_utf8_lossy(&opaque);
        assert!(!as_str.contains("s.txt"));
        assert!(!as_str.contains("original_filename"));
    }
}
