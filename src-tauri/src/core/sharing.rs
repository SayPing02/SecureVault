// ZIP packaging for sharing fragments between users
//
// When sharing: we zip up exactly k (threshold) fragments - thats the
// minimum needed to reconstruct. Giving more would weaken the scheme.
//
// When importing: unzip, parse the .svf files, and hand them back
// to the caller for reconstruction + re-fragmentation.

use crate::core::error::{CoreError, CoreResult};
use crate::core::model::Fragment;
use std::io::{Cursor, Read, Write};
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

// Build a zip in memory with minimum fragments
pub fn package_for_sharing(fragments: &[Fragment]) -> CoreResult<Vec<u8>> {
    let first = fragments
        .first()
        .ok_or_else(|| CoreError::Archive("no fragments to package".into()))?;

    let needed = first.threshold as usize;
    if fragments.len() < needed {
        return Err(CoreError::Archive(format!(
            "need {} fragments to share, only have {}",
            needed, fragments.len()
        )));
    }

    let mut buffer = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut buffer);
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        for frag in fragments.iter().take(needed) {
            let name = format!("fragment_{}.svf", frag.index);
            let json = serde_json::to_vec_pretty(frag)?;
            zip.start_file(name, opts)
                .map_err(|e| CoreError::Archive(e.to_string()))?;
            zip.write_all(&json)?;
        }

        zip.finish().map_err(|e| CoreError::Archive(e.to_string()))?;
    }

    Ok(buffer.into_inner())
}

// Parse a shared zip back into fragments
pub fn import_shared_bundle(zip_bytes: &[u8]) -> CoreResult<Vec<Fragment>> {
    let cursor = Cursor::new(zip_bytes);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| CoreError::Archive(e.to_string()))?;

    let mut fragments = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)
            .map_err(|e| CoreError::Archive(e.to_string()))?;

        if !entry.name().ends_with(".svf") {
            continue; // skip non-fragment files
        }

        let mut contents = String::new();
        entry.read_to_string(&mut contents)?;

        let frag: Fragment = serde_json::from_str(&contents)
            .map_err(|e| CoreError::InvalidFragment(
                format!("couldn't parse fragment: {e}")
            ))?;
        fragments.push(frag);
    }

    if fragments.is_empty() {
        return Err(CoreError::Archive(
            "no .svf files found in the bundle".into()
        ));
    }

    // make sure all fragments are for the same file
    let first_id = fragments[0].file_id.clone();
    if fragments.iter().any(|f| f.file_id != first_id) {
        return Err(CoreError::InvalidFragment(
            "bundle has fragments from different files".into()
        ));
    }

    fragments.sort_by_key(|f| f.index);
    Ok(fragments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::fragmenter;
    use crate::core::model::SplitParams;

    #[test]
    fn test_share_and_import() {
        let params = SplitParams {
            total_fragments: 5,
            threshold: 3,
            password: None,
        };
        let frags = fragmenter::split_file(
            b"shareable content", "share.txt", &params
        ).unwrap();

        let zip = package_for_sharing(&frags).unwrap();
        let imported = import_shared_bundle(&zip).unwrap();

        // should only have k=3 fragments in the bundle
        assert_eq!(imported.len(), 3);

        // should be able to reconstruct from those 3
        let recovered = fragmenter::reconstruct_file(&imported, None).unwrap();
        assert_eq!(recovered, b"shareable content");
    }

    #[test]
    fn test_empty_zip() {
        let mut buf = Cursor::new(Vec::new());
        ZipWriter::new(&mut buf).finish().unwrap();
        assert!(import_shared_bundle(&buf.into_inner()).is_err());
    }
}
