// ZIP packaging for sharing fragments
//
// Fragments are exported as .svf files in opaque format (base64 encoded)
// so the contents are not human readable, but any machine can decode
// them without needing the sender's app secret.

use crate::core::error::{CoreError, CoreResult};
use crate::core::model::Fragment;
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

// Build a zip containing all N fragments as opaque .svf files
pub fn package_all_fragments(fragments: &[Fragment]) -> CoreResult<Vec<u8>> {
    if fragments.is_empty() {
        return Err(CoreError::Archive("no fragments to package".into()));
    }

    let mut buffer = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut buffer);
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        for frag in fragments {
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
        .map_err(|e| CoreError::InvalidFragment(e))
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
            threshold: 3,
            password: None,
        };
        let frags = fragmenter::split_file(
            b"shareable content", "share.txt", &params
        ).unwrap();

        // package all 5
        let zip = package_all_fragments(&frags).unwrap();
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

    #[test]
    fn test_opaque_is_not_readable() {
        let params = SplitParams {
            total_fragments: 3,
            threshold: 2,
            password: None,
        };
        let frags = fragmenter::split_file(b"secret", "s.txt", &params).unwrap();
        let opaque = frags[0].to_opaque_bytes().unwrap();

        // the opaque bytes should NOT contain the filename in plain text
        let as_str = String::from_utf8_lossy(&opaque);
        assert!(!as_str.contains("s.txt"));
        assert!(!as_str.contains("original_filename"));
    }
}
