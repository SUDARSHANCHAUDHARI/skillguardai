use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct WalkCaps { pub max_file_bytes: u64, pub max_total_bytes: u64, pub max_files: usize }
impl Default for WalkCaps {
    fn default() -> Self { Self { max_file_bytes: 1 << 20, max_total_bytes: 20 << 20, max_files: 2000 } }
}

pub struct TextFile {
    // Part of the documented TextFile interface; not read internally yet.
    #[allow(dead_code)] pub path: PathBuf,
    pub rel: String,
    pub content: String,
}

fn is_binary(bytes: &[u8]) -> bool { bytes.iter().take(8000).any(|&b| b == 0) }

/// Media/binary assets a text pattern scanner never inspects. Skipped by extension
/// BEFORE the size cap, so a large asset (e.g. a demo `.mp4`) never errors a scan.
/// The fail-closed cap still applies to oversized *text* files (an evasion vector).
/// Note: `.svg` is intentionally NOT here — it is XML and can carry inline `<script>`.
fn is_skippable_asset(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()).map(|s| s.to_ascii_lowercase()).as_deref(),
        Some(
            "mp4" | "mov" | "avi" | "mkv" | "webm" | "png" | "jpg" | "jpeg" | "gif" | "webp"
            | "bmp" | "ico" | "tiff" | "pdf" | "zip" | "gz" | "tar" | "tgz" | "bz2" | "xz"
            | "7z" | "rar" | "woff" | "woff2" | "ttf" | "otf" | "eot" | "mp3" | "wav" | "ogg"
            | "flac" | "m4a" | "class" | "jar" | "so" | "dylib" | "dll" | "exe" | "bin"
            | "wasm" | "parquet" | "db" | "sqlite" | "sqlite3"
        )
    )
}

pub fn collect_text_files(root: &Path, caps: &WalkCaps) -> anyhow::Result<Vec<TextFile>> {
    let mut files = Vec::new();
    let (mut total, mut count) = (0u64, 0usize);
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() { continue; }
        if is_skippable_asset(entry.path()) { continue; }
        count += 1;
        if count > caps.max_files { anyhow::bail!("too many files (> {})", caps.max_files); }
        let len = entry.metadata()?.len();
        if len > caps.max_file_bytes { anyhow::bail!("file too large: {}", entry.path().display()); }
        total += len;
        if total > caps.max_total_bytes { anyhow::bail!("bundle too large (> {} bytes)", caps.max_total_bytes); }
        let bytes = std::fs::read(entry.path())?;
        if is_binary(&bytes) { continue; }
        let rel = entry.path().strip_prefix(root).unwrap_or(entry.path()).to_string_lossy().into_owned();
        files.push(TextFile { path: entry.path().to_path_buf(), rel, content: String::from_utf8_lossy(&bytes).into_owned() });
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn collects_text_skips_binary() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("a.md"), b"hello").unwrap();
        std::fs::write(d.path().join("b.bin"), b"\x00\x01\x02").unwrap();
        let files = collect_text_files(d.path(), &WalkCaps::default()).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].rel, "a.md");
    }
    #[test]
    fn oversize_file_fails_closed() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("big.txt"), vec![b'x'; 2]).unwrap();
        let caps = WalkCaps { max_file_bytes: 1, ..Default::default() };
        assert!(collect_text_files(d.path(), &caps).is_err());
    }
    #[test]
    fn oversize_media_asset_is_skipped_not_errored() {
        // A large .mp4 must be skipped by extension, never trip the cap.
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("demo.mp4"), vec![b'x'; 8]).unwrap();
        std::fs::write(d.path().join("SKILL.md"), b"ok").unwrap();
        let caps = WalkCaps { max_file_bytes: 4, ..Default::default() };
        let files = collect_text_files(d.path(), &caps).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].rel, "SKILL.md");
    }
}
