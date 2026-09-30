//! Content fingerprint of everything that can change a measurement: the crate
//! sources, the built-in models, the embedded nah goldens and guard queries,
//! the vendored third-party code, and the toolchain pins. `build.rs` embeds the fingerprint
//! of the tree it compiled, and the bench recomputes it at run time, so a
//! binary that is older than the tree it is asked to measure or publish is
//! detected. Generated results (`bench/runs`, the scoreboard, the ceilings)
//! and every corpus are excluded: corpora carry their own digests.
//!
//! Symbolic links below a root are refused rather than followed: a link could
//! reach outside the tree or cycle, and nothing measured lives behind one.
//!
//! Shared by `build.rs` through `#[path]`, so it depends only on std and blake3.

use std::path::{Path, PathBuf};

/// Roots below the workspace that are hashed; a missing root contributes nothing.
pub const ROOTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo/config.toml",
    ".cargo/rustc-wrapper.sh",
    "crates",
    "bench/tools",
    "bench/selected-code",
    "third_party",
    "bench/nah/goldens",
    "bench/nah/guard-queries.json",
];
/// Directory names skipped anywhere below a root.
const SKIP: &[&str] = &["target", ".git", "tests", "__pycache__"];

/// `blake3:<hex>` over every included file's workspace-relative path and bytes.
pub fn compute_source_fingerprint(root: &Path) -> std::io::Result<String> {
    let mut files = Vec::new();
    for entry in ROOTS {
        collect(&root.join(entry), &mut files)?;
    }
    files.sort();
    let mut hasher = blake3::Hasher::new();
    for path in files {
        let relative = path.strip_prefix(root).unwrap_or(&path);
        hasher.update(relative.to_string_lossy().as_bytes());
        hasher.update(&[0]);
        hasher.update(&std::fs::read(&path)?);
        hasher.update(&[0]);
    }
    Ok(format!("blake3:{}", hasher.finalize().to_hex()))
}

fn collect(path: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_symlink() {
        return Err(std::io::Error::other(format!(
            "{} is a symbolic link; source roots must be plain files and directories",
            path.display()
        )));
    }
    if meta.is_file() {
        out.push(path.to_path_buf());
    } else if meta.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?.path();
            let name = entry.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if SKIP.contains(&name) && std::fs::symlink_metadata(&entry)?.is_dir() {
                continue;
            }
            collect(&entry, out)?;
        }
    }
    Ok(())
}
