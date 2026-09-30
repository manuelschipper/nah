// Build scripts run on the host at build time: the workspace's pure-crate
// lint rules describe runtime crates, not the generator that feeds them.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::path::{Path, PathBuf};

fn files_under(root: &Path, relative: &Path, files: &mut Vec<PathBuf>) {
    let path = root.join(relative);
    if path.is_file() {
        files.push(relative.to_path_buf());
        return;
    }
    let mut entries: Vec<_> = std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap())
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let child = relative.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            files_under(root, &child, files);
        } else if entry.file_type().unwrap().is_file() {
            files.push(child);
        }
    }
}

fn main() {
    let crate_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = crate_dir.parent().unwrap().parent().unwrap();
    let mut files = Vec::new();
    for path in [
        Path::new("Cargo.toml"),
        Path::new("Cargo.lock"),
        Path::new("crates/effinterp-proto/Cargo.toml"),
        Path::new("crates/effinterp-proto/analysis-v1.schema.json"),
        Path::new("crates/effinterp-proto/src"),
        Path::new("crates/effinterp-model-schema/Cargo.toml"),
        Path::new("crates/effinterp-model-schema/src"),
        Path::new("crates/effinterp-engine/Cargo.toml"),
        Path::new("crates/effinterp-engine/build.rs"),
        Path::new("crates/effinterp-engine/models"),
        Path::new("crates/effinterp-engine/src"),
        Path::new("third_party/gosyn/Cargo.toml"),
        Path::new("third_party/gosyn/src"),
        Path::new("crates/effinterp-repo/Cargo.toml"),
        Path::new("crates/effinterp-repo/build.rs"),
        Path::new("crates/effinterp-repo/src"),
    ] {
        files_under(root, path, &mut files);
    }
    files.sort();

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"effinterp/analyzer-build/v1\0");
    for path in files {
        let path_text = path.to_str().unwrap();
        println!("cargo:rerun-if-changed={}", root.join(&path).display());
        hasher.update(path_text.as_bytes());
        hasher.update(b"\0");
        hasher.update(&std::fs::read(root.join(path)).unwrap());
        hasher.update(b"\x1e");
    }
    println!(
        "cargo:rustc-env=EFFINTERP_ANALYZER_BUILD_DIGEST=blake3:{}",
        hasher.finalize().to_hex()
    );
}
