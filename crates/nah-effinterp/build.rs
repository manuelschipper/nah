//! Producer identity for the engine bridge. Records and caches key on it, so it
//! must change whenever any byte that can change an engine-backed decision
//! changes: engine, schema, models, the vendored Go parser, the bridge and
//! protocol sources that project engine evidence, the matcher, trace and
//! observation crates the bridge reads, and the shipped guards `nah-cli`
//! evaluates over the bridge's projection. It is a digest of
//! committed content, not a Git revision, so an archive build without `.git`
//! derives the same identity from the same files.

// Cargo build metadata needs host I/O; the runtime crate remains pure.
#![allow(clippy::disallowed_macros, clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

/// Workspace-relative inputs. Files are hashed as-is; directories recursively.
const INPUTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "crates/effinterp-proto",
    "crates/effinterp-model-schema",
    "crates/effinterp-engine",
    // The matcher evaluates the shipped guard queries over the projected plan.
    "crates/effinterp-matcher",
    // Causal reachability decides which flows the matcher and bridge report.
    "crates/effinterp-trace",
    "third_party/gosyn/Cargo.toml",
    "third_party/gosyn/src",
    "crates/nah-effinterp/Cargo.toml",
    "crates/nah-effinterp/build.rs",
    "crates/nah-effinterp/src",
    "crates/nah-proto/Cargo.toml",
    "crates/nah-proto/src",
    // The shipped guard definitions. The bridge does not depend on policy:
    // `nah-cli` evaluates them over its projection and hands back their gap
    // owners and matches, which change the evidence and its coverage. This
    // crate is the one producer identity, so it hashes them here.
    "crates/nah-policy/Cargo.toml",
    "crates/nah-policy/src",
    // Source and path observation supplies the bytes and filesystem facts the
    // engine and bridge read.
    "crates/nah-observe",
];

/// Directory names below an input that never reach a shipped decision.
const SKIP: &[&str] = &["target", "tests"];

fn collect(root: &Path, relative: &Path, files: &mut Vec<PathBuf>) {
    let path = root.join(relative);
    if path.is_file() {
        files.push(relative.to_path_buf());
        return;
    }
    // A directory is watched as a whole so added or removed files rerun this
    // script, not only edits to files that already existed.
    println!("cargo:rerun-if-changed={}", path.display());
    let mut entries: Vec<_> = std::fs::read_dir(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
        .map(|entry| entry.unwrap())
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let child = relative.join(entry.file_name());
        let file_type = entry.file_type().unwrap();
        if file_type.is_dir() {
            if !SKIP.iter().any(|skip| entry.file_name() == *skip) {
                collect(root, &child, files);
            }
        } else if file_type.is_file() {
            files.push(child);
        } else {
            panic!("producer identity input {} is a symlink", child.display());
        }
    }
}

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest.join("../..");
    let mut files = Vec::new();
    for input in INPUTS {
        collect(&root, Path::new(input), &mut files);
    }
    files.sort();

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"nah/effinterp-producer/v1\0");
    for file in files {
        let text = file
            .components()
            .map(|component| component.as_os_str().to_str().unwrap())
            .collect::<Vec<_>>()
            .join("/");
        println!("cargo:rerun-if-changed={}", root.join(&file).display());
        hasher.update(text.as_bytes());
        hasher.update(b"\0");
        hasher.update(&std::fs::read(root.join(&file)).unwrap());
        hasher.update(b"\x1e");
    }
    println!(
        "cargo:rustc-env=NAH_EFFINTERP_PRODUCER_IDENTITY=effinterp/blake3:{}",
        hasher.finalize().to_hex()
    );
}
