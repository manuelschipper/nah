//! Rust Cargo crate roots: package names and `[lib] path` from `Cargo.toml`, and
//! the crate-qualified module scope of a Rust source file.

use std::collections::BTreeMap;
use std::path::Path;

use crate::CRAWL_SKIP_DIRS;

/// One Cargo package: its `src` directory and optional `[lib] path`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct RustCrate {
    pub(super) src_dir: String,
    /// Repo-relative library file when `[lib] path` names it (`src/cat.rs`).
    pub(super) lib_path: Option<String>,
}

/// Rust package names from the repo's `Cargo.toml`s -> crate source layout.
/// Walks the tree (bounded, skipping vendored/build dirs) reading each
/// `[package] name`, with hyphens mapped to underscores as `use` paths spell
/// crate names.
pub(super) fn collect_rust_crates(
    root: &Path,
    admit: &mut dyn FnMut(&Path) -> bool,
) -> BTreeMap<String, RustCrate> {
    fn walk(
        root: &Path,
        dir: &Path,
        depth: u32,
        out: &mut BTreeMap<String, RustCrate>,
        admit: &mut dyn FnMut(&Path) -> bool,
    ) {
        if depth > 4 || out.len() >= 256 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
        entries.sort_by_key(|e| e.path());
        for entry in entries {
            let path = entry.path();
            if crate::canonical_repo_path(root, &path).is_none() {
                continue;
            }
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                // Test/fixture trees hold sample Cargo.tomls (bat's TOML
                // syntax fixtures), never workspace members.
                if CRAWL_SKIP_DIRS.contains(&name.as_str())
                    || matches!(
                        name.as_str(),
                        "tests" | "testdata" | "fixtures" | "examples"
                    )
                {
                    continue;
                }
                walk(root, &path, depth + 1, out, admit);
            } else if ft.is_file()
                && entry.file_name() == "Cargo.toml"
                && admit(&path)
                && let Ok(text) = std::fs::read_to_string(&path)
                && let Some(name) = cargo_package_name(&text)
            {
                let crate_dir = path.parent().unwrap_or(root);
                let src = crate_dir.join("src");
                let rel_src =
                    crate::canonical_repo_path(root, &src).expect("crate source path is canonical");
                let lib_path = cargo_lib_path(&text).and_then(|p| {
                    let abs = crate_dir.join(p);
                    crate::canonical_repo_path(root, &abs)
                });
                // First (shallowest) definition wins.
                out.entry(name.replace('-', "_")).or_insert(RustCrate {
                    src_dir: rel_src,
                    lib_path,
                });
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, 0, &mut out, admit);
    out
}

/// The `name` under a Cargo.toml's `[package]` section, if any.
fn cargo_package_name(text: &str) -> Option<String> {
    cargo_table_value(text, "package", "name")
}

/// The `path` under a Cargo.toml's `[lib]` section, if any.
fn cargo_lib_path(text: &str) -> Option<String> {
    cargo_table_value(text, "lib", "path")
}

/// A string value under a one-level Cargo.toml table (`[package] name = ...`).
fn cargo_table_value(text: &str, table: &str, key: &str) -> Option<String> {
    let mut in_table = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(section) = line.strip_prefix('[') {
            in_table = section.trim_end_matches(']').trim() == table;
            continue;
        }
        if in_table
            && let Some(rest) = line.strip_prefix(key)
            && let Some(value) = rest.trim_start().strip_prefix('=')
        {
            return Some(
                value
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'')
                    .to_string(),
            );
        }
    }
    None
}

pub(super) fn rust_scope(path: &str, crates: &BTreeMap<String, RustCrate>) -> String {
    for (name, krate) in crates {
        if krate.lib_path.as_deref() == Some(path)
            || path == format!("{}/lib.rs", krate.src_dir)
            || path == format!("{}/main.rs", krate.src_dir)
        {
            return name.clone();
        }
        if let Some(rest) = path.strip_prefix(&format!("{}/", krate.src_dir)) {
            let module = rest
                .strip_suffix("/mod.rs")
                .or_else(|| rest.strip_suffix(".rs"))
                .unwrap_or(rest)
                .replace('/', "::");
            return format!("{name}::{module}");
        }
    }
    path.strip_suffix(".rs").unwrap_or(path).replace('/', "::")
}
