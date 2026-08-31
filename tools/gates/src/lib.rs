#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! CI gates for the nah workspace: crate purity and dependency direction.
//!
//! These validators are shared by the live workspace checks and seeded-red
//! self-tests, so CI proves both that the tree is clean and that each gate
//! rejects a known violation.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Crates whose code must be pure: no I/O, env, clocks, processes, unsafe, or
/// ambient global state. Enforced in layers: compiler-resolved Clippy
/// restrictions, this lexical guardrail, and dependency allowlists.
pub const PURE_CRATES: &[&str] = &[
    "nah-proto",
    "nah-parse",
    "nah-inline",
    "nah-actions",
    "nah-policy",
];

/// Tokens that must never appear in a pure crate's `src/`. Coarse on
/// purpose: a false positive is a loud conversation; a false negative is a
/// purity hole. `std::{` forbids grouped std imports outright so
/// `use std::{fs, ...}` cannot smuggle a module past token matching.
pub const FORBIDDEN_IN_PURE: &[&str] = &[
    "std::fs",
    "std::env",
    "std::process",
    "std::time",
    "std::net",
    "std::io",
    "std::os",
    "std::thread",
    "std::{",
    "include!",
    "include !",
    "#[path",
    "print!",
    "println!",
    "eprint!",
    "eprintln!",
    "dbg!",
];

/// Allowed pipeline dependency edges for normal and build dependencies.
/// Workspace tooling is never an application dependency.
/// Dev-dependencies are unrestricted except in the corpus harness, whose tests
/// must use the application seam. Panics on a crate it has never heard of —
/// the coverage test leans on that.
pub fn allowed_nah_deps(krate: &str) -> &'static [&'static str] {
    match krate {
        "nah-proto" => &[],
        "nah-parse" => &["nah-proto"],
        "nah-inline" => &["nah-proto"],
        "nah-actions" => &["nah-proto", "nah-parse", "nah-inline"],
        "nah-observe" => &["nah-proto"],
        "nah-policy" => &["nah-proto", "nah-inline"],
        "nah-extensions" => &["nah-proto"],
        // The daemon reads the trusted roots `nah trust` persists.
        "nah-effinterp" => &["nah-proto", "nah-extensions"],
        // The CLI owns application orchestration. It may compose every
        // runtime layer, but never test tooling or the corpus harness.
        "nah-cli" => &[
            "nah-proto",
            "nah-parse",
            "nah-inline",
            "nah-actions",
            "nah-observe",
            "nah-policy",
            "nah-extensions",
            "nah-effinterp",
        ],
        // The corpus harness drives the same application seam from frozen
        // fixtures. It must not assemble a second decision pipeline.
        "nah-corpus" => &["nah-proto", "nah-cli"],
        other => panic!("unknown crate {other}: add it to allowed_nah_deps"),
    }
}

/// External (non-nah) crates a pure crate may depend on. This grows one
/// reviewed dependency at a time. None means the crate is not pure and is
/// unrestricted by this particular check.
pub fn allowed_external_deps(krate: &str) -> Option<&'static [&'static str]> {
    match krate {
        "nah-proto" => Some(&["effinterp-proto", "serde", "serde_json"]),
        "nah-parse" => Some(&["tree-sitter", "tree-sitter-bash"]),
        "nah-inline" => Some(&[
            "serde_json",
            "tree-sitter",
            "tree-sitter-javascript",
            "tree-sitter-python",
            "tree-sitter-typescript",
        ]),
        "nah-actions" => Some(&["idna"]),
        krate if PURE_CRATES.contains(&krate) => Some(&[]),
        _ => None,
    }
}

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

/// A workspace package with its dependencies resolved to real package names.
#[derive(Debug)]
pub struct PackageDeps {
    pub name: String,
    /// Real package names of normal (non-dev, non-build) dependencies.
    pub normal_deps: Vec<String>,
    /// Real package names of build-dependencies.
    pub build_deps: Vec<String>,
    /// Real package names of dev-dependencies.
    pub dev_deps: Vec<String>,
    /// Production target roots reported by Cargo (libraries and binaries).
    pub source_paths: Vec<PathBuf>,
    /// Custom build-script targets reported by Cargo.
    pub build_scripts: Vec<PathBuf>,
}

/// A workspace manifest's path dependency, resolved by Cargo.
#[derive(Debug)]
pub struct PathDependency {
    pub package: String,
    pub dependency: String,
    pub path: PathBuf,
}

/// Workspace packages via `cargo metadata`, which resolves the forms string
/// scanning misses: `[dependencies.x]` table headers, `package = "x"`
/// renames, and members living outside `crates/`.
pub fn workspace_packages() -> Vec<PackageDeps> {
    let out = Command::new("cargo")
        .args(["metadata", "--locked", "--no-deps", "--format-version", "1"])
        .current_dir(workspace_root())
        .output()
        .expect("run cargo metadata");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("parse cargo metadata");
    meta["packages"]
        .as_array()
        .expect("packages array")
        .iter()
        .map(|pkg| {
            let deps = pkg["dependencies"].as_array().expect("dependencies");
            let by_kind = |kind: Option<&str>| -> Vec<String> {
                deps.iter()
                    .filter(|d| d["kind"].as_str() == kind)
                    .map(|d| d["name"].as_str().expect("dep name").to_string())
                    .collect()
            };
            PackageDeps {
                name: pkg["name"].as_str().expect("package name").to_string(),
                normal_deps: by_kind(None),
                build_deps: by_kind(Some("build")),
                dev_deps: by_kind(Some("dev")),
                source_paths: pkg["targets"]
                    .as_array()
                    .expect("targets")
                    .iter()
                    .filter(|target| {
                        target["kind"]
                            .as_array()
                            .expect("target kinds")
                            .iter()
                            .any(|kind| matches!(kind.as_str(), Some("lib" | "rlib" | "bin")))
                    })
                    .map(|target| {
                        PathBuf::from(target["src_path"].as_str().expect("target src_path"))
                    })
                    .collect(),
                build_scripts: pkg["targets"]
                    .as_array()
                    .expect("targets")
                    .iter()
                    .filter(|target| {
                        target["kind"]
                            .as_array()
                            .expect("target kinds")
                            .iter()
                            .any(|kind| kind.as_str() == Some("custom-build"))
                    })
                    .map(|target| {
                        PathBuf::from(target["src_path"].as_str().expect("target src_path"))
                    })
                    .collect(),
            }
        })
        .collect()
}

/// Workspace path dependencies via `cargo metadata`.
pub fn workspace_path_dependencies() -> Vec<PathDependency> {
    let out = Command::new("cargo")
        .args(["metadata", "--locked", "--no-deps", "--format-version", "1"])
        .current_dir(workspace_root())
        .output()
        .expect("run cargo metadata");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("parse cargo metadata");
    meta["packages"]
        .as_array()
        .expect("packages array")
        .iter()
        .flat_map(|pkg| {
            pkg["dependencies"]
                .as_array()
                .expect("dependencies")
                .iter()
                .filter_map(|dependency| {
                    Some(PathDependency {
                        package: pkg["name"].as_str().expect("package name").to_owned(),
                        dependency: dependency["name"]
                            .as_str()
                            .expect("dependency name")
                            .to_owned(),
                        path: PathBuf::from(dependency["path"].as_str()?),
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Layering violations in normal and build dependencies. The corpus harness
/// also applies the same allowlist to dev-dependencies because its executable
/// harness lives under `tests/`. Shared with a seeded-red fixture so this is
/// tested independently of today's clean graph.
pub fn dependency_direction_violations(
    packages: &[PackageDeps],
    tooling: &[&str],
    workspace_names: &[&str],
) -> Vec<String> {
    let mut violations = Vec::new();
    for pkg in packages {
        if tooling.contains(&pkg.name.as_str()) {
            continue;
        }
        let allowed = allowed_nah_deps(&pkg.name);
        for (kind, deps) in [
            ("dependency", &pkg.normal_deps),
            ("build-dependency", &pkg.build_deps),
        ] {
            for dep in deps
                .iter()
                .filter(|d| workspace_names.contains(&d.as_str()))
            {
                if !allowed.contains(&dep.as_str()) {
                    violations.push(format!(
                        "{} has forbidden {kind} {dep}, allowed: {allowed:?}",
                        pkg.name
                    ));
                }
            }
        }
        if pkg.name == "nah-corpus" {
            for dep in pkg
                .dev_deps
                .iter()
                .filter(|d| workspace_names.contains(&d.as_str()))
            {
                if !allowed.contains(&dep.as_str()) {
                    violations.push(format!(
                        "{} has forbidden dev-dependency {dep}, allowed: {allowed:?}",
                        pkg.name
                    ));
                }
            }
        }
    }
    violations
}

/// External effectinterp crates may link only at the designated boundary.
pub fn effinterp_linkage_violations(packages: &[PackageDeps]) -> Vec<String> {
    let mut violations = Vec::new();
    for pkg in packages {
        if matches!(pkg.name.as_str(), "nah-effinterp" | "nah-cli") {
            continue;
        }
        for (kind, deps) in [
            ("dependency", &pkg.normal_deps),
            ("build-dependency", &pkg.build_deps),
        ] {
            for dep in deps.iter().filter(|dep| {
                dep.starts_with("effinterp-")
                    && !(pkg.name == "nah-proto" && dep.as_str() == "effinterp-proto")
            }) {
                violations.push(format!(
                    "{} has forbidden {kind} {dep}; link effectinterp through nah-effinterp",
                    pkg.name
                ));
            }
        }
    }
    violations
}

/// Path dependencies must not escape the workspace through relative paths or symlinks.
pub fn path_dependency_violations(dependencies: &[PathDependency], root: &Path) -> Vec<String> {
    let root = root.canonicalize().expect("canonical workspace root");
    dependencies
        .iter()
        .filter_map(|dependency| {
            let path = dependency
                .path
                .canonicalize()
                .expect("canonical path dependency");
            (!path.starts_with(&root)).then(|| {
                format!(
                    "{} has path dependency {} outside workspace: {}",
                    dependency.package,
                    dependency.dependency,
                    path.display()
                )
            })
        })
        .collect()
}

/// The private source replacement must stay pinned to both dependency declarations.
pub fn effinterp_revision_violations(manifest: &str, config: &str) -> Vec<String> {
    let config_rev = section_revision(config, "source.effinterp");
    let mut violations = Vec::new();
    for dependency in [
        "effinterp-daemon",
        "effinterp-engine",
        "effinterp-proto",
        "effinterp-repo",
    ] {
        let dependency_rev = manifest.lines().find_map(|line| {
            let line = line.trim();
            line.starts_with(dependency)
                .then(|| quoted_assignment(line, "rev"))
                .flatten()
        });
        match (dependency_rev, config_rev) {
            (Some(dependency_rev), Some(config_rev)) if dependency_rev == config_rev => {}
            (Some(dependency_rev), Some(config_rev)) => violations.push(format!(
                "{dependency} rev {dependency_rev} differs from source.effinterp rev {config_rev}"
            )),
            (None, _) => violations.push(format!("{dependency} has no pinned rev")),
            (_, None) => violations.push("source.effinterp has no pinned rev".to_owned()),
        }
    }
    violations
}

fn section_revision<'a>(text: &'a str, section: &str) -> Option<&'a str> {
    let header = format!("[{section}]");
    let mut in_section = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_section = line == header;
        } else if in_section && line.starts_with("rev") {
            return quoted_assignment(line, "rev");
        }
    }
    None
}

fn quoted_assignment<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let (_, value) = line.split_once(key)?;
    let value = value
        .trim_start()
        .strip_prefix('=')?
        .trim_start()
        .strip_prefix('"')?;
    value.split_once('"').map(|(value, _)| value)
}

/// Dependency purity violations. Pure crates may use only explicitly
/// allowlisted normal dependencies and may never use a build script/dependency.
pub fn pure_dependency_violations(packages: &[PackageDeps]) -> Vec<String> {
    let mut violations = Vec::new();
    for pkg in packages {
        let Some(external) = allowed_external_deps(&pkg.name) else {
            continue;
        };
        let allowed_nah = allowed_nah_deps(&pkg.name);
        for dep in &pkg.normal_deps {
            let allowed = if dep.starts_with("nah-") {
                allowed_nah.contains(&dep.as_str())
            } else {
                external.contains(&dep.as_str())
            };
            if !allowed {
                violations.push(format!(
                    "{}: dependency {dep} is not allowlisted for a pure crate",
                    pkg.name
                ));
            }
        }
        if !pkg.build_deps.is_empty() {
            violations.push(format!(
                "{}: build-dependencies are forbidden in pure crates: {:?}",
                pkg.name, pkg.build_deps
            ));
        }
        if !pkg.build_scripts.is_empty() {
            violations.push(format!(
                "{}: build scripts are forbidden in pure crates: {:?}",
                pkg.name, pkg.build_scripts
            ));
        }
    }
    violations
}

/// All `.rs` files under a directory, recursively.
pub fn rust_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read source directory {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read entry in {}: {e}", dir.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|e| format!("cannot inspect entry in {}: {e}", dir.display()))?;
        let path = entry.path();
        if file_type.is_symlink() {
            return Err(format!(
                "source tree contains forbidden symlink {}",
                path.display()
            ));
        }
        if file_type.is_dir() {
            out.extend(rust_files(&path)?);
        } else if file_type.is_file() && path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// A line is scanned unless it is a comment line (trimmed, starts with
/// `//`). Mid-line `//` is NOT stripped: `"https://…"; std::fs::…` must not
/// hide a call behind a string literal. A doc mention of a forbidden token
/// tripping the gate is a loud false positive — the acceptable direction.
pub fn scannable(line: &str) -> Option<&str> {
    if line.trim_start().starts_with("//") {
        None
    } else {
        Some(line)
    }
}

/// Lexical purity violations in one Rust source file. Clippy catches resolved
/// aliases; this catches forbidden modules and source-inclusion escape hatches.
pub fn impure_source_violations(krate: &str, file: &Path, text: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let Some(code) = scannable(line) else {
            continue;
        };
        for token in FORBIDDEN_IN_PURE {
            if code.contains(token) {
                violations.push(format!(
                    "{}:{}: forbidden token `{token}` in pure crate {krate}",
                    file.display(),
                    lineno + 1
                ));
            }
        }
    }
    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Forbidden tokens found in one line, as the purity gate would see it.
    fn hits(line: &str) -> Vec<&'static str> {
        scannable(line)
            .map(|code| {
                FORBIDDEN_IN_PURE
                    .iter()
                    .copied()
                    .filter(|t| code.contains(t))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn grouped_std_import_is_flagged() {
        assert!(!hits("use std::{fs, path::PathBuf};").is_empty());
    }

    #[test]
    fn string_masked_io_is_flagged() {
        // A `//` inside a string literal must not hide the rest of the line.
        let line = r#"let u = "https://x"; std::fs::read_to_string(u);"#;
        assert!(hits(line).contains(&"std::fs"));
    }

    #[test]
    fn comment_lines_are_skipped() {
        assert!(hits("// std::fs is discussed here").is_empty());
        assert!(hits("    /// docs may mention std::env freely").is_empty());
        assert!(hits("//! module docs: std::process too").is_empty());
    }

    #[test]
    fn print_macros_and_std_os_are_flagged() {
        assert!(!hits(r#"println!("debug");"#).is_empty());
        assert!(!hits("dbg!(x);").is_empty());
        assert!(!hits("std::os::unix::fs::symlink(a, b);").is_empty());
    }

    #[test]
    fn seeded_impure_source_is_rejected_by_live_validator() {
        let violations = impure_source_violations(
            "nah-parse",
            Path::new("seeded.rs"),
            "pub fn seeded() { let _ = std::fs::read(\"secret\"); }",
        );
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("forbidden token `std::fs`"));
    }

    #[test]
    fn metadata_sees_real_package_names() {
        // The dep gate must see through `package = "..."` renames and
        // `[dependencies.x]` table forms; cargo metadata reports real names,
        // proven here against the live workspace parser dependencies.
        let pkgs = workspace_packages();
        let parse = pkgs.iter().find(|p| p.name == "nah-parse").unwrap();
        for dependency in ["tree-sitter", "tree-sitter-bash"] {
            assert!(parse.normal_deps.contains(&dependency.to_owned()));
        }
    }
}
