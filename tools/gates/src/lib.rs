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
pub const PURE_CRATES: &[&str] = &["nah-proto", "nah-policy"];

/// Engine crates without I/O: the plan protocol, its graph walker, and the
/// matcher that evaluates guard queries over it. They are held to the same
/// purity rules, so pure Nah crates may link them directly; engine analysis
/// stays behind nah-effinterp.
pub const PURE_ENGINE_CRATES: &[&str] =
    &["effinterp-proto", "effinterp-trace", "effinterp-matcher"];

/// Every crate held to the purity rules.
pub fn pure_crates() -> impl Iterator<Item = &'static str> {
    PURE_CRATES.iter().chain(PURE_ENGINE_CRATES).copied()
}

pub fn is_pure(krate: &str) -> bool {
    pure_crates().any(|pure| pure == krate)
}

/// `std::net` value types a pure crate may name: parsing an address performs
/// no network I/O. They are removed from a line before it is scanned, so any
/// other `std::net` path on that line is still rejected.
pub const PURE_STD_NET_TYPES: &[&str] = &[
    "std::net::IpAddr",
    "std::net::Ipv4Addr",
    "std::net::Ipv6Addr",
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
        // The engine's consumer-neutral plan graph is the one engine contract
        // the protocol crate embeds.
        "nah-proto" => &["effinterp-proto"],
        "nah-observe" => &["nah-proto"],
        // Guards are matcher queries over the engine's plan types.
        "nah-policy" => &["nah-proto", "effinterp-matcher", "effinterp-proto"],
        "nah-extensions" => &["nah-proto"],
        // The bridge is the only Nah crate that drives the engine. It supplies
        // the labels the matcher reads, and never depends on policy: the CLI
        // composes shipped guard evaluation with it.
        "nah-effinterp" => &[
            "nah-proto",
            "nah-observe",
            "effinterp-engine",
            "effinterp-matcher",
            "effinterp-proto",
            "effinterp-trace",
        ],
        // The CLI owns application orchestration. It may compose every
        // runtime layer, but never test tooling or the corpus harness.
        "nah-cli" => &[
            "nah-proto",
            "nah-observe",
            "nah-policy",
            "nah-extensions",
            "nah-effinterp",
        ],
        // The corpus harness drives the application seam from frozen
        // fixtures.
        "nah-corpus" => &["nah-proto", "nah-cli", "nah-policy", "nah-corpus-schema"],
        // The corpus row schema depends on no Nah or engine crate, so the
        // engine bench can decode the corpus the harness qualifies against.
        "nah-corpus-schema" => &[],
        // Engine crates layer upward from the protocol: schema, engine, then
        // repository analysis.
        "effinterp-proto" => &[],
        "effinterp-model-schema" => &["effinterp-proto"],
        "effinterp-engine" => &["effinterp-proto", "effinterp-model-schema"],
        "effinterp-repo" => &["effinterp-proto", "effinterp-engine"],
        "effinterp-conformance" => &["effinterp-proto"],
        // The pure guard-query evaluator walks plans with the trace crate.
        "effinterp-trace" => &["effinterp-proto"],
        "effinterp-matcher" => &["effinterp-proto", "effinterp-trace"],
        // Engine development tools: none is a dependency of the shipped binary.
        "effinterp-testkit" => &["effinterp-proto", "effinterp-engine"],
        // Model and bench assertions are evaluated by the shared matcher.
        "effinterp-model-factory" => &[
            "effinterp-proto",
            "effinterp-engine",
            "effinterp-matcher",
            "effinterp-model-schema",
        ],
        "effinterp-bench" => &[
            "effinterp-proto",
            "effinterp-engine",
            "effinterp-repo",
            "effinterp-trace",
            "effinterp-testkit",
            "effinterp-matcher",
            "nah-corpus-schema",
        ],
        other => panic!("unknown crate {other}: add it to allowed_nah_deps"),
    }
}

/// External (non-workspace) crates a pure crate may depend on. This grows one
/// reviewed dependency at a time. None means the crate is not pure and is
/// unrestricted by this particular check.
pub fn allowed_external_deps(krate: &str) -> Option<&'static [&'static str]> {
    match krate {
        // sha2 only fingerprints observation facts in memory; icu_properties
        // and idna supply the compiled Unicode script data and punycode
        // decoding the lookalike-host classifier reads.
        "nah-proto" => Some(&["serde", "serde_json", "sha2", "icu_properties", "idna"]),
        // blake3 digests canonical plan bytes in memory; serde_path_to_error
        // locates decode failures.
        "effinterp-proto" => Some(&["serde", "serde_json", "blake3", "serde_path_to_error"]),
        "effinterp-matcher" => Some(&["serde", "serde_json"]),
        krate if is_pure(krate) => Some(&[]),
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

/// Workspace test binaries: the source root of every integration test target
/// Cargo links for a workspace member, relative to the workspace root. Cargo
/// links one binary per `tests/*.rs` file or declared `[[test]]`, and every
/// worktree's `target/` carries a copy of each.
pub fn workspace_test_binaries() -> Vec<PathBuf> {
    let root = workspace_root();
    let out = Command::new("cargo")
        .args(["metadata", "--locked", "--no-deps", "--format-version", "1"])
        .current_dir(&root)
        .output()
        .expect("run cargo metadata");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("parse cargo metadata");
    let mut binaries = meta["packages"]
        .as_array()
        .expect("packages array")
        .iter()
        .flat_map(|pkg| pkg["targets"].as_array().expect("targets"))
        .filter(|target| {
            target["kind"]
                .as_array()
                .expect("target kinds")
                .iter()
                .any(|kind| kind.as_str() == Some("test"))
        })
        .map(|target| {
            Path::new(target["src_path"].as_str().expect("target src_path"))
                .strip_prefix(&root)
                .expect("workspace test target lies inside the workspace")
                .to_path_buf()
        })
        .collect::<Vec<_>>();
    binaries.sort();
    binaries
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

/// Engine crates link into Nah only at designated boundaries: the bridge and
/// pure Nah crates' use of the pure engine crates. Engine analysis is reached only through nah-effinterp. Edges
/// between engine crates are their own layering, checked by the allowlist.
pub fn effinterp_linkage_violations(packages: &[PackageDeps]) -> Vec<String> {
    let mut violations = Vec::new();
    for pkg in packages {
        if pkg.name.starts_with("effinterp-") || pkg.name == "nah-effinterp" {
            continue;
        }
        for (kind, deps) in [
            ("dependency", &pkg.normal_deps),
            ("build-dependency", &pkg.build_deps),
        ] {
            for dep in deps.iter().filter(|dep| {
                dep.starts_with("effinterp-")
                    && !(PURE_CRATES.contains(&pkg.name.as_str())
                        && PURE_ENGINE_CRATES.contains(&dep.as_str()))
            }) {
                violations.push(format!(
                    "{} has forbidden {kind} {dep}; link the engine through nah-effinterp",
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

/// The engine packages that must resolve from this workspace and nowhere else.
pub const ENGINE_PACKAGES: &[&str] = &[
    "effinterp-proto",
    "effinterp-model-schema",
    "effinterp-engine",
    "effinterp-repo",
    "effinterp-conformance",
    "effinterp-bench",
    "effinterp-model-factory",
    "effinterp-trace",
    "effinterp-testkit",
    "effinterp-matcher",
];

/// One package of the fully resolved dependency graph.
#[derive(Debug)]
pub struct ResolvedPackage {
    pub name: String,
    /// Cargo's source id; `None` is a workspace path package.
    pub source: Option<String>,
    pub manifest_path: PathBuf,
}

/// Every package Cargo resolves for the workspace, dependencies included.
pub fn resolved_packages() -> Vec<ResolvedPackage> {
    let out = Command::new("cargo")
        .args(["metadata", "--locked", "--format-version", "1"])
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
        .map(|pkg| ResolvedPackage {
            name: pkg["name"].as_str().expect("package name").to_owned(),
            source: pkg["source"].as_str().map(str::to_owned),
            manifest_path: PathBuf::from(pkg["manifest_path"].as_str().expect("manifest_path")),
        })
        .collect()
}

/// Each engine package resolves exactly once, from a manifest inside this
/// workspace. A registry or Git copy, a duplicate instance, or a manifest
/// outside the tree would let a second engine reach a decision.
pub fn engine_source_violations(packages: &[ResolvedPackage], root: &Path) -> Vec<String> {
    let root = root.canonicalize().expect("canonical workspace root");
    let mut violations = Vec::new();
    for name in ENGINE_PACKAGES {
        let found: Vec<_> = packages.iter().filter(|pkg| pkg.name == *name).collect();
        match found.as_slice() {
            [] => violations.push(format!("{name} is missing from the resolved graph")),
            [package] => {
                if let Some(source) = &package.source {
                    violations.push(format!("{name} resolves from {source}, not the workspace"));
                } else if !package
                    .manifest_path
                    .canonicalize()
                    .is_ok_and(|manifest| manifest.starts_with(&root))
                {
                    violations.push(format!(
                        "{name} manifest {} is outside the workspace",
                        package.manifest_path.display()
                    ));
                }
            }
            many => violations.push(format!("{name} resolves {} times", many.len())),
        }
    }
    violations
}

/// Dependency purity violations. Pure crates may use only explicitly
/// allowlisted normal dependencies and may never use a build script/dependency.
/// A workspace dependency must itself be pure, so purity holds transitively.
pub fn pure_dependency_violations(packages: &[PackageDeps]) -> Vec<String> {
    let mut violations = Vec::new();
    for pkg in packages {
        let Some(external) = allowed_external_deps(&pkg.name) else {
            continue;
        };
        let allowed_nah = allowed_nah_deps(&pkg.name);
        for dep in &pkg.normal_deps {
            let allowed = if dep.starts_with("nah-") || dep.starts_with("effinterp-") {
                allowed_nah.contains(&dep.as_str()) && is_pure(dep)
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
        let code = PURE_STD_NET_TYPES
            .iter()
            .fold(code.to_owned(), |code, path| code.replace(path, ""));
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

/// The evidence graph (`nah_proto::effects`) must not depend on producers; the
/// bridge must not gain ambient resolution or command execution.
pub fn evidence_boundary_violations(evidence_graph: &str, bridge: &str) -> Vec<String> {
    let mut violations = Vec::new();
    // effinterp_proto is the plan contract nah-proto embeds, not a producer.
    for token in [
        "effinterp_engine",
        "effinterp_repo",
        "effinterp_matcher",
        "serde_json::Value",
    ] {
        if evidence_graph.contains(token) {
            violations.push(format!(
                "evidence graph contains producer or untyped payload token {token}"
            ));
        }
    }
    for token in [
        "with_resolver",
        "analyze_with_resolver",
        "std::process",
        "std::fs",
        "std::env",
        "consult_extensions",
    ] {
        if bridge.contains(token) {
            violations.push(format!("bridge contains side-effect token {token}"));
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
            "nah-proto",
            Path::new("seeded.rs"),
            "pub fn seeded() { let _ = std::fs::read(\"secret\"); }",
        );
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("forbidden token `std::fs`"));

        // Engine protocol code may parse addresses but never open a socket.
        let violations = impure_source_violations(
            "effinterp-proto",
            Path::new("seeded.rs"),
            "let ok = a.parse::<std::net::Ipv6Addr>().is_ok(); std::net::TcpStream::connect(a);",
        );
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("forbidden token `std::net`"));
    }

    #[test]
    fn metadata_sees_real_package_names() {
        // The dep gate must see through `package = "..."` renames and
        // `[dependencies.x]` table forms; cargo metadata reports real names,
        // proven here against the live protocol crate's dependencies.
        let pkgs = workspace_packages();
        let proto = pkgs.iter().find(|p| p.name == "nah-proto").unwrap();
        for dependency in ["effinterp-proto", "sha2"] {
            assert!(proto.normal_deps.contains(&dependency.to_owned()));
        }
    }
}
