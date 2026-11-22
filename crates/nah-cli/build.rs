//! Names the source commit in `nah --version` when the build is not a tagged
//! release, so two builds that carry the same version number can be told
//! apart: `nah 1.8.0 (dev b22b9075)`. Only source whose commit carries the
//! release tag `v<version>` prints the version alone.
//!
//! The commit comes from the workspace's own Git checkout or, for a tree
//! made by `git archive`, from `archived-commit.txt`, which Git fills in
//! when it writes the archive (`export-subst` in `.gitattributes`). A Git
//! repository merely enclosing the source is never asked. Source with
//! neither prints `(dev)`, since nothing shows it is a release.

// Cargo build metadata needs host I/O and a Git process.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::path::{Path, PathBuf};
use std::process::Command;

const ARCHIVED: &str = "archived-commit.txt";

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
}

/// The commit and tags of the checkout whose top level is `root`.
fn checkout(root: &Path) -> Option<(String, Vec<String>)> {
    let toplevel = git(root, &["rev-parse", "--show-toplevel"])?;
    if Path::new(&toplevel).canonicalize().ok()? != root {
        return None;
    }
    let commit = git(root, &["rev-parse", "HEAD"])?;
    // Rerun when HEAD moves, its branch advances, or a tag is added. Cargo
    // reruns on every build for a path that does not exist, so only existing
    // ones are named.
    let mut watched = vec!["HEAD".to_owned(), "packed-refs".into(), "refs/tags".into()];
    watched.extend(git(root, &["rev-parse", "--symbolic-full-name", "HEAD"]));
    for name in watched {
        if let Some(path) =
            git(root, &["rev-parse", "--git-path", &name]).map(|path| root.join(path))
            && path.exists()
        {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    let tags = git(root, &["tag", "--points-at", "HEAD"])?
        .lines()
        .map(str::to_owned)
        .collect();
    Some((commit, tags))
}

/// The commit and tags `git archive` wrote into `path`: the full commit on
/// the first line, the ref names pointing at it (`tag: v1.8.0, ...`) on the
/// second. Outside an archive the placeholders are left as they are.
fn archived(path: &Path) -> (Option<String>, Vec<String>) {
    let text = std::fs::read_to_string(path).unwrap();
    let mut lines = text.lines();
    let commit = lines
        .next()
        .filter(|commit| commit.len() >= 8 && commit.chars().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_owned);
    let tags = lines
        .next()
        .unwrap_or_default()
        .split(", ")
        .filter_map(|name| name.strip_prefix("tag: "))
        .map(str::to_owned)
        .collect();
    (commit, tags)
}

fn main() {
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest.join("../..").canonicalize().unwrap();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={ARCHIVED}");
    let (commit, tags) = checkout(&root).map_or_else(
        || archived(&manifest.join(ARCHIVED)),
        |(commit, tags)| (Some(commit), tags),
    );
    let release_tag = format!("v{version}");
    let described = if tags.contains(&release_tag) {
        version
    } else {
        match commit {
            Some(commit) => format!("{version} (dev {})", &commit[..8]),
            None => format!("{version} (dev)"),
        }
    };
    println!("cargo:rustc-env=NAH_VERSION={described}");
}
