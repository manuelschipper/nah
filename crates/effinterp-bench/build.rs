//! Embed the identity of the tree this binary is built from: the source
//! fingerprint (see `src/fingerprint.rs`), the compiler, and the profile. The
//! bench compares the embedded fingerprint with a fresh one before it
//! measures, resumes, or publishes, so an out-of-date binary cannot measure a
//! newer tree.
// Build scripts run on the host at build time: the workspace's pure-crate
// lint rules describe runtime crates, not the generator that feeds them.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::path::Path;
use std::process::Command;

#[path = "src/fingerprint.rs"]
mod fingerprint;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let root = Path::new(&manifest_dir).join("../..");
    for entry in fingerprint::ROOTS {
        println!("cargo:rerun-if-changed={}", root.join(entry).display());
    }
    let digest = fingerprint::compute_source_fingerprint(&root).expect("source fingerprint");
    println!("cargo:rustc-env=EFFINTERP_SOURCE_FINGERPRINT={digest}");
    let rustc = std::env::var("RUSTC").expect("RUSTC is set for build scripts");
    let out = Command::new(&rustc)
        .arg("--version")
        .output()
        .unwrap_or_else(|e| panic!("cannot run {rustc} --version: {e}"));
    assert!(
        out.status.success(),
        "{rustc} --version failed: {}",
        out.status
    );
    let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
    println!("cargo:rustc-env=EFFINTERP_BUILD_RUSTC={version}");
    // Every build-config fact is required: an identity with unknown fields
    // could not tell two builds apart.
    for (name, var) in [
        ("EFFINTERP_BUILD_PROFILE", "PROFILE"),
        ("EFFINTERP_BUILD_OPT_LEVEL", "OPT_LEVEL"),
        ("EFFINTERP_BUILD_DEBUG", "DEBUG"),
        ("EFFINTERP_BUILD_TARGET", "TARGET"),
    ] {
        let value = std::env::var(var).unwrap_or_else(|_| panic!("Cargo did not set {var}"));
        println!("cargo:rustc-env={name}={value}");
    }
    // Absent means no flags; Cargo sets it only when flags exist.
    let rustflags = std::env::var("CARGO_ENCODED_RUSTFLAGS")
        .unwrap_or_default()
        .replace('\x1f', " ");
    println!("cargo:rustc-env=EFFINTERP_BUILD_RUSTFLAGS={rustflags}");
}
