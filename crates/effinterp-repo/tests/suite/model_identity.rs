//! Content-derived model-set identity and the order-sensitive analyzed-input
//! fingerprint: rebuilding the same repository is deterministic, editing a file
//! moves the fingerprint, and the model set is a content hash rather than a
//! hand-maintained version literal.
#![allow(clippy::disallowed_methods)]

use effinterp_repo::{IndexLimits, build_index};
use effinterp_testkit::repo_fixture::repo_test_fixture;

const APP: &str = "#!/usr/bin/env python\nfrom util import wipe\nwipe(\"/var/cache/app\")\n";
const UTIL: &str = "import os, shutil\ndef wipe(root):\n    shutil.rmtree(root)\n";

/// Two indexes of the same repository produce identical fingerprints.
#[test]
fn rebuild_is_deterministic() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "mid-determinism",
        &[("app.py", APP), ("util.py", UTIL)],
    );
    let a = build_index(&root, IndexLimits::default());
    let b = build_index(&root, IndexLimits::default());
    assert_eq!(a.fingerprint, b.fingerprint);
    assert_eq!(a.model_set, b.model_set);
}

/// Changing a file's content changes its per-file digest and the aggregate
/// fingerprint.
#[test]
fn content_change_moves_fingerprint() {
    let before = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "mid-change-a",
        &[("app.py", APP), ("util.py", UTIL)],
    );
    let after = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "mid-change-b",
        &[
            ("app.py", APP),
            (
                "util.py",
                "import os, shutil\ndef wipe(root):\n    shutil.rmtree(root + '/x')\n",
            ),
        ],
    );
    let a = build_index(&before, IndexLimits::default());
    let b = build_index(&after, IndexLimits::default());

    let dig_a = a.dependency_manifest.source_digest("util.py").unwrap();
    let dig_b = b.dependency_manifest.source_digest("util.py").unwrap();
    assert_ne!(dig_a, dig_b, "the edited file's digest must change");
    assert_ne!(a.fingerprint, b.fingerprint, "the aggregate must move");
}

/// The model-set identity is a content hash (blake3), not the old
/// `builtin@<version>` literal, and is stable across builds.
#[test]
fn model_set_is_a_content_hash() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "mid-modelset",
        &[("app.py", APP)],
    );
    let idx = build_index(&root, IndexLimits::default());
    let hex = idx
        .model_set
        .strip_prefix("builtin:blake3:")
        .expect("model set is a blake3 hash");
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!idx.model_set.contains(env!("CARGO_PKG_VERSION")));
    assert_eq!(
        idx.model_set,
        effinterp_engine::Catalog::builtin().model_set_id()
    );
}
