//! The stored form of the repository index: serialization is deterministic
//! (incremental updates compare it to detect an unchanged snapshot) and carries
//! the analysis state composition and the Go package view derive.
#![allow(clippy::disallowed_methods)]

use std::path::PathBuf;

use effinterp_engine::Assurance;
use effinterp_repo::{IndexLimits, REPO_INDEX_SCHEMA, Selector, build_index, reach, save_index};
use effinterp_testkit::repo_fixture::repo_test_fixture;

/// A multi-language repo exercising direct effects, cross-file composition,
/// and boundaries — everything the stored form must carry.
fn mixed_repo(tag: &str) -> PathBuf {
    repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        tag,
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom util import run, wipe\nwipe(\"/data/cache\")\nrun()\n",
            ),
            (
                "util.py",
                "import shutil\nimport subprocess\ndef wipe(p):\n    shutil.rmtree(p)\ndef run():\n    subprocess.run([\"/bin/task\"])\n",
            ),
            (
                "deploy.sh",
                "#!/bin/sh\nrm -rf /var/cache/app\nmystery-command --wipe\n",
            ),
        ],
    )
}

#[test]
fn go_package_view_resolves_a_sibling_file_constant() {
    // The Go package view substitutes a constant declared in a sibling file of
    // the same package.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "store-go-package-values",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc main() { os.RemoveAll(target) }\n",
            ),
            (
                "vals.go",
                "package main\n\nconst target = \"/implicit-const\"\n",
            ),
        ],
    );
    let built = build_index(&root, IndexLimits::default());
    let sel = Selector::parse("fs:/implicit-const").unwrap();
    assert!(
        !reach(&built, &sel, None)
            .payload
            .as_reach()
            .unwrap()
            .matches
            .is_empty(),
        "the index must resolve the package constant"
    );
}

#[test]
fn serialization_is_deterministic() {
    let built = build_index(&mixed_repo("store-determinism"), IndexLimits::default());
    let saved = save_index(&built);
    assert!(saved.ends_with('\n'));
    assert!(saved.contains(REPO_INDEX_SCHEMA));
    assert_eq!(saved, save_index(&built), "same index, identical bytes");
}

#[test]
fn lifecycle_metadata_is_composed_and_stored() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "store-lifecycle-metadata",
        &[(
            "app.py",
            r#"#!/usr/bin/env python3
import missing
import os
from argparse import ArgumentParser
def command():
    os.remove("/dispatched")
    missing.opaque()
parser = ArgumentParser()
parser.set_defaults(func=command)
parser.parse_args()
"#,
        )],
    );
    let built = build_index(&root, IndexLimits::default());
    let saved = save_index(&built);
    assert!(saved.contains(r#""assurance": "heuristic""#));
    assert!(saved.contains(r#""via_dispatch""#));

    let composition = built.composition("app.py").unwrap();
    assert_eq!(composition.effects.len(), 1);
    assert_eq!(
        composition.occurrence_effects[0].assurance,
        Assurance::Heuristic
    );
    assert!(composition.occurrence_effects[0].via_dispatch.is_some());
    assert!(
        composition.boundaries.iter().any(|boundary| {
            boundary.reason == "cross_module" && boundary.via_dispatch.is_some()
        })
    );
}
