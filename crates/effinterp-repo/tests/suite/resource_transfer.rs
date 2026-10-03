//! Cross-file transfer pairings: a helper that copies or renames keeps the
//! source-to-destination relation after composition and argument
//! substitution, and both endpoint facts stay selectable.
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

use effinterp_repo::{
    Composition, IndexLimits, RepoChange, apply_changes, build_index, effects_of, save_index,
};
use effinterp_testkit::repo_fixture::repo_test_fixture;

fn repo(tag: &str, files: &[(&str, &str)]) -> PathBuf {
    repo_test_fixture(Path::new(env!("CARGO_TARGET_TMPDIR")), tag, files)
}

/// Each composed transfer pairing as `(source operation, destination operation)`.
fn transfers(index: &effinterp_repo::RepoIndex, entrypoint: &str) -> Vec<(String, String)> {
    let composition = index.composition(entrypoint).unwrap();
    let operation = |slot: u32| {
        let effect = composition.occurrence_effects[slot as usize].effect;
        composition.effects[effect].effect.operation.0.clone()
    };
    let mut out: Vec<_> = composition
        .transfers
        .iter()
        .map(|binding| (operation(binding.source), operation(binding.destination)))
        .collect();
    out.sort();
    out
}

const HELPER: &[(&str, &str)] = &[
    (
        "lib.py",
        "import shutil\n\n\ndef back_up(source, destination):\n    shutil.copy(source, destination)\n",
    ),
    (
        "app.py",
        "#!/usr/bin/env python\nfrom lib import back_up\n\nback_up('/w/a.txt', '/w/b.txt')\n",
    ),
];

/// Acceptance 4: a parameterized cross-file helper keeps its pairing after the
/// caller's arguments are substituted, and both endpoint facts are selectable
/// through the ordinary effect surface.
#[test]
fn a_cross_file_helper_keeps_its_pairing_and_both_endpoint_facts() {
    let index = build_index(&repo("transfer-helper", HELPER), IndexLimits::default());
    assert_eq!(
        transfers(&index, "app.py"),
        vec![(
            "filesystem.read".to_string(),
            "filesystem.write".to_string()
        )],
    );

    let effects = effects_of(&index, "app.py").unwrap();
    for (operation, path) in [
        ("filesystem.read", "/w/a.txt"),
        ("filesystem.write", "/w/b.txt"),
    ] {
        assert!(
            effects
                .payload
                .as_effects()
                .unwrap()
                .effects
                .iter()
                .any(|row| {
                    row.operation.0 == operation
                        && effinterp_proto::canonical_json(&row.resource).contains(path)
                }),
            "missing {operation} on {path}"
        );
    }
}

/// Acceptance 4: an incremental rebuild reaches the same pairings as a clean
/// build of the same on-disk state.
#[test]
fn an_incremental_rebuild_matches_a_clean_build() {
    let root = repo("transfer-incremental", HELPER);
    let mut index = build_index(&root, IndexLimits::default());
    let changed = "import shutil\n\n\ndef back_up(source, destination):\n    shutil.copy(source, destination + '.bak')\n";
    std::fs::write(root.join("lib.py"), changed).unwrap();
    apply_changes(
        &mut index,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("lib.py".into())],
    );
    let clean = build_index(&root, IndexLimits::default());
    assert_eq!(transfers(&index, "app.py"), transfers(&clean, "app.py"));
    assert_eq!(save_index(&index), save_index(&clean));
}

/// Acceptance 4: switching the copy to a rename pairs the source deletion with
/// the destination write and adds the deletion to the caller's surface.
#[test]
fn a_rename_adds_the_source_deletion_capability() {
    let before = build_index(
        &repo("transfer-diff-before", HELPER),
        IndexLimits::default(),
    );

    let renamed: Vec<(&str, &str)> = vec![
        (
            "lib.py",
            "import os\n\n\ndef back_up(source, destination):\n    os.rename(source, destination)\n",
        ),
        HELPER[1],
    ];
    let after = build_index(
        &repo("transfer-diff-after", &renamed),
        IndexLimits::default(),
    );
    assert_eq!(
        transfers(&after, "app.py"),
        vec![(
            "filesystem.delete".to_string(),
            "filesystem.write".to_string()
        )],
    );

    let deletes = |index: &effinterp_repo::RepoIndex| {
        effects_of(index, "app.py")
            .unwrap()
            .payload
            .into_effects()
            .unwrap()
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "filesystem.delete")
            .count()
    };
    assert_eq!(deletes(&before), 0);
    assert!(
        deletes(&after) > 0,
        "the rename's source deletion is a new capability"
    );
}

#[test]
fn guarded_transfers_keep_nested_call_conditions() {
    let root = repo(
        "transfer-guarded-calls",
        &[
            (
                "lib.py",
                "import shutil\ndef back_up(source, destination):\n if inner:\n  shutil.copy(source, destination)\n",
            ),
            (
                "app.py",
                "#!/usr/bin/env python\nfrom lib import back_up\nif outer:\n back_up('/w/a', '/w/b')\n back_up('/w/a', '/w/b')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition: &Composition = index.composition("app.py").unwrap();
    assert_eq!(composition.effects.len(), 2);
    assert_eq!(composition.occurrence_effects.len(), 4);
    assert_eq!(composition.transfers.len(), 2);
    // Each call instance keeps both its own guard and the helper's guard.
    let guards: Vec<_> = composition
        .transfers
        .iter()
        .map(|binding| {
            composition.occurrence_effects[binding.destination as usize]
                .condition
                .as_ref()
                .unwrap()
        })
        .collect();
    for guard in &guards {
        assert_eq!(guard.atoms().len(), 2);
    }
    assert_ne!(guards[0].identity_key(), guards[1].identity_key());
}
