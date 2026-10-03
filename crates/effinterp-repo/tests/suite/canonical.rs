//! The canonical effect surface: every query consumes the same merged
//! (direct + cross-file) effect graph, and realm-qualified selectors do not
//! conflate host and container namespaces.
#![allow(clippy::disallowed_methods)]

use effinterp_repo::{IndexLimits, ResourceSelector, build_index, effects_of, reach};
use effinterp_testkit::repo_fixture::repo_test_fixture;

const APP: &str = "#!/usr/bin/env python\nfrom util import wipe\nwipe(\"/var/cache/app\", name)\n";
const UTIL: &str =
    "import os, shutil\ndef wipe(root, t):\n    shutil.rmtree(os.path.join(root, t))\n";

/// A cross-file delete must appear in BOTH effects_of and reach — the two
/// query surfaces describe the same effect graph.
#[test]
fn cross_file_effect_is_in_both_forward_and_reverse() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "canon-both",
        &[("app.py", APP), ("util.py", UTIL)],
    );
    let idx = build_index(&root, IndexLimits::default());

    let fwd = effects_of(&idx, "app.py").expect("app.py analyzed");
    let in_forward = fwd.payload.as_effects().unwrap().effects.iter().any(|e| {
        e.operation.as_str() == "filesystem.delete"
            && effinterp_proto::display_resource_with_scope(&e.resource).contains("var/cache/app")
    });
    assert!(in_forward, "effects_of must include the cross-file delete");

    let rev = reach(
        &idx,
        &ResourceSelector::parse("fs:/var/cache/app").unwrap(),
        None,
    );
    let in_reverse = rev.payload.as_reach().unwrap().indeterminate.iter().any(|row| matches!(row,
        effinterp_proto::Indeterminate::Effect { fact, matched: effinterp_proto::Match::Indeterminate { reason: effinterp_proto::MatchReason::Unbound { .. } }, .. }
        if fact.entrypoint == "app.py" && fact.operation.0 == "filesystem.delete"));
    assert!(in_reverse, "reach must include the cross-file delete");
}

/// Adding a call to a cross-file delete adds that delete to the caller's
/// forward surface.
#[test]
fn added_cross_file_delete_reaches_the_caller_surface() {
    let before = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "canon-diff-a",
        &[
            ("app.py", "#!/usr/bin/env python\nprint('hi')\n"),
            ("util.py", UTIL),
        ],
    );
    let after = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "canon-diff-b",
        &[("app.py", APP), ("util.py", UTIL)],
    );
    let deletes = |root: &std::path::Path| {
        let index = build_index(root, IndexLimits::default());
        effects_of(&index, "app.py")
            .unwrap()
            .payload
            .into_effects()
            .unwrap()
            .effects
            .into_iter()
            .filter(|effect| effect.operation.as_str() == "filesystem.delete")
            .count()
    };
    assert_eq!(deletes(&before), 0);
    assert!(
        deletes(&after) > 0,
        "the new cross-file delete reaches app.py"
    );
}

/// One effective effect per (realm, operation, resource, origin): repeated
/// traversals of the same code site dedup, while the same delete from two
/// different files stays one row per origin (distinct code sites).
#[test]
fn direct_and_composed_overlap_is_deduped() {
    // app.py directly deletes /shared AND calls (twice) a helper that deletes
    // /shared from another file.
    let app = "#!/usr/bin/env python\nimport shutil\nfrom util import wipe_shared\nshutil.rmtree(\"/shared\")\nwipe_shared()\nwipe_shared()\n";
    let util = "import shutil\ndef wipe_shared():\n    shutil.rmtree(\"/shared\")\n";
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "canon-dedup",
        &[("app.py", app), ("util.py", util)],
    );
    let idx = build_index(&root, IndexLimits::default());
    let fwd = effects_of(&idx, "app.py").unwrap();
    let deletes: Vec<_> = fwd
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|e| {
            e.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource_with_scope(&e.resource).contains("shared")
        })
        .collect();
    assert_eq!(deletes.len(), 2, "one row per origin site: {deletes:?}");
    for origin in ["app.py", "util.py"] {
        assert_eq!(
            deletes
                .iter()
                .filter(|e| e
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    == origin)
                .count(),
            1,
            "the same site must not be listed twice"
        );
    }
}

const REALM_REPO: &str = "#!/bin/sh\ndocker exec postgres rm /etc/passwd\n";

/// A host-qualified query must NOT match a container-realm effect; a
/// container-qualified query must; any-realm must.
#[test]
fn realm_selectors_do_not_conflate_host_and_container() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "canon-realm",
        &[("deploy.sh", REALM_REPO)],
    );
    let idx = build_index(&root, IndexLimits::default());

    let host = reach(
        &idx,
        &ResourceSelector::parse("host/fs:/etc/passwd").unwrap(),
        None,
    );
    assert!(
        host.payload.as_reach().unwrap().matches.is_empty(),
        "host query must not match a container delete: {:?}",
        host.payload.as_reach().unwrap().matches
    );

    let container = reach(
        &idx,
        &ResourceSelector::parse("container:postgres/fs:/etc/passwd").unwrap(),
        None,
    );
    assert!(
        container
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.operation.as_str() == "filesystem.delete"),
        "container query must match its container's delete"
    );

    let any = reach(
        &idx,
        &ResourceSelector::parse("any-realm/fs:/etc/passwd").unwrap(),
        None,
    );
    assert!(
        any.payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.operation.as_str() == "filesystem.delete"),
        "any-realm query must match"
    );
}

/// `container:name` without a trailing `/family:` is a plain container-resource
/// selector, not a realm qualifier.
#[test]
fn bare_container_selector_is_not_a_realm() {
    let s = ResourceSelector::parse("container:postgres").unwrap();
    assert_eq!(s.family, "container");
    assert_eq!(s.needle, "postgres");
}
