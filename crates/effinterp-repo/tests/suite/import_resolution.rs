//! In-repo import resolution against real project layouts: Python `src/`
//! layout and deep packages resolve to files by module name relative to a
//! source root. External calls are quiet only when modeled or explicitly
//! inert; an unmodeled effectful stdlib call and an unknown in-repo callee
//! both stay LOUD.
#![allow(clippy::disallowed_methods)]

use effinterp_repo::{IndexLimits, ResourceSelector, build_index, effects_of, reach};
use effinterp_testkit::repo_fixture::repo_test_fixture;

/// A `src/` layout: `src` is not a package (no `__init__.py`) but `src/app` and
/// `src/pkg` are, so `src/pkg/util.py` is imported as `pkg.util`. The entrypoint
/// `from pkg.util import wipe; wipe("/var/cache/app")` must resolve cross-file.
#[test]
fn src_layout_import_resolves_cross_file() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "impres-srclayout",
        &[
            ("src/app/__init__.py", ""),
            (
                "src/app/main.py",
                "#!/usr/bin/env python\nfrom pkg.util import wipe\nwipe(\"/var/cache/app\")\n",
            ),
            ("src/pkg/__init__.py", ""),
            (
                "src/pkg/util.py",
                "import shutil\ndef wipe(p):\n    shutil.rmtree(p)\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(
        &idx,
        &ResourceSelector::parse("fs:/var/cache/app").unwrap(),
        None,
    );
    let hit = report
        .payload
        .as_reach()
        .unwrap()
        .matches
        .iter()
        .find(|h| {
            h.fact.entrypoint == "src/app/main.py" && h.fact.operation.0 == "filesystem.delete"
        })
        .expect("src-layout import composes the cross-file delete");
    assert!(
        hit.fact.provenance_roots.iter().any(|root| report
            .provenance
            .nodes
            .iter()
            .any(|node| &node.id == root && node.occurrence.origin == "src/pkg/util.py")),
        "provenance crosses into src/pkg/util.py"
    );
}

/// A deep package `a/b/c.py` (with `a` and `a/b` both packages, source root the
/// repo root) is imported as `a.b.c` and resolves.
#[test]
fn deep_package_import_resolves() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "impres-deep",
        &[
            ("a/__init__.py", ""),
            ("a/b/__init__.py", ""),
            (
                "a/b/c.py",
                "import shutil\ndef wipe(p):\n    shutil.rmtree(p)\n",
            ),
            (
                "main.py",
                "#!/usr/bin/env python\nfrom a.b.c import wipe\nwipe(\"/srv/deep\")\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(
        &idx,
        &ResourceSelector::parse("fs:/srv/deep").unwrap(),
        None,
    );
    let hit = report
        .payload
        .as_reach()
        .unwrap()
        .matches
        .iter()
        .find(|h| h.fact.entrypoint == "main.py" && h.fact.operation.0 == "filesystem.delete")
        .expect("deep-package import composes the cross-file delete");
    assert!(
        hit.fact.provenance_roots.iter().any(|root| report
            .provenance
            .nodes
            .iter()
            .any(|node| &node.id == root && node.occurrence.origin == "a/b/c.py")),
        "provenance crosses into a/b/c.py"
    );
}

/// A call into an explicitly-inert stdlib module (`re`) is a QUIET
/// `external_inert` boundary: it does not widen any domain, so it cannot force
/// coverage to Partial.
#[test]
fn inert_stdlib_call_is_quiet_not_coverage_degrading() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "impres-stdlib",
        &[(
            "app.py",
            "#!/usr/bin/env python\nfrom re import compile\ncompile(\"x\")\n",
        )],
    );
    let idx = build_index(&root, IndexLimits::default());
    let comp = idx
        .composition("app.py")
        .expect("app.py composes a boundary for the stdlib call");

    assert!(
        comp.boundaries.iter().any(|b| b.reason == "external_inert"),
        "inert stdlib call yields an external_inert boundary: {:?}",
        comp.boundaries
    );
    assert!(
        !comp
            .boundaries
            .iter()
            .any(|b| b.reason == "cross_module" || b.reason == "external_unmodeled"),
        "inert stdlib call must NOT yield a loud boundary: {:?}",
        comp.boundaries
    );
    // The mechanism that degrades coverage is a boundary's domain list; a quiet
    // boundary carries none, so no domain is widened.
    let widened: Vec<&str> = comp
        .boundaries
        .iter()
        .flat_map(|b| b.domains.iter().map(|s| s.as_str()))
        .collect();
    assert!(
        widened.is_empty(),
        "no domain may be widened by an inert stdlib call: {widened:?}"
    );
    // Composition itself contributes no coverage degradation (the engine's own
    // plan-level handling of the unresolved call is a separate concern).
    assert!(
        !comp
            .coverage
            .iter()
            .any(|(_, level)| matches!(level, effinterp_proto::CoverageLevel::Partial)),
        "inert stdlib call must not degrade composed coverage: {:?}",
        comp.coverage
    );
}

/// An unmodeled call into an EFFECTFUL stdlib module (`sqlite3`) is external by
/// provenance but must not be behaviorally silent: it surfaces as a LOUD
/// `external_unmodeled` boundary. `sqlite3` is exactly identified, so the
/// boundary clouds only the database it opens and the file backing it —
/// domains it cannot reach stay answerable.
#[test]
fn unmodeled_effectful_stdlib_call_is_a_loud_boundary() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "impres-stdlib-effectful",
        &[(
            "app.py",
            "#!/usr/bin/env python\nimport sqlite3\nsqlite3.connect(\"app.db\")\n",
        )],
    );
    let idx = build_index(&root, IndexLimits::default());
    let comp = idx
        .composition("app.py")
        .expect("app.py composes a boundary for the unmodeled stdlib call");

    let boundary = comp
        .boundaries
        .iter()
        .find(|b| b.reason == "external_unmodeled")
        .expect("unmodeled effectful stdlib call is an external_unmodeled boundary");
    assert_eq!(boundary.domains, vec!["database", "filesystem"]);
    let report = effects_of(&idx, "app.py")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report
            .boundaries
            .iter()
            .any(|b| b.reason == "external_unmodeled"),
        "the effects report surfaces the unmodeled-external boundary: {:?}",
        report.boundaries
    );
    assert!(
        report
            .coverage
            .iter()
            .any(|(domain, level)| domain == "filesystem"
                && level.level == effinterp_proto::CoverageLevel::Partial),
        "unmodeled effectful stdlib call degrades coverage to partial: {:?}",
        report.coverage
    );
    assert!(
        !report
            .boundaries
            .iter()
            .filter(|b| b.reason == "external_unmodeled")
            .any(|b| b.domains.iter().any(|d| d == "network")),
        "a database call must not raise a network boundary: {:?}",
        report.boundaries
    );
}

/// Unmodeled effectful calls into modules the engine has models for
/// (`shutil.chown`, `socket.create_connection`) must not be silent either: the
/// plan records an explicit `external_unmodeled` boundary, while modeled calls
/// in the same file (`shutil.rmtree`, `urllib.request.urlopen`) stay quiet and
/// contribute their effects.
#[test]
fn unmodeled_methods_of_modeled_stdlib_modules_are_not_silent() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "impres-stdlib-unmodeled-method",
        &[(
            "app.py",
            "#!/usr/bin/env python\nimport shutil\nimport socket\nimport urllib.request\n\
             shutil.rmtree(\"/var/data\")\nshutil.chown(\"/var/data\", \"app\")\n\
             socket.create_connection((\"db.internal\", 5432))\n\
             urllib.request.urlopen(\"https://example.com\")\n",
        )],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "app.py")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();

    // The modeled calls resolve to concrete effects.
    assert!(
        report.effects.iter().any(|e| {
            e.operation.0 == "filesystem.delete"
                && effinterp_proto::display_resource(&e.resource).contains("/var/data")
        }),
        "modeled shutil.rmtree still yields the delete: {:?}",
        report.effects
    );
    // The unmodeled effectful calls each surface as an explicit boundary.
    for callee in ["shutil.chown", "socket.create_connection"] {
        assert!(
            report
                .boundaries
                .iter()
                .any(|b| b.reason == "external_unmodeled"
                    && b.detail.as_deref().is_some_and(|d| d.contains(callee))),
            "{callee} must surface as an external_unmodeled boundary: {:?}",
            report.boundaries
        );
    }
}

/// A genuinely-unknown in-repo callee (no such module in the repo, not stdlib,
/// not relative) still produces the LOUD cross_module boundary that widens every
/// domain and degrades coverage — the conservative default.
#[test]
fn unknown_in_repo_call_is_loud_and_degrades_coverage() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "impres-unknown",
        &[(
            "app.py",
            "#!/usr/bin/env python\nfrom helpers import wipe\nwipe(\"/var/data\")\n",
        )],
    );
    let idx = build_index(&root, IndexLimits::default());
    let comp = idx
        .composition("app.py")
        .expect("app.py composes an unresolved-call boundary");

    let cross = comp
        .boundaries
        .iter()
        .find(|b| b.reason == "cross_module")
        .expect("unknown in-repo call is a loud cross_module boundary");
    for domain in effinterp_proto::DOMAINS {
        assert!(
            cross.domains.iter().any(|d| d == domain),
            "cross_module boundary widens every domain; missing {domain}: {:?}",
            cross.domains
        );
    }
    // The widened domains degrade effective coverage to Partial.
    let report = effects_of(&idx, "app.py").unwrap();
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .coverage
            .iter()
            .any(|(domain, level)| domain == "filesystem"
                && level.level == effinterp_proto::CoverageLevel::Partial),
        "unknown in-repo call degrades filesystem coverage to partial: {:?}",
        report.coverage
    );
}
