//! A refused pytest listing must stay a partial `observation-unavailable` gap.
//! The corpus runner accepts a full plan when the row asked for partial, and
//! entry-point autoload would keep these rows partial even if the listing gap
//! disappeared. Autoload is off in the fixtures, so this is the check.

use nah_corpus::{corpus_dir, decision_shape, load_cases, load_fixtures};

#[test]
fn refused_pytest_listings_stay_partial_observation_gaps() {
    let dir = corpus_dir();
    let cases = load_cases(&dir).expect("corpus");
    let fixtures = load_fixtures(&dir.join("FIXTURES.json")).expect("fixtures");
    // Delegates: the unread test module is not a delete. The unlistable parent
    // still imports its conftest, so that row blocks, and the listing gap is
    // what keeps the plan partial.
    let rows = [
        ("fs-home.pytest-listing-refused-delegates", false),
        ("fs-home.pytest-listing-refused-module-delegates", false),
        ("fs-home.pytest-unlistable-parent-conftest", true),
    ];
    for (id, blocks) in rows {
        let case = cases
            .iter()
            .find(|case| case.id == id)
            .unwrap_or_else(|| panic!("missing {id}"));
        let shape = decision_shape(case, &fixtures).unwrap_or_else(|error| panic!("{id}: {error}"));
        assert_eq!(shape.blocks, blocks, "{id}");
        assert!(
            shape.coverage_partial,
            "{id} coverage became full; gaps {:?}",
            shape.gaps
        );
        assert!(
            shape.gaps.iter().any(
                |(category, code)| category == "Unmodeled" && code == "observation-unavailable"
            ),
            "{id} gaps {:?}",
            shape.gaps
        );
    }
}

#[test]
fn pytest_coverage_requires_plain_collection() {
    let dir = corpus_dir();
    let cases = load_cases(&dir).expect("corpus");
    let fixtures = load_fixtures(&dir.join("FIXTURES.json")).expect("fixtures");
    let rows = [
        ("fs-home.pytest-plain-full", None, false),
        (
            "fs-home.pytest-warning-ini-mixed-endings-gap",
            Some("unread-config"),
            false,
        ),
        (
            "fs-home.pytest-cli-discovery-gap",
            Some("frontend-partial"),
            false,
        ),
        (
            "fs-home.pytest-per-argument-discovery-gap",
            Some("frontend-partial"),
            false,
        ),
        (
            "fs-home.pytest-registration-tuple-gap",
            Some("frontend-partial"),
            false,
        ),
        (
            "fs-home.pytest-registration-global-gap",
            Some("frontend-partial"),
            false,
        ),
        (
            "fs-home.pytest-plugin-environment-gap",
            Some("environment-configuration"),
            false,
        ),
        (
            "fs-home.pytest-startup-warning-import-gap",
            Some("frontend-partial"),
            false,
        ),
        (
            "fs-home.pytest-startup-warning-import-module-gap",
            Some("frontend-partial"),
            false,
        ),
        (
            "fs-home.pytest-startup-warning-builtin-delegates",
            None,
            false,
        ),
        (
            "fs-home.pytest-startup-reads-excluded-conftest",
            Some("frontend-partial"),
            true,
        ),
        (
            "fs-home.python-local-pytest-decorator-result-gap",
            Some("unresolved-call"),
            false,
        ),
    ];
    let warning_filters = [
        ("fs-home.pytest-warning-ini-gap", true),
        ("fs-home.pytest-warning-ini-module-gap", true),
        ("fs-home.pytest-warning-ini-builtin-full", false),
        ("fs-home.pytest-warning-pyproject-gap", true),
        ("fs-home.pytest-warning-native-pyproject-gap", true),
        ("fs-home.pytest-warning-cli-gap", true),
        ("fs-home.pytest-warning-cli-builtin-full", false),
        ("fs-home.pytest-warning-override-gap", true),
        ("fs-home.pytest-warning-override-builtin-full", false),
    ];
    for (id, gap, blocks) in rows.into_iter().chain(
        warning_filters
            .into_iter()
            .map(|(id, imports)| (id, imports.then_some("frontend-partial"), false)),
    ) {
        let case = cases.iter().find(|case| case.id == id).expect(id);
        let shape = decision_shape(case, &fixtures).unwrap_or_else(|error| panic!("{id}: {error}"));
        assert_eq!(shape.blocks, blocks, "{id}");
        assert_eq!(shape.coverage_partial, gap.is_some(), "{id}: {shape:?}");
        if let Some(gap) = gap {
            assert!(
                shape.gaps.iter().any(|(_, code)| code == gap),
                "{id}: {shape:?}"
            );
        }
    }
    // The Python wrapper can have independent gaps. Ignoring the startup
    // environment must remove the warning-category gap in particular.
    for id in [
        "fs-home.pytest-ignore-env-skips-startup-warning-import",
        "fs-home.pytest-isolated-skips-startup-warning-import",
    ] {
        let case = cases.iter().find(|case| case.id == id).expect(id);
        let shape = decision_shape(case, &fixtures).unwrap_or_else(|error| panic!("{id}: {error}"));
        assert!(
            shape
                .gaps
                .iter()
                .all(|(_, code)| code != "frontend-partial"),
            "{id}: {shape:?}"
        );
    }
}

#[test]
fn unread_pytest_code_and_ordinary_module_paths_do_not_claim_full_coverage() {
    let dir = corpus_dir();
    let cases = load_cases(&dir).expect("corpus");
    let fixtures = load_fixtures(&dir.join("FIXTURES.json")).expect("fixtures");
    // Imported pytest callables, a literal `__path__`, a bare imported
    // decorator, and a top-level relative sibling are followed, so the payload
    // blocks. Discovery settings that cannot be applied, and a dynamic
    // `__path__`, stay partial. The neighbour of each is a plain delegate.
    let rows = [
        ("fs-home.pytest-imported-callable-collected", None, true),
        (
            "fs-home.pytest-imported-callable-module-collected",
            None,
            true,
        ),
        ("fs-home.pytest-imported-callable-delegates", None, false),
        (
            "fs-home.pytest-native-toml-testpaths-gap",
            Some("frontend-partial"),
            false,
        ),
        (
            "fs-home.pytest-dot-toml-testpaths-gap",
            Some("frontend-partial"),
            false,
        ),
        ("fs-home.pytest-native-toml-plain-delegates", None, false),
        (
            "fs-home.pytest-pyproject-native-beside-ini-gap",
            Some("frontend-partial"),
            false,
        ),
        ("fs-home.pytest-pyproject-empty-ini-delegates", None, false),
        ("fs-home.ordinary-module-path-child-collected", None, true),
        ("fs-home.ordinary-module-path-child-delegates", None, false),
        (
            "fs-home.ordinary-module-dynamic-path-gap",
            Some("unrecoverable-source"),
            false,
        ),
        (
            "fs-home.python-bare-imported-decorator-collected",
            None,
            true,
        ),
        (
            "fs-home.python-bare-imported-decorator-delegates",
            None,
            false,
        ),
        (
            "fs-home.python-ordinary-relative-sibling-collected",
            None,
            true,
        ),
        (
            "fs-home.python-ordinary-relative-sibling-delegates",
            None,
            false,
        ),
    ];
    for (id, gap, blocks) in rows {
        let case = cases.iter().find(|case| case.id == id).expect(id);
        let shape = decision_shape(case, &fixtures).unwrap_or_else(|error| panic!("{id}: {error}"));
        assert_eq!(shape.blocks, blocks, "{id}: {shape:?}");
        // A collected callable is conditional, so a blocking row may be partial
        // for that reason. Full coverage is required only of the plain neighbours.
        if !blocks {
            assert_eq!(shape.coverage_partial, gap.is_some(), "{id}: {shape:?}");
        }
        if let Some(gap) = gap {
            assert!(
                shape.gaps.iter().any(|(_, code)| code == gap),
                "{id}: {shape:?}"
            );
        }
    }
}
