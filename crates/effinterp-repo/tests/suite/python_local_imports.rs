//! Cross-file composition through Python constructs that a leaf-node analyzer
//! used to miss: a `from ... import` written INSIDE a function body, and a call
//! nested as an argument to another call. Both must still reach the effect they
//! transitively perform in another file.
#![allow(clippy::disallowed_methods)]

use effinterp_repo::{IndexLimits, ResourceSelector, build_index, effects_of, reach};
use effinterp_testkit::repo_fixture::repo_test_fixture;

use crate::support::antecedent_origins;

// A `from lib.fs import wipe` written inside `run`'s body binds `wipe` for the
// cross-file resolver: querying the deleted path reaches app.py THROUGH the
// function-local import into lib/fs.py.

/// Every occurrence a fact's roots derive from, walking the envelope graph
/// backwards the way explanation does.
#[test]
fn function_local_import_resolves_cross_file() {
    for init in ["", "os.remove('/init')\n"] {
        let module = format!("import os\n{init}def wipe(p):\n    os.remove(p)\n");
        let root = repo_test_fixture(
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
            "local-import",
            &[
                (
                    "app.py",
                    "def run():\n    from lib.unused import ignored\n    from lib.fs import wipe\n    wipe(\"/x\")\nif __name__ == \"__main__\":\n    run()\n",
                ),
                ("lib/__init__.py", ""),
                ("lib/fs.py", &module),
                (
                    "lib/unused.py",
                    "import os\nos.remove('/unused-init')\ndef ignored(): pass\n",
                ),
            ],
        );
        let idx = build_index(&root, IndexLimits::default());
        let report = reach(&idx, &ResourceSelector::parse("fs:/x").unwrap(), None);

        let hit = report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .find(|h| {
                h.fact.entrypoint == "app.py" && h.fact.operation.as_str() == "filesystem.delete"
            })
            .expect("function-local import reaches the cross-file delete of /x");
        assert!(
            antecedent_origins(&report.provenance, &hit.fact.provenance_roots)
                .iter()
                .any(|origin| origin.contains("lib/fs.py")),
            "provenance crosses into lib/fs.py: {:?}",
            report.provenance
        );
        let effects = effects_of(&idx, "app.py")
            .unwrap()
            .payload
            .into_effects()
            .unwrap();
        assert!(
            effects.boundaries.iter().all(|boundary| {
                boundary.reason != "unmodeled_import"
                    || !boundary
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.contains("lib.fs"))
            }),
            "{:?}",
            effects.boundaries
        );
        assert!(
            effects.boundaries.iter().any(|boundary| {
                boundary.reason == "unmodeled_import"
                    && boundary
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.contains("lib.unused"))
            }),
            "an import without a composed call keeps its boundary"
        );
        let deletes: Vec<_> = effects
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "filesystem.delete")
            .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
            .collect();
        assert!(deletes.iter().any(|resource| resource == "fs:/x"));
        assert_eq!(
            deletes
                .iter()
                .filter(|resource| *resource == "fs:/init")
                .count(),
            usize::from(!init.is_empty()),
            "{deletes:?}"
        );
        assert!(!deletes.iter().any(|resource| resource == "fs:/unused-init"));
    }
}

/// `sys.exit(go())` records `go` as an outgoing edge even though the call is
/// nested as an argument to `sys.exit`; `go`'s cross-file delete is reached.
#[test]
fn nested_argument_call_is_an_edge() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "nested-arg",
        &[
            (
                "app.py",
                "import sys\nfrom lib.fs import wipe\ndef go():\n    wipe(\"/y\")\n    return 0\nif __name__ == \"__main__\":\n    sys.exit(go())\n",
            ),
            ("lib/__init__.py", ""),
            ("lib/fs.py", "import os\ndef wipe(p):\n    os.remove(p)\n"),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(&idx, &ResourceSelector::parse("fs:/y").unwrap(), None);

    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.entrypoint == "app.py"
                && h.fact.operation.as_str() == "filesystem.delete"),
        "go() nested inside sys.exit(...) reaches the cross-file delete of /y: {:?}",
        report.payload.as_reach().unwrap().matches
    );
}

#[test]
fn same_arity_local_builtin_and_stdlib_names_keep_cross_file_effects() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "python-safe-call-shadowing",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom helpers import len\nfrom re import compile\nlen('x')\ncompile('x')\ndef show(format):\n    format('x')\nshow(len)\n",
            ),
            (
                "helpers.py",
                "import os\ndef len(value):\n    os.remove('/builtin-shadow')\n",
            ),
            (
                "re.py",
                "import os\ndef compile(value):\n    os.remove('/stdlib-shadow')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "app.py")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects.boundaries.iter().any(|boundary| {
            boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("format"))
        }),
        "{:?}",
        effects.boundaries
    );
    for path in ["/builtin-shadow", "/stdlib-shadow"] {
        let report = reach(
            &index,
            &ResourceSelector::parse(&format!("fs:{path}")).unwrap(),
            None,
        );
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .any(|hit| hit.fact.entrypoint == "app.py"
                    && hit.fact.operation.as_str() == "filesystem.delete"),
            "{path}"
        );
    }
}
