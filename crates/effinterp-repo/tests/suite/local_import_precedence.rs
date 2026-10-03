//! A function-local import can SHADOW a same-file def of the same name (the
//! httpie `httpie/__main__.py` shape: a module-level `def main` and, inside
//! it, `from httpie.core import main` before calling `main()`). The call must
//! resolve through the import to the cross-file function, not to the local
//! def of the same name — otherwise the entrypoint's composition stops at the
//! local (already-inlined) def and never reaches the cross-file effect.
#![allow(clippy::disallowed_methods)]

use effinterp_repo::{IndexLimits, ResourceSelector, build_index, reach};
use effinterp_testkit::repo_fixture::repo_test_fixture;

/// app.py has a module-level `def main` (a no-op local function) and, inside
/// it, `from lib.core import main` then `main()`. The call must resolve to
/// lib/core.py's `main`, which performs the cross-file delete — NOT the local
/// `def main`, which does nothing.
#[test]
fn function_local_import_shadows_same_file_def() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "shadow-import",
        &[
            (
                "app.py",
                "def main():\n    from lib.core import main\n    main()\nif __name__ == \"__main__\":\n    main()\n",
            ),
            ("lib/__init__.py", ""),
            (
                "lib/core.py",
                "import os\ndef main():\n    os.remove(\"/z\")\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(&idx, &ResourceSelector::parse("fs:/z").unwrap(), None);

    let hit = report
        .payload
        .as_reach()
        .unwrap()
        .matches
        .iter()
        .find(|h| h.fact.entrypoint == "app.py" && h.fact.operation.0 == "filesystem.delete")
        .expect("the shadowing import reaches lib/core.py's cross-file delete of /z");
    assert!(
        hit.fact.provenance_roots.iter().any(|root| report
            .provenance
            .nodes
            .iter()
            .any(|node| &node.id == root && node.occurrence.origin == "lib/core.py")),
        "provenance crosses into lib/core.py through the shadowing import"
    );
}

/// Without a shadowing import, a bare call to a genuinely-local function must
/// still resolve local (no cross-file effect fabricated) — the precedence fix
/// must not break the common case.
#[test]
fn bare_local_call_without_shadowing_import_stays_local() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "no-shadow",
        &[
            (
                "app.py",
                "def helper():\n    pass\ndef main():\n    helper()\nif __name__ == \"__main__\":\n    main()\n",
            ),
            ("lib/__init__.py", ""),
            (
                "lib/core.py",
                "import os\ndef helper():\n    os.remove(\"/z\")\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(&idx, &ResourceSelector::parse("fs:/z").unwrap(), None);

    assert!(
        !report.payload.as_reach().unwrap().matches.iter().any(|h| {
            h.fact.entrypoint == "app.py" && h.fact.operation.0 == "filesystem.delete"
        }),
        "no import shadows `helper`, so app.py's local (no-op) helper must not \
         be confused with lib/core.py's same-named function: {:?}",
        report.payload.as_reach().unwrap().matches
    );
}
