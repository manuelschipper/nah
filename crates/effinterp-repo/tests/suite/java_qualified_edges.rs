//! Type-qualified cross-file call edges reach across Java files.
//!
//! A Java `Helper.wipe(...)` call on an imported type is recorded as a call
//! edge by the frontend, so building the repo index and reaching the entrypoint
//! traces INTO the imported class's file (which the repo layer resolves from the
//! import FQN to `a/util/Helper.java`).

use effinterp_repo::{IndexLimits, Selector, build_index, effects_of, reach};
use effinterp_testkit::repo_fixture::repo_test_fixture;

use crate::support::antecedent_origins;

const APP: &str = "package a;\nimport a.util.Helper;\npublic class App {\n    public static void main(String[] x) {\n        Helper.wipe(\"/var/cache/app\");\n    }\n}\n";

// The acceptance fixture: the callee uses `new java.io.File(p).delete()` —
// the type-qualified call edge composes into Helper.java and the inline-
// qualified `java.io.File` receiver resolves to the File model, so the
// delete surfaces with the caller's argument substituted in.

/// Every occurrence a fact's roots derive from, walking the envelope graph
/// backwards the way explanation does.
#[test]
fn java_type_qualified_call_composes_into_imported_class() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "jqe-file",
        &[
            ("src/App.java", APP),
            (
                "src/a/util/Helper.java",
                "package a.util;\npublic class Helper {\n    public static void wipe(String p) {\n        new java.io.File(p).delete();\n    }\n}\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "src/App.java")
        .expect("App.java is an entrypoint")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        idx.registry.files.contains_key("src/a/util/Helper.java"),
        "Helper.java analyzed and in the registry"
    );
    assert!(
        report
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource_with_scope(&e.resource)
                    .contains("/var/cache/app")
                && e.origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str()
                    .ends_with("Helper.java")),
        "new java.io.File(p).delete() composes with the argument bound: {:?}",
        report.effects
    );
}

/// With a MODELED callee body (`Files.delete`), the same type-qualified edge
/// carries a real cross-file effect all the way to the resource query.
#[test]
fn java_type_qualified_call_reaches_cross_file_delete() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "jqe-files",
        &[
            ("src/App.java", APP),
            (
                "src/a/util/Helper.java",
                "package a.util;\nimport java.nio.file.Files;\nimport java.nio.file.Path;\npublic class Helper {\n    public static void wipe(String p) {\n        Files.delete(Path.of(p));\n    }\n}\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(&idx, &Selector::parse("fs:/var/cache/app").unwrap(), None);
    let hit = report
        .payload
        .as_reach()
        .unwrap()
        .matches
        .iter()
        .find(|h| {
            h.fact.entrypoint == "src/App.java" && h.fact.operation.as_str() == "filesystem.delete"
        })
        .expect("type-qualified call composes cross-file to the delete");
    assert!(
        antecedent_origins(&report.provenance, &hit.fact.provenance_roots)
            .iter()
            .any(|origin| origin.contains("Helper.java")),
        "provenance crosses into Helper.java: {:?}",
        report.provenance
    );
}

#[test]
fn same_named_class_in_the_wrong_package_never_satisfies_an_import() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "jqe-wrong-package",
        &[
            (
                "src/App.java",
                "package app;\nimport wanted.Helper;\npublic class App {\npublic static void main(String[] x) { Helper.wipe(); }\n}",
            ),
            (
                "src/wrong/Helper.java",
                "package wrong; public class Helper { public static void wipe() { new java.io.File(\"/wrong-package\").delete(); } }",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = effects_of(&idx, "src/App.java")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report.effects.is_empty(),
        "same-name class in wrong package dispatched: {:?}",
        report.effects
    );
}
