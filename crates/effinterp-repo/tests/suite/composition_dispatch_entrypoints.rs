#![allow(clippy::disallowed_methods)]

use std::path::Path;

use effinterp_repo::{
    EntrypointKind, IndexLimits, SkipCategory, build_index, effective_surface, effects_of,
};
use effinterp_testkit::repo_fixture::repo_test_fixture;

fn resources(index: &effinterp_repo::RepoIndex, entrypoint: &str) -> Vec<String> {
    let mut resources: Vec<_> = effects_of(index, entrypoint)
        .unwrap()
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    resources.sort();
    resources
}

#[test]
fn typed_framework_models_activate_only_the_proven_receiver() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7b-typed-frameworks",
        &[(
            "app.py",
            r#"#!/usr/bin/env python3
from argparse import ArgumentParser
from cleo.application import Application as BaseApplication
import os

class Application(BaseApplication):
    def _run(self): os.remove("/cleo-fired")

class SameNames:
    def run(self): pass
    def _run(self): os.remove("/same-name-inert")

def argparse_handler(): os.remove("/argparse-fired")

parser = ArgumentParser()
parser.set_defaults(func=argparse_handler)
parser.parse_args()

Application().run()
SameNames().run()
"#,
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(
        resources(&index, "app.py"),
        ["fs:/argparse-fired", "fs:/cleo-fired"]
    );
    let composition = index.composition("app.py").unwrap();
    assert!(
        composition.occurrence_effects.iter().all(|effect| {
            effect
                .via_dispatch
                .as_ref()
                .is_some_and(|via| matches!(via.model.as_str(), "argparse" | "cleo-application"))
        }),
        "{:?}",
        composition.effects
    );
}

#[test]
fn console_script_requires_and_retains_manifest_evidence() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7b-manifest-entry",
        &[
            (
                "pyproject.toml",
                "[project]\nname = \"app\"\n[project.scripts]\napp = \"pkg.cli:main\"\n",
            ),
            (
                "pkg/cli.py",
                "import os\ndef main(): os.remove('/manifest-entry')\n",
            ),
            (
                "pkg/decoy.py",
                "import os\ndef main(): os.remove('/not-an-entry')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let entry = index
        .entrypoints
        .iter()
        .find(|entry| entry.entrypoint.id == "pkg/cli.py")
        .unwrap();
    assert_eq!(
        entry.entrypoint.evidence.kind,
        EntrypointKind::ConsoleScript
    );
    assert_eq!(entry.entrypoint.source_file, "pkg/cli.py");
    assert_eq!(entry.entrypoint.evidence.file, "pyproject.toml");
    assert_eq!(entry.entrypoint.evidence.line, Some(4));
    assert_eq!(entry.entrypoint.entry_function.as_deref(), Some("main"));
    assert!(
        index
            .entrypoints
            .iter()
            .all(|entry| entry.entrypoint.id != "pkg/decoy.py")
    );
    assert_eq!(resources(&index, "pkg/cli.py"), ["fs:/manifest-entry"]);
    assert_eq!(
        effective_surface(&index, "pkg/cli.py").unwrap().source_file,
        "pkg/cli.py"
    );
}

#[test]
fn unresolved_console_script_emits_a_discovery_boundary() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7b-unresolved-manifest-entry",
        &[(
            "pyproject.toml",
            "[project.scripts]\napp = \"pkg.missing:main\"\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.entrypoints.is_empty());
    assert!(index.skipped.iter().any(|skip| {
        skip.path == "pyproject.toml"
            && skip.category == SkipCategory::Failure
            && skip
                .reason
                .contains("console script target \"pkg.missing:main\"")
    }));
}

#[test]
fn over_cap_typed_trait_set_emits_boundary_without_activation() {
    let mut implementations = String::from("pub trait Action { fn act(&self); }\n");
    for index in 0..5 {
        implementations.push_str(&format!(
            "pub struct T{index}; impl Action for T{index} {{ fn act(&self) {{ std::fs::remove_file(\"/rust-{index}\").ok(); }} }}\n"
        ));
    }
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7b-trait-cap",
        &[
            (
                "src/main.rs",
                "mod actions;\nuse crate::actions::Action;\nfn main() { let value: &dyn Action = external(); value.act(); }\n",
            ),
            ("src/actions.rs", &implementations),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("src/main.rs").unwrap();
    assert!(composition.effects.is_empty());
    assert!(composition.boundaries.iter().any(|boundary| {
        boundary.reason == "dynamic_dispatch"
            && boundary.detail.contains("trait Action")
            && boundary.detail.contains("5 typed candidates")
    }));
}

#[test]
fn unresolved_typed_trait_emits_boundary_without_activation() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p7b-trait-unresolved",
        &[
            (
                "src/main.rs",
                "mod action;\nuse crate::action::Action;\nfn main() { let value: &dyn Action = unknown(); value.act(); }\n",
            ),
            ("src/action.rs", "pub trait Action { fn act(&self); }\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("src/main.rs").unwrap();
    assert!(composition.effects.is_empty());
    assert!(composition.boundaries.iter().any(|boundary| {
        boundary.reason == "dynamic_dispatch"
            && boundary.detail.contains("trait Action")
            && boundary.detail.contains("0 typed candidates")
    }));
}
