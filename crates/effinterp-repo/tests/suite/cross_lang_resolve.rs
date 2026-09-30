//! Cross-file import resolution for Go, Ruby, and Rust: `Registry::build` over
//! a fixture repo, then `resolve_import` on the real extracted import bindings.
//!
//! These test the resolver directly; end-to-end Ruby composition is covered
//! in `ruby_compose.rs`.
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

use effinterp_engine::Assurance;
use effinterp_proto::display_resource_with_scope;
use effinterp_repo::{CrawlLimits, IndexLimits, Registry, RepoIndex, build_index};
use effinterp_testkit::repo_fixture::repo_test_fixture;

/// Resolve every import of `importer` and return the target file paths (the
/// import that could not be resolved is omitted).
fn resolved_targets(reg: &Registry, importer_path: &str) -> Vec<(String, Option<String>)> {
    let importer = reg.files.get(importer_path).expect("importer registered");
    importer
        .summary
        .imports
        .iter()
        .map(|imp| {
            let target = reg.resolve_import(importer, imp).map(|f| f.path.clone());
            (imp.module.clone(), target)
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
enum CallTargetClass {
    Exact(Vec<String>),
    BoundedAlternatives(Vec<String>),
    TypedBoundary,
    Miss,
}

fn classify_p13e_target(
    index: &RepoIndex,
    entrypoint: &str,
) -> Result<CallTargetClass, &'static str> {
    let Some(composition) = index.composition(entrypoint) else {
        return Err("entrypoint was not analyzed");
    };
    let mut effects: Vec<_> = composition
        .occurrence_effects
        .iter()
        .filter_map(|occurrence| {
            let effect = &composition.effects[occurrence.effect].effect;
            let resource = display_resource_with_scope(&effect.resource);
            (effect.operation.0 == "filesystem.delete" && resource.contains("/p13e/"))
                .then_some((resource, occurrence.assurance))
        })
        .collect();
    effects.sort_by(|left, right| left.0.cmp(&right.0));
    effects.dedup();
    if effects.len() == 1 && effects[0].1 == Assurance::Exact {
        return Ok(CallTargetClass::Exact(
            effects.into_iter().map(|effect| effect.0).collect(),
        ));
    }
    if (2..=4).contains(&effects.len())
        && effects
            .iter()
            .all(|effect| effect.1 == Assurance::Alternatives)
    {
        return Ok(CallTargetClass::BoundedAlternatives(
            effects.into_iter().map(|effect| effect.0).collect(),
        ));
    }
    if effects.is_empty()
        && composition.boundaries.iter().any(|boundary| {
            boundary.reason == "dynamic_dispatch" && boundary.detail.contains("typed candidates")
        })
    {
        return Ok(CallTargetClass::TypedBoundary);
    }
    if effects.is_empty()
        && composition
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unresolved_call")
    {
        return Ok(CallTargetClass::Miss);
    }
    Err("unsupported call-target evidence")
}

fn go_interface_source(implementations: usize) -> String {
    let mut source =
        String::from("package main\nimport \"os\"\ntype Eraser interface { Erase() }\n");
    for index in 0..implementations {
        source.push_str(&format!(
            "type T{index} struct{{}}\nfunc (*T{index}) Erase() {{ os.Remove(\"/p13e/alternative-{index}\") }}\n"
        ));
    }
    source.push_str("func main() { var value Eraser; value.Erase() }\n");
    source
}

fn java_interface_root(tag: &str, implementations: usize) -> PathBuf {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        tag,
        &[
            (
                "src/main/java/p13e/Eraser.java",
                "package p13e;\npublic interface Eraser { void erase(); }\n",
            ),
            (
                "src/main/java/p13e/App.java",
                "package p13e;\npublic class App { public static void main(String[] args) { Eraser eraser; eraser.erase(); } }\n",
            ),
        ],
    );
    for index in 0..implementations {
        std::fs::write(
            root.join(format!("src/main/java/p13e/Eraser{index}.java")),
            format!(
                "package p13e;\nimport java.nio.file.Files;\nimport java.nio.file.Path;\npublic class Eraser{index} implements Eraser {{ public void erase() {{ try {{ Files.delete(Path.of(\"/p13e/alternative-{index}\")); }} catch (Exception error) {{}} }} }}\n"
            ),
        )
        .unwrap();
    }
    root
}

#[test]
fn repository_call_targets_have_exact_bounded_boundary_or_miss_outcomes() {
    let exact_root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p13e-target-exact",
        &[
            (
                "app.py",
                "#!/usr/bin/env python3\nfrom helper import erase\nerase()\n",
            ),
            (
                "helper.py",
                "import os\ndef erase(): os.remove('/p13e/exact')\n",
            ),
        ],
    );
    assert_eq!(
        classify_p13e_target(&build_index(&exact_root, IndexLimits::default()), "app.py"),
        Ok(CallTargetClass::Exact(vec!["fs:/p13e/exact".into()]))
    );

    let alternatives = go_interface_source(4);
    let alternatives_root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p13e-target-alternatives",
        &[
            ("go.mod", "module example.test/p13e\n\ngo 1.21\n"),
            ("main.go", &alternatives),
        ],
    );
    assert_eq!(
        classify_p13e_target(
            &build_index(&alternatives_root, IndexLimits::default()),
            "main.go"
        ),
        Ok(CallTargetClass::BoundedAlternatives(vec![
            "fs:/p13e/alternative-0".into(),
            "fs:/p13e/alternative-1".into(),
            "fs:/p13e/alternative-2".into(),
            "fs:/p13e/alternative-3".into(),
        ]))
    );

    let boundary_root = java_interface_root("p13e-target-boundary", 5);
    assert_eq!(
        classify_p13e_target(
            &build_index(&boundary_root, IndexLimits::default()),
            "src/main/java/p13e/App.java"
        ),
        Ok(CallTargetClass::TypedBoundary)
    );

    let miss_root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p13e-target-miss",
        &[
            (
                "app.py",
                "#!/usr/bin/env python3\nfrom helper import Wrong\nWrong().erase()\n",
            ),
            (
                "helper.py",
                "import os\nclass Right:\n    def erase(self): os.remove('/p13e/wrong-receiver')\nclass Wrong: pass\n",
            ),
        ],
    );
    assert_eq!(
        classify_p13e_target(&build_index(&miss_root, IndexLimits::default()), "app.py"),
        Ok(CallTargetClass::Miss)
    );
}

#[test]
fn unclassified_call_target_evidence_is_not_reported_as_a_miss() {
    let heuristic = go_interface_source(1);
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p13e-target-unclassified",
        &[
            ("go.mod", "module example.test/p13e\n\ngo 1.21\n"),
            ("main.go", &heuristic),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert_eq!(
        classify_p13e_target(&index, "main.go"),
        Err("unsupported call-target evidence")
    );
    assert_eq!(
        classify_p13e_target(&index, "missing.go"),
        Err("entrypoint was not analyzed")
    );
}

#[test]
fn go_import_resolves_via_go_mod_prefix() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xlang-go",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport \"example.com/app/util\"\nfunc main() { util.Wipe(\"/x\") }\n",
            ),
            (
                "util/util.go",
                "package util\nimport \"os\"\nfunc Wipe(p string) { os.RemoveAll(p) }\n",
            ),
        ],
    );
    let (reg, _, _) = Registry::build(&root, &CrawlLimits::default());
    // main.go's import of the local package resolves into its directory.
    let from_main = resolved_targets(&reg, "main.go");
    assert!(
        from_main.contains(&("example.com/app/util".into(), Some("util/util.go".into()))),
        "go module import -> package file: {from_main:?}"
    );
    // util.go's std import (os) stays unresolved (external, not a repo file).
    let from_util = resolved_targets(&reg, "util/util.go");
    assert!(
        from_util.iter().any(|(m, t)| m == "os" && t.is_none()),
        "std import stays external: {from_util:?}"
    );
}

#[test]
fn go_without_go_mod_stays_unresolved() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xlang-go-nomod",
        &[
            (
                "main.go",
                "package main\nimport \"example.com/app/util\"\nfunc main() { util.Wipe(\"/x\") }\n",
            ),
            ("util/util.go", "package util\nfunc Wipe(p string) {}\n"),
        ],
    );
    let (reg, _, _) = Registry::build(&root, &CrawlLimits::default());
    // No go.mod -> the module prefix is unknown -> conservatively unresolved.
    for (_, target) in resolved_targets(&reg, "main.go") {
        assert!(target.is_none(), "no go.mod: imports stay external");
    }
}

#[test]
fn rust_use_crate_path_resolves_to_module_file() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xlang-rust",
        &[
            (
                "app.rs",
                "use crate::util::wipe;\nuse std::fs;\nfn main() { wipe(std::path::Path::new(\"/x\")); }\n",
            ),
            (
                "util.rs",
                "use std::fs;\npub fn wipe(p: &std::path::Path) { fs::remove_dir_all(p).ok(); }\n",
            ),
        ],
    );
    let (reg, _, _) = Registry::build(&root, &CrawlLimits::default());
    let targets = resolved_targets(&reg, "app.rs");
    assert!(
        targets
            .iter()
            .any(|(m, t)| m == "crate::util::wipe" && t.as_deref() == Some("util.rs")),
        "use crate::util::wipe -> util.rs: {targets:?}"
    );
    // std imports are external.
    assert!(
        targets
            .iter()
            .any(|(m, t)| m.starts_with("std") && t.is_none()),
        "std use stays external: {targets:?}"
    );
}

#[test]
fn rust_mod_rs_layout_resolves() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xlang-rust-modrs",
        &[
            ("app.rs", "use crate::util::wipe;\nfn main() { wipe(); }\n"),
            ("util/mod.rs", "pub fn wipe() {}\n"),
        ],
    );
    let (reg, _, _) = Registry::build(&root, &CrawlLimits::default());
    let targets = resolved_targets(&reg, "app.rs");
    assert!(
        targets
            .iter()
            .any(|(_, t)| t.as_deref() == Some("util/mod.rs")),
        "crate::util -> util/mod.rs: {targets:?}"
    );
}

#[test]
fn ruby_require_relative_resolves() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xlang-ruby",
        &[
            (
                "app.rb",
                "require_relative 'util'\nrequire 'json'\nUtil.wipe('/x')\n",
            ),
            (
                "util.rb",
                "require 'fileutils'\ndef wipe(p)\n  FileUtils.rm_rf(p)\nend\n",
            ),
        ],
    );
    let (reg, _, _) = Registry::build(&root, &CrawlLimits::default());
    let targets = resolved_targets(&reg, "app.rb");
    assert!(
        targets
            .iter()
            .any(|(m, t)| m == "./util" && t.as_deref() == Some("util.rb")),
        "require_relative 'util' -> util.rb: {targets:?}"
    );
    // A gem require with no matching repo file stays unresolved.
    assert!(
        targets.iter().any(|(m, t)| m == "json" && t.is_none()),
        "gem require stays external: {targets:?}"
    );
}

/// A compiled-language file with a program entry (`fn main` / `func main`) is
/// discovered as an entrypoint and analyzed from that entry, so a repo of pure
/// Rust/Go source is no longer blind.
#[test]
fn main_bearing_source_files_are_entrypoints() {
    use effinterp_repo::{IndexLimits, Selector, build_index, reach};
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("mainfiles");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("main.rs"),
        "use std::fs;\nfn main() { fs::remove_dir_all(\"/var/cache/app\").unwrap(); }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("lib.rs"),
        "pub fn helper() -> i32 { 1 }\n", // no main: not an entrypoint
    )
    .unwrap();

    let idx = build_index(&root, IndexLimits::default());
    let ids: Vec<&str> = idx
        .entrypoints
        .iter()
        .map(|e| e.entrypoint.id.as_str())
        .collect();
    assert!(
        ids.contains(&"main.rs"),
        "main.rs is an entrypoint: {ids:?}"
    );
    assert!(
        !ids.contains(&"lib.rs"),
        "lib.rs (no main) is not an entrypoint"
    );

    let report = reach(&idx, &Selector::parse("fs:/var/cache/app").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.entrypoint == "main.rs"
                && h.fact.operation.as_str() == "filesystem.delete"),
        "reach finds fn main's delete"
    );
}

/// The ripgrep shape: a binary crate rooted in a workspace subdirectory whose
/// `main` reaches a filesystem effect only through (1) a `crate::`-qualified
/// call resolved against the crate root, (2) a `mod.rs` that merely RE-EXPORTS
/// the target from a submodule, and (3) a same-file helper that makes the next
/// cross-file call. All three must compose for the effect to surface.
#[test]
fn rust_workspace_reexport_and_local_helper_compose_to_an_effect() {
    use effinterp_repo::{Selector, build_index, reach};
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xlang-rust-ripgrep-shape",
        &[
            (
                "crates/core/main.rs",
                "fn main() { crate::flags::parse(); }\n",
            ),
            (
                "crates/core/flags/mod.rs",
                "mod parse;\nmod config;\npub use crate::flags::parse::parse;\n",
            ),
            (
                "crates/core/flags/parse.rs",
                "pub fn parse() { parse_low(); }\nfn parse_low() { crate::flags::config::wipe(); }\n",
            ),
            (
                "crates/core/flags/config.rs",
                "pub fn wipe() { local_wipe(); }\nfn local_wipe() { std::fs::remove_dir_all(\"/var/cache/app\").ok(); }\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(&idx, &Selector::parse("fs:/var/cache/app").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.entrypoint == "crates/core/main.rs"
                && h.fact.operation.as_str() == "filesystem.delete"),
        "main composes across crate-root/re-export/local-helper: matches={:?} indeterminate={:?}",
        report.payload.as_reach().unwrap().matches,
        report.payload.as_reach().unwrap().indeterminate
    );
}

/// A crate-root `pub extern crate grep_cli as cli` makes `grep::cli::hostname`
/// resolve into the aliased crate. `resolve_import` lands on the crate root;
/// `resolve_export` then chases `pub use crate::hostname::hostname` to the
/// defining file. The mapping here is the import-resolution hop.
#[test]
fn rust_workspace_crate_root_alias_resolves_to_aliased_crate() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xlang-rust-grep-extern-crate-alias",
        &[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"crates/core\", \"crates/grep\", \"crates/cli\"]\n",
            ),
            (
                "crates/core/Cargo.toml",
                "[package]\nname = \"core\"\nversion = \"0.1.0\"\n",
            ),
            (
                "crates/core/src/main.rs",
                "use grep::cli::hostname;\nfn main() { hostname(); }\n",
            ),
            (
                "crates/grep/Cargo.toml",
                "[package]\nname = \"grep\"\nversion = \"0.1.0\"\n",
            ),
            (
                "crates/grep/src/lib.rs",
                "pub extern crate grep_cli as cli;\n",
            ),
            (
                "crates/cli/Cargo.toml",
                "[package]\nname = \"grep-cli\"\nversion = \"0.1.0\"\n",
            ),
            (
                "crates/cli/src/lib.rs",
                "mod hostname;\npub use crate::hostname::hostname;\n",
            ),
            (
                "crates/cli/src/hostname.rs",
                "pub fn hostname() { std::fs::remove_file(\"/var/hostname.lock\"); }\n",
            ),
        ],
    );
    let (reg, _, _) = Registry::build(&root, &CrawlLimits::default());
    let from_bin = resolved_targets(&reg, "crates/core/src/main.rs");
    assert!(
        from_bin.contains(&(
            "grep::cli::hostname".into(),
            Some("crates/cli/src/lib.rs".into()),
        )),
        "grep::cli::hostname resolves to the aliased crate root: {from_bin:?}"
    );
    let from_cli = resolved_targets(&reg, "crates/cli/src/lib.rs");
    assert!(
        from_cli.contains(&(
            "crate::hostname::hostname".into(),
            Some("crates/cli/src/hostname.rs".into()),
        )),
        "cli crate re-export chases to hostname.rs: {from_cli:?}"
    );
}

#[test]
fn go_package_initializers_and_rust_build_scripts_are_entrypoints() {
    use effinterp_repo::{build_index, effects_of};

    let go_root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xlang-go-package-init",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            ("main.go", "package main\nfunc main() {}\n"),
            (
                "init.go",
                "package main\nimport \"os\"\nvar ready = prepare()\nfunc prepare() bool { os.RemoveAll(\"/go-package-init\"); return true }\n",
            ),
        ],
    );
    let go_index = build_index(&go_root, IndexLimits::default());
    assert!(
        effects_of(&go_index, "main.go")
            .unwrap()
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(
                |effect| effinterp_proto::display_resource_with_scope(&effect.resource)
                    == "fs:/go-package-init"
            )
    );

    let rust_root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xlang-rust-build-script",
        &[
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nbuild = \"build.rs\"\n",
            ),
            (
                "build.rs",
                "fn main() { std::fs::write(\"/rust-build-output\", \"ok\"); }\n",
            ),
            ("src/lib.rs", "pub fn library() {}\n"),
        ],
    );
    let rust_index = build_index(&rust_root, IndexLimits::default());
    assert!(
        rust_index
            .entrypoints
            .iter()
            .any(|entry| entry.entrypoint.id == "build.rs")
    );
    assert!(
        effects_of(&rust_index, "build.rs")
            .unwrap()
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(
                |effect| effinterp_proto::display_resource_with_scope(&effect.resource)
                    == "fs:/rust-build-output"
            )
    );
}

#[test]
fn java_import_resolves_via_package_path() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xlang-java",
        &[
            (
                "src/main/java/com/example/App.java",
                "package com.example;\nimport com.example.util.Helper;\npublic class App {\n  public static void main(String[] a) { Helper.wipe(\"/var/cache/app\"); }\n}\n",
            ),
            (
                "src/main/java/com/example/util/Helper.java",
                "package com.example.util;\nimport java.io.File;\npublic class Helper {\n  public static void wipe(String p) { new File(p).delete(); }\n}\n",
            ),
        ],
    );
    let (reg, _, _) = Registry::build(&root, &CrawlLimits::default());
    let from_app = resolved_targets(&reg, "src/main/java/com/example/App.java");
    assert!(
        from_app.contains(&(
            "com.example.util.Helper".into(),
            Some("src/main/java/com/example/util/Helper.java".into())
        )),
        "java FQN import -> package file under a source root: {from_app:?}"
    );
    // A java.* standard-library type is not a repo file.
    let from_helper = resolved_targets(&reg, "src/main/java/com/example/util/Helper.java");
    assert!(
        from_helper
            .iter()
            .any(|(m, t)| m == "java.io.File" && t.is_none()),
        "stdlib type stays external: {from_helper:?}"
    );
}

#[test]
fn php_require_resolves_relative() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "xlang-php",
        &[
            (
                "index.php",
                "<?php\nrequire __DIR__ . '/lib/helper.php';\nwipe('/var/cache/app');\n",
            ),
            (
                "lib/helper.php",
                "<?php\nfunction wipe($p) { unlink($p); }\n",
            ),
        ],
    );
    let (reg, _, _) = Registry::build(&root, &CrawlLimits::default());
    let from_index = resolved_targets(&reg, "index.php");
    assert!(
        from_index
            .iter()
            .any(|(_, t)| t.as_deref() == Some("lib/helper.php")),
        "php require -> the required file: {from_index:?}"
    );
}
