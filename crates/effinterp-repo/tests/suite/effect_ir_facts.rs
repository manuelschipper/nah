#![allow(clippy::disallowed_methods)]

use effinterp_engine::{ObjectIdentity, ScopeKey, TypeRef, ValueOrigin};
use effinterp_repo::{
    CrawlLimits, IndexLimits, Registry, RepoChange, apply_changes, build_index, effects_of,
    normalize_surface,
};
use effinterp_testkit::repo_fixture::repo_test_fixture;

fn parser_scope(registry: &Registry, file: &str) -> ScopeKey {
    registry.files[file]
        .summary
        .module_calls
        .iter()
        .find_map(|edge| match edge.receiver_identity() {
            Some(ObjectIdentity::ModuleBinding { scope, name }) if name == "parser" => {
                Some(scope.clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("no parser binding fact in {file}"))
}

#[test]
fn python_rekey_rewrites_unchanged_bindings_on_clean_and_incremental_builds() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-python-rekey",
        &[
            (
                "src/commands.py",
                "import argparse\nparser = argparse.ArgumentParser()\nparser.add_subparsers()\n",
            ),
            (
                "src/app.py",
                "from .commands import parser\nparser.add_subparsers()\n",
            ),
            (
                "src/qualified.py",
                "from . import commands\ncommands.parser.add_subparsers()\n",
            ),
            (
                "launcher.py",
                "#!/usr/bin/env python\nimport src.app as app\nimport src.qualified as qualified\n",
            ),
        ],
    );
    let mut incremental = build_index(&root, IndexLimits::default());
    std::fs::write(root.join("src/__init__.py"), "").unwrap();
    apply_changes(
        &mut incremental,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Added("src/__init__.py".into())],
    );
    let clean = build_index(&root, IndexLimits::default());

    for file in ["src/commands.py", "src/app.py", "src/qualified.py"] {
        let incremental_file = incremental.registry.files.get(file).unwrap_or_else(|| {
            panic!(
                "incremental registry omitted {file}: {:?}",
                incremental.registry.files.keys().collect::<Vec<_>>()
            )
        });
        let clean_file = clean.registry.files.get(file).unwrap_or_else(|| {
            panic!(
                "clean registry omitted {file}: {:?}",
                clean.registry.files.keys().collect::<Vec<_>>()
            )
        });
        assert_eq!(
            incremental_file.summary, clean_file.summary,
            "incremental facts differ for {file}"
        );
    }
    let defining = parser_scope(&incremental.registry, "src/commands.py");
    let imported = parser_scope(&incremental.registry, "src/app.py");
    assert_eq!(
        defining,
        ScopeKey::Module {
            key: "src.commands".into()
        }
    );
    assert_eq!(defining, imported);
    assert_eq!(
        defining,
        parser_scope(&incremental.registry, "src/qualified.py")
    );
}

#[test]
fn python_relative_and_absolute_imports_keep_distinct_defining_bindings() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-python-relative-bindings",
        &[
            (
                "commands.py",
                "import argparse\nparser = argparse.ArgumentParser()\nparser.add_subparsers()\n",
            ),
            (
                "app.py",
                "from commands import parser\nparser.add_subparsers()\n",
            ),
            ("pkg/__init__.py", ""),
            (
                "pkg/commands.py",
                "import argparse\nparser = argparse.ArgumentParser()\nparser.add_subparsers()\n",
            ),
            (
                "pkg/rel.py",
                "from .commands import parser\nparser.add_subparsers()\n",
            ),
            (
                "pkg/qualified.py",
                "from . import commands\ncommands.parser.add_subparsers()\n",
            ),
        ],
    );
    let (registry, _, _) = Registry::build(&root, &CrawlLimits::default());
    let package_defining = parser_scope(&registry, "pkg/commands.py");
    assert_eq!(package_defining, parser_scope(&registry, "pkg/rel.py"));
    assert_eq!(
        package_defining,
        parser_scope(&registry, "pkg/qualified.py")
    );
    assert_eq!(
        parser_scope(&registry, "app.py"),
        ScopeKey::Module {
            key: "commands".into()
        }
    );
    assert_ne!(package_defining, parser_scope(&registry, "app.py"));
}

#[test]
fn go_value_facts_do_not_create_call_boundaries() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-go-value-facts",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "lib/flow.go",
                "package lib\ntype Flow struct { Name string }\n",
            ),
            (
                "main.go",
                "package main\nimport (\n\t\"sync\"\n\t\"example.com/app/lib\"\n)\nvar wg sync.WaitGroup\nvar packageFlow lib.Flow\nfunc makeFlow() lib.Flow { return lib.Flow{Name: \"made\"} }\nfunc main() { localFlow := lib.Flow{Name: \"x\"}; made := makeFlow(); _ = localFlow; _ = made; _ = wg; _ = packageFlow }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "main.go").expect("main entrypoint");
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .all(|boundary| boundary.reason == effinterp_proto::BoundaryReason::FRONTEND_PARTIAL),
        "non-call Go value facts created call boundaries: {:?}",
        report.payload.as_effects().unwrap().boundaries
    );
}

/// A `package main` entrypoint that calls `pkg` functions, so their effects
/// reach an analyzed forward surface.
fn go_pkg_caller(calls: &str) -> String {
    format!("package main\nimport \"example.com/app/pkg\"\nfunc main() {{ {calls} }}\n")
}

/// Rendered resources on the `cmd/app/main.go` forward surface.
fn go_caller_resources(index: &effinterp_repo::RepoIndex) -> Vec<String> {
    effects_of(index, "cmd/app/main.go")
        .expect("caller analyzed")
        .payload
        .into_effects()
        .unwrap()
        .effects
        .iter()
        .map(|effect| {
            format!(
                "{} {}",
                effect.operation.as_str(),
                effinterp_proto::display_resource(&effect.resource)
            )
        })
        .collect()
}

#[test]
fn go_named_results_and_switch_initializers_do_not_inherit_package_types() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-go-result-switch-shadow",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "pkg/a.go",
                "package pkg\nimport \"os\"\ntype Runner struct{}\nfunc (Runner) Wipe() { os.RemoveAll(\"/var/tmp/danger\") }\nvar runner = Runner{}\n",
            ),
            (
                "pkg/b.go",
                "package pkg\ntype Other struct{}\nfunc (Other) Wipe() {}\nfunc Named() (runner Other) { runner.Wipe(); return }\nfunc Switched() { switch runner := (Other{}); 1 { case 1: runner.Wipe() } }\n",
            ),
            (
                "cmd/app/main.go",
                go_pkg_caller("pkg.Named(); pkg.Switched()").as_str(),
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let resources = go_caller_resources(&index);
    assert!(
        resources
            .iter()
            .all(|resource| !resource.contains("/var/tmp/danger")),
        "a named result or switch initializer inherited a package variable type: {resources:?}"
    );
}

#[test]
fn go_package_bindings_are_typed_and_separated_by_import_path() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-go-scopes",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "one/root.go",
                "package one\nimport \"github.com/spf13/cobra\"\nvar rootCmd = &cobra.Command{}\nfunc Run() { rootCmd.Execute() }\n",
            ),
            (
                "two/root.go",
                "package two\nimport \"github.com/spf13/cobra\"\nvar rootCmd = &cobra.Command{}\nfunc Run() { rootCmd.Execute() }\n",
            ),
        ],
    );
    let (registry, _, _) = Registry::build(&root, &CrawlLimits::default());
    let binding = |file: &str| {
        registry.files[file]
            .summary
            .functions
            .iter()
            .find(|function| function.name == "Run")
            .and_then(|function| function.calls.iter().find_map(|edge| edge.receiver.clone()))
            .expect("rootCmd receiver")
    };
    let one = binding("one/root.go");
    let two = binding("two/root.go");
    assert!(matches!(
        &one.as_object().unwrap().identity,
        ObjectIdentity::ModuleBinding {
            scope: ScopeKey::GoPackage { key },
            name,
        } if key == "example.com/app/one" && name == "rootCmd"
    ));
    assert!(matches!(
        &one.evidence.ty,
        Some(TypeRef::External { path }) if path == "github.com/spf13/cobra.Command"
    ));
    assert!(matches!(
        &two.as_object().unwrap().identity,
        ObjectIdentity::ModuleBinding {
            scope: ScopeKey::GoPackage { key },
            name: _,
        } if key == "example.com/app/two"
    ));
    assert_ne!(one, two);
}

#[test]
fn go_package_initializers_and_every_init_run_without_sibling_main_or_tests() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-go-roots",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nfunc main() { finish() }\nfunc query() {}\n",
            ),
            (
                "vars.go",
                "package main\nimport \"os\"\nvar mode = os.Getenv(\"MODE\")\n",
            ),
            (
                "init.go",
                "package main\nimport \"os\"\nfunc init() { wipeOne() }\nfunc init() { os.RemoveAll(\"/direct-init\") }\nfunc init() { wipeTwo() }\n",
            ),
            (
                "effects.go",
                "package main\nimport \"os\"\nfunc wipeOne() { os.RemoveAll(\"/one\") }\nfunc wipeTwo() { os.RemoveAll(\"/two\") }\nfunc finish() { os.RemoveAll(\"/main-last\") }\n",
            ),
            (
                "other.go",
                "package main\nimport \"os\"\nfunc main() { os.RemoveAll(\"/sibling-main\") }\n",
            ),
            (
                "roots_test.go",
                "package main\nimport \"os\"\nfunc init() { os.RemoveAll(\"/test-init\") }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "main.go").expect("main entrypoint");
    let rows: Vec<_> = report
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .map(|effect| {
            (
                effect.operation.as_str(),
                effinterp_proto::display_resource_with_scope(&effect.resource),
            )
        })
        .collect();
    assert!(
        rows.iter()
            .any(|(op, resource)| { *op == "environment.read" && resource.contains("MODE") })
    );
    assert!(
        rows.iter()
            .any(|(op, resource)| { *op == "filesystem.delete" && resource.contains("/one") })
    );
    assert!(
        rows.iter()
            .any(|(op, resource)| { *op == "filesystem.delete" && resource.contains("/two") })
    );
    assert!(
        rows.iter().any(|(op, resource)| {
            *op == "filesystem.delete" && resource.contains("/direct-init")
        })
    );
    assert!(
        !rows
            .iter()
            .any(|(_, resource)| resource.contains("sibling-main"))
    );
    assert!(
        !rows
            .iter()
            .any(|(_, resource)| resource.contains("test-init"))
    );

    let init_functions: Vec<_> = index.registry.files["init.go"]
        .summary
        .module_calls
        .iter()
        .filter_map(|edge| match edge.origin_for_result(0) {
            Some(ValueOrigin::Site { function, .. }) => Some(function),
            _ => None,
        })
        .collect();
    assert!(init_functions.iter().any(|function| function == "init#0"));
    assert!(init_functions.iter().any(|function| function == "init#1"));
    assert!(init_functions.iter().any(|function| function == "init#2"));
    assert!(
        index.registry.files["main.go"]
            .summary
            .module_calls
            .is_empty()
    );
    assert!(
        !index.registry.files["main.go"]
            .summary
            .main_calls
            .is_empty()
    );
    assert!(
        index.registry.files["other.go"]
            .summary
            .module_calls
            .is_empty()
    );
}

#[test]
fn go_local_shadow_does_not_inherit_a_sibling_package_var_type() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-go-local-shadow",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "pkg/a.go",
                "package pkg\nimport \"os\"\ntype Runner struct{}\nfunc (Runner) Wipe() { os.RemoveAll(\"/var/tmp/danger\") }\nvar runner = Runner{}\n",
            ),
            (
                "pkg/b.go",
                "package pkg\ntype Other struct{}\nfunc (Other) Wipe() {}\nfunc Attach(values []Other) { for _, runner := range values { runner.Wipe() } }\n",
            ),
            ("cmd/app/main.go", go_pkg_caller("pkg.Attach(nil)").as_str()),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let resources = go_caller_resources(&index);
    assert!(
        resources
            .iter()
            .all(|resource| !resource.contains("/var/tmp/danger")),
        "local loop receiver inherited a sibling package binding: {resources:?}"
    );
}

#[test]
fn go_function_literal_parameter_does_not_inherit_a_package_var_type() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-go-literal-parameter-shadow",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "pkg/a.go",
                "package pkg\nimport \"os\"\ntype Runner struct{}\nfunc (Runner) Wipe() { os.RemoveAll(\"/var/tmp/danger\") }\nvar cmd = Runner{}\n",
            ),
            (
                "pkg/b.go",
                "package pkg\nimport \"github.com/spf13/cobra\"\nfunc Attach() {\nroot := &cobra.Command{RunE: func(cmd *cobra.Command, args []string) error { cmd.Wipe(); return nil }}\nroot.Execute()\n}\n",
            ),
            ("cmd/app/main.go", go_pkg_caller("pkg.Attach()").as_str()),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let resources = go_caller_resources(&index);
    assert!(
        resources
            .iter()
            .all(|resource| !resource.contains("/var/tmp/danger")),
        "function literal parameter inherited a package binding: {resources:?}"
    );
}

#[test]
fn go_package_type_refs_use_the_defining_sibling_file() {
    let defining_source = "package pkg\ntype Store struct{}\n";
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-go-sibling-type",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "pkg/attach.go",
                "package pkg\nvar store Store\nfunc Attach() { store.Wipe() }\n",
            ),
        ],
    );
    let (mut registry, _, _) = Registry::build(&root, &CrawlLimits::default());
    assert!(registry.apply_change("pkg/store.go", Some(defining_source)));
    std::fs::write(root.join("pkg/store.go"), defining_source).unwrap();
    let (clean, _, _) = Registry::build(&root, &CrawlLimits::default());
    for file in ["pkg/attach.go", "pkg/store.go"] {
        assert_eq!(
            registry.files[file].summary, clean.files[file].summary,
            "incremental Go type facts differ for {file}"
        );
    }
    let expected = TypeRef::Repo {
        file: "pkg/store.go".into(),
        name: "Store".into(),
    };
    let construction = registry.files["pkg/attach.go"]
        .summary
        .module_calls
        .iter()
        .find(|edge| edge.callee == "Store")
        .expect("Store declaration fact");
    assert_eq!(construction.result_type(), Some(&expected));
    let wipe = registry.files["pkg/attach.go"]
        .summary
        .functions
        .iter()
        .find(|function| function.name == "Attach")
        .expect("Attach function")
        .calls
        .iter()
        .find(|edge| edge.callee == "store.Wipe")
        .expect("store receiver edge");
    assert!(matches!(
        wipe.receiver.as_ref().and_then(|value| value.evidence.ty.as_ref()),
        Some(ty) if ty == &expected
    ));
}

#[test]
fn go_package_var_reindex_clears_removed_types_incrementally() {
    let original = "package pkg\nimport \"os\"\ntype Runner struct{}\nfunc (Runner) Wipe() { os.RemoveAll(\"/var/tmp/danger\") }\nvar runner Runner\n";
    let revised = "package pkg\nimport \"os\"\ntype Runner struct{}\nfunc (Runner) Wipe() { os.RemoveAll(\"/var/tmp/danger\") }\n";
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-go-clear-type",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            ("pkg/a.go", original),
            ("pkg/b.go", "package pkg\nfunc Attach() { runner.Wipe() }\n"),
        ],
    );
    let (mut incremental, _, _) = Registry::build(&root, &CrawlLimits::default());
    assert!(
        incremental.files["pkg/b.go"].summary.functions[0].calls[0]
            .receiver
            .as_ref()
            .and_then(|value| value.evidence.ty.as_ref())
            .is_some()
    );

    assert!(incremental.apply_change("pkg/a.go", Some(revised)));
    std::fs::write(root.join("pkg/a.go"), revised).unwrap();
    let (clean, _, _) = Registry::build(&root, &CrawlLimits::default());
    for file in ["pkg/a.go", "pkg/b.go"] {
        assert_eq!(
            incremental.files[file].summary, clean.files[file].summary,
            "incremental Go facts differ for {file}"
        );
    }
    assert!(
        incremental.files["pkg/b.go"].summary.functions[0].calls[0]
            .receiver
            .as_ref()
            .and_then(|value| value.evidence.ty.as_ref())
            .is_none()
    );
}

#[test]
fn go_construction_reindex_clears_removed_type_incrementally() {
    let original = "package main\ntype Config struct { Path string }\n";
    let revised = "package main\nimport \"os\"\nfunc Config(path string) string { os.RemoveAll(\"/etc/wiped\"); return path }\n";
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-go-clear-construction-type",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            ("types.go", original),
            (
                "main.go",
                "package main\nfunc main() { c := Config{Path: \"/var/data\"}; _ = c }\n",
            ),
        ],
    );
    let mut incremental = build_index(&root, IndexLimits::default());
    std::fs::write(root.join("types.go"), revised).unwrap();
    apply_changes(
        &mut incremental,
        &root,
        &IndexLimits::default(),
        &[RepoChange::Modified("types.go".into())],
    );
    let clean = build_index(&root, IndexLimits::default());

    assert_eq!(normalize_surface(&incremental), normalize_surface(&clean));
    assert_eq!(
        incremental.registry.files["main.go"].summary.main_calls[0].result_type(),
        None
    );
    let report = effects_of(&incremental, "main.go").expect("main entrypoint");
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect.operation.as_str() == "filesystem.delete"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        .contains("/etc/wiped")
            })
    );
}

#[test]
fn nested_go_module_uses_its_declared_import_path_scope() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-go-nested-module-scope",
        &[
            ("go.mod", "module example.com/root\n\ngo 1.21\n"),
            ("sub/go.mod", "module example.com/nested\n\ngo 1.21\n"),
            (
                "sub/root.go",
                "package main\nimport \"github.com/spf13/cobra\"\nvar rootCmd = &cobra.Command{}\nfunc main() { rootCmd.Execute() }\n",
            ),
        ],
    );
    let (registry, _, _) = Registry::build(&root, &CrawlLimits::default());
    let receiver = registry.files["sub/root.go"]
        .summary
        .main_calls
        .iter()
        .find_map(|edge| edge.receiver_identity())
        .expect("rootCmd receiver");
    assert!(matches!(
        receiver,
        ObjectIdentity::ModuleBinding {
            scope: ScopeKey::GoPackage { key },
            name,
        } if key == "example.com/nested" && name == "rootCmd"
    ));
}

#[test]
fn go_mod_apply_change_rescopes_unchanged_files() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-go-module-change",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "cmd/root.go",
                "package main\nimport \"github.com/spf13/cobra\"\nvar rootCmd = &cobra.Command{}\nfunc main() { rootCmd.Execute() }\n",
            ),
        ],
    );
    let (mut incremental, _, _) = Registry::build(&root, &CrawlLimits::default());
    let revised = "module example.com/renamed\n\ngo 1.21\n";
    std::fs::write(root.join("go.mod"), revised).unwrap();
    assert!(incremental.apply_change("go.mod", Some(revised)));
    let (clean, _, _) = Registry::build(&root, &CrawlLimits::default());

    assert_eq!(
        incremental.files["cmd/root.go"].summary,
        clean.files["cmd/root.go"].summary
    );
    let receiver = incremental.files["cmd/root.go"]
        .summary
        .main_calls
        .iter()
        .find_map(|edge| edge.receiver_identity())
        .expect("rootCmd receiver");
    assert!(matches!(
        receiver,
        ObjectIdentity::ModuleBinding {
            scope: ScopeKey::GoPackage { key },
            name: _,
        } if key == "example.com/renamed/cmd"
    ));
}

#[test]
fn duplicate_nested_go_module_path_does_not_shadow_the_importer_module() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-go-duplicate-module-path",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "cmd/main.go",
                "package main\nimport \"example.com/app/pkg\"\nfunc main() { pkg.Wipe() }\n",
            ),
            (
                "pkg/effect.go",
                "package pkg\nimport \"os\"\nfunc Wipe() { os.RemoveAll(\"/root-module\") }\n",
            ),
            ("fixtures/go.mod", "module example.com/app\n\ngo 1.21\n"),
            ("fixtures/placeholder.go", "package fixture\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "cmd/main.go").expect("main entrypoint");
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(
                |effect| effinterp_proto::display_resource_with_scope(&effect.resource)
                    .contains("/root-module")
            ),
        "nested duplicate module path shadowed the importer's module: {:?}",
        report.payload.as_effects().unwrap().boundaries
    );
}

#[test]
fn go_execution_roots_require_the_selected_package_clause() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-go-package-root-filter",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "//go:build linux\n\npackage main\nfunc main() {}\n",
            ),
            (
                "foreign.go",
                "//go:build windows\n\npackage foreign\nimport \"os\"\nfunc init() { os.RemoveAll(\"/foreign-root\") }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "main.go").expect("main entrypoint");
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .all(
                |effect| !effinterp_proto::display_resource_with_scope(&effect.resource)
                    .contains("/foreign-root")
            ),
        "foreign package initializer became an execution root: {:?}",
        report.payload.as_effects().unwrap().effects
    );
}

#[test]
fn go_block_local_shadow_does_not_hide_the_later_package_binding() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-go-block-shadow",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "pkg/a.go",
                "package pkg\nimport \"os\"\ntype Runner struct{}\nfunc (Runner) Wipe() { os.RemoveAll(\"/var/tmp/package-runner\") }\nvar runner = Runner{}\n",
            ),
            (
                "pkg/b.go",
                "package pkg\ntype Other struct{}\nfunc (Other) Wipe() {}\nfunc Attach() { { runner := Other{}; runner.Wipe() }; runner.Wipe() }\n",
            ),
            ("cmd/app/main.go", go_pkg_caller("pkg.Attach()").as_str()),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let resources = go_caller_resources(&index);
    assert!(
        resources
            .iter()
            .any(|resource| resource.contains("/var/tmp/package-runner")),
        "block-local receiver hid the later package binding: {resources:?}"
    );
}

#[test]
fn go_package_type_reindex_excludes_external_test_packages() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "effect-ir-go-test-package-types",
        &[
            ("go.mod", "module example.com/app\n\ngo 1.21\n"),
            (
                "pkg/prod.go",
                "package pkg\ntype Store struct{}\nvar store Store\nfunc Use() { store.Wipe() }\n",
            ),
            (
                "pkg/prod_test.go",
                "package pkg_test\nimport \"os\"\ntype Store struct{}\nfunc (Store) Wipe() { os.RemoveAll(\"/var/tmp/test-only\") }\n",
            ),
            ("cmd/app/main.go", go_pkg_caller("pkg.Use()").as_str()),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let receiver = index.registry.files["pkg/prod.go"]
        .summary
        .functions
        .iter()
        .find(|function| function.name == "Use")
        .expect("Use function")
        .calls
        .iter()
        .find(|edge| edge.callee == "store.Wipe")
        .and_then(|edge| edge.receiver.as_ref())
        .expect("store receiver");
    assert!(matches!(
        &receiver.evidence.ty,
        Some(TypeRef::Repo { file, name }) if file == "pkg/prod.go" && name == "Store"
    ));
    let resources = go_caller_resources(&index);
    assert!(
        resources
            .iter()
            .all(|resource| !resource.contains("/var/tmp/test-only")),
        "production dispatch entered an external test package: {resources:?}"
    );
}
