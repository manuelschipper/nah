//! Go cross-package composition: callback fields on struct literals (the cobra
//! shape), same-package sibling calls, and method dispatch through
//! constructor-typed receivers. Negatives pin the soundness edges: a callback
//! that never escapes must not execute, and an ambiguously constructed
//! interface value must never dispatch to a guessed implementation.
#![allow(clippy::disallowed_methods)]

use effinterp_engine::Assurance;
use effinterp_proto::ResourceExpr;
use effinterp_repo::{
    IndexLimits, ResourceSelector, build_index, effective_surface, effects_of, reach,
};
use effinterp_testkit::repo_fixture::repo_test_fixture;

use crate::support::antecedent_origins;

// A function-valued field on a struct that never escapes (never passed,
// returned, or dispatched on) must not execute.

/// Every occurrence a fact's roots derive from, walking the envelope graph
/// backwards the way explanation does.
#[test]
fn stored_function_field_does_not_execute_by_source_presence() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-unregistered-callback",
        &[
            ("go.mod", "module ex.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport \"ex.com/app/lib\"\nfunc main() {\n\tlib.Setup()\n}\n",
            ),
            (
                "lib/lib.go",
                "package lib\nimport \"os\"\ntype H struct {\n\tOnRun func()\n}\nfunc Setup() {\n\th := &H{OnRun: wipeAll}\n\t_ = h\n}\nfunc wipeAll() {\n\tos.RemoveAll(\"/never\")\n}\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(&idx, &ResourceSelector::parse("fs:/never").unwrap(), None);
    assert!(
        !report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|h| h.fact.entrypoint == "main.go"),
        "a never-dispatched callback field must not execute: {:?}",
        report.payload.as_reach().unwrap().matches
    );
}

#[test]
fn computed_channel_binding_stays_unresolved_in_repository() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-computed-channel",
        &[
            ("go.mod", "module ex.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc makePaths() chan string { paths := make(chan string, 2); paths <- \"/first\"; return paths }\nfunc main() { paths := makePaths(); paths <- \"/local\"; path := <-paths; os.Remove(path) }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let surface = effective_surface(&index, "main.go").unwrap();
    assert!(
        surface.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && matches!(
                    &effect.resource_expr,
                    ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                )
        }),
        "computed channel binding must remain unresolved: {:?}",
        surface.effects
    );
}

#[test]
fn parameter_channel_receiver_stays_unresolved_in_repository() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-parameter-channel",
        &[
            ("go.mod", "module ex.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport \"ex.com/app/lib\"\nfunc main() { paths := make(chan string, 2); paths <- \"/from-main\"; lib.Consume(paths) }\n",
            ),
            (
                "lib/lib.go",
                "package lib\nimport \"os\"\nfunc Consume(paths chan string) { paths <- \"/local\"; path := <-paths; os.Remove(path) }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let surface = effective_surface(&index, "main.go").unwrap();
    assert!(
        surface.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && matches!(
                    &effect.resource_expr,
                    ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                )
        }),
        "a parameter channel receiver must remain unresolved: {:?}",
        surface.effects
    );
}

#[test]
fn range_and_multi_value_rebindings_stay_unresolved_in_repository() {
    for (tag, main) in [
        (
            "go-range-rebinding",
            "package main\nimport \"os\"\nfunc main() { paths := make(chan string, 1); paths <- \"/stale\"; path := <-paths; for path = range os.Args { os.Remove(path) } }\n",
        ),
        (
            "go-multi-value-rebinding",
            "package main\nimport \"os\"\nfunc lookup() (bool, string) { return true, os.Getenv(\"PATH\") }\nfunc main() { paths := make(chan string, 1); paths <- \"/stale\"; path := <-paths; var ok bool; ok, path = lookup(); _ = ok; os.Remove(path) }\n",
        ),
    ] {
        let root = repo_test_fixture(
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
            tag,
            &[
                ("go.mod", "module ex.com/app\n\ngo 1.21\n"),
                ("main.go", main),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let surface = effective_surface(&index, "main.go").unwrap();
        let deletes: Vec<_> = surface
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "filesystem.delete")
            .collect();
        assert!(
            !deletes.is_empty()
                && deletes.iter().all(|effect| matches!(
                    &effect.resource_expr,
                    ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                )),
            "a rebound value must remain unresolved after composition: {:?}",
            surface.effects
        );
    }
}

#[test]
fn same_name_channel_alias_stays_unresolved_in_repository() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-same-name-channel-alias",
        &[
            ("go.mod", "module ex.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc run() { paths := make(chan string, 2); paths <- \"/local\"; for i := 0; i < 1; i++ { paths := paths; go func() { paths <- \"/other\" }() }; path := <-paths; os.Remove(path) }\nfunc main() { run() }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let surface = effective_surface(&index, "main.go").unwrap();
    assert!(surface.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && matches!(
                &effect.resource_expr,
                ResourceExpr::Unresolved { family } if family.0 == "filesystem"
            )
    }));
}

/// A method call on a variable typed by an unambiguous constructor dispatches
/// into the method — even when the type and method live in a different file of
/// the constructor's package.
#[test]
fn constructor_typed_receiver_dispatches_across_packages() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-recv-dispatch",
        &[
            ("go.mod", "module ex.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport \"ex.com/app/store\"\nfunc main() {\n\ts := store.NewStore()\n\ts.Purge()\n}\n",
            ),
            (
                "store/store.go",
                "package store\nfunc NewStore() *diskStore {\n\treturn &diskStore{}\n}\n",
            ),
            (
                "store/disk.go",
                "package store\nimport \"os\"\ntype diskStore struct{}\nfunc (d *diskStore) Purge() {\n\tos.RemoveAll(\"/data/cache\")\n}\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(
        &idx,
        &ResourceSelector::parse("fs:/data/cache").unwrap(),
        None,
    );
    let hit = report
        .payload
        .as_reach()
        .unwrap()
        .matches
        .iter()
        .find(|h| {
            h.fact.entrypoint == "main.go" && h.fact.operation.as_str() == "filesystem.delete"
        })
        .expect("constructor-typed receiver dispatches into the method");
    assert!(
        antecedent_origins(&report.provenance, &hit.fact.provenance_roots)
            .iter()
            .any(|origin| origin.contains("store/disk.go")),
        "provenance reaches the method's file: {:?}",
        report.provenance
    );
}

/// An interface value whose constructor returns different implementations on
/// different paths is ambiguous: neither candidate's method may be guessed.
#[test]
fn ambiguous_interface_value_never_dispatches() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-iface-ambiguous",
        &[
            ("go.mod", "module ex.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport \"ex.com/app/impls\"\nfunc main() {\n\tx := impls.Pick(true)\n\tx.Do()\n}\n",
            ),
            (
                "impls/impls.go",
                "package impls\nimport \"os\"\ntype Doer interface {\n\tDo()\n}\ntype A struct{}\nfunc (a *A) Do() {\n\tos.RemoveAll(\"/from-a\")\n}\ntype B struct{}\nfunc (b *B) Do() {\n\tos.RemoveAll(\"/from-b\")\n}\nfunc Pick(flag bool) Doer {\n\tif flag {\n\t\treturn &A{}\n\t}\n\treturn &B{}\n}\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    for path in ["fs:/from-a", "fs:/from-b"] {
        let report = reach(&idx, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            !report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .any(|h| h.fact.entrypoint == "main.go"),
            "ambiguous dispatch must not guess an implementation ({path}): {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }
}

#[test]
fn interface_candidate_sets_preserve_cardinality_and_cap() {
    let source = |implementations: usize| {
        let mut source =
            String::from("package main\nimport \"os\"\ntype Doer interface { Do() }\n");
        for index in 0..implementations {
            source.push_str(&format!(
                "type T{index} struct{{}}\nfunc (v *T{index}) Do() {{ os.RemoveAll(\"/go-{index}\") }}\n"
            ));
        }
        source.push_str("func main() { var value Doer; value.Do() }\n");
        source
    };

    let one = source(1);
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-interface-one",
        &[("go.mod", "module ex.com/app\n"), ("main.go", &one)],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("main.go").unwrap();
    assert_eq!(composition.effects.len(), 1);
    assert_eq!(
        composition.occurrence_effects[0].assurance,
        Assurance::Heuristic
    );

    let two = source(2);
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-interface-two",
        &[("go.mod", "module ex.com/app\n"), ("main.go", &two)],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("main.go").unwrap();
    let report = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let resources: Vec<_> = report
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    assert_eq!(resources, ["fs:/go-0", "fs:/go-1"]);
    assert!(
        composition
            .occurrence_effects
            .iter()
            .all(|effect| effect.assurance == Assurance::Alternatives)
    );
    assert!(
        effective_surface(&index, "main.go")
            .unwrap()
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "unresolved_interface")
    );

    let five = source(5);
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-interface-cap",
        &[("go.mod", "module ex.com/app\n"), ("main.go", &five)],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("main.go").unwrap();
    assert!(composition.effects.is_empty());
    assert!(composition.boundaries.iter().any(|boundary| {
        boundary.reason == "dynamic_dispatch"
            && boundary.detail.contains("interface Doer")
            && boundary.detail.contains("5 typed candidates")
    }));
}

#[test]
fn interface_candidates_require_matching_method_signatures() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-interface-signatures",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\ntype Doer interface { Do(path string) }\ntype Right struct{}\nfunc (v *Right) Do(path string) { os.RemoveAll(\"/go-right\") }\ntype WrongArity struct{}\nfunc (v *WrongArity) Do(path string, force bool) { os.RemoveAll(\"/go-wrong-arity\") }\ntype WrongType struct{}\nfunc (v *WrongType) Do(path int) { os.RemoveAll(\"/go-wrong-type\") }\nfunc main() { var value Doer; value.Do(\"/ignored\") }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("main.go").unwrap();
    let report = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let resources: Vec<_> = report
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    assert_eq!(resources, ["fs:/go-right"]);
    assert_eq!(
        composition.occurrence_effects[0].assurance,
        Assurance::Heuristic
    );
}

#[test]
fn interface_candidates_resolve_package_type_aliases() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-interface-signature-aliases",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\ntype Doer interface { Do(handler func(int) error) }\nfunc main() { var value Doer; value.Do(nil) }\n",
            ),
            ("alias.go", "package main\ntype Handler = func(int) error\n"),
            (
                "aliased.go",
                "package main\nimport \"os\"\ntype Aliased struct{}\nfunc (v *Aliased) Do(handler Handler) { os.RemoveAll(\"/go-aliased\") }\n",
            ),
            (
                "plain.go",
                "package main\nimport \"os\"\ntype Plain struct{}\nfunc (v *Plain) Do(handler func(int) error) { os.RemoveAll(\"/go-plain\") }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("main.go").unwrap();
    let report = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let resources: Vec<_> = report
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    assert_eq!(resources, ["fs:/go-aliased", "fs:/go-plain"]);
    assert!(
        composition
            .occurrence_effects
            .iter()
            .all(|effect| effect.assurance == Assurance::Alternatives)
    );
}

#[test]
fn declared_interface_type_survives_factory_binding() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-interface-factory-binding",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\ntype Speaker interface { Speak() }\ntype A struct{}\nfunc (a *A) Speak() { os.RemoveAll(\"/go-factory-a\") }\ntype B struct{}\nfunc (b *B) Speak() { os.RemoveAll(\"/go-factory-b\") }\nfunc pick() Speaker { return nil }\nfunc main() { var value Speaker = pick(); value.Speak() }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("main.go").unwrap();
    let resources: Vec<_> = composition
        .effects
        .iter()
        .map(|effect| effect.effect.resource.clone())
        .collect();
    assert_eq!(resources.len(), 2);
    assert!(
        composition
            .occurrence_effects
            .iter()
            .all(|effect| effect.assurance == Assurance::Alternatives)
    );
    assert!(
        effective_surface(&index, "main.go")
            .unwrap()
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "unresolved_interface")
    );
}

/// A closure bound to a local (`dial := func() {...}; dial()`) carries its
/// cross-package calls into composition (the grpcurl shape).
#[test]
fn closure_bound_local_composes_cross_package_call() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-closure-dial",
        &[
            ("go.mod", "module ex.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport \"ex.com/app/netx\"\nfunc main() {\n\tdial := func() {\n\t\tnetx.Open(\"db.internal:6379\")\n\t}\n\tdial()\n}\n",
            ),
            (
                "netx/netx.go",
                "package netx\nimport \"net\"\nfunc Open(addr string) {\n\tnet.Dial(\"tcp\", addr)\n}\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let comp = idx.composition("main.go").expect("main.go composes");
    assert!(
        comp.effects.iter().any(|e| {
            e.effect.operation.0 == "network.connect"
                && comp.occurrence_effects.iter().any(|occurrence| {
                    comp.effects[occurrence.effect].effect.id == e.effect.id
                        && occurrence.source_file == "netx/netx.go"
                })
        }),
        "closure's cross-package dial composes: {:?}",
        comp.effects
            .iter()
            .map(|e| &e.effect.operation.0)
            .collect::<Vec<_>>()
    );
}

/// A method on a parameter whose declared type is an imported named type
/// (`opts *global.Options`) dispatches into that type's method — the restic
/// `AddFlags` shape. No constructor return is required.
#[test]
fn declared_type_parameter_dispatches_across_packages() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-decl-type-dispatch",
        &[
            ("go.mod", "module ex.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport (\n\t\"ex.com/app/cli\"\n\t\"ex.com/app/global\"\n)\nfunc main() {\n\topts := global.Options{}\n\tcmd := cli.New(&opts)\n\tcmd.Execute()\n}\n",
            ),
            (
                "cli/root.go",
                "package cli\nimport \"ex.com/app/global\"\ntype Command struct {\n\tRun func()\n}\nfunc New(opts *global.Options) *Command {\n\tc := &Command{}\n\topts.AddFlags()\n\treturn c\n}\n",
            ),
            (
                "global/global.go",
                "package global\nimport \"os\"\ntype Options struct{}\nfunc (o *Options) AddFlags() {\n\t_ = os.Getenv(\"RESTIC_REPOSITORY\")\n}\n",
            ),
        ],
    );
    let idx = build_index(&root, IndexLimits::default());
    let report = reach(
        &idx,
        &ResourceSelector::parse("env:RESTIC_REPOSITORY").unwrap(),
        None,
    );
    let hit = report
        .payload
        .as_reach()
        .unwrap()
        .matches
        .iter()
        .find(|h| h.fact.entrypoint == "main.go" && h.fact.operation.as_str() == "environment.read")
        .expect("declared *global.Options parameter dispatches AddFlags");
    assert!(
        antecedent_origins(&report.provenance, &hit.fact.provenance_roots)
            .iter()
            .any(|origin| origin.contains("global/global.go")),
        "provenance reaches AddFlags: {:?}",
        report.provenance
    );
}

#[test]
fn generic_constraint_dispatch_requires_the_interface_signature() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-generic-interface-signature",
        &[
            ("go.mod", "module ex.com/app\n\ngo 1.21\n"),
            (
                "main.go",
                "package main\nimport \"ex.com/app/lib\"\nfunc main() { lib.Run[lib.Right](lib.Right{}) }\n",
            ),
            (
                "lib/contract.go",
                "package lib\ntype Doer interface { Do(path string) }\nfunc Run[T Doer](value T) { value.Do(\"/ignored\") }\n",
            ),
            (
                "lib/right.go",
                "package lib\nimport \"os\"\ntype Right struct{}\nfunc (Right) Do(path string) { os.RemoveAll(\"/go-generic-right\") }\n",
            ),
            (
                "lib/wrong.go",
                "package lib\nimport \"os\"\ntype Wrong struct{}\nfunc (Wrong) Do(path int) { os.RemoveAll(\"/go-generic-wrong\") }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    assert_eq!(deletes, ["fs:/go-generic-right"]);
}

#[test]
fn a_reassigned_package_variable_is_never_an_exact_package_value() {
    // A package variable's published value is only its declaration: any file
    // of the package may assign it before the entrypoint reads it, so the
    // initializer is not the package's value and must not be substituted.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-reassigned-package-var",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc main() { os.RemoveAll(target) }\n",
            ),
            (
                "vars.go",
                "package main\nvar target = \"/initial\"\nfunc init() { target = \"/changed\" }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 1, "{:?}", effects.effects);
    assert!(
        matches!(
            &deletes[0].resource,
            ResourceExpr::Unresolved { .. } | ResourceExpr::Parameter { .. }
        ),
        "{:?}",
        deletes[0]
    );
    // Neither value may be answered exactly, and neither may be excluded: the
    // unresolved deletion matches both paths symbolically.
    for path in ["fs:/initial", "fs:/changed"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            !report.payload.as_reach().unwrap().matches.is_empty()
                || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative"
        );
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
            "{path} must not be claimed concretely: {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }
}

#[test]
fn a_reassigned_package_callable_dispatches_to_no_guessed_target() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-reassigned-package-callable",
        &[
            ("go.mod", "module ex.com/app\n"),
            ("main.go", "package main\nfunc main() { hook() }\n"),
            (
                "vars.go",
                "package main\nimport \"os\"\nvar hook = safeHook\nfunc init() { hook = dangerHook }\nfunc safeHook() { os.RemoveAll(\"/safe\") }\nfunc dangerHook() { os.RemoveAll(\"/danger\") }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !effects
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"),
        "neither alternative may be claimed exactly: {:?}",
        effects.effects
    );
    assert!(
        effects
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "dynamic_dispatch"),
        "{:?}",
        effects.boundaries
    );
    for path in ["fs:/safe", "fs:/danger"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            report.payload.as_reach().unwrap().matches.is_empty(),
            "{path}: {:?}",
            report.payload.as_reach().unwrap().matches
        );
        assert!(
            !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative"
        );
    }
}

#[test]
fn a_package_variable_reassigned_anywhere_is_not_exact_in_its_declaring_file() {
    // The declaration and the read live in the entrypoint file, so the
    // single-file plan is the only view that answers this call. A sibling file
    // assigns the name, so the initializer is not the value the call reads;
    // a variable no file assigns stays exact.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-reassigned-package-var-declaring-file",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nvar target = \"/exact\"\nvar keep = \"/keep\"\nfunc main() { os.RemoveAll(target); os.RemoveAll(keep) }\n",
            ),
            (
                "other.go",
                "package main\nfunc reset() { target = \"/other\" }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !effects.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path },
                    ..
                } if path == "/exact")
        }),
        "the reassigned variable must not be claimed exactly: {:?}",
        effects.effects
    );
    assert!(
        effects.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path },
                    ..
                } if path == "/keep")
        }),
        "a variable no file assigns stays exact: {:?}",
        effects.effects
    );
    for path in ["fs:/exact", "fs:/other"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            !report.payload.as_reach().unwrap().matches.is_empty()
                || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative"
        );
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
            "{path} must not be claimed concretely: {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }
}

#[test]
fn a_package_variable_reassigned_in_its_own_file_is_not_exact() {
    // Same file for the declaration, the assignment, and the read: the plan
    // sees the whole package here and still may not publish the initializer.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-reassigned-package-var-same-file",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nvar target = \"/exact\"\nfunc reset() { target = \"/other\" }\nfunc main() { reset(); os.RemoveAll(target) }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !effects.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Concrete { .. })
        }),
        "neither value may be claimed exactly: {:?}",
        effects.effects
    );
    for path in ["fs:/exact", "fs:/other"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            !report.payload.as_reach().unwrap().matches.is_empty()
                || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative"
        );
    }
}

#[test]
fn a_package_callable_reassigned_by_a_sibling_file_is_not_entered_from_its_declaration() {
    // The callable variable, its initializer's target, and the call all sit in
    // the entrypoint file; a sibling init() assigns another function to it.
    // Entering the declared target would attribute the wrong function's
    // effects with exact assurance.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-reassigned-package-callable-declaring-file",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nvar hook = safeHook\nfunc safeHook() { os.RemoveAll(\"/safe\") }\nfunc main() { hook() }\n",
            ),
            (
                "setup.go",
                "package main\nimport \"os\"\nfunc init() { hook = dangerHook }\nfunc dangerHook() { os.RemoveAll(\"/danger\") }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !effects
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"),
        "neither alternative may be claimed exactly: {:?}",
        effects.effects
    );
    assert!(
        effects
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "dynamic_dispatch"),
        "{:?}",
        effects.boundaries
    );
    for path in ["fs:/safe", "fs:/danger"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            report.payload.as_reach().unwrap().matches.is_empty(),
            "{path}: {:?}",
            report.payload.as_reach().unwrap().matches
        );
        assert!(
            !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative"
        );
    }
}

#[test]
fn package_values_resolve_only_from_selected_build_files() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-package-values-build-selection",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport (\n    \"net\"\n    \"os\"\n)\nfunc main() { net.Listen(listenNetwork, listenAddress); os.RemoveAll(deleteTarget) }\n",
            ),
            (
                "values_selected.go",
                "//go:build gc\n\npackage main\nconst listenNetwork = \"unix\"\nconst listenAddress = \"/tmp/selected.sock\"\nconst deleteTarget = \"/tmp/selected\"\n",
            ),
            (
                "values_excluded.go",
                "/* Copyright */\n//go:build gccgo\n\npackage main\nconst listenNetwork = \"tcp\"\nconst listenAddress = \"wrong.example:9000\"\nconst deleteTarget = \"/wrong\"\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(!index.registry.files.contains_key("values_excluded.go"));
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let listeners: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "network.listen")
        .collect();
    assert_eq!(listeners.len(), 1, "{:?}", effects.effects);
    assert!(listeners.iter().any(|effect| {
        effect.operation.as_str() == "network.listen"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::NetworkEndpoint {
                        host,
                        scheme: Some(scheme),
                        ..
                    }
                } if host == "/tmp/selected.sock" && scheme == "unix"
            )
    }));
    let deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 1, "{:?}", effects.effects);
    assert_eq!(
        effinterp_proto::display_resource_with_scope(&deletes[0].resource),
        "fs:/tmp/selected"
    );
    assert!(effects.effects.iter().all(|effect| {
        !matches!(effect.resource, ResourceExpr::Unresolved { .. })
            && !matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::NetworkEndpoint { host, .. }
                } if host == "wrong.example"
            )
    }));
    let unrelated = reach(
        &index,
        &ResourceSelector::parse("net:other.example").unwrap(),
        None,
    );
    assert!(unrelated.payload.as_reach().unwrap().matches.is_empty());
}

#[test]
fn direct_process_effects_are_not_recomposed_or_retyped() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-direct-process-effect",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os/exec\"\nfunc main() { exec.Command(\"rm\", \"-rf\", \"/data\").Run() }\n",
            ),
        ],
    );
    let effects = effects_of(&build_index(&root, IndexLimits::default()), "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let processes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "process.exec")
        .collect();
    assert_eq!(processes.len(), 1, "{:?}", effects.effects);
    assert!(matches!(
        &processes[0].resource,
        ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::Process { argv, .. }
        } if matches!(
            argv.as_slice(),
            [
                ResourceExpr::Literal { value: flag },
                ResourceExpr::Literal { value: path }
            ] if flag == "-rf" && path == "/data"
        )
    ));
}

#[test]
fn resolved_root_effect_does_not_hide_an_unresolved_occurrence() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-root-unresolved-occurrence",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc main() { os.WriteFile(\"/tmp/known\", nil, 0); os.CreateTemp(\"\", \"x\") }\n",
            ),
        ],
    );
    let effects = effects_of(&build_index(&root, IndexLimits::default()), "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let writes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.write")
        .collect();
    assert_eq!(writes.len(), 2, "{:?}", effects.effects);
    assert!(writes.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath { path }
        } if path == "/tmp/known"
    )));
    assert!(writes.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Unresolved { family } if family.0 == "filesystem"
    )));
}

#[test]
fn callback_handed_to_an_inert_stdlib_call_keeps_its_effects() {
    // `sync` and `sort` are classified effect-free, so nothing else reports
    // them: if the callback they run is dropped, the repository answers a
    // deletion that really happens with a precise negative.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-inert-stdlib-callback",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport (\n\t\"os\"\n\t\"sort\"\n\t\"sync\"\n)\nvar once sync.Once\nvar items []int\nfunc less(i, j int) bool {\n\tos.RemoveAll(\"/sorted\")\n\treturn i < j\n}\nfunc main() {\n\tonce.Do(func() { os.RemoveAll(\"/once\") })\n\tsort.Slice(items, less)\n}\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    for path in ["/once", "/sorted"] {
        assert!(
            effects.effects.iter().any(|effect| {
                effect.operation.as_str() == "filesystem.delete"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        == format!("fs:{path}")
            }),
            "{path} missing from {:?}",
            effects.effects
        );
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
                .any(|hit| hit.fact.entrypoint == "main.go"),
            "{path} unreachable: {:?}",
            report.payload
        );
    }
}

#[test]
fn callback_handed_to_a_late_added_stdlib_invoker_keeps_its_effects() {
    // `slices.CompareFunc` and `runtime.AddCleanup` invoke the callable they
    // are handed just as `sort.Slice` does, and a Go package spans its whole
    // directory, so the callback may be declared in a sibling file: while the
    // entry points were missing from the callback-position table, and while a
    // sibling callback resolved to nothing, the repository answered effects
    // that really happen with a precise negative.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-late-stdlib-callback",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport (\n\t\"runtime\"\n\t\"slices\"\n)\nfunc main() {\n\tslices.CompareFunc([]int{1}, []int{2}, compare)\n\tt := 1\n\truntime.AddCleanup(&t, cleanup, 1)\n}\n",
            ),
            (
                "hooks.go",
                "package main\nimport \"os\"\nfunc compare(a, b int) int {\n\tos.RemoveAll(\"/compared\")\n\treturn a - b\n}\nfunc cleanup(x int) { os.RemoveAll(\"/cleaned\") }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    for path in ["/compared", "/cleaned"] {
        assert!(
            effects.effects.iter().any(|effect| {
                effect.operation.as_str() == "filesystem.delete"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        == format!("fs:{path}")
            }),
            "{path} missing from {:?}",
            effects.effects
        );
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
                .any(|hit| hit.fact.entrypoint == "main.go"),
            "{path} unreachable: {:?}",
            report.payload
        );
    }
}

#[test]
fn stdlib_flag_constants_raise_no_boundary_at_repository_scope() {
    // `os.O_RDONLY` and friends are exact inert values: modeling them as calls
    // made every domain partial and produced all-domain unmodeled boundaries
    // from both the plan and composition.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-stdlib-flag-constants",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc main() {\n\tos.OpenFile(logPath, os.O_APPEND|os.O_CREATE, 0644)\n\tos.OpenFile(logPath, os.O_RDONLY, 0644)\n}\n",
            ),
            (
                "values.go",
                "package main\n\nconst logPath = \"/var/log/app.log\"\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects
            .effects
            .iter()
            .any(
                |effect| effinterp_proto::display_resource_with_scope(&effect.resource)
                    == "fs:/var/log/app.log"
            ),
        "{:?}",
        effects.effects
    );
    assert!(
        effects
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() == "frontend_partial"),
        "{:?}",
        effects.boundaries
    );
}

#[test]
fn function_value_passed_as_data_reaches_nothing() {
    // A function value handed to a call that never invokes it is data; a
    // guessed firing would make `reach` answer a match that cannot happen.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-function-value-as-data",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport (\n\t\"fmt\"\n\t\"os\"\n)\nfunc cleanup() { os.RemoveAll(\"/data\") }\nfunc main() { fmt.Println(cleanup) }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !effects
            .effects
            .iter()
            .any(
                |effect| effinterp_proto::display_resource_with_scope(&effect.resource)
                    == "fs:/data"
            ),
        "{:?}",
        effects.effects
    );
    let report = reach(&index, &ResourceSelector::parse("fs:/data").unwrap(), None);
    assert!(
        report.payload.as_reach().unwrap().matches.is_empty(),
        "{:?}",
        report.payload
    );
}

#[test]
fn goos_named_file_without_separator_is_selected() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-bare-goos-filename",
        &[
            ("go.mod", "module ex.com/app\n"),
            ("main.go", "package main\nfunc main() { Wipe() }\n"),
            (
                "windows.go",
                "package main\nimport \"os\"\nfunc Wipe() { os.RemoveAll(\"/probe-target\") }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.registry.files.contains_key("windows.go"));
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(effects.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.delete"
            && effinterp_proto::display_resource_with_scope(&effect.resource) == "fs:/probe-target"
    }));
}

#[test]
fn exact_callable_values_flow_through_assignments_parameters_returns_and_fields() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-callable-value-flow",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                r#"package main
import "os"
type Hooks struct { Run func() }
func first() { os.RemoveAll("/from-assignment") }
func second() { os.RemoveAll("/from-return") }
func third() { os.RemoveAll("/from-field") }
func fourth() { os.RemoveAll("/from-field-assignment") }
func invoke(fn func()) { fn() }
func identity(fn func()) func() { return fn }
func main() {
    assigned := first
    invoke(assigned)
    invoke(packageHandler)
    returned := identity(second)
    returned()
    hooks := Hooks{Run: third}
    hooks.Run()
    hooks.Run = fourth
    hooks.Run()
    worker := Worker{}
    method := worker.Remove
    invoke(method)
}
"#,
            ),
            (
                "handlers.go",
                r#"package main
import "os"
var packageHandler = packageFunction
func packageFunction() { os.RemoveAll("/from-package-value") }
type Worker struct{}
func (Worker) Remove() { os.RemoveAll("/from-method") }
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let resources: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    assert!(
        resources
            .iter()
            .any(|resource| resource == "fs:/from-assignment")
    );
    assert!(
        resources
            .iter()
            .any(|resource| resource == "fs:/from-package-value")
    );
    assert!(
        resources
            .iter()
            .any(|resource| resource == "fs:/from-return")
    );
    assert!(
        resources
            .iter()
            .any(|resource| resource == "fs:/from-field")
    );
    assert!(
        resources
            .iter()
            .any(|resource| resource == "fs:/from-field-assignment"),
        "{resources:?}"
    );
    assert!(
        resources
            .iter()
            .any(|resource| resource == "fs:/from-method"),
        "{resources:?}"
    );
}

#[test]
fn ambiguous_callable_rebinding_is_explicit_and_never_guessed() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-ambiguous-callable",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc left() { os.RemoveAll(\"/left\") }\nfunc right() { os.RemoveAll(\"/right\") }\nfunc main() { fn := left; if os.Getenv(\"SIDE\") != \"\" { fn = right }; fn() }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("main.go").unwrap();
    assert!(composition.effects.iter().all(|effect| {
        !matches!(
            &effect.effect.resource,
            ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath { path }
            } if matches!(path.as_str(), "/left" | "/right")
        )
    }));
    assert!(
        composition
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "dynamic_dispatch")
    );
}

#[test]
fn escaped_callables_and_same_named_apis_do_not_guess_effects() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-escaped-callable",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                r#"package main
import (
    "os"
    escape "example.com/escape"
    transport "example.com/net"
)
func wipe() { os.RemoveAll("/escaped") }
func main() {
    escape.Store(wipe)
    transport.Listen("unix", "/tmp/not-a-listener.sock")
}
"#,
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("main.go").unwrap();
    assert!(composition.effects.iter().all(|effect| {
        effect.effect.operation.0 != "network.listen"
            && !matches!(
                &effect.effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path }
                } if path == "/escaped"
            )
    }));
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "escaped_callable")
    );
}

#[test]
fn ordinary_struct_fields_do_not_escape_as_callables() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-plain-struct-field",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\ntype Config struct { Path string }\nfunc main() { c := Config{Path: \"/tmp/x\"}; show(c.Path) }\n",
            ),
            (
                "show.go",
                "package main\nimport \"fmt\"\nfunc show(value string) { fmt.Println(value) }\n",
            ),
        ],
    );
    let effects = effects_of(&build_index(&root, IndexLimits::default()), "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "escaped_callable")
    );
}

#[test]
fn exact_inert_stdlib_function_values_stay_domain_free() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-inert-function-value",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"strings\"\nfunc invoke(fn func(string) string) { _ = fn(\" value \") }\nfunc main() { invoke(strings.TrimSpace) }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("main.go").unwrap();
    assert!(composition.effects.is_empty());
    assert!(
        composition
            .boundaries
            .iter()
            .all(|boundary| boundary.domains.is_empty())
    );
}

#[test]
fn callbacks_composition_resolves_are_not_escaped_callables() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-resolved-callback",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc cleanup() { os.RemoveAll(\"/cb\") }\nfunc main() { run(cleanup) }\n",
            ),
            ("run.go", "package main\nfunc run(f func()) { f() }\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource_with_scope(&effect.resource) == "fs:/cb"),
        "{:?}",
        effects.effects
    );
    assert!(
        effects
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "escaped_callable"),
        "{:?}",
        effects.boundaries
    );
    let unrelated = reach(
        &index,
        &ResourceSelector::parse("fs:/etc/shadow").unwrap(),
        None,
    );
    assert!(unrelated.payload.as_reach().unwrap().matches.is_empty());
    assert!(
        unrelated
            .payload
            .as_reach()
            .unwrap()
            .indeterminate
            .iter()
            .filter_map(|row| match row {
                effinterp_proto::Indeterminate::Boundary { evidence } => Some(evidence),
                _ => None,
            })
            .all(|row| row.boundary_reason.as_str() == "frontend_partial"),
        "{:?}",
        unrelated.payload.as_reach().unwrap().indeterminate
    );
}

#[test]
fn cgo_build_variants_select_the_cgo_file() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-cgo-build-variants",
        &[
            ("go.mod", "module ex.com/app\n"),
            ("main.go", "package main\nfunc main() { Wipe() }\n"),
            (
                "impl_cgo.go",
                "//go:build cgo\n\npackage main\nimport \"os\"\nfunc Wipe() { os.RemoveAll(\"/cgo-path\") }\n",
            ),
            (
                "impl_nocgo.go",
                "//go:build !cgo\n\npackage main\nimport \"os\"\nfunc Wipe() { os.RemoveAll(\"/nocgo-path\") }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(index.registry.files.contains_key("impl_cgo.go"));
    assert!(!index.registry.files.contains_key("impl_nocgo.go"));
    let deletes: Vec<_> = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap()
        .effects
        .into_iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    assert_eq!(deletes, ["fs:/cgo-path"]);
}

/// Resolving `main`'s package constant explains one plan unknown — the one
/// `main` itself raised. An identical unknown from `init` is a different
/// conclusion and must stay on the surface.
#[test]
fn package_value_resolution_keeps_an_unknown_raised_outside_main() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-init-unknown-survives",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc init() { os.RemoveAll(os.Getenv(\"JUNK\")) }\nfunc main() { os.RemoveAll(target) }\n",
            ),
            ("const.go", "package main\nconst target = \"/data\"\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 2, "{:?}", effects.effects);
    assert!(deletes.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath { path }
        } if path == "/data"
    )));
    assert!(deletes.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Unresolved { family } if family.0 == "filesystem"
    )));
    // The surviving unknown must keep an unrelated path answerable.
    let unrelated = reach(&index, &ResourceSelector::parse("fs:/other").unwrap(), None);
    assert!(
        !unrelated.payload.as_reach().unwrap().matches.is_empty()
            || !unrelated
                .payload
                .as_reach()
                .unwrap()
                .indeterminate
                .is_empty(),
        "a deletion of an unknown path may not yield a precise negative"
    );
}

/// A callable handed to a name no package file declares is invoked by code the
/// analysis never sees. Neither the frontend's marker nor composition may drop
/// it: the callable's own effects are not attributed anywhere.
#[test]
fn callable_passed_to_an_unresolvable_target_stays_a_boundary() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-unresolvable-escape",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc wipe() { os.RemoveAll(\"/escaped\") }\nfunc main() { register(wipe) }\n",
            ),
            // A sibling the Go parser rejects: `register` exists in the
            // package but never in the index.
            ("reg.go", "package main\nfunc register(f func()) { f( }\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "escaped_callable"
                && boundary.domains.iter().any(|domain| domain == "filesystem")),
        "{:?}",
        effects.boundaries
    );
    let escaped = reach(
        &index,
        &ResourceSelector::parse("fs:/escaped").unwrap(),
        None,
    );
    assert!(
        !escaped.payload.as_reach().unwrap().matches.is_empty()
            || !escaped.payload.as_reach().unwrap().indeterminate.is_empty(),
        "an escaped callable may not yield a precise negative"
    );
}

/// A const spec that omits its expression list repeats the previous one, so the
/// package value is exact across files.
#[test]
fn implicit_package_constant_resolves_across_files() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-implicit-package-const",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc main() { os.RemoveAll(target) }\n",
            ),
            (
                "values.go",
                "package main\nconst (\n\tfirst = \"/implicit-const\"\n\ttarget\n)\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 1, "{:?}", effects.effects);
    assert_eq!(
        effinterp_proto::display_resource_with_scope(&deletes[0].resource),
        "fs:/implicit-const"
    );
}

/// A callable held in a struct field reaches a standard-library entry point
/// exactly, with no boundary standing in for it.
#[test]
fn struct_field_callable_reaches_a_stdlib_call_exactly() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-field-callable-stdlib",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport (\n\t\"os\"\n\t\"sort\"\n)\ntype hooks struct{ less func(i, j int) bool }\nfunc compare(i, j int) bool {\n\tos.RemoveAll(\"/field-callback\")\n\treturn i < j\n}\nfunc main() {\n\th := hooks{less: compare}\n\tsort.Slice([]int{2, 1}, h.less)\n}\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = reach(
        &index,
        &ResourceSelector::parse("fs:/field-callback").unwrap(),
        None,
    );
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| hit.fact.entrypoint == "main.go"),
        "{:?}",
        report.payload
    );
}

/// A field a branch reassigns holds one of a finite set of callables. Both may
/// run, so both must be reported rather than the read collapsing to an opaque
/// property whose callables nobody can see.
#[test]
fn ambiguous_struct_field_callable_reports_every_alternative() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-ambiguous-field-callable",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport (\n\t\"os\"\n\t\"sort\"\n)\ntype hooks struct{ less func(i, j int) bool }\nfunc compare(i, j int) bool {\n\tos.RemoveAll(\"/field-callback\")\n\treturn i < j\n}\nfunc other(i, j int) bool {\n\tos.RemoveAll(\"/other-callback\")\n\treturn i > j\n}\nfunc main() {\n\th := hooks{less: compare}\n\tif len(os.Args) > 1 {\n\t\th.less = other\n\t}\n\tsort.Slice([]int{2, 1}, h.less)\n}\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    for path in ["/field-callback", "/other-callback"] {
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
                .any(|hit| hit.fact.entrypoint == "main.go"),
            "{path}: {:?}",
            report.payload
        );
    }
}

/// `for _, f = range xs` rebinds a name declared before the loop. A range over
/// an empty collection runs no iteration, so that name may still hold what it
/// held before: the value must not be discarded outright.
#[test]
fn assign_form_range_keeps_the_pre_loop_binding() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-assign-range-binding",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc wipe() { os.RemoveAll(\"/tmp/wiped\") }\nfunc main() {\n\tvar fns []func()\n\tf := wipe\n\tfor _, f = range fns {\n\t\t_ = f\n\t}\n\tf()\n}\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let composition = index.composition("main.go").unwrap();
    assert!(
        composition
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "dynamic_dispatch"),
        "{:?}",
        composition.boundaries
    );
    let report = reach(
        &index,
        &ResourceSelector::parse("fs:/tmp/wiped").unwrap(),
        None,
    );
    assert!(
        !report.payload.as_reach().unwrap().matches.is_empty()
            || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
        "a discarded pre-loop callable must not become a precise negative: {:?}",
        report.payload
    );
}

/// A package-level name the index cannot resolve is one call, described twice:
/// the root summary keeps it as an unbound name and the single-file plan as an
/// unknown. Only one row may reach the surface.
#[test]
fn unresolvable_package_name_reports_one_effect() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-unresolvable-package-name",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc main() { os.RemoveAll(TestOnly) }\n",
            ),
            (
                "helper_test.go",
                "package main\nconst TestOnly = \"/test-only\"\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let surface = effective_surface(&index, "main.go").unwrap();
    let deletes: Vec<_> = surface
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 1, "{deletes:?}");
    assert!(
        matches!(
            &deletes[0].resource_expr,
            ResourceExpr::Unresolved { .. } | ResourceExpr::Parameter { .. }
        ),
        "{:?}",
        deletes[0]
    );
}

#[test]
fn local_binding_never_resolves_to_a_same_named_package_function() {
    // A Go package spans its directory, but a local variable shadows every
    // package symbol spelled the same way: resolving the call by name reported
    // the sibling's deletion as an exact effect of a program that cannot
    // perform it. The local's own target is the answer — the closure a factory
    // returned, or a boundary when the value names no callable at all.
    let returned = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-shadowed-local-callee",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc makeHandler() func() {\n\treturn func() { os.Remove(\"/safe\") }\n}\nfunc main() {\n\thandler := makeHandler()\n\thandler()\n}\n",
            ),
            (
                "helper.go",
                "package main\nimport \"os\"\nfunc handler() { os.RemoveAll(\"/danger\") }\n",
            ),
        ],
    );
    let index = build_index(&returned, IndexLimits::default());
    let report = reach(
        &index,
        &ResourceSelector::parse("fs:/danger").unwrap(),
        None,
    );
    assert!(
        report.payload.as_reach().unwrap().matches.is_empty(),
        "a shadowed sibling must not be called: {:?}",
        report.payload.as_reach().unwrap().matches
    );
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !effects
            .effects
            .iter()
            .any(
                |effect| effinterp_proto::display_resource_with_scope(&effect.resource)
                    == "fs:/danger"
            ),
        "{:?}",
        effects.effects
    );
    // The returned literal is the exact target: a closure crossing a return is
    // a callable value this analysis can name and enter.
    assert!(
        effects
            .effects
            .iter()
            .any(
                |effect| effinterp_proto::display_resource_with_scope(&effect.resource)
                    == "fs:/safe"
            ),
        "the returned closure's own effect must be reported: {:?}",
        effects.effects
    );
    assert!(
        effects
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() == "frontend_partial"),
        "an exactly resolved call needs no dispatch boundary: {:?}",
        effects.boundaries
    );

    // A callable taken out of a collection names no target at all, so the call
    // is an explicit boundary rather than the sibling spelled the same way.
    let unnameable = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-unnameable-local-callee",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc main() {\n\thandlers := map[string]func(){\"a\": func() { os.Remove(\"/safe\") }}\n\th := handlers[os.Getenv(\"K\")]\n\th()\n}\n",
            ),
            (
                "helper.go",
                "package main\nimport \"os\"\nfunc h() { os.RemoveAll(\"/danger\") }\n",
            ),
        ],
    );
    let index = build_index(&unnameable, IndexLimits::default());
    let report = reach(
        &index,
        &ResourceSelector::parse("fs:/danger").unwrap(),
        None,
    );
    assert!(
        report.payload.as_reach().unwrap().matches.is_empty(),
        "a shadowed sibling must not be called: {:?}",
        report.payload.as_reach().unwrap().matches
    );
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "dynamic_dispatch"),
        "an unnameable call target must be a boundary: {:?}",
        effects.boundaries
    );
}

#[test]
fn callable_parameter_resolves_to_its_argument_not_a_same_named_sibling() {
    // The callable a caller hands over is the exact target of the parameter's
    // call, whether it is called directly or handed on to a standard-library
    // invoker; a sibling function spelled like the parameter is unrelated.
    for (tag, imports, apply) in [
        (
            "go-parameter-callee-direct",
            "\"os\"",
            "func apply(xs []int, less func(int, int) bool) { _ = less(1, 2) }",
        ),
        (
            "go-parameter-callee-stdlib",
            "\"os\"\n\t\"sort\"",
            "func apply(xs []int, less func(int, int) bool) { sort.Slice(xs, less) }",
        ),
    ] {
        let root = repo_test_fixture(
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
            tag,
            &[
                ("go.mod", "module ex.com/app\n"),
                (
                    "main.go",
                    &format!(
                        "package main\nimport (\n\t{imports}\n)\nfunc safeLess(i, j int) bool {{\n\tos.Remove(\"/safe\")\n\treturn i < j\n}}\n{apply}\nfunc main() {{ apply([]int{{2, 1}}, safeLess) }}\n"
                    ),
                ),
                (
                    "helper.go",
                    "package main\nimport \"os\"\nfunc less(a, b int) bool {\n\tos.RemoveAll(\"/danger\")\n\treturn a < b\n}\n",
                ),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let danger = reach(
            &index,
            &ResourceSelector::parse("fs:/danger").unwrap(),
            None,
        );
        assert!(
            danger.payload.as_reach().unwrap().matches.is_empty(),
            "{tag}: {:?}",
            danger.payload
        );
        assert!(
            danger
                .payload
                .as_reach()
                .unwrap()
                .indeterminate
                .iter()
                .filter_map(|row| match row {
                    effinterp_proto::Indeterminate::Boundary { evidence } => Some(evidence),
                    _ => None,
                })
                .all(|row| row.boundary_reason.as_str() == "frontend_partial"),
            "{tag}: {:?}",
            danger.payload
        );
        let safe = reach(&index, &ResourceSelector::parse("fs:/safe").unwrap(), None);
        assert!(
            safe.payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .any(|hit| hit.fact.entrypoint == "main.go"
                    && hit.fact.assurance == Some(effinterp_proto::ResolutionAssurance::Exact)),
            "{tag}: the supplied callable is the exact target: {:?}",
            safe.payload
        );
    }
}

#[test]
fn an_unrebound_package_callable_is_still_entered_exactly() {
    // The counterpart of the rebinding guards: no file of the package assigns
    // the variable, so its declared target is the one that runs.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-unrebound-package-callable",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nvar hook = safeHook\nfunc safeHook() { os.RemoveAll(\"/safe\") }\nfunc main() { hook() }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path },
                    ..
                } if path == "/safe")
        }),
        "{:?}",
        effects.effects
    );
    assert!(
        effects
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() == "frontend_partial"),
        "{:?}",
        effects.boundaries
    );
}

#[test]
fn an_exported_package_variable_assigned_by_an_importer_is_not_exact() {
    // A package variable is written from outside its own package through the
    // import qualifier. Its declaration therefore describes only what it held
    // before that write, and substituting the initializer would claim the
    // wrong resource exactly while excluding the one the program touches.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-cross-package-var-assignment",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"ex.com/app/lib\"\nfunc main() { lib.Target = \"/danger\"; lib.Wipe() }\n",
            ),
            (
                "lib/lib.go",
                "package lib\nimport \"os\"\nvar Target = \"/safe\"\nfunc Wipe() { os.RemoveAll(Target) }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 1, "{:?}", effects.effects);
    assert!(
        matches!(
            &deletes[0].resource,
            ResourceExpr::Unresolved { .. } | ResourceExpr::Parameter { .. }
        ),
        "{:?}",
        deletes[0]
    );
    for path in ["fs:/safe", "fs:/danger"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            !report.payload.as_reach().unwrap().matches.is_empty()
                || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative"
        );
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
            "{path} must not be claimed concretely: {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }
}

#[test]
fn an_exported_package_callable_assigned_by_an_importer_dispatches_to_no_guess() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-cross-package-callable-assignment",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport (\n\t\"os\"\n\n\t\"ex.com/app/lib\"\n)\nfunc wipeDanger() { os.RemoveAll(\"/danger\") }\nfunc main() { lib.Handler = wipeDanger; lib.Run() }\n",
            ),
            (
                "lib/lib.go",
                "package lib\nimport \"os\"\nfunc safe() { os.RemoveAll(\"/safe\") }\nvar Handler = safe\nfunc Run() { Handler() }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !effects
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"),
        "neither alternative may be claimed exactly: {:?}",
        effects.effects
    );
    assert!(
        effects
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "dynamic_dispatch"),
        "{:?}",
        effects.boundaries
    );
    for path in ["fs:/safe", "fs:/danger"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative"
        );
    }
}

#[test]
fn an_exported_package_variable_no_one_assigns_stays_exact() {
    // The precision guard for the two cases above: only an actual write may
    // cost the package its exact value.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-cross-package-var-unassigned",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"ex.com/app/lib\"\nfunc main() { lib.Wipe() }\n",
            ),
            (
                "lib/lib.go",
                "package lib\nimport \"os\"\nvar Target = \"/exact\"\nfunc Wipe() { os.RemoveAll(Target) }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = reach(&index, &ResourceSelector::parse("fs:/exact").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| hit.fact.entrypoint == "main.go"
                && matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })
                && hit.fact.assurance == Some(effinterp_proto::ResolutionAssurance::Exact)),
        "{:?}",
        report.payload
    );
}

#[test]
fn a_write_a_callee_reaches_indirectly_costs_the_caller_its_exact_value() {
    // Three shapes of the same write: a pointer forwarded to a second callee,
    // a pointer receiver, and a pointer taken of a local. None of them may
    // leave the declaration's value claimed as the path the program deletes.
    for (tag, source) in [
        (
            "go-forwarded-pointer-write",
            "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc forward(c *Config) { c.Path = \"/actual\" }\nfunc mutate(c *Config) { forward(c) }\nfunc main() {\n\tc := &Config{Path: \"/declared\"}\n\tmutate(c)\n\tos.Remove(c.Path)\n}\n",
        ),
        (
            "go-receiver-write",
            "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc (c *Config) Set(p string) { c.Path = p }\nfunc main() {\n\tc := &Config{Path: \"/declared\"}\n\tc.Set(\"/actual\")\n\tos.Remove(c.Path)\n}\n",
        ),
        (
            "go-aliased-pointer-write",
            "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc mutate(c *Config) { c.Path = \"/actual\" }\nfunc main() {\n\tcfg := Config{Path: \"/declared\"}\n\tp := &cfg\n\tmutate(p)\n\tos.Remove(cfg.Path)\n}\n",
        ),
    ] {
        let root = repo_test_fixture(
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
            tag,
            &[("go.mod", "module ex.com/app\n"), ("main.go", source)],
        );
        let index = build_index(&root, IndexLimits::default());
        for path in ["fs:/declared", "fs:/actual"] {
            let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
            assert!(
                !report.payload.as_reach().unwrap().matches.is_empty()
                    || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
                "{tag}: {path} must not be a precise negative"
            );
            assert!(
                report
                    .payload
                    .as_reach()
                    .unwrap()
                    .matches
                    .iter()
                    .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
                "{tag}: {path} must not be claimed concretely: {:?}",
                report.payload.as_reach().unwrap().matches
            );
        }
    }
}

#[test]
fn a_write_a_callable_reaches_through_a_value_costs_the_caller_its_exact_value() {
    // Five shapes of the same write, each reaching the caller's struct through
    // a callable this walk never enters: a closure handed to a call, an inline
    // literal, a collection element, a struct field, and a method value. None
    // of them may claim the declared path concretely, and none may turn the
    // path the program really deletes into a precise negative.
    for (tag, source) in [
        (
            "go-closure-handed-to-a-call",
            "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc run(f func()) { f() }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tf := func() { c.Path = \"/actual\" }\n\trun(f)\n\tos.Remove(c.Path)\n}\n",
        ),
        (
            "go-literal-handed-to-a-call",
            "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc run(f func()) { f() }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\trun(func() { c.Path = \"/actual\" })\n\tos.Remove(c.Path)\n}\n",
        ),
        (
            "go-closure-in-a-collection",
            "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tfs := []func(){func() { c.Path = \"/actual\" }}\n\tfs[0]()\n\tos.Remove(c.Path)\n}\n",
        ),
        (
            "go-closure-in-a-field",
            "package main\nimport \"os\"\ntype Config struct{ Path string }\ntype Holder struct{ Fn func() }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\th := Holder{Fn: func() { c.Path = \"/actual\" }}\n\th.Fn()\n\tos.Remove(c.Path)\n}\n",
        ),
        (
            "go-method-value",
            "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc (c *Config) Retarget() { c.Path = \"/actual\" }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tm := c.Retarget\n\tm()\n\tos.Remove(c.Path)\n}\n",
        ),
    ] {
        let root = repo_test_fixture(
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
            tag,
            &[("go.mod", "module ex.com/app\n"), ("main.go", source)],
        );
        let index = build_index(&root, IndexLimits::default());
        for path in ["fs:/declared", "fs:/actual"] {
            let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
            assert!(
                !report.payload.as_reach().unwrap().matches.is_empty()
                    || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
                "{tag}: {path} must not be a precise negative"
            );
            assert!(
                report
                    .payload
                    .as_reach()
                    .unwrap()
                    .matches
                    .iter()
                    .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
                "{tag}: {path} must not be claimed concretely: {:?}",
                report.payload.as_reach().unwrap().matches
            );
        }
    }
}

#[test]
fn a_write_a_callable_runs_out_of_order_costs_the_caller_its_exact_value() {
    // Twenty-seven shapes whose callable runs at a moment the walk cannot place: a
    // deferred body, which observes the value the function returns with, a
    // goroutine, which observes either, and a named closure stored in a field,
    // a map, or a slice. The write the body races against is a bare name, a
    // struct field, one made through a pointer the block binds below the
    // callable, one a sibling literal makes — to the name itself or through an
    // address it puts in a container, a composite literal, a field, or a
    // pointer of its own — or one a callee makes through a pointer receiver or
    // an address it was handed, directly, out of a container, a field, a
    // channel, or a sibling literal. The write may also reach the caller
    // through a method value that escapes to a name, a sibling literal, or a
    // composite literal, or through an address a type switch's init hands
    // away, and the receiver a pointer-receiver method writes may be reached
    // through a pointer alias or an interface variable bound to one. None may
    // claim the declared path concretely, and none may turn the
    // path the program really deletes into a precise negative.
    for (tag, source) in [
        (
            "go-deferred-closure",
            "package main\nimport \"os\"\nfunc main() {\n\tc := \"/declared\"\n\tdefer func() { os.Remove(c) }()\n\tc = \"/actual\"\n}\n",
        ),
        (
            "go-goroutine-closure",
            "package main\nimport \"os\"\nfunc main() {\n\tp := \"/declared\"\n\tgo func() { p = \"/actual\" }()\n\tos.Remove(p)\n}\n",
        ),
        (
            "go-deferred-closure-reading-a-field",
            "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tdefer func() { os.Remove(c.Path) }()\n\tc.Path = \"/actual\"\n}\n",
        ),
        (
            "go-goroutine-closure-reading-a-field",
            "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := &Config{Path: \"/declared\"}\n\tgo func() { os.Remove(c.Path) }()\n\tc.Path = \"/actual\"\n}\n",
        ),
        (
            "go-deferred-closure-reading-through-a-pointer-write",
            "package main\nimport \"os\"\nfunc main() {\n\tp := \"/declared\"\n\tq := &p\n\tdefer func() { os.Remove(p) }()\n\t*q = \"/actual\"\n}\n",
        ),
        (
            "go-deferred-closure-with-a-pointer-bound-below-it",
            "package main\nimport \"os\"\nfunc main() {\n\tp := \"/declared\"\n\tdefer func() { os.Remove(p) }()\n\tq := &p\n\t*q = \"/actual\"\n}\n",
        ),
        (
            "go-deferred-closure-beside-a-sibling-literal",
            "package main\nimport \"os\"\nfunc main() {\n\tp := \"/declared\"\n\tdefer func() { os.Remove(p) }()\n\tfunc() { p = \"/actual\" }()\n}\n",
        ),
        (
            "go-deferred-closure-beside-a-write-through-a-handed-address",
            "package main\nimport \"os\"\nfunc mutate(s *string) { *s = \"/actual\" }\nfunc main() {\n\tp := \"/declared\"\n\tdefer func() { os.Remove(p) }()\n\tmutate(&p)\n}\n",
        ),
        (
            "go-deferred-closure-beside-a-pointer-receiver-write",
            "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc (c *Config) Update(p string) { c.Path = p }\nfunc main() {\n\tc := &Config{Path: \"/declared\"}\n\tdefer func() { os.Remove(c.Path) }()\n\tc.Update(\"/actual\")\n}\n",
        ),
        (
            "go-deferred-closure-beside-a-write-through-a-stored-address",
            "package main\nimport \"os\"\nfunc main() {\n\tp := \"/declared\"\n\tdefer func() { os.Remove(p) }()\n\tm := map[string]*string{\"k\": &p}\n\t*m[\"k\"] = \"/actual\"\n}\n",
        ),
        (
            "go-deferred-closure-beside-a-write-through-an-assigned-address",
            "package main\nimport \"os\"\nfunc main() {\n\tp := \"/declared\"\n\tdefer func() { os.Remove(p) }()\n\tm := map[string]*string{}\n\tm[\"k\"] = &p\n\t*m[\"k\"] = \"/actual\"\n}\n",
        ),
        (
            "go-deferred-closure-beside-a-write-through-a-field-address",
            "package main\nimport \"os\"\ntype Holder struct{ C *string }\nfunc main() {\n\tp := \"/declared\"\n\tdefer func() { os.Remove(p) }()\n\tvar h Holder\n\th.C = &p\n\t*h.C = \"/actual\"\n}\n",
        ),
        (
            "go-deferred-closure-beside-a-write-through-a-channelled-address",
            "package main\nimport \"os\"\nfunc main() {\n\tp := \"/declared\"\n\tdefer func() { os.Remove(p) }()\n\tch := make(chan *string, 1)\n\tch <- &p\n\tq := <-ch\n\t*q = \"/actual\"\n}\n",
        ),
        (
            "go-deferred-closure-beside-a-sibling-literal-callee-write",
            "package main\nimport \"os\"\nfunc mutate(s *string) { *s = \"/actual\" }\nfunc main() {\n\tp := \"/declared\"\n\tdefer func() { os.Remove(p) }()\n\tfunc() { mutate(&p) }()\n}\n",
        ),
        (
            "go-deferred-closure-beside-a-sibling-literal-container-write",
            "package main\nimport \"os\"\nfunc main() {\n\tp := \"/declared\"\n\tdefer func() { os.Remove(p) }()\n\tfunc() {\n\t\tm := map[string]*string{}\n\t\tm[\"k\"] = &p\n\t\t*m[\"k\"] = \"/actual\"\n\t}()\n}\n",
        ),
        (
            "go-deferred-closure-beside-a-sibling-literal-composite-write",
            "package main\nimport \"os\"\nfunc main() {\n\tp := \"/declared\"\n\tdefer func() { os.Remove(p) }()\n\tfunc() {\n\t\tm := map[string]*string{\"k\": &p}\n\t\t*m[\"k\"] = \"/actual\"\n\t}()\n}\n",
        ),
        (
            "go-deferred-closure-beside-a-sibling-literal-pointer-write",
            "package main\nimport \"os\"\nfunc main() {\n\tp := \"/declared\"\n\tdefer func() { os.Remove(p) }()\n\tfunc() {\n\t\tq := &p\n\t\t*q = \"/actual\"\n\t}()\n}\n",
        ),
        (
            "go-deferred-closure-beside-a-sibling-literal-field-write",
            "package main\nimport \"os\"\nfunc main() {\n\tp := \"/declared\"\n\tdefer func() { os.Remove(p) }()\n\tfunc() {\n\t\tvar h struct{ C *string }\n\t\th.C = &p\n\t\t*h.C = \"/actual\"\n\t}()\n}\n",
        ),
        (
            "go-named-closure-in-a-field",
            "package main\nimport \"os\"\ntype Config struct{ Path string }\ntype Holder struct{ Fn func() }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tcb := func() { c.Path = \"/actual\" }\n\th := Holder{Fn: cb}\n\th.Fn()\n\tos.Remove(c.Path)\n}\n",
        ),
        (
            "go-named-closure-in-a-map",
            "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tcb := func() { c.Path = \"/actual\" }\n\tm := map[string]func(){}\n\tm[\"k\"] = cb\n\tm[\"k\"]()\n\tos.Remove(c.Path)\n}\n",
        ),
        (
            "go-named-closure-in-a-slice",
            "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tcb := func() { c.Path = \"/actual\" }\n\tfns := []func(){cb}\n\tfns[0]()\n\tos.Remove(c.Path)\n}\n",
        ),
        (
            "go-deferred-closure-beside-an-escaping-method-value",
            "package main\nimport \"os\"\ntype Box struct{ V string }\nfunc (b *Box) Set() { b.V = \"/actual\" }\nvar run func()\nfunc main() {\n\tb := Box{V: \"/declared\"}\n\tdefer func() { os.Remove(b.V) }()\n\trun = b.Set\n\trun()\n}\n",
        ),
        (
            "go-deferred-closure-beside-a-sibling-literal-method-value",
            "package main\nimport \"os\"\ntype Box struct{ V string }\nfunc (b *Box) Set() { b.V = \"/actual\" }\nvar run func()\nfunc main() {\n\tb := Box{V: \"/declared\"}\n\tdefer func() { os.Remove(b.V) }()\n\th := func() { run = b.Set }\n\th()\n\trun()\n}\n",
        ),
        (
            "go-deferred-closure-beside-a-method-value-in-a-composite-literal",
            "package main\nimport \"os\"\ntype Box struct{ V string }\nfunc (b *Box) Set() { b.V = \"/actual\" }\nvar reg []func()\nfunc main() {\n\tb := Box{V: \"/declared\"}\n\tdefer func() { os.Remove(b.V) }()\n\treg = []func(){b.Set}\n\treg[0]()\n}\n",
        ),
        (
            "go-deferred-closure-beside-an-alias-receiver-write",
            "package main\nimport \"os\"\ntype Box struct{ Path string }\nfunc (b *Box) Set() { b.Path = \"/actual\" }\nfunc main() {\n\tb := Box{Path: \"/declared\"}\n\tdefer func() { os.Remove(b.Path) }()\n\ts := &b\n\ts.Set()\n}\n",
        ),
        (
            "go-deferred-closure-beside-an-interface-receiver-write",
            "package main\nimport \"os\"\ntype Setter interface{ Set() }\ntype Box struct{ Path string }\nfunc (b *Box) Set() { b.Path = \"/actual\" }\nfunc main() {\n\tb := Box{Path: \"/declared\"}\n\tdefer func() { os.Remove(b.Path) }()\n\tvar s Setter = &b\n\ts.Set()\n}\n",
        ),
        (
            "go-deferred-closure-beside-a-type-switch-init-escape",
            "package main\nimport \"os\"\nvar sink map[string]*string\nvar probe interface{}\nfunc mutate() { *sink[\"k\"] = \"/actual\" }\nfunc main() {\n\tp := \"/declared\"\n\tdefer func() { os.Remove(p) }()\n\tsink = map[string]*string{}\n\tswitch sink[\"k\"] = &p; v := probe.(type) {\n\tcase int:\n\t\t_ = v\n\t}\n\tmutate()\n}\n",
        ),
    ] {
        let root = repo_test_fixture(
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
            tag,
            &[("go.mod", "module ex.com/app\n"), ("main.go", source)],
        );
        let index = build_index(&root, IndexLimits::default());
        for path in ["fs:/declared", "fs:/actual"] {
            let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
            assert!(
                !report.payload.as_reach().unwrap().matches.is_empty()
                    || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
                "{tag}: {path} must not be a precise negative"
            );
            assert!(
                report
                    .payload
                    .as_reach()
                    .unwrap()
                    .matches
                    .iter()
                    .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
                "{tag}: {path} must not be claimed concretely: {:?}",
                report.payload.as_reach().unwrap().matches
            );
        }
    }
}

#[test]
fn an_exported_package_variable_read_by_an_importer_resolves_to_its_value() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-imported-package-var-read",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport (\n\t\"os\"\n\n\t\"ex.com/app/lib\"\n)\nfunc main() { os.Remove(lib.Target) }\n",
            ),
            ("lib/lib.go", "package lib\n\nvar Target = \"/exact\"\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .collect();
    assert_eq!(
        deletes.len(),
        1,
        "the read has one conclusion: {:?}",
        effects.effects
    );
    let report = reach(&index, &ResourceSelector::parse("fs:/exact").unwrap(), None);
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| hit.fact.entrypoint == "main.go"
                && matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
        "{:?}",
        report.payload
    );
}

#[test]
fn an_exported_package_variable_the_importer_assigns_is_not_read_as_its_declaration() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-imported-package-var-rebound-read",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport (\n\t\"os\"\n\n\t\"ex.com/app/lib\"\n)\nfunc main() {\n\tlib.Target = \"/actual\"\n\tos.Remove(lib.Target)\n}\n",
            ),
            ("lib/lib.go", "package lib\n\nvar Target = \"/declared\"\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    let deletes: Vec<_> = effects
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 1, "{:?}", effects.effects);
    assert!(
        matches!(
            &deletes[0].resource,
            ResourceExpr::Unresolved { .. } | ResourceExpr::Parameter { .. }
        ),
        "{:?}",
        deletes[0]
    );
    for path in ["fs:/declared", "fs:/actual"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
            "{path} must not be claimed concretely: {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }
}

#[test]
fn a_callable_field_a_callee_swaps_is_not_dispatched_to_its_declared_target() {
    // The caller built the struct and knows the field it wrote, but the callee
    // received a pointer to it and assigned that field: the declared callable
    // is no longer what runs, so it must neither fire nor be excluded.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-callee-swaps-callable-field",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\ntype H struct{ fn func() }\nfunc safe() { os.RemoveAll(\"/safe\") }\nfunc danger() { os.RemoveAll(\"/danger\") }\nfunc swap(h *H) { h.fn = danger }\nfunc main() {\n\th := &H{fn: safe}\n\tswap(h)\n\th.fn()\n}\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        !effects
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"),
        "neither alternative may be claimed exactly: {:?}",
        effects.effects
    );
    assert!(
        !effects.boundaries.is_empty(),
        "the swapped field must be reported as an unknown target"
    );
    for path in ["fs:/safe", "fs:/danger"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            report.payload.as_reach().unwrap().matches.is_empty(),
            "{path}: {:?}",
            report.payload.as_reach().unwrap().matches
        );
        assert!(
            !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative"
        );
    }
}

#[test]
fn a_cross_package_method_that_writes_its_receiver_costs_the_caller_its_value() {
    // The receiver's type is declared in another package of this repository,
    // whose method body the entry file cannot read either: a qualified type is
    // no more readable than a sibling file's, so neither path may be answered
    // precisely.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-cross-package-receiver-write",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport (\n\t\"os\"\n\n\t\"ex.com/app/lib\"\n)\nfunc main() {\n\tc := lib.Config{Path: \"/declared\"}\n\tc.Retarget()\n\tos.Remove(c.Path)\n}\n",
            ),
            (
                "lib/lib.go",
                "package lib\n\ntype Config struct{ Path string }\n\nfunc (c *Config) Retarget() { c.Path = \"/actual\" }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    for path in ["fs:/declared", "fs:/actual"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            !report.payload.as_reach().unwrap().matches.is_empty()
                || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative"
        );
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
            "{path} must not be claimed concretely: {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }
}

#[test]
fn a_dot_free_module_path_is_not_the_standard_library() {
    // `go mod init app` needs no dotted domain, so an import path without one
    // is not evidence of the standard library: `lib.Config`'s method body is
    // as unreadable to the entry file as under any other module path.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-dot-free-module-receiver-write",
        &[
            (
                "go.mod",
                "module app
",
            ),
            (
                "main.go",
                "package main\nimport (\n\t\"os\"\n\n\t\"app/lib\"\n)\nfunc main() {\n\tc := lib.Config{Path: \"/declared\"}\n\tc.Retarget()\n\tos.Remove(c.Path)\n}\n",
            ),
            (
                "lib/lib.go",
                "package lib\n\ntype Config struct{ Path string }\n\nfunc (c *Config) Retarget() { c.Path = \"/actual\" }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    for path in ["fs:/declared", "fs:/actual"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            !report.payload.as_reach().unwrap().matches.is_empty()
                || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative"
        );
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
            "{path} must not be claimed concretely: {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }
}

#[test]
fn a_module_path_under_a_standard_library_root_is_not_the_standard_library() {
    // `weak` is a standard-library package, but `weak/foo/lib` is this
    // repository's own: only the whole import path decides, so the method body
    // the entry file cannot read still costs it its exact receiver.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-stdlib-root-collision",
        &[
            ("go.mod", "module weak/foo\n"),
            (
                "main.go",
                "package main\nimport (\n\t\"os\"\n\n\t\"weak/foo/lib\"\n)\nfunc main() {\n\tc := lib.Config{Path: \"/declared\"}\n\tc.Retarget()\n\tos.Remove(c.Path)\n}\n",
            ),
            (
                "lib/lib.go",
                "package lib\n\ntype Config struct{ Path string }\n\nfunc (c *Config) Retarget() { c.Path = \"/actual\" }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    for path in ["fs:/declared", "fs:/actual"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            !report.payload.as_reach().unwrap().matches.is_empty()
                || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative"
        );
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
            "{path} must not be claimed concretely: {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }
}

#[test]
fn a_write_through_a_copied_pointer_costs_the_caller_its_value() {
    // `q := p` copies a pointer: the three names are one storage, so the write
    // through the copy leaves neither path answerable precisely.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-copied-pointer-alias",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tp := &c\n\tq := p\n\tq.Path = \"/actual\"\n\tos.Remove(c.Path)\n}\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    for path in ["fs:/declared", "fs:/actual"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            !report.payload.as_reach().unwrap().matches.is_empty()
                || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative"
        );
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
            "{path} must not be claimed concretely: {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }
}

#[test]
fn a_method_writing_through_a_pointer_alias_costs_the_caller_its_value() {
    // `s := &b` types `s` from the storage it addresses, so `s.Set()` is the
    // same pointer-receiver write that `b.Set()` would be and neither path
    // stays answerable precisely.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-alias-receiver-write",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\ntype Box struct{ Path string }\nfunc (b *Box) Set() { b.Path = \"/actual\" }\nfunc main() {\n\tb := Box{Path: \"/declared\"}\n\ts := &b\n\ts.Set()\n\tos.Remove(b.Path)\n}\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    for path in ["fs:/declared", "fs:/actual"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            !report.payload.as_reach().unwrap().matches.is_empty()
                || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative"
        );
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
            "{path} must not be claimed concretely: {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }
}

#[test]
fn a_method_reached_through_a_pointer_alias_reaches_the_resource_it_touches() {
    // The receiver's type comes from the variable `&b` addresses, so the
    // method's own deletion is reported instead of silently dropped.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-alias-receiver-read",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\ntype Box struct{ Path string }\nfunc (b *Box) Wipe() { os.RemoveAll(b.Path) }\nfunc main() {\n\tb := Box{Path: \"/target\"}\n\ts := &b\n\ts.Wipe()\n}\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = reach(
        &index,
        &ResourceSelector::parse("fs:/target").unwrap(),
        None,
    );
    assert!(
        !report.payload.as_reach().unwrap().matches.is_empty(),
        "the aliased receiver's deletion must not be a precise negative: {:?}",
        report.payload
    );
}

#[test]
fn a_method_on_a_new_allocation_reaches_the_resource_it_touches() {
    // `new(Box)` names the type it allocates exactly as a composite literal
    // does, so the method call on it dispatches.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-new-allocation-receiver",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\ntype Box struct{ Path string }\nfunc (b *Box) Wipe() { os.RemoveAll(\"/target\") }\nfunc main() {\n\ts := new(Box)\n\ts.Wipe()\n}\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = reach(
        &index,
        &ResourceSelector::parse("fs:/target").unwrap(),
        None,
    );
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
        "the allocated receiver's deletion must be reachable: {:?}",
        report.payload
    );
}

#[test]
fn a_method_on_a_constructor_result_reaches_the_resource_it_touches() {
    // `newRemover().Wipe()` holds the constructor's result in no name; the
    // method still dispatches, so the path it deletes is a concrete match.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-constructor-result-method",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nfunc main() { newRemover().Wipe() }\n",
            ),
            (
                "remover.go",
                "package main\nimport \"os\"\ntype Remover struct{ path string }\nfunc newRemover() *Remover { return &Remover{path: \"/target\"} }\nfunc (r *Remover) Wipe() { os.RemoveAll(\"/target\") }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = reach(
        &index,
        &ResourceSelector::parse("fs:/target").unwrap(),
        None,
    );
    assert!(
        report
            .payload
            .as_reach()
            .unwrap()
            .matches
            .iter()
            .any(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
        "the chained method's deletion must be reachable: {:?}",
        report.payload
    );
}

#[test]
fn two_closures_sharing_a_name_cost_the_caller_its_value() {
    // Two functions each bind a closure to `w`, so the name says nothing about
    // which body `run` calls; the caller's struct may be rewritten either way.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-shared-closure-name-writes",
        &[
            (
                "go.mod",
                "module ex.com/app
",
            ),
            (
                "main.go",
                "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc noop() {\n\tw := func(x *Config) {}\n\tw(nil)\n}\nfunc run(c *Config) {\n\tw := func(x *Config) { x.Path = \"/actual\" }\n\tw(c)\n}\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\trun(&c)\n\tnoop()\n\tos.Remove(c.Path)\n}\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    for path in ["fs:/declared", "fs:/actual"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            !report.payload.as_reach().unwrap().matches.is_empty()
                || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative"
        );
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
            "{path} must not be claimed concretely: {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }
}

#[test]
fn a_body_local_closure_shadowing_a_package_function_costs_the_caller_its_value() {
    // `run` calls the closure it bound to `apply`, not the package function of
    // that name, so the package function's empty write set says nothing about
    // what the call does to the caller's struct.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-shadowed-package-func-writes",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc apply(c *Config) {}\nfunc run(c *Config) {\n\tapply := func(x *Config) { x.Path = \"/actual\" }\n\tapply(c)\n}\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\trun(&c)\n\tos.Remove(c.Path)\n}\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    for path in ["fs:/declared", "fs:/actual"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            !report.payload.as_reach().unwrap().matches.is_empty()
                || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative"
        );
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
            "{path} must not be claimed concretely: {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }
}

#[test]
fn a_sibling_file_method_that_writes_its_receiver_costs_the_caller_its_value() {
    // The type and its pointer-receiver method live in a second file of the
    // same package, so the entry file cannot read the body it calls: neither
    // the declared nor the assigned path may be answered precisely.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-sibling-receiver-write",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tc.Retarget()\n\tos.Remove(c.Path)\n}\n",
            ),
            (
                "config.go",
                "package main\n\ntype Config struct{ Path string }\n\nfunc (c *Config) Retarget() { c.Path = \"/actual\" }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    for path in ["fs:/declared", "fs:/actual"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            !report.payload.as_reach().unwrap().matches.is_empty()
                || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative"
        );
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
            "{path} must not be claimed concretely: {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }
}

#[test]
fn an_address_that_escapes_into_untracked_storage_costs_the_caller_its_value() {
    // Three ways an address leaves the names the walk follows: a callee returns
    // it, a struct literal holds it, and a slice element holds it. In each the
    // later write reaches the variable, so neither path may be answered
    // precisely.
    for (name, body) in [
        (
            "returned",
            "func ptr(c *Config) *Config { return c }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tp := ptr(&c)\n\tp.Path = \"/actual\"\n\tos.Remove(c.Path)\n}\n",
        ),
        (
            "literal",
            "type Holder struct{ C *Config }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\th := Holder{C: &c}\n\th.C.Path = \"/actual\"\n\tos.Remove(c.Path)\n}\n",
        ),
        (
            "element",
            "func main() {\n\tc := Config{Path: \"/declared\"}\n\tps := []*Config{&c}\n\tps[0].Path = \"/actual\"\n\tos.Remove(c.Path)\n}\n",
        ),
    ] {
        let root = repo_test_fixture(
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("go-escaped-address-{name}"),
            &[
                ("go.mod", "module ex.com/app\n"),
                (
                    "main.go",
                    &format!(
                        "package main\nimport \"os\"\ntype Config struct{{ Path string }}\n{body}"
                    ),
                ),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        for path in ["fs:/declared", "fs:/actual"] {
            let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
            assert!(
                !report.payload.as_reach().unwrap().matches.is_empty()
                    || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
                "{name}: {path} must not be a precise negative"
            );
            assert!(
                report
                    .payload
                    .as_reach()
                    .unwrap()
                    .matches
                    .iter()
                    .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
                "{name}: {path} must not be claimed concretely: {:?}",
                report.payload.as_reach().unwrap().matches
            );
        }
    }
}

#[test]
fn a_callable_swapped_through_an_escaped_address_is_not_answered_precisely() {
    // The slice element holds the struct's address, so the callable field it
    // rewrites is unknown: the declared function must not be claimed and the
    // assigned one must not be excluded.
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-escaped-address-callable",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\ntype H struct{ Fn func() }\nfunc safe() { os.RemoveAll(\"/safe\") }\nfunc wipe() { os.RemoveAll(\"/danger\") }\nfunc main() {\n\th := H{Fn: safe}\n\ths := []*H{&h}\n\ths[0].Fn = wipe\n\th.Fn()\n}\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    for path in ["fs:/safe", "fs:/danger"] {
        let report = reach(&index, &ResourceSelector::parse(path).unwrap(), None);
        assert!(
            !report.payload.as_reach().unwrap().matches.is_empty()
                || !report.payload.as_reach().unwrap().indeterminate.is_empty(),
            "{path} must not be a precise negative: {:?}",
            report.payload
        );
        assert!(
            report
                .payload
                .as_reach()
                .unwrap()
                .matches
                .iter()
                .all(|hit| matches!(hit.matched, effinterp_proto::Match::Satisfied { .. })),
            "{path} must not be claimed concretely: {:?}",
            report.payload.as_reach().unwrap().matches
        );
    }
}

#[test]
fn cross_package_callable_variable_respects_importer_rebinding() {
    for (tag, rebind, initializer) in [
        ("go-imported-callable-exact", "", "execute"),
        (
            "go-imported-callable-literal",
            "",
            "func(args []string) { os.Remove(\"/package-callable\") }",
        ),
        (
            "go-imported-callable-rebound",
            "commands.Execute = func(args []string) {};",
            "execute",
        ),
    ] {
        let main = format!(
            "package main\nimport \"ex.com/app/commands\"\nfunc main() {{ {rebind} commands.Execute([]string{{\"arg\"}}) }}\n"
        );
        let commands = format!(
            "package commands\nimport \"os\"\nvar Execute = {initializer}\nfunc execute(args []string) {{ os.Remove(\"/package-callable\") }}\n"
        );
        let root = repo_test_fixture(
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
            tag,
            &[
                ("go.mod", "module ex.com/app\n"),
                ("main.go", &main),
                (
                    "commands/a.go",
                    "package commands\nimport \"os\"\nvar Another = func(args []string) { os.Remove(\"/wrong-callable\") }\n",
                ),
                ("commands/commands.go", &commands),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let effects = effects_of(&index, "main.go")
            .unwrap()
            .payload
            .into_effects()
            .unwrap();
        assert_eq!(
            effects
                .effects
                .iter()
                .any(|effect| effect.operation.as_str() == "filesystem.delete"),
            rebind.is_empty(),
            "{tag}: {effects:?}"
        );
        assert!(
            !effects.effects.iter().any(|effect| matches!(
                &effect.resource, ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path }, ..
                } if path == "/wrong-callable"
            )),
            "{tag}: {effects:?}"
        );
        assert_eq!(
            effects
                .boundaries
                .iter()
                .any(|boundary| boundary.reason == "unresolved_call"
                    && boundary
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.contains("Execute"))),
            !rebind.is_empty(),
            "{tag}: {effects:?}"
        );
    }
}

#[test]
fn cross_package_external_bound_callable_stays_a_boundary() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-imported-external-bound-callable",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"ex.com/app/commands\"\nfunc main() { commands.Remove(\"/external-bound\") }\n",
            ),
            (
                "commands/commands.go",
                "package commands\nimport \"os\"\nvar Remove = os.RemoveAll\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects.boundaries.iter().any(|boundary| {
            boundary.reason == "unresolved_call"
                && boundary.detail.as_deref().is_some_and(|detail| {
                    detail.contains("Remove") && detail.contains("commands/commands.go")
                })
        }),
        "{effects:?}"
    );
}

#[test]
fn cross_package_literal_callable_fields_reach_their_targets() {
    for (tag, rebind) in [
        ("go-imported-field-exact", ""),
        (
            "go-imported-field-ambiguous",
            "if len(os.Args) > 1 { c.RunE = commands.Other };",
        ),
    ] {
        let main = format!(
            "package main\nimport (\n\"os\"\n\"ex.com/app/registry\"\n\"ex.com/app/commands\"\n)\nfunc main() {{ _ = os.Args; c := &registry.Command{{RunE: commands.Cleanup}}; {rebind} c.RunE() }}\n"
        );
        let root = repo_test_fixture(
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
            tag,
            &[
                ("go.mod", "module ex.com/app\n"),
                ("main.go", &main),
                (
                    "registry/command.go",
                    "package registry\ntype Command struct { RunE func() }\n",
                ),
                (
                    "commands/commands.go",
                    "package commands\nimport \"os\"\nfunc Cleanup() { os.RemoveAll(\"/field-cleanup\") }\nfunc Other() { os.RemoveAll(\"/field-other\") }\n",
                ),
            ],
        );
        let index = build_index(&root, IndexLimits::default());
        let effects = effects_of(&index, "main.go")
            .unwrap()
            .payload
            .into_effects()
            .unwrap();
        for path in if rebind.is_empty() {
            vec!["/field-cleanup"]
        } else {
            vec!["/field-cleanup", "/field-other"]
        } {
            assert!(
                effects.effects.iter().any(|effect| {
                    effect.operation.as_str() == "filesystem.delete"
                        && matches!(&effect.resource, ResourceExpr::Concrete {
                            identity: effinterp_proto::ResourceIdentity::FsPath { path: actual }, ..
                        } if actual == path)
                }) || (!rebind.is_empty()
                    && effects.boundaries.iter().any(|boundary| boundary.reason
                        == "dynamic_dispatch"
                        && boundary
                            .detail
                            .as_deref()
                            .is_some_and(|detail| detail.contains("RunE")))),
                "{tag}: {path}: {effects:?}"
            );
        }
        if rebind.is_empty() {
            assert!(
                !effects
                    .boundaries
                    .iter()
                    .any(|boundary| boundary.reason == "unresolved_call"
                        && boundary
                            .detail
                            .as_deref()
                            .is_some_and(|detail| detail.contains("RunE"))),
                "{effects:?}"
            );
        }
    }
}

#[test]
fn go_import_call_targets_exclude_test_files() {
    for (tag, production, test_package) in [
        ("go-import-test-target", true, "pkg"),
        ("go-import-only-test-target", false, "pkg"),
        ("go-import-external-test-target", true, "pkg_test"),
    ] {
        let test_source = format!(
            "package {test_package}\nimport \"os\"\nfunc New() {{ os.RemoveAll(\"/test-only\") }}\n"
        );
        let mut files = vec![
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"ex.com/app/pkg\"\nfunc main() { pkg.New() }\n",
            ),
            ("pkg/a_test.go", test_source.as_str()),
        ];
        if production {
            files.push(("pkg/x.go", "package pkg\n"));
        }
        let root = repo_test_fixture(
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
            tag,
            &files,
        );
        let index = build_index(&root, IndexLimits::default());
        let effects = effects_of(&index, "main.go")
            .unwrap()
            .payload
            .into_effects()
            .unwrap();
        assert!(
            !effects
                .effects
                .iter()
                .any(|effect| effect.operation.as_str() == "filesystem.delete"),
            "{effects:?}"
        );
        assert!(
            !effects.boundaries.iter().any(|boundary| boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("_test.go"))),
            "{effects:?}"
        );
        assert!(
            effects.boundaries.iter().any(|boundary| {
                if production {
                    boundary.reason == "unresolved_call"
                        && boundary
                            .detail
                            .as_deref()
                            .is_some_and(|detail| detail.contains("pkg/x.go"))
                } else {
                    boundary.reason == "cross_module"
                        && boundary
                            .detail
                            .as_deref()
                            .is_some_and(|detail| detail.contains("ex.com/app/pkg"))
                }
            }),
            "{effects:?}"
        );
    }
}

#[test]
fn callable_appended_to_package_slice_stays_dynamic() {
    let root = repo_test_fixture(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "go-package-slice-callable",
        &[
            ("go.mod", "module ex.com/app\n"),
            (
                "main.go",
                "package main\nimport \"os\"\nvar handlers []func()\nfunc cleanup() { os.RemoveAll(\"/stored-callable\") }\nfunc main() { handlers = append(handlers, cleanup); for _, h := range handlers { h() } }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let effects = effects_of(&index, "main.go")
        .unwrap()
        .payload
        .into_effects()
        .unwrap();
    assert!(
        effects
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "dynamic_dispatch"),
        "{effects:?}"
    );
    assert!(
        !effects
            .effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"),
        "{effects:?}"
    );
}

#[test]
fn sibling_summaries_preserve_unresolved_dispatch() {
    for (tag, body, callee) in [
        ("map", "handlers[\"k\"]()", "handlers"),
        ("dynamic", "var selected func(); selected()", "selected"),
        (
            "method",
            "var client interface{}; client.Deploy()",
            "Deploy",
        ),
        ("returned", "factory()()", "factory()"),
        ("resolved", "cleanup()", "cleanup"),
    ] {
        let helper = format!("package main\nfunc helper() {{ {body} }}\n");
        for called in [false, true] {
            let main = if called { "helper()" } else { "" };
            let root = repo_test_fixture(
                std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
                &format!("go-summary-dispatch-{tag}-{called}"),
                &[
                    ("go.mod", "module ex.com/app\n"),
                    (
                        "main.go",
                        &format!("package main\nfunc main() {{ {main} }}\n"),
                    ),
                    ("helper.go", &helper),
                    (
                        "cleanup.go",
                        "package main\nimport \"os\"\nfunc cleanup() { os.Remove(\"/resolved\") }\n",
                    ),
                ],
            );
            let index = build_index(&root, IndexLimits::default());
            let effects = effective_surface(&index, "main.go").unwrap();
            if tag == "resolved" {
                assert_eq!(
                    effects
                        .effects
                        .iter()
                        .any(|effect| effect.operation.as_str() == "filesystem.delete"),
                    called,
                    "{effects:?}"
                );
            }
            assert_eq!(
                effects.boundaries.iter().any(|boundary| {
                    boundary.reason.as_str() == "unresolved_call"
                        && boundary
                            .detail
                            .as_deref()
                            .is_some_and(|detail| detail.ends_with(callee))
                        && boundary.domains.len() == effinterp_proto::DOMAINS.len()
                        && boundary.provenance.iter().any(|step| matches!(step,
                            effinterp_repo::ProvenanceStep::CrossFile { into, .. } if into == "helper.go:helper"
                        ))
                }),
                called && tag != "resolved",
                "{tag}, called={called}: {effects:?}"
            );
        }
    }
}
