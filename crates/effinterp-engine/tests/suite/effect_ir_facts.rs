use effinterp_engine::{
    CallEdge, Lang, ObjectIdentity, ScopeKey, TypeRef, ValueOrigin, module_summaries,
};
use effinterp_proto::SourceDialect;

fn edges(summary: &effinterp_engine::ModuleSummary) -> Vec<&CallEdge> {
    summary
        .module_calls
        .iter()
        .chain(&summary.main_calls)
        .chain(summary.functions.iter().flat_map(|f| &f.calls))
        .collect()
}

fn receiver_origin(edge: &CallEdge) -> &ValueOrigin {
    edge.receiver
        .as_ref()
        .and_then(|value| value.evidence.origin.as_ref())
        .unwrap_or_else(|| panic!("missing receiver origin: {:?}", edge.receiver))
}

#[test]
fn site_context_is_deterministic_for_every_frontend() {
    let cases = [
        (
            Lang::Python,
            "import helper\nhelper.run()\n",
            "pkg/app.py",
            ScopeKey::Module {
                key: "pkg.app".into(),
            },
        ),
        (
            Lang::Js(SourceDialect::Js),
            "import { run } from './helper.js';\nrun();\n",
            "src/app.js",
            ScopeKey::Module {
                key: "src/app.js".into(),
            },
        ),
        (
            Lang::Go,
            "package main\nfunc main() { helper() }\n",
            "cmd/main.go",
            ScopeKey::GoPackage {
                key: "example.com/app/cmd".into(),
            },
        ),
        (
            Lang::Ruby,
            "require_relative 'helper'\nhelper()\n",
            "lib/app.rb",
            ScopeKey::Module {
                key: "lib/app.rb".into(),
            },
        ),
        (
            Lang::Rust,
            "fn main() { helper::run(); }\n",
            "src/main.rs",
            ScopeKey::RustModule { key: "app".into() },
        ),
        (
            Lang::Java,
            "class App { static void main(String[] args) { Helper.run(); } }",
            "src/App.java",
            ScopeKey::Module {
                key: "src/App.java".into(),
            },
        ),
        (
            Lang::Php,
            "<?php function helper() {} helper();",
            "src/app.php",
            ScopeKey::Module {
                key: "src/app.php".into(),
            },
        ),
    ];

    for (lang, source, file, scope) in cases {
        let first = module_summaries(
            source,
            lang,
            file,
            scope.clone(),
            &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), lang),
        );
        let second = module_summaries(
            source,
            lang,
            file,
            scope,
            &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), lang),
        );
        assert_eq!(first, second, "repeated {lang:?} extraction changed");
        let facts = edges(&first);
        assert!(!facts.is_empty(), "{lang:?} emitted no ordinary call fact");
        assert!(facts.iter().all(|edge| {
            matches!(
                edge.origin_for_result(0),
                Some(ValueOrigin::Site { file: emitted, .. }) if emitted == file
            )
        }));
    }
}

#[test]
fn module_and_main_facts_do_not_share_site_origins() {
    let summary = module_summaries(
        "class C:\n    @staticmethod\n    def make():\n        return C()\ndef main():\n    pass\nx = C.make()\nif __name__ == '__main__':\n    main()\n",
        Lang::Python,
        "app.py",
        ScopeKey::Module { key: "app".into() },
        &effinterp_engine::SummaryBudget::for_lang(
            &effinterp_engine::default_limits(),
            Lang::Python,
        ),
    );
    let receiver = summary
        .module_calls
        .iter()
        .find(|edge| edge.callee == "C.make")
        .and_then(|edge| edge.receiver.as_ref())
        .and_then(|receiver| receiver.evidence.origin.as_ref())
        .expect("C.make receiver origin");
    let main = summary
        .main_calls
        .iter()
        .find(|edge| edge.callee == "main")
        .and_then(|edge| edge.results.first())
        .and_then(|result| result.value.evidence.origin.as_ref())
        .expect("main call origin");
    assert_ne!(receiver, main);
}

fn cobra_summary(scope: &str) -> effinterp_engine::ModuleSummary {
    module_summaries(
        r#"package cmd
import "github.com/spf13/cobra"
var rootCmd = &cobra.Command{Use: "root"}
var childCmd = &cobra.Command{RunE: run}
func run() {}
func init() { rootCmd.AddCommand(childCmd) }
func main() { rootCmd.Execute() }
"#,
        Lang::Go,
        "cmd/root.go",
        ScopeKey::GoPackage { key: scope.into() },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Go),
    )
}

#[test]
fn go_cobra_emits_typed_bindings_constructor_sites_and_attachment_children() {
    let summary = cobra_summary("example.com/one/cmd");
    let add = summary
        .module_calls
        .iter()
        .find(|edge| edge.callee.ends_with(".AddCommand"))
        .expect("AddCommand edge");
    assert!(matches!(
        add.receiver_identity(),
        Some(ObjectIdentity::ModuleBinding {
            scope: ScopeKey::GoPackage { key },
            name,
        }) if key == "example.com/one/cmd" && name == "rootCmd"
    ));
    assert!(matches!(
        add.receiver.as_ref().and_then(|value| value.evidence.ty.as_ref()),
        Some(TypeRef::External { path }) if path == "github.com/spf13/cobra.Command"
    ));
    let (child_argument, child_identity) = add.object_arguments().next().expect("child object");
    assert!(matches!(
        child_identity,
        ObjectIdentity::ModuleBinding {
            scope: ScopeKey::GoPackage { key },
            name,
        } if key == "example.com/one/cmd" && name == "childCmd"
    ));
    assert!(matches!(
        child_argument.value.evidence.ty.as_ref(),
        Some(TypeRef::External { path }) if path == "github.com/spf13/cobra.Command"
    ));
    assert!(matches!(
        add.origin_for_result(0),
        Some(ValueOrigin::Site { function, .. }) if function == "init#0"
    ));

    let constructors: Vec<_> = summary
        .module_calls
        .iter()
        .filter(|edge| {
            edge.result_type()
                == Some(&TypeRef::External {
                    path: "github.com/spf13/cobra.Command".into(),
                })
        })
        .collect();
    assert_eq!(constructors.len(), 2);
    assert_ne!(
        constructors[0].origin_for_result(0),
        constructors[1].origin_for_result(0)
    );
    assert!(constructors.iter().all(|edge| {
        matches!(edge.origin_for_result(0), Some(ValueOrigin::Site { function, .. }) if function.is_empty())
    }));
    assert!(constructors.iter().any(|edge| {
        edge.callback_arguments().any(|(argument, function)| {
            argument.name.as_deref() == Some("RunE") && function == "run"
        })
    }));
}

#[test]
fn go_package_scope_and_multiple_init_sites_do_not_collide() {
    let one = cobra_summary("example.com/one/cmd");
    let two = cobra_summary("example.com/two/cmd");
    let recv_scope = |summary: &effinterp_engine::ModuleSummary| {
        summary
            .main_calls
            .iter()
            .find_map(|edge| match edge.receiver_identity() {
                Some(ObjectIdentity::ModuleBinding { scope, .. }) => Some(scope.clone()),
                _ => None,
            })
            .expect("typed main receiver")
    };
    assert_ne!(recv_scope(&one), recv_scope(&two));

    let multiple = module_summaries(
        "package main\nfunc init() { first() }\nfunc init() { second() }\n",
        Lang::Go,
        "init.go",
        ScopeKey::GoPackage { key: "main".into() },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Go),
    );
    let functions: Vec<_> = multiple
        .module_calls
        .iter()
        .filter_map(|edge| match edge.origin_for_result(0) {
            Some(ValueOrigin::Site { function, .. }) => Some(function),
            _ => None,
        })
        .collect();
    assert!(functions.iter().any(|function| function == "init#0"));
    assert!(functions.iter().any(|function| function == "init#1"));
}

#[test]
fn python_parser_bindings_and_derived_sites_have_stable_identity() {
    let summary = module_summaries(
        "import argparse\nparser = argparse.ArgumentParser()\nsub = parser.add_subparsers()\ncmd = sub.add_parser('one')\ncmd = sub.add_parser('two')\n",
        Lang::Python,
        "commands.py",
        ScopeKey::Module {
            key: "commands".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(
            &effinterp_engine::default_limits(),
            Lang::Python,
        ),
    );
    let parser_call = summary
        .module_calls
        .iter()
        .find(|edge| edge.callee.ends_with("add_subparsers"))
        .expect("parser receiver call");
    assert!(matches!(
        parser_call.receiver_identity(),
        Some(ObjectIdentity::ModuleBinding {
            scope: ScopeKey::Module { key },
            name,
        }) if key == "commands" && name == "parser"
    ));
    assert!(matches!(
        parser_call
            .receiver
            .as_ref()
            .and_then(|value| value.evidence.ty.as_ref()),
        Some(TypeRef::External { path }) if path == "argparse.ArgumentParser"
    ));
    let sites: Vec<_> = summary
        .module_calls
        .iter()
        .filter(|edge| edge.callee.ends_with("add_parser"))
        .map(|edge| edge.origin_for_result(0).expect("add_parser site"))
        .collect();
    assert_eq!(sites.len(), 2);
    assert_ne!(sites[0], sites[1]);

    for source in [
        "from commands import parser\nparser.add_subparsers()\n",
        "import commands\ncommands.parser.add_subparsers()\n",
    ] {
        let imported = module_summaries(
            source,
            Lang::Python,
            "app.py",
            ScopeKey::Module { key: "app".into() },
            &effinterp_engine::SummaryBudget::for_lang(
                &effinterp_engine::default_limits(),
                Lang::Python,
            ),
        );
        assert!(imported.module_calls.iter().any(|edge| matches!(
            edge.receiver_identity(),
            Some(ObjectIdentity::ModuleBinding {
                scope: ScopeKey::Module { key },
                name,
            }) if key == "commands" && name == "parser"
        )));
    }
}

#[test]
fn java_nested_construction_has_its_own_method_site() {
    let summary = module_summaries(
        "class App { static void main(String[] args) { new App().run(); } void run() {} }",
        Lang::Java,
        "src/App.java",
        ScopeKey::Module {
            key: "src/App.java".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Java),
    );
    let method = summary
        .main_calls
        .iter()
        .find(|edge| edge.callee == "App.run")
        .expect("constructed receiver method edge");
    let receiver_origin = receiver_origin(method);
    assert_ne!(method.origin_for_result(0).as_ref(), Some(receiver_origin));
    assert!(matches!(
        receiver_origin,
        ValueOrigin::Site { function, .. } if function == "App.main"
    ));
    assert!(matches!(
        method.origin_for_result(0),
        Some(ValueOrigin::Site { function, .. }) if function == "App.main"
    ));
    let constructor = summary
        .main_calls
        .iter()
        .find(|edge| edge.callee == "App")
        .expect("ordinary constructor edge");
    assert_eq!(
        constructor.origin_for_result(0).as_ref(),
        Some(receiver_origin)
    );
}

#[test]
fn javascript_nested_construction_has_its_own_call_site() {
    let summary = module_summaries(
        "class App {}\nfunction apply(value) {}\napply(new App());\n",
        Lang::Js(SourceDialect::Js),
        "src/app.js",
        ScopeKey::Module {
            key: "src/app.js".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(
            &effinterp_engine::default_limits(),
            Lang::Js(SourceDialect::Js),
        ),
    );
    let call = summary
        .module_calls
        .iter()
        .find(|edge| edge.callee == "apply")
        .expect("call with constructed argument");
    let receiver_origin = call
        .object_arguments()
        .next()
        .and_then(|(argument, _)| argument.value.evidence.origin.as_ref())
        .expect("constructed argument origin");
    assert_ne!(call.origin_for_result(0).as_ref(), Some(receiver_origin));
    assert!(matches!(
        receiver_origin,
        ValueOrigin::Site { function, .. } if function.is_empty()
    ));
}

#[test]
fn go_inline_cobra_children_and_binding_aliases_keep_identity() {
    let summary = module_summaries(
        r#"package main
import "github.com/spf13/cobra"
var rootCmd = &cobra.Command{}
func run() {}
func init() {
    alias := rootCmd
    alias.AddCommand(&cobra.Command{Run: run})
}
"#,
        Lang::Go,
        "cmd/root.go",
        ScopeKey::GoPackage {
            key: "example.com/app/cmd".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Go),
    );
    let add = summary
        .module_calls
        .iter()
        .find(|edge| edge.callee == "alias.AddCommand")
        .expect("aliased AddCommand edge");
    assert!(matches!(
        add.receiver_identity(),
        Some(ObjectIdentity::ModuleBinding {
            scope: ScopeKey::GoPackage { key },
            name,
        }) if key == "example.com/app/cmd" && name == "rootCmd"
    ));
    assert!(matches!(
        add.receiver.as_ref().and_then(|value| value.evidence.ty.as_ref()),
        Some(TypeRef::External { path }) if path == "github.com/spf13/cobra.Command"
    ));
    let (child, _) = add.object_arguments().next().expect("inline Cobra child");
    assert!(matches!(
        child.value.evidence.ty.as_ref(),
        Some(TypeRef::External { path }) if path == "github.com/spf13/cobra.Command"
    ));
    let child_origin = child
        .value
        .evidence
        .origin
        .as_ref()
        .expect("inline Cobra child origin");
    assert!(matches!(
        child_origin,
        ValueOrigin::Site { function, .. } if function == "init#0"
    ));
    let constructor = summary
        .module_calls
        .iter()
        .find(|edge| {
            edge.origin_for_result(0).as_ref() == Some(child_origin)
                && edge.callee == "cobra.Command"
                && edge.callback_arguments().any(|(argument, function)| {
                    argument.name.as_deref() == Some("Run") && function == "run"
                })
        })
        .expect("ordinary inline Cobra constructor edge with seed field");
    assert_eq!(
        constructor.result_type(),
        Some(&TypeRef::External {
            path: "github.com/spf13/cobra.Command".into(),
        })
    );
}

#[test]
fn python_tuple_bindings_have_distinct_result_value_origins() {
    let summary = module_summaries(
        "def pair():\n    return 1, 2\na, b = pair()\n",
        Lang::Python,
        "app.py",
        ScopeKey::Module { key: "app".into() },
        &effinterp_engine::SummaryBudget::for_lang(
            &effinterp_engine::default_limits(),
            Lang::Python,
        ),
    );
    let edge = summary
        .module_calls
        .iter()
        .find(|edge| edge.callee == "pair")
        .expect("pair call edge");
    assert_eq!(
        edge.result_bindings().collect::<Vec<_>>(),
        vec![(0, "a"), (1, "b")]
    );
    assert_eq!(edge.results.len(), 2);
    let first = edge.origin_for_result(0).expect("first result origin");
    let second = edge.origin_for_result(1).expect("second result origin");
    assert_eq!(
        edge.results
            .iter()
            .filter_map(|result| result.value.evidence.origin.clone())
            .collect::<Vec<_>>(),
        vec![first.clone(), second.clone()]
    );
    assert_ne!(first, second);
    assert!(matches!(
        second,
        ValueOrigin::Site {
            result_index: 1,
            ..
        }
    ));
}

#[test]
fn go_declared_value_and_call_sites_do_not_collide() {
    let summary = module_summaries(
        r#"package main
import "github.com/spf13/cobra"
func other() {}
func run() {
    var command cobra.Command
    command.Execute()
    other()
    command.Help()
}
"#,
        Lang::Go,
        "cmd/main.go",
        ScopeKey::GoPackage {
            key: "example.com/app/cmd".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Go),
    );
    let calls = &summary
        .functions
        .iter()
        .find(|function| function.name == "run")
        .expect("run function")
        .calls;
    let execute = calls
        .iter()
        .find(|edge| edge.callee == "command.Execute")
        .expect("Execute edge");
    let other = calls
        .iter()
        .find(|edge| edge.callee == "other")
        .expect("other edge");
    let help = calls
        .iter()
        .find(|edge| edge.callee == "command.Help")
        .expect("Help edge");
    assert_eq!(receiver_origin(execute), receiver_origin(help));
    assert_ne!(
        Some(receiver_origin(execute)),
        execute.origin_for_result(0).as_ref()
    );
    assert_ne!(
        Some(receiver_origin(execute)),
        other.origin_for_result(0).as_ref()
    );

    let edge_origins: Vec<_> = calls
        .iter()
        .map(|edge| edge.origin_for_result(0).expect("edge origin"))
        .collect();
    let unique: std::collections::HashSet<_> = edge_origins.iter().collect();
    assert_eq!(unique.len(), edge_origins.len());
}

#[test]
fn go_local_shadows_and_predeclared_values_are_not_package_bindings() {
    let summary = module_summaries(
        r#"package main
import "github.com/spf13/cobra"
type Runner struct{}
type Other struct{}
var runner = Runner{}
var rootCmd = &cobra.Command{}
func (Runner) Wipe() {}
func (Other) Wipe() {}
func attach(values []Other) {
    for _, runner := range values {
        runner.Wipe()
    }
    rootCmd.AddCommand(nil)
}
"#,
        Lang::Go,
        "cmd/main.go",
        ScopeKey::GoPackage {
            key: "example.com/app/cmd".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Go),
    );
    let calls = &summary
        .functions
        .iter()
        .find(|function| function.name == "attach")
        .expect("attach function")
        .calls;
    let wipe = calls
        .iter()
        .find(|edge| edge.callee == "runner.Wipe")
        .expect("loop receiver edge");
    assert!(matches!(
        wipe.receiver_identity(),
        Some(ObjectIdentity::Local {
            name,
            fallback: None,
        }) if name == "runner"
    ));
    let add = calls
        .iter()
        .find(|edge| edge.callee == "rootCmd.AddCommand")
        .expect("AddCommand edge");
    assert!(add.object_arguments().next().is_none());
}

#[test]
fn go_named_results_and_switch_initializers_are_local_bindings() {
    let summary = module_summaries(
        r#"package main
type Runner struct{}
type Other struct{}
var runner = Runner{}
func (Runner) Wipe() {}
func (Other) Wipe() {}
func named() (runner Other) {
    runner.Wipe()
    return
}
func switched() {
    switch runner := (Other{}); 1 {
    case 1:
        runner.Wipe()
    }
}
"#,
        Lang::Go,
        "cmd/main.go",
        ScopeKey::GoPackage {
            key: "example.com/app/cmd".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Go),
    );

    for function in ["named", "switched"] {
        let wipe = summary
            .functions
            .iter()
            .find(|entry| entry.name == function)
            .unwrap_or_else(|| panic!("missing {function} function"))
            .calls
            .iter()
            .find(|edge| edge.callee == "runner.Wipe")
            .unwrap_or_else(|| panic!("missing {function} receiver edge"));
        assert!(matches!(
            wipe.receiver_identity(),
            Some(ObjectIdentity::Class { name, .. }) if name == "Other"
        ));
    }
}

#[test]
fn go_function_literal_parameters_are_local_bindings() {
    let summary = module_summaries(
        r#"package main
import "github.com/spf13/cobra"
type Runner struct{}
var cmd = Runner{}
func (Runner) Wipe() {}
func attach() {
    root := &cobra.Command{RunE: func(cmd *cobra.Command, args []string) error {
        cmd.Wipe()
        return nil
    }}
    root.Execute()
}
"#,
        Lang::Go,
        "cmd/main.go",
        ScopeKey::GoPackage {
            key: "example.com/app/cmd".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Go),
    );
    let wipe = summary
        .functions
        .iter()
        .filter(|function| function.name.starts_with("func#"))
        .flat_map(|function| &function.calls)
        .find(|edge| edge.callee == "cmd.Wipe")
        .expect("literal parameter receiver edge");
    assert!(matches!(
        wipe.receiver_identity(),
        Some(ObjectIdentity::Class { name, .. }) if name == "cobra.Command"
    ));
    assert!(matches!(
        wipe.receiver.as_ref().and_then(|value| value.evidence.ty.as_ref()),
        Some(TypeRef::External { path }) if path == "github.com/spf13/cobra.Command"
    ));
}

#[test]
fn go_unknown_package_type_does_not_claim_the_current_file() {
    let summary = module_summaries(
        "package pkg\nvar store Store\nfunc Attach() { store.Wipe() }\n",
        Lang::Go,
        "pkg/attach.go",
        ScopeKey::GoPackage {
            key: "example.com/app/pkg".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Go),
    );
    let construction = summary
        .module_calls
        .iter()
        .find(|edge| edge.callee == "Store")
        .expect("Store declaration fact");
    assert_eq!(construction.result_type(), None);
    let wipe = summary
        .functions
        .iter()
        .find(|function| function.name == "Attach")
        .expect("Attach function")
        .calls
        .iter()
        .find(|edge| edge.callee == "store.Wipe")
        .expect("store receiver edge");
    assert!(matches!(
        wipe.receiver_identity(),
        Some(ObjectIdentity::ModuleBinding { .. })
    ));
    assert!(
        wipe.receiver
            .as_ref()
            .is_some_and(|value| value.evidence.ty.is_none())
    );
}

#[test]
fn java_declared_value_and_call_sites_do_not_collide() {
    let summary = module_summaries(
        "class App { static void main(String[] args) { App app; app.run(); Helper.other(); app.stop(); } void run() {} void stop() {} } class Helper { static void other() {} }",
        Lang::Java,
        "src/App.java",
        ScopeKey::Module {
            key: "src/App.java".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Java),
    );
    let calls = &summary.main_calls;
    let run = calls
        .iter()
        .find(|edge| edge.callee == "app.run")
        .expect("run edge");
    let other = calls
        .iter()
        .find(|edge| edge.callee == "Helper.other")
        .expect("other edge");
    let stop = calls
        .iter()
        .find(|edge| edge.callee == "app.stop")
        .expect("stop edge");
    assert_eq!(receiver_origin(run), receiver_origin(stop));
    assert_ne!(
        Some(receiver_origin(run)),
        other.origin_for_result(0).as_ref()
    );
    let edge_origins: Vec<_> = calls
        .iter()
        .map(|edge| edge.origin_for_result(0).expect("edge origin"))
        .collect();
    let unique: std::collections::HashSet<_> = edge_origins.iter().collect();
    assert_eq!(unique.len(), edge_origins.len());
}

#[test]
fn javascript_binding_uses_one_construction_origin() {
    let summary = module_summaries(
        "class App { start() {} stop() {} }\nconst app = new App();\napp.start();\napp.stop();\n",
        Lang::Js(SourceDialect::Js),
        "src/app.js",
        ScopeKey::Module {
            key: "src/app.js".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(
            &effinterp_engine::default_limits(),
            Lang::Js(SourceDialect::Js),
        ),
    );
    let receiver_origin = |callee: &str| {
        summary
            .module_calls
            .iter()
            .find(|edge| edge.callee == callee)
            .and_then(|edge| {
                edge.receiver
                    .as_ref()
                    .and_then(|value| value.evidence.origin.clone())
            })
            .unwrap_or_else(|| panic!("missing construction origin for {callee}"))
    };
    assert_eq!(receiver_origin("app.start"), receiver_origin("app.stop"));
}

#[test]
fn python_nested_constructor_argument_reuses_its_edge_origin() {
    let summary = module_summaries(
        "class Inner: pass\nclass Outer:\n    def __init__(self, inner): pass\nvalue = Outer(Inner())\n",
        Lang::Python,
        "pkg/models.py",
        ScopeKey::Module {
            key: "pkg.models".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(
            &effinterp_engine::default_limits(),
            Lang::Python,
        ),
    );
    let outer = summary
        .module_calls
        .iter()
        .find(|edge| edge.callee == "Outer")
        .expect("Outer constructor edge");
    let inner = summary
        .module_calls
        .iter()
        .find(|edge| edge.callee == "Inner")
        .expect("Inner constructor edge");
    let nested_origin = outer
        .object_arguments()
        .next()
        .and_then(|(argument, _)| argument.value.evidence.origin.as_ref())
        .expect("nested constructor argument");
    assert_eq!(Some(nested_origin), inner.origin_for_result(0).as_ref());
    assert_ne!(outer.origin_for_result(0), inner.origin_for_result(0));
}

#[test]
fn go_cobra_factories_and_anonymous_seed_fields_emit_constructor_facts() {
    let summary = module_summaries(
        r#"package main
import "github.com/spf13/cobra"
var rootCmd = &cobra.Command{Run: func(cmd *cobra.Command, args []string) {}}
func run(cmd *cobra.Command, args []string) {}
func makeCmd() *cobra.Command { return &cobra.Command{Run: run} }
func main() { rootCmd.Execute() }
"#,
        Lang::Go,
        "main.go",
        ScopeKey::GoPackage {
            key: "example.com/app".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Go),
    );
    let root = summary
        .module_calls
        .iter()
        .find(|edge| edge.callee == "cobra.Command")
        .expect("package Cobra constructor");
    let anonymous = root
        .callback_arguments()
        .find(|(argument, _)| argument.name.as_deref() == Some("Run"))
        .expect("anonymous Run seed");
    assert!(anonymous.1.starts_with("func#"));
    assert!(
        summary
            .functions
            .iter()
            .any(|function| function.name == anonymous.1)
    );

    let factory = summary
        .functions
        .iter()
        .find(|function| function.name == "makeCmd")
        .expect("factory function");
    let returned = factory
        .calls
        .iter()
        .find(|edge| edge.callee == "cobra.Command")
        .expect("returned Cobra constructor");
    assert!(matches!(
        returned.origin_for_result(0),
        Some(ValueOrigin::Site { .. })
    ));
    assert!(returned.callback_arguments().any(|(argument, function)| {
        argument.name.as_deref() == Some("Run") && function == "run"
    }));
}

#[test]
fn go_block_local_shadow_restores_the_package_binding() {
    let summary = module_summaries(
        "package pkg\ntype Runner struct{}\ntype Other struct{}\nvar runner = Runner{}\nfunc probe() {\n    { runner := Other{}; runner.Wipe() }\n    runner.Wipe()\n}\n",
        Lang::Go,
        "pkg/probe.go",
        ScopeKey::GoPackage {
            key: "example.com/app/pkg".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Go),
    );
    let calls: Vec<_> = summary
        .functions
        .iter()
        .find(|function| function.name == "probe")
        .expect("probe function")
        .calls
        .iter()
        .filter(|edge| edge.callee == "runner.Wipe")
        .collect();
    assert_eq!(calls.len(), 2);
    assert!(matches!(
        calls[0].receiver_identity(),
        Some(ObjectIdentity::Class { name, .. }) if name == "Other"
    ));
    assert!(matches!(
        calls[1].receiver_identity(),
        Some(ObjectIdentity::ModuleBinding {
            scope: ScopeKey::GoPackage { key },
            name,
        }) if key == "example.com/app/pkg" && name == "runner"
    ));
    assert!(matches!(
        calls[1]
            .receiver
            .as_ref()
            .and_then(|value| value.evidence.ty.as_ref()),
        Some(TypeRef::Repo { file, name }) if file == "pkg/probe.go" && name == "Runner"
    ));
}

#[test]
fn go_nested_call_sites_follow_lexical_source_order() {
    let summary = module_summaries(
        "package pkg\nfunc probe() { outer(inner()) }\n",
        Lang::Go,
        "pkg/probe.go",
        ScopeKey::GoPackage {
            key: "example.com/app/pkg".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), Lang::Go),
    );
    let calls = &summary
        .functions
        .iter()
        .find(|function| function.name == "probe")
        .expect("probe function")
        .calls;
    let ordinal = |callee: &str| {
        calls
            .iter()
            .find(|edge| edge.callee == callee)
            .and_then(|edge| edge.origin_for_result(0))
            .and_then(|origin| match origin {
                ValueOrigin::Site { ordinal, .. } => Some(ordinal),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing Site for {callee}"))
    };
    assert!(ordinal("outer") < ordinal("inner"));
}
