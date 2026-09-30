use super::*;
use effinterp_engine::{
    CallResult, FunctionEntry, Lang, ModuleSummary, RUST_DEFERRED_COMMAND, ScopeKey, Summary,
    ValueArgument, ValueOrigin, merge_arguments, module_summaries, positional_arguments,
};
use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryScope, Domain, ExecutionRealm, Modality, Operation,
    ResourceIdentity, SourceDialect,
};

fn param(n: &str) -> ResourceExpr {
    ResourceExpr::Parameter {
        name: n.to_string(),
    }
}
fn concrete(p: &str) -> ResourceExpr {
    ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: p.to_string(),
        },
    }
}
fn callback_arguments(
    resources: Vec<ResourceExpr>,
    name: Option<&str>,
    index: usize,
    function: &str,
) -> Vec<ValueArgument> {
    let mut arguments = positional_arguments(resources);
    merge_arguments(
        &mut arguments,
        vec![ValueArgument {
            name: name.map(str::to_string),
            index,
            value: SemanticValue::callable(function),
        }],
    );
    arguments
}
fn delete_effect(resource: ResourceExpr) -> Effect {
    Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new("filesystem.delete"),
        resource,
        attributes: Default::default(),
        modality: Modality::May,
        condition: None,
        realm: ExecutionRealm::Host,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance: vec![],
    }
}
fn module(path: &str, functions: Vec<FunctionEntry>, imports: Vec<ImportBinding>) -> ModuleFile {
    ModuleFile {
        path: path.to_string(),
        dir: path
            .rsplit_once('/')
            .map(|(d, _)| d.to_string())
            .unwrap_or_default(),
        lang: Lang::Python,
        summary: ModuleSummary {
            functions,
            module_calls: Vec::new(),
            imports,
            ..Default::default()
        },
        digest: "d".to_string(),
    }
}

fn go_module(path: &str, summary: ModuleSummary) -> ModuleFile {
    ModuleFile {
        path: path.to_string(),
        dir: String::new(),
        lang: Lang::Go,
        summary,
        digest: "d".to_string(),
    }
}

fn go_site(file: &str, function: &str, ordinal: u32) -> ValueOrigin {
    ValueOrigin::Site {
        file: file.to_string(),
        function: function.to_string(),
        ordinal,
        result_index: 0,
    }
}

#[test]
fn javascript_literal_import_callback_composes_its_namespace_call() {
    let wrapper_path = "bin/prettier.cjs";
    let target_path = "src/cli/index.js";
    let summary = module_summaries(
        r#"function run() {
                var dynamicImport = new Function("module", "return import(module)");
                return dynamicImport("../src/cli/index.js").then(cli => cli.run());
            }
            module.exports.__promise = run();"#,
        Lang::Js(SourceDialect::Js),
        wrapper_path,
        ScopeKey::Module {
            key: wrapper_path.to_string(),
        },
        &effinterp_engine::SummaryBudget::for_lang(
            &effinterp_engine::default_limits(),
            Lang::Js(SourceDialect::Js),
        ),
    );
    let target = module_summaries(
        "import { readFile } from 'fs/promises'; export function run() { readFile('input.txt'); }",
        Lang::Js(SourceDialect::Js),
        target_path,
        ScopeKey::Module {
            key: target_path.to_string(),
        },
        &effinterp_engine::SummaryBudget::for_lang(
            &effinterp_engine::default_limits(),
            Lang::Js(SourceDialect::Js),
        ),
    );
    let wrapper = ModuleFile {
        path: wrapper_path.to_string(),
        dir: "bin".to_string(),
        lang: Lang::Js(SourceDialect::Js),
        summary,
        digest: "wrapper".to_string(),
    };
    let target = ModuleFile {
        path: target_path.to_string(),
        dir: "src/cli".to_string(),
        lang: Lang::Js(SourceDialect::Js),
        summary: target,
        digest: "target".to_string(),
    };
    let mut registry = Registry::default();
    registry
        .files
        .insert(wrapper.path.clone(), wrapper.clone().into());
    registry.files.insert(target.path.clone(), target.into());
    assert!(
        wrapper
            .summary
            .module_calls
            .iter()
            .any(|call| call.callee == "run"),
        "wrapper roots: {:?}",
        wrapper.summary.module_calls
    );

    let callback_call = wrapper
        .function("run")
        .and_then(|function| {
            function
                .calls
                .iter()
                .find(|call| call.callee.contains("#dynamic-import"))
        })
        .expect("callback namespace call");
    assert!(matches!(
        registry
            .linker(wrapper.lang)
            .resolve_callee(&registry, &wrapper, &callback_call.callee),
        Resolution::Targets(_)
    ));
    assert_eq!(
        registry.files[target_path]
            .function("run")
            .expect("target run")
            .summary
            .effects
            .len(),
        1
    );

    let composition = compose_roots(
        &registry,
        &wrapper,
        wrapper_path,
        &wrapper.summary.module_calls,
    );
    assert!(
        composition.occurrence_effects.iter().any(|occurrence| {
            composition.effects[occurrence.effect].effect.operation.0 == "filesystem.read"
                && occurrence.source_file == target_path
        }),
        "literal import callback did not compose: {:?}",
        composition.boundaries
    );
}

#[test]
fn go_package_roots_run_initializers_then_inits_then_selected_main() {
    let called = |name: &str, path: &str| FunctionEntry {
        name: name.to_string(),
        summary: Summary {
            control_flow: Default::default(),
            effects: vec![delete_effect(concrete(path))],
            ..Default::default()
        },
        ..Default::default()
    };
    let effects = go_module(
        "effects.go",
        ModuleSummary {
            functions: vec![
                called("wipeOne", "/one"),
                called("wipeTwo", "/two"),
                called("finish", "/main-last"),
            ],
            ..Default::default()
        },
    );
    let init = go_module(
        "init.go",
        ModuleSummary {
            functions: vec![
                FunctionEntry {
                    name: "init#0".into(),
                    ..Default::default()
                },
                FunctionEntry {
                    name: "init#1".into(),
                    summary: Summary {
                        control_flow: Default::default(),
                        effects: vec![delete_effect(concrete("/direct-init"))],
                        ..Default::default()
                    },
                    ..Default::default()
                },
                FunctionEntry {
                    name: "init#2".into(),
                    ..Default::default()
                },
            ],
            module_calls: vec![
                CallEdge {
                    callee: "wipeOne".into(),
                    results: vec![CallResult::new(
                        0,
                        None,
                        Some(go_site("init.go", "init#0", 0)),
                        None,
                    )],
                    ..Default::default()
                },
                CallEdge {
                    callee: "wipeTwo".into(),
                    results: vec![CallResult::new(
                        0,
                        None,
                        Some(go_site("init.go", "init#2", 0)),
                        None,
                    )],
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
    );
    let entry = go_module(
        "main.go",
        ModuleSummary {
            main_calls: vec![CallEdge {
                callee: "finish".into(),
                results: vec![CallResult::new(
                    0,
                    None,
                    Some(go_site("main.go", "main", 0)),
                    None,
                )],
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let vars = go_module(
        "vars.go",
        ModuleSummary {
            module_effects: vec![Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new("environment.read"),
                resource: ResourceExpr::Environment {
                    name: "MODE".into(),
                },
                attributes: Default::default(),
                modality: Modality::May,
                condition: None,
                realm: ExecutionRealm::Host,
                execution: effinterp_proto::ExecutionNodeRef(0),
                provenance: Vec::new(),
            }],
            ..Default::default()
        },
    );
    let mut registry = Registry::default();
    for file in [effects, init, entry.clone(), vars] {
        registry.files.insert(file.path.clone(), file.into());
    }

    let walk: Vec<_> = compose(&registry, &entry, None)
        .effects
        .iter()
        .map(|effect| format!("{:?}", effect.effect.resource))
        .collect();
    let position = |needle: &str| {
        walk.iter()
            .position(|resource| resource.contains(needle))
            .unwrap_or_else(|| panic!("missing {needle} in {walk:?}"))
    };
    assert!(position("MODE") < position("/one"));
    assert!(position("/one") < position("/direct-init"));
    assert!(position("/direct-init") < position("/two"));
    assert!(position("/two") < position("/main-last"));
}

/// util.py:wipe(root,t) deletes join(root,t); app.py imports it and run()
/// calls wipe("/var/cache/app", name). Composition must produce
/// filesystem.delete join("/var/cache/app", <name>) across files.
#[test]
fn composes_cross_file_call_with_argument_substitution() {
    let wipe = FunctionEntry {
        name: "wipe".to_string(),
        summary: Summary {
            control_flow: Default::default(),
            params: vec!["root".into(), "t".into()],
            effects: vec![delete_effect(ResourceExpr::Join {
                parts: vec![param("root"), param("t")],
            })],
            effect_models: vec![],
            transfers: vec![],
            returns: None,
            boundaries: vec![],
            coverage: vec![(Domain::new("filesystem"), CoverageLevel::Partial)],
        },
        calls: vec![],
        ..Default::default()
    };
    let util = module("util.py", vec![wipe], vec![]);
    let app = module(
        "app.py",
        vec![],
        vec![ImportBinding {
            local: "wipe".into(),
            module: "util".into(),
            imported: Some("wipe".into()),
        }],
    );
    let mut reg = Registry::default();
    reg.files.insert("util.py".into(), util.into());
    reg.files.insert("app.py".into(), app.clone().into());
    reg.register_python_module("util", "util.py");

    let roots = vec![CallEdge {
        callee: "wipe".into(),
        arguments: positional_arguments(vec![concrete("/var/cache/app"), param("name")]),
        ..Default::default()
    }];
    let comp = compose_roots(&reg, &app, "app.py:run", &roots);

    assert_eq!(comp.effects.len(), 1);
    let e = &comp.effects[0];
    assert_eq!(e.effect.operation.0, "filesystem.delete");
    assert_eq!(comp.occurrence_effects[0].source_file, "util.py");
    assert_eq!(
        e.effect.resource,
        ResourceExpr::Join {
            parts: vec![concrete("/var/cache/app"), param("name")],
        }
    );
    assert_eq!(
        comp.occurrence_effects[0].path,
        vec!["app.py:run".to_string(), "util.py:wipe".to_string()]
    );
    assert_eq!(comp.deps, vec!["util.py".to_string()]);
    for suffix in ["name", ""] {
        let roots = vec![CallEdge {
            callee: "wipe".into(),
            arguments: positional_arguments(vec![
                concrete("/var/cache/app"),
                ResourceExpr::Literal {
                    value: suffix.into(),
                },
            ]),
            ..Default::default()
        }];
        let comp = compose_roots(&reg, &app, "app.py:run", &roots);
        assert_eq!(comp.effects.len(), 1);
        assert_eq!(
            comp.effects[0].effect.resource,
            concrete(&format!("/var/cache/app{suffix}"))
        );
    }
}

#[test]
fn composes_parameterized_boundary_resources() {
    let opaque = FunctionEntry {
        name: "opaque".into(),
        summary: Summary {
            control_flow: Default::default(),
            params: vec!["root".into()],
            boundaries: vec![Boundary {
                reason: BoundaryReason::DYNAMIC_CALL,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                domains: vec![Domain::new("filesystem")],
                affected_resource: Some(param("root")),
                callee: None,
                provenance: Vec::new(),
                limit: None,
                detail: None,
            }],
            coverage: vec![(Domain::new("filesystem"), CoverageLevel::Partial)],
            ..Default::default()
        },
        ..Default::default()
    };
    let util = module("util.py", vec![opaque], vec![]);
    let app = module(
        "app.py",
        vec![],
        vec![ImportBinding {
            local: "opaque".into(),
            module: "util".into(),
            imported: Some("opaque".into()),
        }],
    );
    let mut reg = Registry::default();
    reg.files.insert("util.py".into(), util.into());
    reg.files.insert("app.py".into(), app.clone().into());
    reg.register_python_module("util", "util.py");

    let roots = [CallEdge {
        callee: "opaque".into(),
        arguments: positional_arguments(vec![concrete("/var/cache")]),
        ..Default::default()
    }];
    let roots = vec![roots[0].clone(); 8];
    let comp = compose_roots(&reg, &app, "app.py:run", &roots);

    assert_eq!(comp.boundaries.len(), 1);
    assert_eq!(comp.boundaries[0].occurrences, 1);
    assert_eq!(comp.boundaries[0].exemplar_paths.len(), 1);
    // Only the first call enters the function; seven replay its memoized boundary.
    assert_eq!(comp.budget.steps, 17);
    assert_eq!(
        comp.boundaries[0].affected_resource,
        Some(concrete("/var/cache"))
    );
}

#[test]
fn unresolved_import_is_a_boundary_not_silent() {
    let app = module(
        "app.py",
        vec![],
        vec![ImportBinding {
            local: "thing".into(),
            module: "external_pkg".into(),
            imported: Some("thing".into()),
        }],
    );
    let mut reg = Registry::default();
    reg.files.insert("app.py".into(), app.clone().into());
    let roots = vec![CallEdge {
        callee: "thing".into(),
        arguments: positional_arguments(Vec::<ResourceExpr>::new()),
        ..Default::default()
    }];
    let comp = compose_roots(&reg, &app, "app.py", &roots);
    assert!(comp.effects.is_empty());
    assert!(comp.boundaries.iter().any(|b| b.reason == "cross_module"));
}

#[test]
fn cross_file_recursion_converges() {
    let f = FunctionEntry {
        name: "f".into(),
        summary: Summary {
            control_flow: Default::default(),
            params: vec![],
            effects: vec![delete_effect(concrete("/x"))],
            effect_models: vec![],
            transfers: vec![],
            returns: None,
            boundaries: vec![],
            coverage: vec![],
        },
        calls: vec![CallEdge {
            callee: "g".into(),
            arguments: positional_arguments(Vec::<ResourceExpr>::new()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let g = FunctionEntry {
        name: "g".into(),
        summary: Summary {
            control_flow: Default::default(),
            params: vec![],
            effects: vec![delete_effect(concrete("/y"))],
            effect_models: vec![],
            transfers: vec![],
            returns: None,
            boundaries: vec![],
            coverage: vec![],
        },
        calls: vec![CallEdge {
            callee: "f".into(),
            arguments: positional_arguments(Vec::<ResourceExpr>::new()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let a = module(
        "a.py",
        vec![f],
        vec![ImportBinding {
            local: "g".into(),
            module: "b".into(),
            imported: Some("g".into()),
        }],
    );
    let b = module(
        "b.py",
        vec![g],
        vec![ImportBinding {
            local: "f".into(),
            module: "a".into(),
            imported: Some("f".into()),
        }],
    );
    let mut reg = Registry::default();
    reg.files.insert("a.py".into(), a.clone().into());
    reg.files.insert("b.py".into(), b.into());
    reg.register_python_module("a", "a.py");
    reg.register_python_module("b", "b.py");

    let roots = vec![CallEdge {
        callee: "g".into(),
        arguments: positional_arguments(Vec::<ResourceExpr>::new()),
        ..Default::default()
    }];
    let comp = compose_roots(&reg, &a, "a.py:f", &roots);
    assert!(!comp.boundaries.iter().any(|b| b.reason == "recursive_call"));
    assert_eq!(comp.recursion_truncations, 0);
    for resource in ["/x", "/y"] {
        assert!(
            comp.effects
                .iter()
                .any(|effect| effect.effect.resource == concrete(resource))
        );
    }
    assert!(comp.effects.len() < 10);
}

#[test]
fn converged_recursive_walk_replays_under_sibling_paths() {
    let function = |name: &str, effect: &str, callee: Option<&str>| FunctionEntry {
        name: name.into(),
        summary: Summary {
            control_flow: Default::default(),
            params: vec![],
            effects: vec![delete_effect(concrete(effect))],
            effect_models: vec![],
            transfers: vec![],
            returns: None,
            boundaries: vec![],
            coverage: vec![],
        },
        calls: callee
            .map(|callee| CallEdge {
                callee: callee.into(),
                arguments: positional_arguments(Vec::<ResourceExpr>::new()),
                ..Default::default()
            })
            .into_iter()
            .collect(),
        ..Default::default()
    };
    let app = module(
        "app.py",
        vec![],
        vec![
            ImportBinding {
                local: "x".into(),
                module: "x".into(),
                imported: Some("x".into()),
            },
            ImportBinding {
                local: "x2".into(),
                module: "x2".into(),
                imported: Some("x2".into()),
            },
            ImportBinding {
                local: "b".into(),
                module: "b".into(),
                imported: Some("b".into()),
            },
        ],
    );
    let x = module(
        "x.py",
        vec![function("x", "/from_x", Some("a"))],
        vec![ImportBinding {
            local: "a".into(),
            module: "a".into(),
            imported: Some("a".into()),
        }],
    );
    let x2 = module(
        "x2.py",
        vec![function("x2", "/from_x2", Some("a"))],
        vec![ImportBinding {
            local: "a".into(),
            module: "a".into(),
            imported: Some("a".into()),
        }],
    );
    let a = module(
        "a.py",
        vec![function("a", "/from_a", Some("b"))],
        vec![ImportBinding {
            local: "b".into(),
            module: "b".into(),
            imported: Some("b".into()),
        }],
    );
    let b = module(
        "b.py",
        vec![function("b", "/from_b", Some("c"))],
        vec![ImportBinding {
            local: "c".into(),
            module: "c".into(),
            imported: Some("c".into()),
        }],
    );
    let c = module(
        "c.py",
        vec![function("c", "/from_c", Some("a"))],
        vec![ImportBinding {
            local: "a".into(),
            module: "a".into(),
            imported: Some("a".into()),
        }],
    );
    let mut registry = Registry::default();
    for file in [&app, &x, &x2, &a, &b, &c] {
        registry
            .files
            .insert(file.path.clone(), file.clone().into());
        registry.register_python_module(file.path.trim_end_matches(".py"), &file.path);
    }
    let roots = ["x", "x2", "b"].map(|callee| CallEdge {
        callee: callee.into(),
        arguments: positional_arguments(Vec::<ResourceExpr>::new()),
        ..Default::default()
    });

    let composition = compose_roots(&registry, &app, "app.py", &roots);
    assert!(
        !composition
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == BoundaryReason::RECURSIVE_CALL)
    );
    assert_eq!(composition.recursion_truncations, 0);
    let a_effect = composition
        .occurrence_effects
        .iter()
        .find(|occurrence| occurrence.source_file == "a.py")
        .map(|occurrence| occurrence.effect)
        .expect("a.py effect");
    let a_paths = composition
        .occurrence_effects
        .iter()
        .filter(|occurrence| occurrence.effect == a_effect)
        .map(|occurrence| occurrence.path.as_slice())
        .collect::<Vec<_>>();
    assert_eq!(
        a_paths
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        a_paths.len()
    );
    let sibling_paths = |caller: &str| {
        a_paths
            .iter()
            .filter(|path| path.get(1).is_some_and(|step| step == caller))
            .map(|path| &path[2..])
            .collect::<Vec<_>>()
    };
    assert!(!sibling_paths("x.py:x").is_empty());
    assert_eq!(sibling_paths("x.py:x"), sibling_paths("x2.py:x2"));
    assert!(a_paths.iter().any(|path| {
        *path
            == [
                "app.py".to_string(),
                "b.py:b".to_string(),
                "c.py:c".to_string(),
                "a.py:a".to_string(),
            ]
    }));
}

fn ruby_module(
    path: &str,
    functions: Vec<FunctionEntry>,
    imports: Vec<ImportBinding>,
) -> ModuleFile {
    ModuleFile {
        path: path.to_string(),
        dir: path
            .rsplit_once('/')
            .map(|(d, _)| d.to_string())
            .unwrap_or_default(),
        lang: Lang::Ruby,
        summary: ModuleSummary {
            functions,
            module_calls: Vec::new(),
            imports,
            ..Default::default()
        },
        digest: "d".to_string(),
    }
}

/// Ruby's flat namespace: `require_relative 'util'` pulls util.rb's methods
/// into app.rb, so a bare `wipe(...)` call resolves cross-file.
#[test]
fn ruby_flat_require_composes_a_bare_call() {
    let wipe = FunctionEntry {
        name: "wipe".into(),
        summary: Summary {
            control_flow: Default::default(),
            params: vec!["p".into()],
            effects: vec![delete_effect(param("p"))],
            effect_models: vec![],
            transfers: vec![],
            returns: None,
            boundaries: vec![],
            coverage: vec![(Domain::new("filesystem"), CoverageLevel::Partial)],
        },
        calls: vec![],
        ..Default::default()
    };
    let util = ruby_module("util.rb", vec![wipe], vec![]);
    // require_relative 'util' -> a whole-module import (imported: None).
    let app = ruby_module(
        "app.rb",
        vec![],
        vec![ImportBinding {
            local: "util".into(),
            module: "util".into(),
            imported: None,
        }],
    );
    let mut reg = Registry::default();
    reg.files.insert("util.rb".into(), util.into());
    reg.files.insert("app.rb".into(), app.clone().into());

    // A bare call `wipe("/var/cache")` — no receiver, not a named import.
    let roots = vec![CallEdge {
        callee: "wipe".into(),
        arguments: positional_arguments(vec![concrete("/var/cache")]),
        ..Default::default()
    }];
    let comp = compose_roots(&reg, &app, "app.rb", &roots);
    assert_eq!(comp.effects.len(), 1);
    assert_eq!(comp.effects[0].effect.operation.0, "filesystem.delete");
    assert_eq!(comp.occurrence_effects[0].source_file, "util.rb");
    assert_eq!(comp.effects[0].effect.resource, concrete("/var/cache"));
    assert_eq!(comp.occurrence_effects[0].assurance, Assurance::Heuristic);
}

/// A local function passed as an argument and invoked through the parameter
/// composes the passed function's effect (httpie: `raw_main(main_program=program)`
/// then `main_program(...)` inside `raw_main`).
#[test]
fn callback_parameter_composes_the_passed_function() {
    let program = FunctionEntry {
        name: "program".into(),
        summary: Summary {
            control_flow: Default::default(),
            params: vec!["p".into()],
            effects: vec![delete_effect(param("p"))],
            effect_models: vec![],
            transfers: vec![],
            returns: None,
            boundaries: vec![],
            coverage: vec![(Domain::new("filesystem"), CoverageLevel::Partial)],
        },
        calls: vec![],
        ..Default::default()
    };
    let raw_main = FunctionEntry {
        name: "raw_main".into(),
        summary: Summary {
            control_flow: Default::default(),
            params: vec!["main_program".into(), "p".into()],
            effects: vec![],
            effect_models: vec![],
            transfers: vec![],
            returns: None,
            boundaries: vec![],
            coverage: vec![],
        },
        calls: vec![CallEdge {
            callee: "main_program".into(),
            arguments: positional_arguments(vec![param("p")]),
            ..Default::default()
        }],
        ..Default::default()
    };
    let app = module("app.py", vec![program, raw_main], vec![]);
    let mut reg = Registry::default();
    reg.files.insert("app.py".into(), app.clone().into());

    // raw_main(main_program=program, p="/var/cache") — keyword callback.
    let roots = vec![CallEdge {
        callee: "raw_main".into(),
        arguments: callback_arguments(
            vec![param("unused"), concrete("/var/cache")],
            Some("main_program"),
            0,
            "program",
        ),
        ..Default::default()
    }];
    let comp = compose_roots(&reg, &app, "app.py:main", &roots);
    assert_eq!(comp.effects.len(), 1);
    assert_eq!(comp.effects[0].effect.operation.0, "filesystem.delete");
    assert_eq!(comp.occurrence_effects[0].source_file, "app.py");
    assert_eq!(comp.effects[0].effect.resource, concrete("/var/cache"));
    assert_eq!(
        comp.occurrence_effects[0].path,
        vec![
            "app.py:main".to_string(),
            "app.py:raw_main".to_string(),
            "app.py:program".to_string(),
        ]
    );
}

fn cmd_callback_module() -> ModuleFile {
    let cmd = FunctionEntry {
        name: "_cmd".into(),
        summary: Summary {
            control_flow: Default::default(),
            params: vec!["args".into()],
            effects: vec![delete_effect(concrete("/tmp/venv"))],
            effect_models: vec![],
            transfers: vec![],
            returns: None,
            boundaries: vec![],
            coverage: vec![(Domain::new("filesystem"), CoverageLevel::Partial)],
        },
        calls: vec![],
        ..Default::default()
    };
    module("app.py", vec![cmd], vec![])
}

/// Direct callback passing (`asyncio.run(main)`) is not registration: the
/// callee itself invokes the function, no dispatch trigger required.
#[test]
fn direct_callback_passing_needs_no_trigger() {
    let app = cmd_callback_module();
    let mut reg = Registry::default();
    reg.files.insert("app.py".into(), app.clone().into());

    let roots = vec![CallEdge {
        callee: "asyncio.run".into(),
        arguments: callback_arguments(vec![], None, 0, "_cmd"),
        ..Default::default()
    }];
    let comp = compose_roots(&reg, &app, "app.py:main", &roots);
    assert_eq!(comp.effects.len(), 1);
    assert_eq!(comp.effects[0].effect.operation.0, "filesystem.delete");
}

/// An fn_arg that names no function of the calling file never dispatches.
#[test]
fn unresolved_sink_ignores_unknown_callback_name() {
    let app = module("app.py", vec![], vec![]);
    let mut reg = Registry::default();
    reg.files.insert("app.py".into(), app.clone().into());

    let roots = vec![CallEdge {
        callee: "p.set_defaults".into(),
        arguments: callback_arguments(vec![], Some("func"), 0, "not_a_function"),
        ..Default::default()
    }];
    let comp = compose_roots(&reg, &app, "app.py:build", &roots);
    assert!(comp.effects.is_empty());
}

/// Positional form: `apply(work, path)` binds `fn` by index and `fn(...)`
/// inside `apply` resolves to `work`.
#[test]
fn callback_parameter_positional_binds_by_index() {
    let work = FunctionEntry {
        name: "work".into(),
        summary: Summary {
            control_flow: Default::default(),
            params: vec!["p".into()],
            effects: vec![delete_effect(param("p"))],
            effect_models: vec![],
            transfers: vec![],
            returns: None,
            boundaries: vec![],
            coverage: vec![],
        },
        calls: vec![],
        ..Default::default()
    };
    let apply = FunctionEntry {
        name: "apply".into(),
        summary: Summary {
            control_flow: Default::default(),
            params: vec!["fn".into(), "p".into()],
            effects: vec![],
            effect_models: vec![],
            transfers: vec![],
            returns: None,
            boundaries: vec![],
            coverage: vec![],
        },
        calls: vec![CallEdge {
            callee: "fn".into(),
            arguments: positional_arguments(vec![param("p")]),
            ..Default::default()
        }],
        ..Default::default()
    };
    let app = module("app.py", vec![work, apply], vec![]);
    let mut reg = Registry::default();
    reg.files.insert("app.py".into(), app.clone().into());

    let roots = vec![CallEdge {
        callee: "apply".into(),
        arguments: callback_arguments(vec![param("unused"), concrete("/tmp/x")], None, 0, "work"),
        ..Default::default()
    }];
    let comp = compose_roots(&reg, &app, "app.py:run", &roots);
    assert_eq!(comp.effects.len(), 1);
    assert_eq!(comp.effects[0].effect.resource, concrete("/tmp/x"));
}

/// Importing a module executes its top level, and `from pkg import name`
/// also loads the `pkg.name` submodule. A constructor call there resolves
/// to `Class.__init__`.
#[test]
fn import_time_constructor_reaches_init() {
    let init = FunctionEntry {
        name: "ConfigManager.__init__".into(),
        summary: Summary {
            control_flow: Default::default(),
            params: vec!["self".into()],
            effects: vec![delete_effect(concrete("/etc/ansible.cfg"))],
            effect_models: vec![],
            transfers: vec![],
            returns: None,
            boundaries: vec![],
            coverage: vec![],
        },
        calls: vec![],
        ..Default::default()
    };
    let manager = module("manager.py", vec![init], vec![]);
    let mut constants = module(
        "constants.py",
        vec![],
        vec![ImportBinding {
            local: "ConfigManager".into(),
            module: "manager".into(),
            imported: Some("ConfigManager".into()),
        }],
    );
    constants.summary.module_calls = vec![CallEdge {
        callee: "ConfigManager".into(),
        arguments: positional_arguments(Vec::<ResourceExpr>::new()),
        ..Default::default()
    }];
    let playbook = module(
        "playbook.py",
        vec![],
        vec![ImportBinding {
            local: "C".into(),
            module: "ansible".into(),
            imported: Some("constants".into()),
        }],
    );
    let pkg = module("ansible/__init__.py", vec![], vec![]);
    let mut reg = Registry::default();
    reg.files.insert("manager.py".into(), manager.into());
    reg.files.insert("constants.py".into(), constants.into());
    reg.files
        .insert("playbook.py".into(), playbook.clone().into());
    reg.files.insert("ansible/__init__.py".into(), pkg.into());
    reg.register_python_module("manager", "manager.py");
    reg.register_python_module("ansible", "ansible/__init__.py");
    reg.register_python_module("ansible.constants", "constants.py");

    let comp = compose(&reg, &playbook, None);
    assert!(
        comp.occurrence_effects
            .iter()
            .any(
                |e| comp.effects[e.effect].effect.operation.0 == "filesystem.delete"
                    && e.source_file == "manager.py"
            ),
        "import-time ConfigManager() should reach __init__, got {:?}",
        comp.effects
            .iter()
            .map(|e| &e.effect.operation.0)
            .collect::<Vec<_>>()
    );
}

/// Deferred `Command` specialization is claimed from the frontend's explicit
/// marker, never from a process effect that merely lacks an executable.
#[test]
fn only_the_deferred_command_marker_is_specialized() {
    let composed = |executable: &str| {
        let spawn = FunctionEntry {
            name: "spawn".into(),
            summary: Summary {
                control_flow: Default::default(),
                effects: vec![Effect {
                    request_assurance: effinterp_proto::RequestAssurance::Conservative,
                    id: Default::default(),
                    operation: Operation::new("process.exec"),
                    resource: ResourceExpr::Concrete {
                        identity: ResourceIdentity::Process {
                            executable: executable.to_string(),
                            path: None,
                            argv: vec![
                                ResourceExpr::Literal {
                                    value: "less".into(),
                                },
                                ResourceExpr::Literal { value: "-R".into() },
                            ],
                            cwd: None,
                        },
                    },
                    attributes: Default::default(),
                    modality: Modality::May,
                    condition: None,
                    realm: ExecutionRealm::Host,
                    execution: effinterp_proto::ExecutionNodeRef(0),
                    provenance: vec![],
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let mut app = module("app.py", vec![spawn], vec![]);
        app.summary.module_calls = vec![CallEdge {
            callee: "spawn".into(),
            ..Default::default()
        }];
        let mut reg = Registry::default();
        reg.files.insert("app.py".into(), app.clone().into());
        compose(&reg, &app, None)
            .effects
            .iter()
            .filter_map(|composed| match &composed.effect.resource {
                ResourceExpr::Concrete {
                    identity:
                        ResourceIdentity::Process {
                            executable, argv, ..
                        },
                } => Some((executable.clone(), argv.len())),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    assert!(
        composed(RUST_DEFERRED_COMMAND)
            .iter()
            .any(|(executable, argv)| executable == "less" && *argv == 1),
        "a marked template resolves its executable and keeps the remaining argument"
    );
    let unmarked = composed("");
    assert!(
        unmarked.iter().all(|(executable, _)| executable != "less"),
        "an unmarked process effect must not be specialized, got {unmarked:?}"
    );
}

/// A bare call with no matching required file stays unresolved (conservative:
/// Ruby resolution must not invent a target).
#[test]
fn ruby_bare_call_without_a_matching_require_is_not_resolved() {
    let app = ruby_module("app.rb", vec![], vec![]);
    let mut reg = Registry::default();
    reg.files.insert("app.rb".into(), app.clone().into());
    let roots = vec![CallEdge {
        callee: "mystery".into(),
        arguments: positional_arguments(Vec::<ResourceExpr>::new()),
        ..Default::default()
    }];
    let comp = compose_roots(&reg, &app, "app.rb", &roots);
    assert!(comp.effects.is_empty());
}

// An unconditional occurrence makes the aggregate unconditional even when its
// evidence is beyond the retention cap; removing it must restore the summary.
#[test]
fn composed_condition_summary_tracks_unconditional_occurrences() {
    let mut composition = Composition::default();
    composition.budget.limits.max_composed_effects = 1;
    let mut effect = delete_effect(concrete("/shared"));
    effect.condition = Some(effinterp_proto::Condition::Widened);
    let conditional = EffectOccurrence {
        effect,
        source_file: "leaf.py".into(),
        path: vec!["app.py".into(), "leaf.py:run".into()],
        assurance: Assurance::Exact,
        via_dispatch: None,
    };
    assert!(push_bound_composed_effect(
        &mut composition,
        conditional.clone()
    ));
    let mut unconditional = conditional.clone();
    unconditional.effect.condition = None;
    assert!(push_bound_composed_effect(
        &mut composition,
        unconditional.clone()
    ));
    assert_eq!(composition.effects.len(), 1);
    assert_eq!(composition.effects[0].effect.condition, None);
    assert_eq!(composition.effects[0].occurrences, 2);
    remove_composed_occurrence(&mut composition, 1);
    assert_eq!(
        composition.effects[0].effect.condition,
        conditional.effect.condition
    );
    composition.budget.limits.max_composed_occurrences = 1;
    assert!(push_bound_composed_effect(&mut composition, unconditional));
    assert_eq!(composition.effects[0].effect.condition, None);
    assert_eq!(composition.effects[0].occurrences, 2);
    assert_eq!(composition.occurrence_effects.len(), 1);
    assert_eq!(
        composition.occurrence_effects[0].condition,
        conditional.effect.condition
    );
}

#[test]
fn request_assurance_survives_composition_without_merging_or_uncertain_promotion() {
    use effinterp_proto::RequestAssurance::{Conservative, Exact};
    let effect = EffectOccurrence {
        effect: delete_effect(concrete("/selected")),
        source_file: "leaf.py".into(),
        path: vec!["app.py".into(), "leaf.py:run".into()],
        assurance: Assurance::Exact,
        via_dispatch: None,
    };
    let mut certified = effect.clone();
    certified.effect.request_assurance = Exact;
    let mut composition = Composition::default();
    assert!(push_bound_composed_effect(&mut composition, effect));
    assert!(push_bound_composed_effect(
        &mut composition,
        certified.clone()
    ));
    assert_eq!(composition.effects.len(), 2);
    assert_ne!(
        composition.effects[0].effect.id,
        composition.effects[1].effect.id
    );
    assert_eq!(
        composition
            .effect_evidence()
            .map(|(effect, _, _)| effect.request_assurance)
            .collect::<Vec<_>>(),
        vec![Conservative, Exact]
    );

    for uncertain in [Assurance::Alternatives, Assurance::Heuristic] {
        let mut candidate = certified.clone();
        candidate.assurance = uncertain;
        let mut composition = Composition::default();
        assert!(push_bound_composed_effect(&mut composition, candidate));
        assert_eq!(
            composition.effects[0].effect.request_assurance,
            Conservative
        );
    }
    certified.effect.condition = Some(effinterp_proto::Condition::Widened);
    let mut composition = Composition::default();
    assert!(push_bound_composed_effect(&mut composition, certified));
    assert_eq!(
        composition.effects[0].effect.request_assurance,
        Conservative
    );
}
