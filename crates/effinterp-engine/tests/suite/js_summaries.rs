//! Function summaries in the JS/TS frontend: a call substitutes the caller's
//! argument expressions for the callee's parameters, so effects specialize per
//! call site and thread across the local call graph.

use effinterp_engine::{Engine, Lang, ScopeKey, module_summaries};
use effinterp_proto::{
    Plan, ResourceExpr, ResourceIdentity, SourceDialect, Subject, validate_plan,
};

fn js(source: &str) -> Plan {
    analyze(source, SourceDialect::Js)
}

fn ts(source: &str) -> Plan {
    analyze(source, SourceDialect::Ts)
}

fn analyze(source: &str, dialect: SourceDialect) -> Plan {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Source {
            language: "js".into(),
            source: source.to_string(),
            dialect: Some(dialect),
            cwd: Some("/app".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn has(plan: &Plan, op: &str, path: &str) -> bool {
    plan.effects.iter().any(|e| {
        e.operation.0 == op
            && matches!(&e.resource,
                ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: p } } if p == path)
    })
}

fn ops(plan: &Plan) -> Vec<&str> {
    plan.effects
        .iter()
        .map(|e| e.operation.0.as_str())
        .collect()
}

/// Parts of the single filesystem.delete's Join resource, rendered as
/// concrete-path or `<sym>`, for asserting parameter substitution.
fn delete_join_parts(plan: &Plan) -> Vec<String> {
    let e = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .expect("a filesystem.delete effect");
    match &e.resource {
        ResourceExpr::Join { parts } => parts
            .iter()
            .map(|p| match p {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } => path.clone(),
                ResourceExpr::Unresolved { .. } => "<sym>".to_string(),
                other => format!("{other:?}"),
            })
            .collect(),
        other => panic!("expected a Join delete resource, got {other:?}"),
    }
}

#[test]
fn call_substitutes_arguments_into_callee_effects() {
    let plan = js(r#"
        const fs = require('fs'); const path = require('path');
        function wipe(root, t) { fs.rmSync(path.join(root, t), { recursive: true }); }
        wipe('/tmp/cache', name);
    "#);
    assert_eq!(delete_join_parts(&plan), vec!["/tmp/cache", "<sym>"]);
    assert!(ops(&plan).contains(&"filesystem.delete"));
}

#[test]
fn copy_effects_survive_composition_with_independent_resources() {
    let plan = js(r#"
        const fs = require('fs');
        function copy(source, destination) { fs.copyFileSync(source, destination); }
        function stage(input, output) { copy(input, output); }
        stage('./scripts/input.js', `./build/${name}.js`);
    "#);

    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0.starts_with("filesystem"))
            .count(),
        2
    );
    assert!(has(&plan, "filesystem.read", "/app/scripts/input.js"));
    let write = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.write")
        .expect("a destination write");
    let ResourceExpr::Join { parts } = &write.resource else {
        panic!("expected a symbolic destination, got {:?}", write.resource);
    };
    assert!(matches!(
        parts.first(),
        Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        }) if path == "/app/build"
    ));
    assert!(
        parts
            .iter()
            .any(|part| matches!(part, ResourceExpr::Unresolved { .. }))
    );
}

#[test]
fn uncalled_summarized_function_is_not_executed() {
    let plan = js(r#"
        const fs = require('fs');
        function wipe(root) { fs.rmSync(root); }
        console.log('hi');
    "#);
    assert!(!ops(&plan).contains(&"filesystem.delete"));
}

#[test]
fn called_function_process_receiver_requires_runtime_evidence() {
    let real = ts(r#"
        function defaults() { resolveDefaults(process.env) }
        defaults()
    "#);
    assert!(ops(&real).contains(&"environment.read"));

    for source in [
        "function defaults({ process }) { resolveDefaults(process.env) }; defaults(fake)",
        "function defaults(...process) { resolveDefaults(process.env) }; defaults(fake)",
    ] {
        assert!(!ops(&ts(source)).contains(&"environment.read"), "{source}");
    }
}

#[test]
fn called_function_uses_lexical_process_receiver_evidence() {
    let shadowed_module = js(r#"
        const process = { env: { SECRET: 'fake' } }
        function readSecret() { return process.env.SECRET }
        function run() {
            const process = require('node:process')
            readSecret()
        }
        run()
    "#);
    assert!(!ops(&shadowed_module).contains(&"environment.read"));
    assert!(
        shadowed_module
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "partial_analysis")
    );

    let runtime_module = js(r#"
        function readSecret() { return process.env.SECRET }
        function run() {
            const process = { env: { SECRET: 'fake' } }
            readSecret()
        }
        run()
    "#);
    assert!(ops(&runtime_module).contains(&"environment.read"));
}

#[test]
fn direct_parameter_argument_is_substituted() {
    let plan = js(r#"
        const fs = require('fs');
        function del(p) { fs.unlinkSync(p); }
        del('/var/data/x');
    "#);
    assert!(has(&plan, "filesystem.delete", "/var/data/x"));
}

#[test]
fn called_twice_specializes_each_call() {
    let plan = js(r#"
        const fs = require('fs');
        function del(p) { fs.rmSync(p); }
        del('/a'); del('/b');
    "#);
    assert!(has(&plan, "filesystem.delete", "/a"));
    assert!(has(&plan, "filesystem.delete", "/b"));
}

#[test]
fn transitive_call_chain_threads_arguments() {
    let plan = js(r#"
        const fs = require('fs');
        function del(p) { fs.rmSync(p); }
        function mid(a) { del(a); }
        function outer(b) { mid(b); }
        outer('/deep/target');
    "#);
    assert!(has(&plan, "filesystem.delete", "/deep/target"));
}

#[test]
fn recursion_terminates() {
    let plan = js(r#"
        const fs = require('fs');
        function loop(p) { fs.rmSync(p); loop(p); }
        loop('/x');
    "#);
    validate_plan(&plan).unwrap();
    assert!(has(&plan, "filesystem.delete", "/x"));
}

#[test]
fn fewer_arguments_leave_parameters_symbolic() {
    let plan = js(r#"
        const fs = require('fs'); const path = require('path');
        function wipe(root, t) { fs.rmSync(path.join(root, t)); }
        wipe('/only');
    "#);
    assert_eq!(delete_join_parts(&plan), vec!["/only", "<sym>"]);
}

#[test]
fn ts_summary_substitution_ignores_annotations() {
    let plan = ts(r#"
        import { rmSync } from 'fs';
        function wipe(root: string): void { rmSync(root); }
        wipe('/ts/target');
    "#);
    assert!(has(&plan, "filesystem.delete", "/ts/target"));
}

#[test]
fn erased_types_do_not_change_the_canonical_js_graph() {
    let javascript = r#"
        import { rmSync } from 'fs';
        function wipe(path        )       { rmSync(path); }
        wipe('/same');
    "#;
    let typescript = r#"
        import { rmSync } from 'fs';
        function wipe(path: string): void { rmSync(path); }
        wipe('/same');
    "#;
    let javascript = js(javascript);
    let typescript = ts(typescript);
    assert_eq!(javascript.effects.len(), typescript.effects.len());
    for (javascript, typescript) in javascript.effects.iter().zip(&typescript.effects) {
        // Source text and dialect participate in identity even when types erase.
        assert_ne!(javascript.id, typescript.id);
        let mut typescript = typescript.clone();
        typescript.id = javascript.id.clone();
        assert_eq!(javascript, &typescript);
    }
    assert_eq!(javascript.boundaries, typescript.boundaries);
    assert_eq!(javascript.provenance, typescript.provenance);
    assert_eq!(
        javascript
            .causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .nodes
            .iter()
            .map(|node| (&node.occurrence, node.execution, &node.realm, node.modality))
            .collect::<Vec<_>>(),
        typescript
            .causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .nodes
            .iter()
            .map(|node| (&node.occurrence, node.execution, &node.realm, node.modality))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        javascript
            .causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .edges
            .iter()
            .map(|edge| (edge.reason, edge.modality))
            .collect::<Vec<_>>(),
        typescript
            .causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .edges
            .iter()
            .map(|edge| (edge.reason, edge.modality))
            .collect::<Vec<_>>()
    );
    assert_eq!(javascript.coverage, typescript.coverage);
}

#[test]
fn deterministic_across_runs() {
    let source = r#"
        const fs = require('fs');
        function del(p) { fs.rmSync(p); }
        del('/a'); del('/b');
    "#;
    let a = effinterp_proto::canonical_json(&js(source));
    let b = effinterp_proto::canonical_json(&js(source));
    assert_eq!(a, b);
}

#[test]
fn environment_mutations_are_captured_in_function_summaries() {
    let source = r#"
        function configure() {
            const values = { B: "2" };
            delete process.env.DEBUG;
            Object.assign(process.env, { A: "1" }, values);
        }
    "#;
    let summary = module_summaries(
        source,
        Lang::Js(SourceDialect::Js),
        "src/config.js",
        ScopeKey::Module {
            key: "src/config.js".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(
            &effinterp_engine::default_limits(),
            Lang::Js(SourceDialect::Js),
        ),
    );
    let configure = summary
        .functions
        .iter()
        .find(|function| function.name == "configure")
        .unwrap();
    let is_env_name = |effect: &effinterp_proto::Effect, expected: &str| {
        matches!(&effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name },
            } | ResourceExpr::Environment { name } if name == expected)
    };
    for name in ["DEBUG", "A", "B"] {
        assert!(configure.summary.effects.iter().any(|effect| {
            effect.operation.0 == "environment.write" && is_env_name(effect, name)
        }));
    }
    let deleted = configure
        .summary
        .effects
        .iter()
        .find(|effect| is_env_name(effect, "DEBUG"))
        .unwrap();
    assert_eq!(
        deleted.attributes.get("unset"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    assert!(
        configure
            .summary
            .effects
            .iter()
            .all(|effect| effect.operation.0 != "environment.read")
    );
}
