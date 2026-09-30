//! Cross-module extraction for JS/TS: a file's callable surface (per-function
//! parameterized summaries, outgoing call edges, and import bindings).

use effinterp_engine::{
    ImportBinding, Lang, ModuleSummary, ScopeKey, SemanticValueKind, js_external_effects,
    module_summaries,
};
use effinterp_proto::{ResourceExpr, ResourceIdentity, SourceDialect};

fn js(source: &str) -> ModuleSummary {
    module_summaries(
        source,
        Lang::Js(SourceDialect::Js),
        "src/mod.js",
        ScopeKey::Module {
            key: "src/mod.js".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(
            &effinterp_engine::default_limits(),
            Lang::Js(SourceDialect::Js),
        ),
    )
}

fn ts(source: &str) -> ModuleSummary {
    module_summaries(
        source,
        Lang::Js(SourceDialect::Ts),
        "src/mod.ts",
        ScopeKey::Module {
            key: "src/mod.ts".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(
            &effinterp_engine::default_limits(),
            Lang::Js(SourceDialect::Ts),
        ),
    )
}

fn function<'a>(m: &'a ModuleSummary, name: &str) -> &'a effinterp_engine::FunctionEntry {
    m.functions
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no function {name}"))
}

#[test]
fn parameterized_effect_and_local_call_edge() {
    let m = js(r#"
        const fs = require('fs');
        const path = require('path');
        function wipe(root, t) { fs.rmSync(path.join(root, t), { recursive: true }); }
        function run() { wipe(BASE, name); }
    "#);

    // wipe's summary: a delete on join(param root, param t).
    let wipe = function(&m, "wipe");
    assert_eq!(wipe.summary.params, vec!["root", "t"]);
    assert_eq!(wipe.summary.effects.len(), 1);
    let e = &wipe.summary.effects[0];
    assert_eq!(e.operation.0, "filesystem.delete");
    match &e.resource {
        ResourceExpr::Join { parts } => {
            assert!(matches!(&parts[0], ResourceExpr::Parameter { name } if name == "root"));
            assert!(matches!(&parts[1], ResourceExpr::Parameter { name } if name == "t"));
        }
        other => panic!("expected join, got {other:?}"),
    }
    // wipe makes no outgoing user calls (fs/path are modeled/inert).
    assert!(wipe.calls.is_empty());

    // run calls the local wipe -> a call edge with the two argument exprs.
    let run = function(&m, "run");
    assert!(run.summary.effects.is_empty());
    assert_eq!(run.calls.len(), 1);
    assert_eq!(run.calls[0].callee, "wipe");
    assert_eq!(run.calls[0].arguments.len(), 2);

    let m = js(r#"
        const fs = require('fs');
        function proof(flag) {
            fs.unlinkSync('/before');
            if (flag) { fs.unlinkSync('/arm'); } else { fs.unlinkSync('/arm'); }
            leaf();
            fs.unlinkSync('/after');
        }
        function defaults(p = fs.unlinkSync('/default')) { fs.unlinkSync('/body'); }
        function deferred() { register(() => fs.unlinkSync('/callback')); }
        function never() { fs.unlinkSync('/never'); while (true) {} }
    "#);
    let m: ModuleSummary = serde_json::from_slice(&serde_json::to_vec(&m).unwrap()).unwrap();
    assert!(
        m.module_effects.is_empty(),
        "defaults and callbacks do not run at definition"
    );
    let proof = function(&m, "proof");
    assert_eq!(proof.calls.len(), 1);
    assert_eq!(proof.summary.effects.len(), 4);
    for (returns, expected) in [
        (None, [true, false, false, false]),
        (
            Some(effinterp_engine::CallContract::from_flags(
                true, false, false,
            )),
            [true, false, false, true],
        ),
        (
            Some(effinterp_engine::CallContract::from_flags(
                false, false, false,
            )),
            [false; 4],
        ),
    ] {
        let required = proof.summary.control_flow.requirements(
            &mut |_| false,
            &mut |_| returns.clone(),
            &mut |_, _| true,
        );
        for (slot, expected) in expected.into_iter().enumerate() {
            assert_eq!(
                required
                    .on_success
                    .contains(&effinterp_engine::ControlFact::Effect(slot as u32)),
                expected,
                "slot {slot}, return {returns:?}"
            );
        }
    }
    for (name, expected) in [
        ("defaults", vec![false, true]),
        ("deferred", vec![false]),
        ("never", vec![false]),
    ] {
        let summary = &function(&m, name).summary;
        assert_eq!(summary.effects.len(), expected.len(), "{name}");
        let required =
            summary
                .control_flow
                .requirements(&mut |_| false, &mut |_| None, &mut |_, _| true);
        for (slot, expected) in expected.into_iter().enumerate() {
            assert_eq!(
                required
                    .on_success
                    .contains(&effinterp_engine::ControlFact::Effect(slot as u32)),
                expected,
                "{name} slot {slot}"
            );
        }
    }
}

#[test]
fn copy_summary_parameterizes_source_and_destination() {
    let m = ts(r#"
        import { cp } from 'node:fs/promises';
        export async function copy(source: string, destination: string) {
            await cp(source, destination, { recursive: true });
        }
    "#);
    let effects = &function(&m, "copy").summary.effects;
    assert_eq!(effects.len(), 2);

    let read = effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.read")
        .expect("a source read");
    assert!(matches!(
        &read.resource,
        ResourceExpr::Parameter { name } if name == "source"
    ));
    assert!(!read.attributes.contains_key("recursive"));

    let write = effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.write")
        .expect("a destination write");
    assert!(matches!(
        &write.resource,
        ResourceExpr::Parameter { name } if name == "destination"
    ));
    assert_eq!(
        write.attributes.get("recursive"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
}

#[test]
fn external_copy_model_preserves_argument_roles() {
    let effects = js_external_effects(
        "fs",
        "copyFileSync",
        &[
            ResourceExpr::Parameter {
                name: "source".into(),
            },
            ResourceExpr::Parameter {
                name: "destination".into(),
            },
        ],
    )
    .expect("copyFileSync is modeled");

    assert_eq!(effects.len(), 2);
    assert_eq!(effects[0].operation.0, "filesystem.read");
    assert!(matches!(
        &effects[0].resource,
        ResourceExpr::Parameter { name } if name == "source"
    ));
    assert_eq!(effects[1].operation.0, "filesystem.write");
    assert!(matches!(
        &effects[1].resource,
        ResourceExpr::Parameter { name } if name == "destination"
    ));
}

#[test]
fn named_import_call_is_an_edge_and_binding() {
    let m = js(r#"
        import { wipe } from './util';
        function run() { wipe(x); }
    "#);
    assert!(m.imports.contains(&ImportBinding {
        local: "wipe".to_string(),
        module: "./util".to_string(),
        imported: Some("wipe".to_string()),
    }));
    let run = function(&m, "run");
    assert_eq!(run.calls.len(), 1);
    assert_eq!(run.calls[0].callee, "wipe");
}

#[test]
fn function_local_shadow_does_not_remove_an_import_binding() {
    let m = js(r#"
        import { rmSync } from 'fs';
        export function run() { rmSync('/shadow'); }
        function helper() { const rmSync = 0; return rmSync; }
    "#);
    assert!(m.imports.iter().any(|binding| {
        binding.local == "rmSync"
            && binding.module == "fs"
            && binding.imported.as_deref() == Some("rmSync")
    }));
    assert!(
        function(&m, "run")
            .summary
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
}

#[test]
fn dynamic_import_is_an_import_binding() {
    let m = js(r#"
        await import('@app/cli');
        import './side.js';
        const { init } = await import('./commands/init');
    "#);
    assert!(
        m.imports
            .iter()
            .any(|b| b.module == "@app/cli" && b.local.is_empty()),
        "side-effect import() records the package specifier: {:?}",
        m.imports
    );
    assert!(
        m.imports
            .iter()
            .any(|b| b.module == "./side.js" && b.local.is_empty()),
        "side-effect import declaration records the specifier: {:?}",
        m.imports
    );
    assert!(
        m.imports.iter().any(|b| {
            b.local == "init"
                && b.module == "./commands/init"
                && b.imported.as_deref() == Some("init")
        }),
        "destructured import() is a named binding: {:?}",
        m.imports
    );
}

#[test]
fn literal_function_import_wrapper_binds_the_promise_callback_namespace() {
    let m = js(r#"#!/usr/bin/env node
        function run() {
            var dynamicImport = new Function("module", "return import(module)");
            return dynamicImport("../src/cli/index.js").then(function runCli(cli) {
                return cli.run();
            });
        }
        module.exports.__promise = run();
    "#);

    let binding = m
        .scoped_imports
        .iter()
        .find(|binding| binding.module == "../src/cli/index.js")
        .expect("the literal wrapper target is a scoped import");
    let run = function(&m, "run");
    let callback_call = run
        .calls
        .iter()
        .find(|call| call.callee == format!("{}.run", binding.local))
        .expect("the callback receiver uses the imported namespace");
    assert!(callback_call.awaited);
    assert!(callback_call.receiver.is_none());
    assert!(
        run.calls
            .iter()
            .all(|call| !call.callee.starts_with("dynamicImport")),
        "the transparent loader is not an outgoing call: {:?}",
        run.calls
    );

    let direct = js("import('../src/cli/index.js').then(cli => cli.run())");
    let binding = direct
        .scoped_imports
        .iter()
        .find(|binding| binding.module == "../src/cli/index.js")
        .expect("the direct import callback also binds its namespace");
    let callback_call = direct
        .module_calls
        .iter()
        .find(|call| call.callee == format!("{}.run", binding.local))
        .expect("direct import callback was recorded");
    assert!(callback_call.awaited);
    assert!(callback_call.receiver.is_none());
}

#[test]
fn nonliteral_function_import_shapes_do_not_bind_callback_members() {
    let cases = [
        r#"var dynamicImport = new Function("module", "log(); return import(module)");
            dynamicImport("../src/cli/index.js").then(cli => cli.run());"#,
        r#"var dynamicImport = new Function("module", "return import(module)");
            dynamicImport("../src/" + name).then(cli => cli.run());"#,
        r#"var dynamicImport = new Function("module", "return import(module)");
            dynamicImport = replacement;
            dynamicImport("../src/cli/index.js").then(cli => cli.run());"#,
        r#"var dynamicImport = new Function("module", "return import(module)");
            dynamicImport("../src/cli/index.js").then(other);"#,
    ];

    for (index, body) in cases.into_iter().enumerate() {
        let source = format!("function run() {{ {body} }}\nrun();");
        let m = js(&source);
        assert!(
            m.scoped_imports.is_empty(),
            "case {index} invented an import: {:?}",
            m.scoped_imports
        );
        assert!(
            function(&m, "run")
                .calls
                .iter()
                .all(|call| !call.callee.contains("#dynamic-import")),
            "case {index} invented a callback target: {:?}",
            function(&m, "run").calls
        );
    }
}

#[test]
fn function_import_wrapper_keeps_finite_targets_bounded() {
    let finite = js(r#"
        function run(flag) {
            var dynamicImport = new Function("module", "return import(module)");
            return dynamicImport(flag ? "./a.js" : "./b.js").then(cli => cli.run());
        }
        run(process.env.FLAG);
    "#);
    assert_eq!(finite.scoped_imports.len(), 2);
    assert_eq!(function(&finite, "run").calls.len(), 2);

    let target = (0..65)
        .rev()
        .fold("\"./last.js\"".to_string(), |alternate, index| {
            format!("flag{index} ? \"./{index}.js\" : {alternate}")
        });
    let source = format!(
        "function run() {{\n\
         var dynamicImport = new Function(\"module\", \"return import(module)\");\n\
         return dynamicImport({target}).then(cli => cli.run());\n\
         }}\nrun();"
    );
    let over_limit = js(&source);
    assert!(over_limit.scoped_imports.is_empty());
    assert!(
        function(&over_limit, "run")
            .calls
            .iter()
            .all(|call| !call.callee.contains("#dynamic-import"))
    );
}

#[test]
fn require_and_default_and_namespace_imports() {
    let m = js(r#"
        const u = require('./util');
        const { rm } = require('./fs');
        import def from './d';
        import * as ns from './n';
    "#);
    assert!(m.imports.contains(&ImportBinding {
        local: "u".into(),
        module: "./util".into(),
        imported: None,
    }));
    assert!(m.imports.contains(&ImportBinding {
        local: "rm".into(),
        module: "./fs".into(),
        imported: Some("rm".into()),
    }));
    assert!(m.imports.contains(&ImportBinding {
        local: "def".into(),
        module: "./d".into(),
        imported: Some("default".into()),
    }));
    assert!(m.imports.contains(&ImportBinding {
        local: "ns".into(),
        module: "./n".into(),
        imported: None,
    }));
}

#[test]
fn member_call_on_namespace_import_is_an_edge() {
    let m = js(r#"
        const u = require('./util');
        function run() { u.wipe(p); }
    "#);
    let run = function(&m, "run");
    assert_eq!(run.calls.len(), 1);
    assert_eq!(run.calls[0].callee, "u.wipe");
}

#[test]
fn modeled_calls_are_effects_not_edges() {
    let m = js(r#"
        const fs = require('fs');
        function f(p) { fs.writeFileSync(p, 'x'); fetch('http://a/b'); }
    "#);
    let f = function(&m, "f");
    assert!(
        f.calls.is_empty(),
        "modeled fs/fetch must not be call edges"
    );
    let ops: Vec<&str> = f
        .summary
        .effects
        .iter()
        .map(|e| e.operation.0.as_str())
        .collect();
    assert!(ops.contains(&"filesystem.write"));
    assert!(ops.contains(&"network.request"));
}

#[test]
fn inert_calls_are_not_edges() {
    let m = js(r#"
        function f() { console.log('x'); Math.max(1, 2); JSON.stringify({}); }
    "#);
    assert!(function(&m, "f").calls.is_empty());
}

#[test]
fn malformed_source_is_empty_never_panics() {
    let m = js("function ( { { { ]]] const fs =");
    // No usable functions; must not panic.
    let _ = m.functions.len();
}

#[test]
fn ts_annotations_are_ignored() {
    let m = ts(r#"
        import { rm } from './fs';
        function wipe(root: string, t: string): void { rm(root); }
    "#);
    let wipe = function(&m, "wipe");
    // rm is a user import here (from './fs', not node fs) -> a call edge.
    assert_eq!(wipe.calls.len(), 1);
    assert_eq!(wipe.calls[0].callee, "rm");
    assert!(
        m.imports
            .iter()
            .any(|i| i.local == "rm" && i.module == "./fs")
    );
}

#[test]
fn return_value_summary_is_parameterized() {
    let m = js(r#"
        const path = require('path');
        const BASE = '/var/cache';
        function cachePath(t) { return path.join(BASE, t); }
    "#);
    let cache_path = function(&m, "cachePath");
    // returns := Join[<BASE resolved to /var/cache>, Parameter t].
    let returns = cache_path
        .summary
        .returns
        .as_ref()
        .expect("cachePath has an inferred return");
    let SemanticValueKind::Join(parts) = &returns.kind else {
        panic!("expected Join, got {returns:?}");
    };
    assert!(
        parts
            .iter()
            .any(|p| matches!(p.lower_resource(), ResourceExpr::Concrete { .. })),
        "BASE constant is baked into the return: {parts:?}"
    );
    assert!(
        parts
            .iter()
            .any(|p| matches!(p.lower_resource(), ResourceExpr::Parameter { name } if name == "t")),
        "the parameter stays symbolic: {parts:?}"
    );
}

#[test]
fn nonresolvable_return_is_none() {
    let m = js(r#"
        function mk() { return compute(); }
    "#);
    assert!(function(&m, "mk").summary.returns.is_none());
}

#[test]
fn extraction_is_deterministic() {
    let src = r#"
        const fs = require('fs');
        function a(p) { fs.rmSync(p); b(p); }
        function b(q) { fs.writeFileSync(q, 'x'); }
    "#;
    let one = format!("{:?}", js(src));
    let two = format!("{:?}", js(src));
    assert_eq!(one, two);
}

#[test]
fn inline_callback_argument_is_summarized() {
    // ni's `runCli(async (agent, args) => { ... })`: the callback body's
    // effects and call edges belong to the module-level execution.
    let m = ts(r#"
        import { runCli } from './runner'
        import { fetchNpmPackages } from './fetch'
        runCli(async (agent, args) => {
            const env = process.env.CI
            await fetchNpmPackages(args[0])
        })
    "#);
    assert!(
        m.module_effects
            .iter()
            .any(|e| e.operation.0 == "environment.read"),
        "callback-body env read is a module effect"
    );
    assert!(
        m.module_calls
            .iter()
            .any(|c| c.callee == "fetchNpmPackages"),
        "callback-body call is a module call edge"
    );
}

#[test]
fn process_env_summaries_require_runtime_receiver_evidence() {
    let real = ts(r#"
        import process from 'node:process'
        export function defaults() {
            process.env.PATH = '/x'
            return process.env.TOKEN
        }
    "#);
    let real_effects = &function(&real, "defaults").summary.effects;
    assert!(
        real_effects
            .iter()
            .any(|effect| effect.operation.0 == "environment.read")
    );
    assert!(
        real_effects
            .iter()
            .any(|effect| effect.operation.0 == "environment.write")
    );

    let shadowed = ts(r#"
        const process = { env: { TOKEN: 'fake' } }
        export function defaults() {
            process.env.PATH = '/x'
            return process.env.TOKEN
        }
    "#);
    let summary = &function(&shadowed, "defaults").summary;
    assert!(
        !summary
            .effects
            .iter()
            .any(|effect| effect.operation.0.starts_with("environment."))
    );
    assert!(
        summary
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "partial_analysis")
    );
    assert_eq!(
        summary
            .boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "partial_analysis")
            .count(),
        1
    );
}

#[test]
fn named_callback_uses_lexical_process_receiver_evidence() {
    let shadowed_module = js(r#"
        const process = { env: { SECRET: 'fake' } }
        function readSecret() { return process.env.SECRET }
        export function run() {
            const process = require('node:process')
            invoke(readSecret)
        }
    "#);
    let shadowed_summary = &function(&shadowed_module, "run").summary;
    assert!(
        !shadowed_summary
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "environment.read")
    );
    assert!(
        shadowed_summary
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "partial_analysis")
    );

    let runtime_module = js(r#"
        function readSecret() { return process.env.SECRET }
        export function run() {
            const process = { env: { SECRET: 'fake' } }
            invoke(readSecret)
        }
    "#);
    assert!(
        function(&runtime_module, "run")
            .summary
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "environment.read")
    );
}

#[test]
fn typescript_expression_wrappers_preserve_summary_resources() {
    let m = ts(r#"
        import { readFileSync } from 'fs';
        export function run() {
            readFileSync('/summary' as string);
            fetch('http://summary.example/path' as string);
            const home = (process.env as any).HOME;
        }
    "#);
    let effects = &function(&m, "run").summary.effects;
    assert!(effects.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if effect.operation.0 == "filesystem.read" && path == "/summary"
    )));
    assert!(effects.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { host, .. }
        } if effect.operation.0 == "network.request" && host == "summary.example"
    )));
    assert!(effects.iter().any(|effect| {
        effect.operation.0 == "environment.read"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name }
            } if name == "HOME")
    }));
}

#[test]
fn named_and_star_reexports_become_bindings() {
    let m = ts(r#"
        export * from './core.ts'
        export { fs, glob as globby } from './vendor.ts'
    "#);
    assert!(
        m.imports
            .iter()
            .any(|b| b.local == "*" && b.module == "./core.ts"),
        "star re-export recorded under the reserved local"
    );
    assert!(m.imports.iter().any(|b| b.local == "fs"
        && b.module == "./vendor.ts"
        && b.imported.as_deref() == Some("fs")));
    assert!(m.imports.iter().any(|b| b.local == "globby"
        && b.module == "./vendor.ts"
        && b.imported.as_deref() == Some("glob")));
}

#[test]
fn local_exports_are_distinct_from_private_definitions() {
    let m = js(r#"
        function privateWipe() {}
        function localWipe() {}
        export { localWipe as wipe }
        export function visible() {}
    "#);
    assert_eq!(
        m.exported_definitions,
        [
            ("visible".to_string(), "visible".to_string()),
            ("wipe".to_string(), "localWipe".to_string()),
        ]
    );
}

#[test]
fn commonjs_assignments_confirm_local_and_forwarded_exports() {
    let m = js(r#"
        const { forwarded } = require('./impl.js')
        function localWipe() {}
        function other() {}
        module.exports = { wipe: localWipe, forwarded }
        module.exports.other = other
    "#);
    assert_eq!(
        m.exported_definitions,
        [
            ("other".to_string(), "other".to_string()),
            ("wipe".to_string(), "localWipe".to_string()),
        ]
    );
    assert!(m.exports.iter().any(|binding| {
        binding.local == "forwarded"
            && binding.module == "./impl.js"
            && binding.imported.as_deref() == Some("forwarded")
    }));
}

#[test]
fn commonjs_variable_rebinding_drops_export_evidence() {
    let m = js(r#"
        function wipe() {}
        var exports = {}
        exports.wipe = wipe
    "#);
    assert!(m.exported_definitions.is_empty());
}

#[test]
fn commonjs_destructured_and_function_bindings_drop_export_evidence() {
    for source in [
        "function wipe() {}\nconst { exports } = globalThis\nexports.wipe = wipe",
        "function wipe() {}\nfunction exports() {}\nexports.wipe = wipe",
        "function wipe() {}\nexports.wipe = wipe\nfunction exports() {}",
    ] {
        let m = js(source);
        assert!(
            m.exported_definitions.is_empty(),
            "a local exports binding must not confirm runtime exports: {source}"
        );
    }
}

#[test]
fn commonjs_whole_module_require_is_a_star_forward() {
    let m = js(r#"module.exports = require('./impl.js')"#);
    assert!(m.exports.iter().any(|binding| {
        binding.local == "*" && binding.module == "./impl.js" && binding.imported.is_none()
    }));
}

#[test]
fn wrapped_const_aliases_external_module() {
    // zx's vendor-extra.ts: `export const fs = wrap('fs', _fs)`.
    let m = ts(r#"
        import * as _fs from 'fs-extra'
        import { fetch as _nodeFetch } from 'node-fetch-native'
        function wrap(name, api) { return api }
        export const fs = wrap('fs', _fs)
        export const nodeFetch = wrap('nodeFetch', _nodeFetch)
    "#);
    // fs-extra canonicalizes to fs; the const aliases the whole module.
    assert!(
        m.imports
            .iter()
            .any(|b| b.local == "fs" && b.module == "fs" && b.imported.is_none()),
        "wrapped namespace import aliases the module"
    );
    // A named external import aliases that one export.
    assert!(
        m.imports.iter().any(|b| b.local == "nodeFetch"
            && b.module == "node-fetch-native"
            && b.imported.as_deref() == Some("fetch")),
        "wrapped named import aliases the export"
    );
}

#[test]
fn rebound_wrapped_const_never_aliases() {
    let m = ts(r#"
        import * as _fs from 'fs-extra'
        function wrap(name, api) { return api }
        export let fs = wrap('fs', _fs)
        fs = somethingElse()
    "#);
    assert!(
        !m.imports.iter().any(|b| b.local == "fs"),
        "a rebound const drops the alias"
    );
}

#[test]
fn wrap_of_two_external_imports_is_ambiguous() {
    let m = ts(r#"
        import * as _fs from 'fs-extra'
        import * as _glob from 'glob'
        function wrap(a, b) { return a }
        export const fs = wrap(_glob, _fs)
    "#);
    assert!(
        !m.imports.iter().any(|b| b.local == "fs"),
        "two wrapped modules never alias"
    );
}

#[test]
fn default_export_function_is_named_default() {
    let m = js(r#"
        export default async function run(opts) {
            const t = process.env.TOKEN
        }
    "#);
    assert!(
        m.functions.iter().any(|f| f.name == "default"),
        "export default function is callable as default: {:?}",
        m.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
    let def = function(&m, "default");
    assert!(
        def.summary
            .effects
            .iter()
            .any(|e| e.operation.0 == "environment.read")
    );
}

#[test]
fn default_export_alias_calls_the_local_function() {
    let m = js(r#"
        async function runTasks(opts) { const t = process.env.TOKEN }
        export default runTasks
    "#);
    let def = function(&m, "default");
    assert_eq!(def.calls.len(), 1);
    assert_eq!(def.calls[0].callee, "runTasks");
}

#[test]
fn class_methods_are_qualified_and_default_class_is_aliased() {
    let m = js(r#"
        class Shell {
            exec(cmd) { require('child_process').exec(cmd) }
        }
        export default Shell
    "#);
    assert!(
        m.classes.iter().any(|c| c.name == "Shell"),
        "named class is recorded: {:?}",
        m.classes
    );
    assert!(
        m.classes
            .iter()
            .any(|c| c.name == "default" && c.bases == ["Shell"]),
        "default export aliases the class: {:?}",
        m.classes
    );
    let exec = function(&m, "Shell.exec");
    assert!(
        exec.summary
            .effects
            .iter()
            .any(|e| e.operation.0 == "process.exec")
    );
}

#[test]
fn module_objects_singletons_and_factory_returns_have_member_identities() {
    let module = js(r#"
        import { spawn } from 'child_process'
        export const bash = { execute() { spawn('rm') } }
        export const tools = { bash: { execute: () => spawn('rm') } }
        export default { execute() { spawn('rm') } }

        class Bash { execute() { spawn('rm') } }
        export const tool = new Bash()

        export function createWriteTool() {
            return { execute() { spawn('rm') } }
        }
        function ambiguousFactory(flag) {
            if (flag) return { execute() { spawn('rm') } }
            return other
        }
        function divergentObjectFactory(flag) {
            if (flag) return { execute() { spawn('rm') } }
            return { execute() { spawn('ls') } }
        }

        const key = 'ignored'
        const computed = { [key]() {} }
        const accessors = { get execute() { return 1 }, set execute(value) {} }
        let rebound = { execute() {} }
        rebound = { execute() {} }
        export const reassigned = { execute() { spawn('rm') } }
        reassigned.execute = function () { spawn('ls') }
    "#);

    for name in [
        "bash.execute",
        "tools.bash.execute",
        "default.execute",
        "createWriteTool.execute",
    ] {
        function(&module, name);
        assert!(
            module
                .exported_definitions
                .iter()
                .any(|(exported, local)| exported == name && local == name),
            "{name} is exported: {:?}",
            module.exported_definitions
        );
    }
    assert!(
        module.functions.iter().all(|function| {
            !matches!(
                function.name.as_str(),
                "computed.key" | "accessors.execute" | "rebound.execute" | "reassigned.execute"
            )
        }),
        "computed, accessor, rebound, and reassigned properties are excluded: {:?}",
        module.functions
    );

    let constructor = module
        .module_calls
        .iter()
        .find(|call| {
            call.callee == "Bash" && call.result_bindings().any(|(_, binding)| binding == "tool")
        })
        .expect("module singleton constructor edge");
    assert!(constructor.result_type().is_some());

    let factory = function(&module, "createWriteTool");
    assert_eq!(
        factory.returns_instances,
        vec![Some("createWriteTool".to_string())]
    );
    assert!(
        module
            .classes
            .iter()
            .any(|class| class.name == "createWriteTool")
    );
    assert!(
        function(&module, "ambiguousFactory")
            .returns_instances
            .is_empty()
    );
    assert!(module.classes.iter().all(|class| !matches!(
        class.name.as_str(),
        "ambiguousFactory" | "divergentObjectFactory"
    )));
    assert!(
        function(&module, "divergentObjectFactory")
            .returns_instances
            .is_empty()
    );
}

#[test]
fn returning_a_namespace_import_is_a_returned_instance() {
    let m = ts(r#"
        import * as npm from './npm.ts'
        import * as yarn from './yarn.ts'
        export async function getTool(kind: string) {
            if (kind === 'yarn') return yarn
            return npm
        }
    "#);
    let get = function(&m, "getTool");
    // Divergent returns must not pick a winner.
    assert!(
        get.returns_instances.is_empty(),
        "two namespace returns stay unknown: {:?}",
        get.returns_instances
    );

    let m = ts(r#"
        import * as npm from './npm.ts'
        export async function getTool() { return npm }
    "#);
    let get = function(&m, "getTool");
    assert_eq!(get.returns_instances, vec![Some("npm".to_string())]);
}

#[test]
fn returned_object_method_callback_keeps_its_producer_identity() {
    let module = ts(r#"
        import { promises as fs } from 'node:fs'
        async function openTemp() {
            return fs.open('tmp', 'w').then(fd => ({
                cleanup() { fd.close().then(() => fs.unlink('tmp')) },
            }))
        }
        async function writeSafe() {
            const temp = await openTemp()
            return fs.writeFile('out', 'x').finally(temp.cleanup)
        }
        async function negative() {
            const temp = await openTemp()
            return fs.writeFile('out', 'x').finally(other.cleanup)
        }
        "#);
    let cleanup = function(&module, "openTemp.cleanup");
    assert!(
        cleanup
            .summary
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
            || cleanup
                .calls
                .iter()
                .any(|call| call.callee.ends_with(".unlink")),
        "returned cleanup body was not summarized: {cleanup:?}"
    );
    assert!(function(&module, "writeSafe").calls.iter().any(|call| {
        call.callback_arguments()
            .any(|(_, function)| function == "openTemp.cleanup")
    }));
    assert!(function(&module, "negative").calls.iter().all(|call| {
        call.callback_arguments()
            .all(|(_, function)| function != "openTemp.cleanup")
    }));
}

#[test]
fn named_callback_argument_is_a_fn_arg() {
    let m = ts(r#"
        import { init } from './commands/init'
        cli.command('init').action(init)
    "#);
    assert!(
        m.module_calls.iter().any(|c| c
            .callback_arguments()
            .any(|(_, function)| function == "init")),
        "action(init) records the imported handler: {:?}",
        m.module_calls
    );
}

#[test]
fn unpassed_local_function_is_not_a_module_effect() {
    let m = js(r#"
        import { exec } from 'child_process'
        const unused = () => exec('rm -rf /')
        console.log('ok')
    "#);
    assert!(
        m.module_effects
            .iter()
            .all(|e| e.operation.0 != "process.exec"),
        "an assigned-but-never-passed function is not invoked: {:?}",
        m.module_effects
    );
}

#[test]
fn object_literal_callback_is_summarized() {
    let m = js(r#"
        import { exec } from 'child_process'
        const task = () => exec('git status')
        spinner.show({ task })
    "#);
    assert!(
        m.module_calls.iter().any(|c| c
            .callback_arguments()
            .any(|(_, function)| function == "task")),
        "object-literal task records the local callback: {:?}",
        m.module_calls
    );
}

#[test]
fn exec_first_arg_is_the_process_resource() {
    let m = ts(r#"
        import { exec } from 'tinyexec'
        export async function add(path: string) {
            await exec('git', ['add', path])
        }
    "#);
    let add = function(&m, "add");
    let exec = add
        .summary
        .effects
        .iter()
        .find(|e| e.operation.0 == "process.exec")
        .expect("tinyexec exec is a process effect");
    match &exec.resource {
        ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::Process { executable, .. },
        } => assert_eq!(executable, "git"),
        other => panic!("expected git executable, got {other:?}"),
    }
}

#[test]
fn url_file_specifier_is_a_filesystem_resource() {
    let m = js(r#"
        import { readFileSync } from 'fs'
        export function load() {
            return readFileSync(new URL('../package.json', import.meta.url))
        }
    "#);
    let load = function(&m, "load");
    assert!(
        load.summary.effects.iter().any(|e| {
            e.operation.0 == "filesystem.read"
                && format!("{:?}", e.resource).contains("package.json")
        }),
        "new URL('../package.json') lowers to a path: {:?}",
        load.summary.effects
    );
}

#[test]
fn nested_helper_is_summarized() {
    // zx's `rmTemp` closure inside `runScript`.
    let m = ts(r#"
        const fs = require('fs')
        function runScript(tempPath) {
            const rmTemp = () => { fs.rmSync(tempPath) }
            rmTemp()
        }
    "#);
    let rm = function(&m, "rmTemp");
    assert!(
        rm.summary
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.delete"),
        "nested helper has its own summary"
    );
}

#[test]
fn commonjs_object_spread_and_member_exports_are_forwards() {
    let m = js(r#"
        module.exports = {
            ...require('./base.js'),
            run: require('./run.js').main,
        }
    "#);
    assert!(m.exports.iter().any(|binding| {
        binding.local == "*" && binding.module == "./base.js" && binding.imported.is_none()
    }));
    assert!(m.exports.iter().any(|binding| {
        binding.local == "run"
            && binding.module == "./run.js"
            && binding.imported.as_deref() == Some("main")
    }));
    assert_eq!(m.module_loads.len(), 2);
}

#[test]
fn rebound_callback_through_object_spread_is_left_unresolved() {
    // A reassigned local holds no single proven function, so neither body
    // runs and the callback stays an unresolved call.
    let m = js(r#"
        import { exec } from 'child_process'
        const stale = () => exec('stale')
        const selected = () => exec('selected')
        let handler = stale
        handler = selected
        const options = { handler }
        const forwarded = { ...options }
        runner(forwarded)
    "#);
    let callbacks: Vec<_> = m
        .module_calls
        .iter()
        .flat_map(|call| call.callback_arguments().map(|(_, name)| name))
        .collect();
    assert!(!callbacks.contains(&"selected"), "{callbacks:?}");
    assert!(!callbacks.contains(&"stale"), "{callbacks:?}");
    assert!(
        m.module_calls
            .iter()
            .any(|call| call.dynamic_target && call.callee == "handler")
    );
    assert!(
        m.module_effects
            .iter()
            .all(|effect| effect.operation.0 != "process.exec")
    );
}

#[test]
fn rebound_commonjs_api_is_not_modeled() {
    let m = js(r#"
        let { rmSync } = require('fs')
        rmSync = userCallback
        export function run() { rmSync('/must-not-delete') }
    "#);
    let run = function(&m, "run");
    assert!(
        run.summary
            .effects
            .iter()
            .all(|effect| effect.operation.0 != "filesystem.delete"),
        "a rebound API must lose module evidence: {run:?}"
    );
    assert!(run.calls.iter().any(|call| call.callee == "rmSync"));
}

#[test]
fn summaries_exclude_server_requests_and_shadowed_fetch() {
    let summary = js(r#"
        const http = require('http');
        function serve(handler) { http.createServer(handler); }
        function localFetch() {
            function fetch() { return 1; }
            fetch();
        }
    "#);
    assert!(function(&summary, "serve").summary.effects.is_empty());
    let local = function(&summary, "localFetch");
    assert!(local.summary.effects.is_empty());
    assert!(local.calls.iter().any(|call| call.callee == "fetch"));
}

#[test]
fn summaries_resolve_option_bindings_and_spreads() {
    let summary = js(r#"
        const base = {recursive: true};
        const RM_OPTS = {...base, force: true};
        const fs = require('fs');
        function clean(source, destination) {
            fs.rmSync(source, RM_OPTS);
            fs.cpSync(source, destination, RM_OPTS);
        }
    "#);
    let effects = &function(&summary, "clean").summary.effects;
    let delete = effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .expect("delete effect");
    assert_eq!(
        delete.attributes.get("recursive"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    let read = effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.read")
        .expect("copy source read");
    assert!(!read.attributes.contains_key("recursive"));
    let write = effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.write")
        .expect("copy destination write");
    assert_eq!(
        write.attributes.get("recursive"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
}

#[test]
fn summaries_lower_const_urls_and_named_path_joins() {
    let summary = js(r#"
        import {join} from 'node:path';
        const fs = require('fs');
        const BASE = 'https://api.example.com/v1';
        function run() {
            fetch(BASE);
            fs.rmSync(join('/srv', 'cache'));
        }
    "#);
    let effects = &function(&summary, "run").summary.effects;
    assert!(effects.iter().any(|effect| {
        effect.operation.0 == "network.request"
            && matches!(&effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, .. }
                } if host == "api.example.com")
    }));
    assert!(effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/srv/cache")
    }));
}

#[test]
fn shell_spawn_summary_keeps_the_composed_command() {
    let summary = js(r#"
        const {spawn} = require('child_process');
        function clean() { spawn('rm', ['-rf', '/tmp/z'], {shell: true}); }
    "#);
    let effect = function(&summary, "clean")
        .summary
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "process.exec")
        .expect("process execution effect");
    assert!(matches!(&effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, .. }
        } if executable == "rm -rf /tmp/z"));
}
