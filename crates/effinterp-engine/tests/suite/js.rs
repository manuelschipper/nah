#![allow(clippy::disallowed_types)]

use effinterp_engine::{AnalysisStats, Engine, default_limits};
use effinterp_proto::{
    BoundaryClass, CoverageLevel, Domain, Plan, ResourceExpr, ResourceIdentity, SourceDialect,
    Subject, validate_plan,
};

fn js(source: &str) -> Plan {
    analyze(source, SourceDialect::Js)
}

fn ts(source: &str) -> Plan {
    analyze(source, SourceDialect::Ts)
}

fn analyze(source: &str, dialect: SourceDialect) -> Plan {
    let plan = Engine::new()
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

fn is_joined_env_path(resource: &ResourceExpr, env: &str, suffix: &str) -> bool {
    matches!(resource, ResourceExpr::Join { parts }
        if matches!(parts.as_slice(), [
            ResourceExpr::Environment { name },
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            }
        ] if name == env && path == suffix))
}

fn ops(plan: &Plan) -> Vec<&str> {
    plan.effects
        .iter()
        .map(|e| e.operation.0.as_str())
        .collect()
}

#[test]
fn no_entry_point_distinguishes_unreached_javascript_callables() {
    let declarations = r#"
        const fs = require('fs');
        export function purge(path) { fs.rmSync(path, { recursive: true }); }
        class Storage { sweep() { fs.rmSync('/class'); } }
        const hooks = { clean() { fs.rmSync('/object'); } };
        export default function () { fs.rmSync('/default'); }
    "#;
    let plan = js(declarations);
    let boundary = plan
        .boundaries
        .iter()
        .find(|boundary| boundary.reason.as_str() == "no_entry_point")
        .expect("declaration-only JavaScript has no execution root");
    assert_eq!(boundary.class, BoundaryClass::Unresolved);
    assert_eq!(
        boundary.detail.as_deref(),
        Some(
            "no execution root reached; declared callables not executed: purge, Storage.sweep, hooks.clean, default"
        )
    );
    for domain in ["environment", "filesystem", "network", "process"] {
        assert_eq!(
            plan.coverage.0[&Domain::new(domain)].level,
            CoverageLevel::Partial
        );
    }

    let reached = js(&format!("{declarations}\npurge('/tmp/reached');"));
    assert!(has(&reached, "filesystem.delete", "/tmp/reached"));
    assert!(
        reached
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );

    let top_level = js(
        "const fs = require('fs'); function stale() { fs.rmSync('/stale'); } fs.rmSync('/top');",
    );
    assert!(has(&top_level, "filesystem.delete", "/top"));
    assert!(
        top_level
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );
    assert!(
        js("")
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );
}

// Regression: same-file member calls previously advertised declarations but
// had no enterable bodies, so their effects were silently dropped.
#[test]
fn same_file_member_calls_and_default_functions_are_entered() {
    let plan = js(r#"
        const fs = require('fs');
        class Storage {
          prep() { fs.rmSync('/class'); }
          flush() { fs.rmSync('/chained'); }
        }
        const storage = new Storage('/tmp');
        storage.prep();
        new Storage().flush();
        const hooks = { clean() { fs.rmSync('/object'); } };
        hooks.clean();
        export default function finish() { fs.rmSync('/default'); }
        finish();
        "#);
    for path in ["/class", "/chained", "/object", "/default"] {
        assert!(has(&plan, "filesystem.delete", path), "missing {path}");
    }
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );

    let unresolved = js(
        "class Storage { prep() {} } let storage = new Storage(); storage = unknown; storage.prep();",
    );
    assert!(unresolved.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "unresolved_call"
            && boundary.detail.as_deref() == Some("call to unresolved member call")
    }));
    assert!(
        unresolved
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "no_entry_point")
    );

    let parameter_receiver = js(r#"
        const fs = require('fs');
        const hooks = { clean() { fs.rmSync('/parameter-local'); } };
        function run(hooks) { hooks.clean(); }
        run(require('./external-hooks'));
        "#);
    assert!(!has(
        &parameter_receiver,
        "filesystem.delete",
        "/parameter-local"
    ));

    let shadowed_constructor = js(r#"
        const fs = require('fs');
        class Storage { prep() { fs.rmSync('/shadowed-local'); } }
        function run() {
          const Storage = require('other-storage');
          const storage = new Storage();
          storage.prep();
        }
        run();
        "#);
    assert!(!has(
        &shadowed_constructor,
        "filesystem.delete",
        "/shadowed-local"
    ));

    let reassigned_member = js(r#"
        const fs = require('fs');
        const hooks = { clean() { fs.rmSync('/original'); } };
        hooks.clean = function () { fs.rmSync('/replacement'); };
        hooks.clean();
        "#);
    assert!(!has(&reassigned_member, "filesystem.delete", "/original"));
    assert!(!has(
        &reassigned_member,
        "filesystem.delete",
        "/replacement"
    ));

    for plan in [
        &parameter_receiver,
        &shadowed_constructor,
        &reassigned_member,
    ] {
        assert!(plan.boundaries.iter().any(|boundary| {
            boundary.reason.as_str() == "unresolved_call"
                && boundary.detail.as_deref() == Some("call to unresolved member call")
        }));
    }
}

fn analyze_js_with_stats(engine: &Engine, source: String) -> (Plan, AnalysisStats) {
    let (plan, stats) = engine
        .analyze_with_stats(&Subject::Source {
            language: "js".into(),
            source,
            dialect: Some(SourceDialect::Js),
            cwd: Some("/app".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    (plan, stats)
}

#[test]
fn source_string_state_scales_with_module_size() {
    let helpers = 1_200;
    let mut source = String::new();
    for index in 0..helpers {
        source.push_str(&format!(
            "function helper{index}(value) {{ return value + {index}; }} const result{index} = helper{index}({index});\n"
        ));
    }

    let (plan, stats) = analyze_js_with_stats(&Engine::new(), source);
    // Hoisting puts every helper in the callable environment, so a single
    // whole-environment scan already walks `helpers` entries. These calls
    // write no captured binding and need none; a scan per call is quadratic.
    assert!(
        stats.state_scan_entries <= helpers as u64,
        "JavaScript source-string state scanned complete module environments per call: {} entries",
        stats.state_scan_entries
    );
    assert!(plan.effects.is_empty());
    // Every call retains a snapshot of the module state, and the snapshots
    // share unchanged bindings. Charging each at the full environment size
    // saturated `max_analysis_bytes` about 147 statements in.
    assert!(
        stats.retained_bytes <= 1024 * helpers as u64,
        "retained JavaScript state was charged per snapshot, not per changed binding: {} bytes",
        stats.retained_bytes
    );
    // Only the dataflow cap on tracked bindings may saturate here.
    assert!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "limit_saturated")
            .all(|boundary| boundary.limit.as_deref() == Some("max_js_causal_slots"))
    );

    // Snapshots that each add a distinct, growing concatenation genuinely
    // retain quadratic state, so they must still saturate the byte limit.
    let mut source = String::from("let path0 = \"/srv\";\n");
    for index in 1..300 {
        let previous = index - 1;
        source.push_str(&format!(
            "function helper{index}() {{ return 1; }} const path{index} = path{previous} + \"/segment{index}\"; helper{index}();\n"
        ));
    }
    let mut limits = default_limits();
    limits.insert("max_analysis_bytes".to_string(), 1 << 20);
    let (plan, _) = analyze_js_with_stats(&Engine::with_limits(limits).unwrap(), source);
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "limit_saturated"
            && boundary.limit.as_deref() == Some("max_analysis_bytes")
    }));
}

#[test]
fn function_import_wrapper_is_transparent_only_for_exact_literal_calls() {
    let exact = js(r#"
        function run() {
            var dynamicImport = new Function("module", "return import(module)");
            return dynamicImport("../src/cli/index.js").then(cli => cli.run());
        }
        run();
    "#);
    assert!(exact.boundaries.iter().all(|boundary| {
        boundary.reason.as_str() != "unmodeled_dynamic_code"
            && boundary
                .detail
                .as_deref()
                .is_none_or(|detail| !detail.contains("dynamicImport"))
    }));

    for source in [
        r#"function run() {
            var dynamicImport = new Function("module", "sideEffect(); return import(module)");
            return dynamicImport("../src/cli/index.js").then(cli => cli.run());
        }
        run();"#,
        r#"function run() {
            var dynamicImport = new Function("module", "return import(module)");
            return dynamicImport("../src/" + name).then(cli => cli.run());
        }
        run();"#,
    ] {
        let plan = js(source);
        assert!(
            plan.boundaries.iter().any(|boundary| matches!(
                boundary.reason.as_str(),
                "unmodeled_dynamic_code" | "unresolved_call"
            )),
            "rejected wrapper shape was not loud: {:?}",
            plan.boundaries
        );
    }
}

#[test]
fn typescript_annotations_are_parsed() {
    let plan = ts(r#"
        import { writeFileSync } from 'fs';
        function save(path: string, data: Buffer): void {
            writeFileSync(path, data);
        }
        save('/tmp/ts-out', Buffer.from('x'));
    "#);
    // The writeFileSync(path, data) call has a symbolic path -> unresolved,
    // but must still be recorded as a write, and TS must parse without error.
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|b| b.reason.as_str() == "parse_error")
    );
    assert!(ops(&plan).contains(&"filesystem.write"));
}

#[test]
fn malformed_source_is_safe() {
    let plan = js(r#"const x = ("#);
    // No panic; a parse-error boundary is recorded.
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "parse_error")
    );
}

#[test]
fn template_literal_path_stays_symbolic() {
    let plan = js(r#"
        const fs = require('fs');
        fs.unlinkSync(`/tmp/${user}/file`);
    "#);
    let del = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(matches!(del.resource, ResourceExpr::Join { .. }));
}

#[test]
fn template_literal_filesystem_segments_use_cooked_values() {
    let plans = [
        js(r#"
            const fs = require('fs');
            fs.rmSync(`/tmp/a\n${process.env.HOME}`);
        "#),
        ts(r#"
            import fs from 'node:fs';
            fs.rmSync(`/tmp/a\n${process.env.HOME}`);
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(&delete.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Literal { value: marker },
                ResourceExpr::Literal { value: path },
                ResourceExpr::Environment { name }
            ] if marker.is_empty() && path == "/tmp/a\n" && name == "HOME")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
    }
}

#[test]
fn whole_path_environment_values_resolve_as_filesystem_paths() {
    let source = r#"
        const fs = require('fs'), os = require('os');
        fs.rmSync(os.homedir(), {recursive: true});
        fs.rmSync(process.env.HOME, {recursive: true});
    "#;
    let deletes = |plan: &Plan| {
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .map(|effect| effect.resource.clone())
            .collect::<Vec<_>>()
    };
    // Unsupplied, the variable stays symbolic, which asks the host for it, and
    // `os.homedir()` keeps its boundary: without `$HOME` it is the account's home.
    let unsupplied = js(source);
    assert!(
        deletes(&unsupplied)
            .iter()
            .all(|resource| matches!(resource,
        ResourceExpr::Environment { name } if name == "HOME"))
    );
    assert!(has_boundary(&unsupplied, "unresolved_call"));

    let with_home = |source: &str| {
        Engine::new()
            .analyze(&Subject::Source {
                language: "js".into(),
                source: source.to_string(),
                dialect: Some(SourceDialect::Js),
                cwd: Some("/app".to_string()),
                context: effinterp_proto::HostContext {
                    env: [("HOME".to_string(), "/home/test".to_string())].into(),
                    ..Default::default()
                },
            })
            .unwrap()
    };
    let supplied = with_home(source);
    assert_eq!(deletes(&supplied).len(), 2);
    assert!(deletes(&supplied).iter().all(|resource| matches!(resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/home/test")));
    assert!(!has_boundary(&supplied, "unresolved_call"));
    // Reading `process`, including a computed property, and a local that
    // merely shares its name keep the supplied value.
    let read_only = with_home(
        "const fs = require('fs'); const {argv} = process; console.log(process['platform']);
         function log(process) { console.log(process); } const p = process;
         if (process && typeof process === 'object') fs.rmSync(p.env.HOME, {recursive: true});",
    );
    assert!(deletes(&read_only).iter().any(|resource| matches!(resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
            if path == "/home/test")));

    // A module that can rewrite the environment first leaves the path unknown,
    // including through a computed or destructured reference to it.
    for rewrite in [
        "process.env.HOME = dir;",
        "Object.assign(process['env'], {HOME: '/tmp'});",
        "const {env} = process; env.HOME = '/tmp';",
        "process.env.HOME++;",
        // A `const` bound to `process` writes the same environment.
        "const p = process; p.env.HOME = dir;",
    ] {
        let source = format!(
            "const fs = require('fs'); {rewrite} fs.rmSync(process.env.HOME, {{recursive: true}});"
        );
        let rewritten = with_home(&source);
        assert!(!deletes(&rewritten).is_empty(), "{rewrite}");
        assert!(
            deletes(&rewritten)
                .iter()
                .all(|resource| matches!(resource, ResourceExpr::Unresolved { .. })),
            "{rewrite}: {:?}",
            deletes(&rewritten)
        );
    }

    // A literal module-scope write is the value later module-scope code sees;
    // code before it sees the host's, and a function body may run after it.
    let at = |path: &'static str| {
        move |resource: &ResourceExpr| {
            matches!(resource,
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: p } } if p == path)
        }
    };
    let literal = with_home(
        "const fs = require('fs'), os = require('os'); fs.rmSync(os.homedir() + '/a');
         process.env.HOME = '/srv'; fs.rmSync(os.homedir() + '/b');
         function later() { fs.rmSync(process.env.HOME + '/c'); } later();",
    );
    let found = deletes(&literal);
    assert_eq!(found.len(), 3, "{found:?}");
    assert!(at("/home/test/a")(&found[0]), "{found:?}");
    assert!(at("/srv/b")(&found[1]), "{found:?}");
    assert!(!matches!(
        &found[2],
        ResourceExpr::Concrete { .. } | ResourceExpr::Environment { .. }
    ));
    // A value read before the write keeps the host's value where it is used.
    let captured = with_home(
        "const fs = require('fs'), os = require('os'); const h = process.env.HOME + '/.ssh';
         const g = os.homedir(); process.env.HOME = '/tmp/build';
         fs.rmSync(h, {recursive: true}); fs.rmSync(g + '/etc', {recursive: true});",
    );
    let found = deletes(&captured);
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(at("/home/test/.ssh")(&found[0]), "{found:?}");
    assert!(at("/home/test/etc")(&found[1]), "{found:?}");
    let command = with_home(
        "const cmd = 'rm -rf ' + require('os').homedir(); process.env.HOME = '/tmp/build';
         require('child_process').execSync(cmd);",
    );
    assert!(deletes(&command).iter().any(at("/home/test")));
    // A default parameter value is read when the function is called, which
    // source position cannot place before or after the write.
    for source in [
        "f(); process.env.HOME = '/tmp/build';
         function f(p = process.env.HOME + '/.ssh') { require('fs').rmSync(p, {recursive: true}); }",
        "function f(p = process.env.HOME + 'etc') { require('fs').rmSync(p, {recursive: true}); }
         process.env.HOME = '/'; f();",
    ] {
        let found = deletes(&with_home(source));
        assert!(!found.is_empty(), "{source}");
        assert!(
            found.iter().all(leaves_environment_unknown),
            "{source}: {found:?}"
        );
    }
    // Names differing only in case may be one variable, as on Windows, so the
    // write keeps the hedge.
    let folded = with_home("process.env.home = '/srv'; require('fs').rmSync(process.env.HOME);");
    assert!(
        deletes(&folded)
            .iter()
            .all(|resource| matches!(resource, ResourceExpr::Unresolved { .. }))
    );
    let conditional =
        with_home("if (flag) process.env.HOME = '/srv'; require('fs').rmSync(process.env.HOME);");
    assert!(
        deletes(&conditional)
            .iter()
            .all(|resource| matches!(resource, ResourceExpr::Unresolved { .. }))
    );

    // A shell command built from the home directory runs once the host
    // supplies it; until then its boundary names the variable to ask for.
    let command = "require('child_process').execSync('rm -rf ' + require('os').homedir());";
    assert!(deletes(&with_home(command)).iter().any(at("/home/test")));
    let unsupplied = js(command);
    assert!(deletes(&unsupplied).is_empty());
    assert!(unsupplied.boundaries.iter().any(|boundary| matches!(
        &boundary.affected_resource,
        Some(ResourceExpr::Concrete { identity: ResourceIdentity::EnvironmentVariable { name } })
            if name == "HOME"
    )));
}

#[test]
fn string_concatenation_preserves_environment_filesystem_parts() {
    let plan = js(r#"
        const fs = require('fs');
        fs.rmSync(process.env.HOME + '/.cache/x');
        fs.rmSync(`${process.env.HOME}/.cache/y`);
    "#);
    let deletes: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 2);
    for (delete, suffix) in deletes.into_iter().zip(["/.cache/x", "/.cache/y"]) {
        assert!(matches!(&delete.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Environment { name },
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                }
            ] if name == "HOME" && path == suffix)));
    }
    assert!(!has_boundary(&plan, "unmodeled_dynamic"));

    let typescript = ts(r#"
        import fs from 'node:fs';
        const home: string | undefined = process.env.HOME;
        fs.rmSync(home! + '/.cache/ts');
    "#);
    assert!(typescript.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Join { parts }
                if matches!(parts.as_slice(), [
                    ResourceExpr::Environment { name },
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    }
                ] if name == "HOME" && path == "/.cache/ts"))
    }));
}

#[test]
fn string_conversion_preserves_sink_typed_concatenations() {
    let plans = [
        js(r#"
            const fs = require('fs');
            fs.rmSync(String(process.env.HOME + '/converted-cache', process.env.TMPDIR));
            fetch(String('https://api.example' + '/converted-meta', 123));
        "#),
        ts(r#"
            import fs from 'node:fs';
            fs.rmSync(String(process.env.HOME + '/converted-cache', process.env.TMPDIR));
            fetch(String('https://api.example' + '/converted-meta', 123));
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(
            &delete.resource,
            "HOME",
            "/converted-cache"
        ));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                },
                ResourceExpr::Literal { value }
            ] if host == "api.example"
                && scheme.as_deref() == Some("https")
                && value == "/converted-meta")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
    }
}

#[test]
fn string_conversion_preserves_first_argument_evaluation_state() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/before';
            fs.rmSync(String(path, path = process.env.TMPDIR + '/after'));
            let url = 'https://one.example' + '/before';
            fetch(String(url, url = 'https://two.example' + '/after'));
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/before';
            fs.rmSync(String(path, path = process.env.TMPDIR + '/after'));
            let url = 'https://one.example' + '/before';
            fetch(String(url, url = 'https://two.example' + '/after'));
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/before"));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                },
                ResourceExpr::Literal { value }
            ] if host == "one.example"
                && scheme.as_deref() == Some("https")
                && value == "/before")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
    }
}

#[test]
fn imported_filesystem_concatenation_is_unmodeled_dynamic() {
    let plans = [
        js(r#"
            import fs from 'node:fs';
            import { base } from './config.js';
            fs.rmSync(base + '/cache');
        "#),
        ts(r#"
            import fs from 'node:fs';
            import { base } from './config.js';
            fs.rmSync(base + '/cache');
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn unknown_filesystem_concatenation_operands_are_unmodeled_dynamic() {
    let plans = [
        js(r#"
            const fs = require('fs');
            fs.rmSync(externalPath + '/x');
            fs.rmSync(globalThis.externalPath + '/x');
        "#),
        ts(r#"
            import fs from 'node:fs';
            fs.rmSync(externalPath + '/x');
            fs.rmSync(globalThis.externalPath + '/x');
        "#),
    ];
    for plan in plans {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn assignment_updates_and_invalidates_source_string_tracking() {
    let assigned = js(r#"
        const fs = require('fs');
        let path;
        path = process.env.HOME + '/.cache/x';
        fs.rmSync(path);
    "#);
    let delete = assigned
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .expect("filesystem delete effect");
    assert!(matches!(&delete.resource, ResourceExpr::Join { parts }
        if matches!(parts.as_slice(), [
            ResourceExpr::Environment { name },
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            }
        ] if name == "HOME" && path == "/.cache/x")));
    assert!(!has_boundary(&assigned, "unmodeled_dynamic"));

    let reassigned = js(r#"
        const fs = require('fs');
        let path = process.env.HOME + '/safe';
        path = buildPath();
        fs.rmSync(path + '/x');
    "#);
    let delete = reassigned
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .expect("filesystem delete effect");
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Unresolved { family } if family.0 == "filesystem"
    ));
    assert!(has_boundary(&reassigned, "unmodeled_dynamic"));
    assert!(!all_full(&reassigned));
}

#[test]
fn compound_assignment_concatenations_keep_symbolic_boundaries() {
    let source = r#"
        const fs = require('fs');
        let direct = process.env.HOME;
        fs.rmSync(direct += '/direct');
        let assigned = process.env.TMPDIR;
        assigned += '/assigned';
        fs.rmSync(assigned);
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn logical_assignment_concatenations_keep_symbolic_boundaries() {
    let source = r#"
        const fs = require('fs');

        let orDirectPath = false;
        fs.rmSync(orDirectPath ||= process.env.HOME + '/or-direct');
        let orAssignedPath = false;
        orAssignedPath ||= process.env.HOME + '/or-assigned';
        fs.rmSync(orAssignedPath);

        let andDirectPath = true;
        fs.rmSync(andDirectPath &&= process.env.HOME + '/and-direct');
        let andAssignedPath = true;
        andAssignedPath &&= process.env.HOME + '/and-assigned';
        fs.rmSync(andAssignedPath);

        let nullishDirectPath = null;
        fs.rmSync(nullishDirectPath ??= process.env.HOME + '/nullish-direct');
        let nullishAssignedPath = null;
        nullishAssignedPath ??= process.env.HOME + '/nullish-assigned';
        fs.rmSync(nullishAssignedPath);

        let orDirectUrl = false;
        fetch(orDirectUrl ||= 'https://example.com' + '/or-direct');
        let orAssignedUrl = false;
        orAssignedUrl ||= 'https://example.com' + '/or-assigned';
        fetch(orAssignedUrl);

        let andDirectUrl = true;
        fetch(andDirectUrl &&= 'https://example.com' + '/and-direct');
        let andAssignedUrl = true;
        andAssignedUrl &&= 'https://example.com' + '/and-assigned';
        fetch(andAssignedUrl);

        let nullishDirectUrl = null;
        fetch(nullishDirectUrl ??= 'https://example.com' + '/nullish-direct');
        let nullishAssignedUrl = null;
        nullishAssignedUrl ??= 'https://example.com' + '/nullish-assigned';
        fetch(nullishAssignedUrl);
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 6);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));

        let requests: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.request")
            .collect();
        assert_eq!(requests.len(), 6);
        assert!(requests.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        )));

        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            12
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn logical_assignment_rhs_source_string_state_is_conditional() {
    let source = r#"
        const fs = require('fs');

        let orPath = process.env.HOME;
        let orKeep = true;
        orKeep ||= (orPath = process.env.TMPDIR + '/or-branch');
        fs.rmSync(orPath + '/after');

        let andPath = process.env.HOME;
        let andKeep = false;
        andKeep &&= (andPath = process.env.TMPDIR + '/and-branch');
        fs.rmSync(andPath + '/after');

        let nullishPath = process.env.HOME;
        let nullishKeep = 'present';
        nullishKeep ??= (nullishPath = process.env.TMPDIR + '/nullish-branch');
        fs.rmSync(nullishPath + '/after');

        let orUrl = 'https://home.example';
        let orUrlKeep = true;
        orUrlKeep ||= (orUrl = 'https://tmp.example/or-branch');
        fetch(orUrl + '/after');

        let andUrl = 'https://home.example';
        let andUrlKeep = false;
        andUrlKeep &&= (andUrl = 'https://tmp.example/and-branch');
        fetch(andUrl + '/after');

        let nullishUrl = 'https://home.example';
        let nullishUrlKeep = 'present';
        nullishUrlKeep ??= (nullishUrl = 'https://tmp.example/nullish-branch');
        fetch(nullishUrl + '/after');
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 3);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));

        let requests: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.request")
            .collect();
        assert_eq!(requests.len(), 3);
        assert!(requests.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        )));

        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            6
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn later_var_initializer_is_not_visible_before_execution() {
    let plans = [
        js(r#"
            const fs = require('fs');
            fs.rmSync(path + '/x');
            var path = process.env.HOME + '/safe';
        "#),
        ts(r#"
            import fs from 'node:fs';
            fs.rmSync(path + '/x');
            var path = process.env.HOME + '/safe';
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn definitely_called_functions_preserve_captured_source_string_assignments() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/safe';
            (() => { path = process.env.TMPDIR + '/current'; })();
            fs.rmSync(path + '/x');
        "#),
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/safe';
            function updatePath() { path = process.env.TMPDIR + '/current'; }
            updatePath();
            fs.rmSync(path + '/x');
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/safe';
            (() => { path = process.env.TMPDIR + '/current'; })();
            fs.rmSync(path + '/x');
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/safe';
            function updatePath(): void { path = process.env.TMPDIR + '/current'; }
            updatePath();
            fs.rmSync(path + '/x');
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(&delete.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Environment { name },
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: current }
                },
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: suffix }
                }
            ] if name == "TMPDIR" && current == "/current" && suffix == "/x")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
    }
}

#[test]
fn nested_named_functions_capture_enclosing_source_strings() {
    let plans = [
        js(r#"
            const fs = require('fs');
            const path = process.env.HOME + '/safe';
            function outer() {
                const path = process.env.TMPDIR + '/inner';
                function remove() { fs.rmSync(path + '/x'); }
                remove();
            }
            outer();
        "#),
        ts(r#"
            import fs from 'node:fs';
            const path = process.env.HOME + '/safe';
            function outer(): void {
                const path = process.env.TMPDIR + '/inner';
                function remove(): void { fs.rmSync(path + '/x'); }
                remove();
            }
            outer();
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(&delete.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Environment { name },
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: inner }
                },
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: suffix }
                }
            ] if name == "TMPDIR" && inner == "/inner" && suffix == "/x")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
        assert!(all_full(&plan));
    }
}

#[test]
fn function_local_declarations_shadow_outer_source_strings_from_entry() {
    let plans = [
        js(r#"
            const fs = require('fs');
            const path = process.env.HOME + '/safe';
            function remove() {
                fs.rmSync(path + '/x');
                var path = process.env.TMPDIR + '/inside';
            }
            remove();
        "#),
        js(r#"
            const fs = require('fs');
            const path = process.env.HOME + '/safe';
            (() => {
                const path = path + '/inside';
                fs.rmSync(path);
            })();
        "#),
        ts(r#"
            import fs from 'node:fs';
            const path = process.env.HOME + '/safe';
            function remove(): void {
                fs.rmSync(path + '/x');
                var path = process.env.TMPDIR + '/inside';
            }
            remove();
        "#),
        ts(r#"
            import fs from 'node:fs';
            const path = process.env.HOME + '/safe';
            (() => {
                const path = path + '/inside';
                fs.rmSync(path);
            })();
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn named_function_binding_patterns_use_bounded_arguments() {
    let plans = [
        js(r#"
            const fs = require('fs');
            const path = process.env.HOME + '/safe';
            function remove({ path }) {
                fs.rmSync(path + '/x');
            }
            remove({ path: process.env.TMPDIR + '/chosen' });
        "#),
        ts(r#"
            import fs from 'node:fs';
            const path = process.env.HOME + '/safe';
            function remove({ path }: { path: string }): void {
                fs.rmSync(path + '/x');
            }
            remove({ path: process.env.TMPDIR + '/chosen' });
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Join { parts }
                if matches!(parts.as_slice(), [
                    ResourceExpr::Environment { name },
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path: chosen }
                    },
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path: suffix }
                    }
                ] if name == "TMPDIR" && chosen == "/chosen" && suffix == "/x")
        ));
    }
}

#[test]
fn function_and_class_bindings_do_not_reuse_outer_source_strings() {
    let plans = [
        js(r#"
            const fs = require('fs');
            const path = process.env.HOME + '/safe';
            function remove() {
                function path() {}
                fs.rmSync(path + '/function');
            }
            remove();
            {
                class path {}
                fs.rmSync(path + '/class');
            }
            fs.rmSync(path);
        "#),
        ts(r#"
            import fs from 'node:fs';
            const path = process.env.HOME + '/safe';
            function remove(): void {
                function path(): void {}
                fs.rmSync(path + '/function');
            }
            remove();
            {
                class path {}
                fs.rmSync(path + '/class');
            }
            fs.rmSync(path);
        "#),
    ];
    for plan in plans {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 3);
        assert_eq!(
            deletes
                .iter()
                .filter(|effect| matches!(
                    &effect.resource,
                    ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                ))
                .count(),
            2
        );
        assert!(is_joined_env_path(&deletes[2].resource, "HOME", "/safe"));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn top_level_function_and_class_concatenations_are_unbounded() {
    let plans = [
        js(r#"
            const fs = require('fs');
            function target() {}
            class endpoint {}
            fs.rmSync(target + '/x');
            fetch('https://api.example' + endpoint + '/meta');
        "#),
        ts(r#"
            import fs from 'node:fs';
            function target(): void {}
            class endpoint {}
            fs.rmSync(target + '/x');
            fetch('https://api.example' + endpoint + '/meta');
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(
            &request.resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        ));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn exported_function_and_class_bindings_are_unbounded_source_strings() {
    let plans = [
        js(r#"
            const fs = require('fs');
            export function target() {}
            fs.rmSync(target + '/x');
        "#),
        js(r#"
            const fs = require('fs');
            export class target {}
            fs.rmSync(target + '/x');
        "#),
        js(r#"
            const fs = require('fs');
            export default function target() {}
            fs.rmSync(target + '/x');
        "#),
        js(r#"
            const fs = require('fs');
            export default class target {}
            fs.rmSync(target + '/x');
        "#),
        ts(r#"
            import fs from 'node:fs';
            export function target(): void {}
            fs.rmSync(target + '/x');
        "#),
        ts(r#"
            import fs from 'node:fs';
            export class target {}
            fs.rmSync(target + '/x');
        "#),
        ts(r#"
            import fs from 'node:fs';
            export default function target(): void {}
            fs.rmSync(target + '/x');
        "#),
        ts(r#"
            import fs from 'node:fs';
            export default class target {}
            fs.rmSync(target + '/x');
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn named_function_expressions_do_not_reuse_outer_source_strings() {
    let plans = [
        js(r#"
            const fs = require('fs');
            const path = process.env.HOME + '/safe';
            const endpoint = 'https://good.example/safe';
            const remove = function path() { fs.rmSync(path + '/x'); };
            const request = function endpoint() { fetch(endpoint + '/meta'); };
            remove();
            (function path() { fs.rmSync(path + '/iife'); })();
            request();
        "#),
        ts(r#"
            import fs from 'node:fs';
            const path = process.env.HOME + '/safe';
            const endpoint = 'https://good.example/safe';
            const remove = function path(): void { fs.rmSync(path + '/x'); };
            const request = function endpoint(): void { fetch(endpoint + '/meta'); };
            remove();
            (function path(): void { fs.rmSync(path + '/iife'); })();
            request();
        "#),
    ];
    for plan in plans {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "network.request"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Unresolved { family } if family.0 == "network"
                )
        }));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn switch_and_class_scopes_do_not_reuse_outer_source_strings() {
    let plans = [
        js(r#"
            const fs = require('fs');
            const path = process.env.HOME + '/safe';
            const value = process.env.TMPDIR + '/outer';
            switch (choice) {
                case 0:
                    fs.rmSync(path + '/switch');
                    let path = 1;
            }
            const Box = class path {
                static { fs.rmSync(path + '/class'); }
            };
            class Holder {
                static {
                    fs.rmSync(value + '/static');
                    let value = 1;
                }
            }
        "#),
        ts(r#"
            import fs from 'node:fs';
            const path = process.env.HOME + '/safe';
            const value = process.env.TMPDIR + '/outer';
            switch (choice) {
                case 0:
                    fs.rmSync(path + '/switch');
                    let path = 1;
            }
            const Box = class path {
                static { fs.rmSync(path + '/class'); }
            };
            class Holder {
                static {
                    fs.rmSync(value + '/static');
                    let value = 1;
                }
            }
        "#),
    ];
    for plan in plans {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 3);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn class_field_initializers_follow_definition_time_execution() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let instance = process.env.HOME;
            let staticField = process.env.HOME;
            let computedKey = process.env.HOME;
            let staticBlock = process.env.HOME;
            class Dormant {
                field = (instance = process.env.TMPDIR);
            }
            class Active {
                [computedKey = process.env.USERPROFILE] = 0;
                static field = (staticField = process.env.TMPDIR);
                static { staticBlock = process.env.CACHE_DIR; }
            }
            fs.rmSync(instance + '/instance');
            fs.rmSync(staticField + '/static-field');
            fs.rmSync(computedKey + '/computed-key');
            fs.rmSync(staticBlock + '/static-block');
        "#),
        ts(r#"
            import fs from 'node:fs';
            let instance = process.env.HOME;
            let staticField = process.env.HOME;
            let computedKey = process.env.HOME;
            let staticBlock = process.env.HOME;
            class Dormant {
                field = (instance = process.env.TMPDIR);
            }
            class Active {
                [computedKey = process.env.USERPROFILE] = 0;
                static field = (staticField = process.env.TMPDIR);
                static { staticBlock = process.env.CACHE_DIR; }
            }
            fs.rmSync(instance + '/instance');
            fs.rmSync(staticField + '/static-field');
            fs.rmSync(computedKey + '/computed-key');
            fs.rmSync(staticBlock + '/static-block');
        "#),
    ];
    for plan in plans {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 4);
        assert!(is_joined_env_path(
            &deletes[0].resource,
            "HOME",
            "/instance"
        ));
        assert!(is_joined_env_path(
            &deletes[1].resource,
            "TMPDIR",
            "/static-field"
        ));
        assert!(is_joined_env_path(
            &deletes[2].resource,
            "USERPROFILE",
            "/computed-key"
        ));
        assert!(is_joined_env_path(
            &deletes[3].resource,
            "CACHE_DIR",
            "/static-block"
        ));
    }
    // A class that may be instantiated runs its instance fields, which may
    // or may not happen: their effects are conditional and their writes
    // join the state before them.
    let live = js(r#"
        const fs = require('fs');
        let instance = process.env.HOME;
        class Live {
            field = (instance = process.env.TMPDIR);
            removed = fs.rmSync('/live-field');
        }
        new Live();
        fs.rmSync(instance + '/instance');
    "#);
    let deletes: Vec<_> = live
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 2);
    assert!(matches!(&deletes[0].resource, ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    } if path == "/live-field"));
    assert!(deletes[0].condition.is_some());
    assert!(deletes[1].condition.is_none());
    assert!(!is_joined_env_path(
        &deletes[1].resource,
        "HOME",
        "/instance"
    ));
    assert!(!is_joined_env_path(
        &deletes[1].resource,
        "TMPDIR",
        "/instance"
    ));
    // Static code runs with the class as `this`, so `new this()` there
    // instantiates it; a TypeScript type reference constructs nothing.
    for source in [
        "class Own { x = require('fs').rmSync('/own'); static { new this(); } }",
        "class Own { x = require('fs').rmSync('/own'); static self = new this(); }",
    ] {
        assert!(has(&js(source), "filesystem.delete", "/own"), "{source}");
    }
    let typed = ts("class Typed { x = require('fs').rmSync('/typed'); } let t: Typed | undefined;");
    assert!(!has(&typed, "filesystem.delete", "/typed"));
}

#[test]
fn destructuring_assignments_invalidate_source_string_tracking() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/safe';
            ({ path } = config);
            fs.rmSync(path + '/x');
        "#),
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/safe';
            [path] = values;
            fs.rmSync(path + '/x');
        "#),
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/safe';
            ({ [key]: path } = config);
            fs.rmSync(path + '/x');
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/safe';
            ({ path } = config);
            fs.rmSync(path + '/x');
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/safe';
            [path] = values;
            fs.rmSync(path + '/x');
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/safe';
            ({ [key]: path } = config);
            fs.rmSync(path + '/x');
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn inline_function_source_strings_do_not_escape_their_lexical_frame() {
    let plan = js(r#"
        const fs = require('fs');
        const path = process.env.HOME + '/safe';
        (() => {
            const path = process.env.TMPDIR + '/inside';
            fs.rmSync(path);
        })();
        fs.rmSync(path);
    "#);
    let deletes: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 2);
    assert!(
        deletes
            .iter()
            .any(|effect| is_joined_env_path(&effect.resource, "TMPDIR", "/inside"))
    );
    assert!(
        deletes
            .iter()
            .any(|effect| is_joined_env_path(&effect.resource, "HOME", "/safe"))
    );
}

#[test]
fn block_source_string_shadow_does_not_escape_lexical_scope() {
    let plan = js(r#"
        const fs = require('fs');
        let path = process.env.HOME + '/safe';
        {
            const path = process.env.TMPDIR + '/inside';
            fs.rmSync(path);
        }
        fs.rmSync(path);
    "#);
    let deletes: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 2);
    assert!(is_joined_env_path(
        &deletes[0].resource,
        "TMPDIR",
        "/inside"
    ));
    assert!(is_joined_env_path(&deletes[1].resource, "HOME", "/safe"));
}

#[test]
fn inline_function_parameters_use_their_call_arguments() {
    let plans = [
        js(r#"
            const fs = require('fs');
            const path = process.env.HOME + '/safe';
            ((path) => fs.rmSync(path))(process.env.TMPDIR + '/inside');
        "#),
        ts(r#"
            import fs from 'node:fs';
            const path = process.env.HOME + '/safe';
            ((path: string) => fs.rmSync(path))(process.env.TMPDIR + '/inside');
        "#),
    ];
    for plan in plans {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 1);
        assert!(is_joined_env_path(
            &deletes[0].resource,
            "TMPDIR",
            "/inside"
        ));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
    }
}

#[test]
fn inline_function_parameters_are_sink_typed_for_network_calls() {
    let plan = js(r#"
        const target = 'https://good.example' + '/old';
        ((target) => fetch(target + '/meta'))('https://evil.example');
    "#);
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "network.request")
        .expect("network request effect");
    assert!(matches!(&request.resource, ResourceExpr::Join { parts }
        if matches!(parts.as_slice(), [
            ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
            },
            ResourceExpr::Literal { value }
        ] if host == "evil.example"
            && scheme.as_deref() == Some("https")
            && value == "/meta")));
    assert!(!has_boundary(&plan, "unmodeled_dynamic"));
}

#[test]
fn unknown_callback_parameters_do_not_reuse_outer_source_strings() {
    let plan = js(r#"
        const fs = require('fs');
        const path = process.env.HOME + '/safe';
        candidates.forEach((path) => fs.rmSync(path));
    "#);
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .expect("filesystem delete effect");
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Unresolved { family } if family.0 == "filesystem"
    ));
    assert!(has_boundary(&plan, "unmodeled_dynamic"));
    assert!(!all_full(&plan));
}

#[test]
fn lexical_binding_patterns_do_not_reuse_outer_source_strings() {
    let plan = js(r#"
        const fs = require('fs');
        const path = process.env.HOME + '/safe';
        (() => {
            const { path } = args;
            fs.rmSync(path);
        })();
        try {
            throw value;
        } catch (path) {
            fs.rmSync(path);
        }
        for (const path of candidates) {
            fs.rmSync(path);
        }
        fs.rmSync(path);
    "#);
    let deletes: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 4);
    assert_eq!(
        deletes
            .iter()
            .filter(|effect| is_joined_env_path(&effect.resource, "HOME", "/safe"))
            .count(),
        1
    );
    assert_eq!(
        deletes
            .iter()
            .filter(|effect| matches!(
                &effect.resource,
                ResourceExpr::Unresolved { family } if family.0 == "filesystem"
            ))
            .count(),
        3
    );
    assert!(has_boundary(&plan, "unmodeled_dynamic"));
    assert!(!all_full(&plan));
}

#[test]
fn for_initializer_lexical_binding_does_not_reuse_outer_source_string() {
    let plans = [
        js(r#"
            const fs = require('fs');
            const path = process.env.HOME + '/outer';
            for (let path = path + '/inner'; false;) {
                fs.rmSync(path + '/x');
            }
        "#),
        ts(r#"
            import fs from 'node:fs';
            const path = process.env.HOME + '/outer';
            for (let path = path + '/inner'; false;) {
                fs.rmSync(path + '/x');
            }
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn for_in_of_lexical_bindings_hide_outer_source_strings_from_iterables() {
    let plans = [
        js(r#"
            const fs = require('fs');
            const path = process.env.HOME;
            for (let path of [fs.rmSync(path + '/tdz')]) {}
        "#),
        js(r#"
            const fs = require('fs');
            const path = process.env.HOME;
            for (let path in { [fs.rmSync(path + '/tdz')]: true }) {}
        "#),
        ts(r#"
            import fs from 'node:fs';
            const path = process.env.HOME;
            for (let path of [fs.rmSync(path + '/tdz')]) {}
        "#),
        ts(r#"
            import fs from 'node:fs';
            const path = process.env.HOME;
            for (let path in { [fs.rmSync(path + '/tdz')]: true }) {}
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn for_loop_assignment_targets_invalidate_source_string_tracking() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let target = process.env.HOME + '/safe';
            for (target of entries) {}
            fs.rmSync(target + '/of');
            target = process.env.HOME + '/safe';
            for (target in entries) {}
            fs.rmSync(target + '/in');
            target = process.env.HOME + '/safe';
            for ({ target } of entries) {}
            fs.rmSync(target + '/pattern');
        "#),
        ts(r#"
            import fs from 'node:fs';
            let target = process.env.HOME + '/safe';
            for (target of entries) {}
            fs.rmSync(target + '/of');
            target = process.env.HOME + '/safe';
            for (target in entries) {}
            fs.rmSync(target + '/in');
            target = process.env.HOME + '/safe';
            for ({ target } of entries) {}
            fs.rmSync(target + '/pattern');
        "#),
    ];
    for plan in plans {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 3);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn called_function_sees_current_module_source_string() {
    let plan = js(r#"
        const fs = require('fs');
        let path = process.env.HOME + '/safe';
        function removeCurrent() {
            fs.rmSync(path);
        }
        path = process.env.TMPDIR + '/current';
        removeCurrent();
    "#);
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .expect("filesystem delete effect");
    assert!(is_joined_env_path(&delete.resource, "TMPDIR", "/current"));
}

#[test]
fn conditional_source_string_reassignment_is_unbounded() {
    let plan = js(r#"
        const fs = require('fs');
        let path = process.env.HOME + '/safe';
        function removeCurrent() {
            fs.rmSync(path);
        }
        if (enabled) {
            path = process.env.TMPDIR + '/conditional';
        }
        removeCurrent();
    "#);
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .expect("filesystem delete effect");
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Unresolved { family } if family.0 == "filesystem"
    ));
    assert!(has_boundary(&plan, "unmodeled_dynamic"));
    assert!(!all_full(&plan));
}

#[test]
fn expression_branches_preserve_possible_source_strings() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/home';
            flag ? (path = process.env.TMPDIR + '/conditional') : 0;
            fs.rmSync(path);
            path = process.env.HOME + '/home';
            flag && (path = process.env.TMPDIR + '/logical');
            fs.rmSync(path);
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/home';
            flag ? (path = process.env.TMPDIR + '/conditional') : 0;
            fs.rmSync(path);
            path = process.env.HOME + '/home';
            flag && (path = process.env.TMPDIR + '/logical');
            fs.rmSync(path);
        "#),
    ];
    for plan in plans {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn switch_abrupt_completion_stops_source_string_propagation() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/home';
            switch (flag) {
                default:
                    break;
                    path = process.env.TMPDIR + '/break';
            }
            fs.rmSync(path);
            function remove(choice) {
                let local = process.env.HOME + '/home';
                switch (choice) {
                    case 0:
                        return;
                        local = process.env.TMPDIR + '/return';
                }
                fs.rmSync(local);
            }
            remove(flag);
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/home';
            switch (flag) {
                default:
                    break;
                    path = process.env.TMPDIR + '/break';
            }
            fs.rmSync(path);
            function remove(choice: number) {
                let local = process.env.HOME + '/home';
                switch (choice) {
                    case 0:
                        return;
                        local = process.env.TMPDIR + '/return';
                }
                fs.rmSync(local);
            }
            remove(flag);
        "#),
    ];
    for plan in plans {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(
            deletes
                .iter()
                .all(|effect| is_joined_env_path(&effect.resource, "HOME", "/home"))
        );
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
    }
}

#[test]
fn switch_and_try_branches_preserve_divergent_source_strings() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let target = process.env.HOME + '/.cache/x';
            switch (choice) {
                case 0:
                    target = process.env.TMPDIR + '/.cache/x';
                    break;
                case 1:
                    target = process.env.HOME + '/.cache/x';
                    break;
            }
            fs.rmSync(target);
            target = process.env.HOME + '/.cache/x';
            try {
                target = process.env.TMPDIR + '/.cache/x';
                if (choice) throw failure;
            } catch {
                target = process.env.HOME + '/.cache/x';
            }
            fs.rmSync(target);
        "#),
        ts(r#"
            import fs from 'node:fs';
            let target = process.env.HOME + '/.cache/x';
            switch (choice) {
                case 0:
                    target = process.env.TMPDIR + '/.cache/x';
                    break;
                case 1:
                    target = process.env.HOME + '/.cache/x';
                    break;
            }
            fs.rmSync(target);
            target = process.env.HOME + '/.cache/x';
            try {
                target = process.env.TMPDIR + '/.cache/x';
                if (choice) throw failure;
            } catch {
                target = process.env.HOME + '/.cache/x';
            }
            fs.rmSync(target);
        "#),
    ];
    for plan in plans {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn update_expressions_invalidate_source_strings() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/safe';
            path++;
            fs.rmSync(path + '/x');
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path: any = process.env.HOME + '/safe';
            path++;
            fs.rmSync(path + '/x');
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn finally_preserves_exceptional_source_string_state() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/safe';
            try {
                if (process.env.FAIL) throw new Error('x');
                path = process.env.TMPDIR + '/inner';
            } finally {
                fs.rmSync(path + '/x');
            }
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/safe';
            try {
                if (process.env.FAIL) throw new Error('x');
                path = process.env.TMPDIR + '/inner';
            } finally {
                fs.rmSync(path + '/x');
            }
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn loop_carried_source_strings_are_unbounded_before_loop_effects() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/first';
            while (keepGoing) {
                fs.rmSync(path);
                path = process.env.TMPDIR + '/later';
            }
        "#),
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/first';
            for (; keepGoing; path = process.env.TMPDIR + '/later') {
                fs.rmSync(path);
            }
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/first';
            while (keepGoing) {
                fs.rmSync(path);
                path = process.env.TMPDIR + '/later';
            }
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/first';
            for (; keepGoing; path = process.env.TMPDIR + '/later') {
                fs.rmSync(path);
            }
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn bounded_binding_patterns_preserve_source_string_joins() {
    let plans = [
        js(r#"
            const fs = require('fs');
            function clearDefault(path = process.env.HOME + '/default') {
                fs.rmSync(path);
            }
            function clearParameter([path]) {
                fs.rmSync(path);
            }
            clearDefault();
            clearParameter([process.env.TMPDIR + '/parameter']);
            const [path] = [process.env.CACHE_DIR + '/local'];
            fs.rmSync(path);
        "#),
        ts(r#"
            import fs from 'node:fs';
            function clearDefault(path = process.env.HOME + '/default') {
                fs.rmSync(path);
            }
            function clearParameter([path]) {
                fs.rmSync(path);
            }
            clearDefault();
            clearParameter([process.env.TMPDIR + '/parameter']);
            const [path] = [process.env.CACHE_DIR + '/local'];
            fs.rmSync(path);
        "#),
    ];
    for plan in plans {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 3);
        for (environment, suffix) in [
            ("HOME", "/default"),
            ("TMPDIR", "/parameter"),
            ("CACHE_DIR", "/local"),
        ] {
            assert!(
                deletes.iter().any(|effect| is_joined_env_path(
                    &effect.resource,
                    environment,
                    suffix
                )),
                "missing {environment}{suffix} resource in {deletes:#?}"
            );
        }
    }
}

#[test]
fn local_binding_pattern_defaults_apply_to_undefined() {
    let source = r#"
        const fs = require('fs');
        const [path = process.env.HOME + '/default'] = [undefined];
        fs.rmSync(path);
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/default"));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
    }
}

#[test]
fn provided_destructuring_values_skip_default_initializers() {
    let source = r#"
        const fs = require('fs');
        let base = process.env.HOME;
        const { path = (base = process.env.TMPDIR) } = { path: 'provided' };
        const [item = (base = process.env.USERPROFILE)] = ['provided'];
        fs.rmSync(base + '/x');
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/x"));
        assert!(!plan.effects.iter().any(|effect| {
            effect.operation.0 == "environment.read"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Environment { name }
                        if matches!(name.as_str(), "TMPDIR" | "USERPROFILE")
                )
        }));
    }
}

#[test]
fn unknown_object_spreads_make_destructuring_defaults_conditional() {
    let source = r#"
        const fs = require('fs');
        let base = process.env.HOME;
        const { selected = (base = process.env.TMPDIR) } = {
            selected: 'provided',
            ...globalThis.config,
        };
        fs.rmSync(base + '/after');
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "environment.read"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name }
                } if name == "TMPDIR")
        }));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn provided_destructuring_assignment_values_skip_default_initializers() {
    let source = r#"
        const fs = require('fs');
        let sibling = process.env.HOME;
        let selected;
        ({ selected = (sibling = process.env.TMPDIR) } = { selected: 'provided' });
        fs.rmSync(sibling + '/after');
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/after"));
        assert!(!plan.effects.iter().any(|effect| {
            effect.operation.0 == "environment.read"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Environment { name } if name.as_str() == "TMPDIR"
                )
        }));
    }
}

#[test]
fn destructuring_initializers_precede_selected_defaults() {
    let source = r#"
        const fs = require('fs');
        let base = process.env.HOME;
        const { selected = (base = process.env.TMPDIR), captured } = { captured: base };
        fs.rmSync(captured + '/captured');
        fs.rmSync(base + '/after');
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().any(|effect| is_joined_env_path(
            &effect.resource,
            "HOME",
            "/captured"
        )));
        assert!(deletes.iter().any(|effect| is_joined_env_path(
            &effect.resource,
            "TMPDIR",
            "/after"
        )));
    }
}

#[test]
fn unreachable_captured_writes_do_not_change_source_strings() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/before';
            function rewrite() {
                return;
                path = process.env.TMPDIR + '/after';
            }
            rewrite();
            fs.rmSync(path);
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/before';
            function rewrite() {
                return;
                path = process.env.TMPDIR + '/after';
            }
            rewrite();
            fs.rmSync(path);
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/before"));
    }
}

#[test]
fn definitely_abrupt_try_and_switch_stop_captured_writes() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let tryPath = process.env.HOME + '/try';
            function rewriteTry() {
                try { return; } finally {}
                tryPath = process.env.TMPDIR + '/try';
            }
            rewriteTry();
            fs.rmSync(tryPath);
            let switchPath = process.env.HOME + '/switch';
            function rewriteSwitch(choice) {
                switch (choice) {
                    case 0: return;
                    default: return;
                }
                switchPath = process.env.TMPDIR + '/switch';
            }
            rewriteSwitch(flag);
            fs.rmSync(switchPath);
        "#),
        ts(r#"
            import fs from 'node:fs';
            let tryPath = process.env.HOME + '/try';
            function rewriteTry() {
                try { return; } finally {}
                tryPath = process.env.TMPDIR + '/try';
            }
            rewriteTry();
            fs.rmSync(tryPath);
            let switchPath = process.env.HOME + '/switch';
            function rewriteSwitch(choice: number) {
                switch (choice) {
                    case 0: return;
                    default: return;
                }
                switchPath = process.env.TMPDIR + '/switch';
            }
            rewriteSwitch(flag);
            fs.rmSync(switchPath);
        "#),
    ];
    for plan in plans {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(
            deletes
                .iter()
                .any(|effect| is_joined_env_path(&effect.resource, "HOME", "/try"))
        );
        assert!(deletes.iter().any(|effect| is_joined_env_path(
            &effect.resource,
            "HOME",
            "/switch"
        )));
    }
}

#[test]
fn labeled_switch_breaks_stop_unreachable_source_string_writes() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/before';
            outer: {
                switch (flag) {
                    default: break outer;
                }
                path = process.env.TMPDIR + '/unreachable';
            }
            fs.rmSync(path);
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/before';
            outer: {
                switch (flag) {
                    default: break outer;
                }
                path = process.env.TMPDIR + '/unreachable';
            }
            fs.rmSync(path);
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/before"));
    }
}

#[test]
fn labeled_switch_break_targets_preserve_source_string_writes() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let base = process.env.HOME;
            selected: switch (flag) {
                default:
                    base = process.env.TMPDIR;
                    break selected;
            }
            fs.rmSync(base + '/labeled-switch');
        "#),
        ts(r#"
            import fs from 'node:fs';
            let base = process.env.HOME;
            selected: switch (flag) {
                default:
                    base = process.env.TMPDIR;
                    break selected;
            }
            fs.rmSync(base + '/labeled-switch');
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(
            &delete.resource,
            "TMPDIR",
            "/labeled-switch"
        ));
    }
}

#[test]
fn generator_calls_do_not_apply_captured_source_string_writes() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/before';
            function* rewrite() {
                path = process.env.TMPDIR + '/never';
            }
            rewrite();
            fs.rmSync(path);
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/before';
            function* rewrite() {
                path = process.env.TMPDIR + '/never';
            }
            rewrite();
            fs.rmSync(path);
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/before"));
    }
}

#[test]
fn deferred_and_conditional_calls_widen_captured_source_string_writes() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/before';
            async function rewrite() {
                await pending;
                path = process.env.TMPDIR + '/later';
            }
            rewrite();
            fs.rmSync(path);
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/before';
            async function rewrite() {
                await pending;
                path = process.env.TMPDIR + '/later';
            }
            rewrite();
            fs.rmSync(path);
        "#),
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/before';
            entries.forEach(() => {
                path = process.env.TMPDIR + '/later';
            });
            fs.rmSync(path);
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/before';
            entries.forEach(() => {
                path = process.env.TMPDIR + '/later';
            });
            fs.rmSync(path);
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn finally_includes_source_string_state_reaching_throw() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/same';
            try {
                path = process.env.TMPDIR + '/intermediate';
                if (failure) throw failure;
                path = process.env.HOME + '/same';
            } finally {
                fs.rmSync(path);
            }
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/same';
            try {
                path = process.env.TMPDIR + '/intermediate';
                if (failure) throw failure;
                path = process.env.HOME + '/same';
            } finally {
                fs.rmSync(path);
            }
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn static_block_var_does_not_hide_captured_source_string_write() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/before';
            function rewrite() {
                class Holder { static { var path; } }
                path = process.env.TMPDIR + '/after';
            }
            rewrite();
            fs.rmSync(path);
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/before';
            function rewrite() {
                class Holder { static { var path; } }
                path = process.env.TMPDIR + '/after';
            }
            rewrite();
            fs.rmSync(path);
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "TMPDIR", "/after"));
    }
}

#[test]
fn conditional_concatenations_keep_symbolic_resources_and_boundaries() {
    let plans = [
        js(r#"
            const fs = require('fs');
            fs.rmSync(flag
                ? process.env.HOME + '/one'
                : process.env.TMPDIR + '/two');
            const target = flag
                ? process.env.HOME + '/one'
                : process.env.TMPDIR + '/two';
            fs.rmSync(target);
        "#),
        ts(r#"
            import fs from 'node:fs';
            fs.rmSync(flag
                ? process.env.HOME + '/one'
                : process.env.TMPDIR + '/two');
            const target: string = flag
                ? process.env.HOME + '/one'
                : process.env.TMPDIR + '/two';
            fs.rmSync(target);
        "#),
    ];
    for plan in plans {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn string_concatenation_preserves_network_path_and_environment_parts() {
    let plans = [
        js(r#"
            const base = 'https://api.example';
            fetch(base + '/meta/auth?t=' + process.env.TOKEN);
        "#),
        ts(r#"
            const base: string = 'https://api.example';
            fetch(base + '/meta/auth?t=' + process.env.TOKEN);
        "#),
    ];
    for plan in plans {
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                },
                ResourceExpr::Literal { value },
                ResourceExpr::Environment { name }
            ] if host == "api.example"
                && scheme.as_deref() == Some("https")
                && value == "/meta/auth?t="
                && name == "TOKEN")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
    }
}

#[test]
fn local_function_returns_preserve_source_string_concatenations() {
    let plans = [
        js(r#"
            const fs = require('fs');
            function cachePath() { return process.env.HOME + '/cache/x'; }
            function endpoint() {
                return 'https://api.example' + '/meta/' + process.env.TOKEN;
            }
            const target = cachePath();
            fs.rmSync(target);
            fetch(endpoint());
        "#),
        ts(r#"
            import fs from 'node:fs';
            function cachePath(): string { return process.env.HOME + '/cache/x'; }
            function endpoint(): string {
                return 'https://api.example' + '/meta/' + process.env.TOKEN;
            }
            const target: string = cachePath();
            fs.rmSync(target);
            fetch(endpoint());
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/cache/x"));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                },
                ResourceExpr::Literal { value },
                ResourceExpr::Environment { name }
            ] if host == "api.example"
                && scheme.as_deref() == Some("https")
                && value == "/meta/"
                && name == "TOKEN")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
    }
}

#[test]
fn non_identifier_callee_returns_are_not_silent() {
    let source = r#"
        const fs = require('fs');
        function target() { return process.env.HOME + '/sequence'; }
        fs.rmSync((0, target)());
        function one() { return process.env.API_BASE + '/one'; }
        function two() { return process.env.API_BASE + '/two'; }
        fetch((globalThis.pick ? one : two)());
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/sequence"));

        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(
            &request.resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        ));
        assert!(has_boundary(&plan, "unresolved_call"));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn with_statement_identifier_writes_keep_resource_sinks_symbolic() {
    let plan = js(r#"
        const fs = require('fs');
        let path = process.env.HOME + '/before';
        const pathScope = { path: 'property' };
        with (pathScope) {
            path = process.env.TMPDIR + '/after';
        }
        fs.rmSync(path);

        let endpoint = 'https://one.example' + '/before';
        const endpointScope = { endpoint: 'property' };
        with (endpointScope) {
            endpoint = 'https://two.example' + '/after';
        }
        fetch(endpoint);
    "#);

    let sinks: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| {
            matches!(
                effect.operation.0.as_str(),
                "filesystem.delete" | "network.request"
            )
        })
        .collect();
    assert_eq!(sinks.len(), 2);
    assert!(sinks.iter().all(|effect| match &effect.resource {
        ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
            "filesystem.delete" => family.0 == "filesystem",
            "network.request" => family.0 == "network",
            _ => false,
        },
        _ => false,
    }));
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        2
    );
    assert!(!all_full(&plan));
}

#[test]
fn with_statement_global_bindings_keep_resource_sinks_symbolic() {
    let plan = js(r#"
        const fs = require('fs');
        const scope = {
            process: { env: { HOME: '/not-the-environment' } },
            String: _value => '/intercepted',
        };
        with (scope) {
            fs.rmSync(process.env.HOME + '/cache');
            fs.rmSync(String('/tmp' + '/converted-cache'));
        }
    "#);

    assert!(!ops(&plan).contains(&"environment.read"));
    let deletes: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 2);
    assert!(deletes.iter().all(|effect| matches!(
        &effect.resource,
        ResourceExpr::Unresolved { family } if family.0 == "filesystem"
    )));
    assert!(has_boundary(&plan, "partial_analysis"));
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        2
    );
    assert!(!all_full(&plan));
}

#[test]
fn with_statement_undefined_binding_skips_parameter_defaults() {
    let plan = js(r#"
        const fs = require('fs');
        const path = process.env.HOME;
        with ({ undefined: path }) {
            ((value = process.env.TMPDIR) => fs.rmSync(value + '/cache'))(undefined);
        }

        const endpoint = 'https://before.example';
        with ({ undefined: endpoint }) {
            ((value = 'https://after.example') => fetch(value + '/meta'))(undefined);
        }
    "#);

    assert!(!plan.effects.iter().any(|effect| {
        effect.operation.0 == "environment.read"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name }
            } if name == "TMPDIR")
    }));
    let sinks: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| {
            matches!(
                effect.operation.0.as_str(),
                "filesystem.delete" | "network.request"
            )
        })
        .collect();
    assert_eq!(sinks.len(), 2);
    assert!(sinks.iter().all(|effect| match &effect.resource {
        ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
            "filesystem.delete" => family.0 == "filesystem",
            "network.request" => family.0 == "network",
            _ => false,
        },
        _ => false,
    }));
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        2
    );
    assert!(!all_full(&plan));
}

#[test]
fn concise_arrow_returns_preserve_source_strings() {
    let source = r#"
        const fs = require('fs');
        const cachePath = () => process.env.HOME + '/arrow-cache';
        const endpoint = () =>
            'https://api.example' + '/arrow-meta/' + process.env.TOKEN;
        fs.rmSync(cachePath());
        fetch(endpoint());
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/arrow-cache"));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                },
                ResourceExpr::Literal { value },
                ResourceExpr::Environment { name }
            ] if host == "api.example"
                && scheme.as_deref() == Some("https")
                && value == "/arrow-meta/"
                && name == "TOKEN")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
    }
}

#[test]
fn bounded_helper_returns_participate_in_caller_concatenations() {
    let source = r#"
        const fs = require('fs');
        function root() { return process.env.HOME; }
        function host() { return 'https://api.example'; }
        fs.rmSync(root() + '/helper-cache');
        fetch(host() + '/helper-meta');
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(
            &delete.resource,
            "HOME",
            "/helper-cache"
        ));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                },
                ResourceExpr::Literal { value }
            ] if host == "api.example"
                && scheme.as_deref() == Some("https")
                && value == "/helper-meta")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
    }
}

#[test]
fn sibling_nested_functions_capture_their_common_lexical_parent() {
    let source = r#"
        const fs = require('fs');
        function outer() {
            const root = process.env.TMPDIR + '/outer';
            function remove() { fs.rmSync(root + '/x'); }
            function dispatch() {
                const root = process.env.HOME + '/caller';
                remove();
            }
            dispatch();
        }
        outer();
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(&delete.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Environment { name },
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: outer }
                },
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: suffix }
                }
            ] if name == "TMPDIR" && outer == "/outer" && suffix == "/x")));
    }
}

#[test]
fn failed_local_function_return_concatenation_is_unmodeled_dynamic() {
    let source = r#"
        const fs = require('fs');
        function cachePath() { return process.env.HOME + 1; }
        fs.rmSync(cachePath());
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn network_environment_base_concatenation_preserves_bounded_parts() {
    let plans = [
        js(r#"
            fetch(process.env.API_BASE + '/meta');
        "#),
        ts(r#"
            fetch(process.env.API_BASE + '/meta');
        "#),
    ];
    for plan in plans {
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Environment { name },
                ResourceExpr::Literal { value }
            ] if name == "API_BASE" && value == "/meta")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
    }
}

#[test]
fn awaited_promise_resolution_preserves_sink_concatenations() {
    let source = r#"
        const fs = require('fs');
        fs.rmSync(await Promise.resolve(process.env.HOME + '/wrapped'));
        fetch(await Promise.resolve(process.env.API_BASE + '/meta'));
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/wrapped"));

        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Environment { name },
                ResourceExpr::Literal { value }
            ] if name == "API_BASE" && value == "/meta")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
        assert!(all_full(&plan));
    }
}

#[test]
fn reassigned_promise_resolution_keeps_sink_concatenations_unbounded() {
    let sources = [
        r#"
            const fs = require('fs');
            Promise.resolve = function (_) {
                return process.env.TMPDIR + '/replacement';
            };
            fs.rmSync(await Promise.resolve(process.env.HOME + '/wrapped'));
            fetch(await Promise.resolve(process.env.API_BASE + '/meta'));
        "#,
        r#"
            const fs = require('fs');
            const promiseAlias = Promise;
            promiseAlias.resolve = globalThis.resolve;
            fs.rmSync(await Promise.resolve(process.env.HOME + '/wrapped'));
            fetch(await Promise.resolve(process.env.API_BASE + '/meta'));
        "#,
    ];
    for source in sources {
        for plan in [js(source), ts(source)] {
            let delete = plan
                .effects
                .iter()
                .find(|effect| effect.operation.0 == "filesystem.delete")
                .expect("filesystem delete effect");
            assert!(matches!(
                &delete.resource,
                ResourceExpr::Unresolved { family } if family.0 == "filesystem"
            ));

            let request = plan
                .effects
                .iter()
                .find(|effect| effect.operation.0 == "network.request")
                .expect("network request effect");
            assert!(matches!(
                &request.resource,
                ResourceExpr::Unresolved { family } if family.0 == "network"
            ));
            assert!(has_boundary(&plan, "unmodeled_dynamic"));
            assert!(!all_full(&plan));
        }
    }
}

#[test]
fn global_this_builtin_reassignments_keep_sink_concatenations_unbounded() {
    let source = r#"
        const fs = require('fs');
        globalThis.Promise.resolve = globalThis.resolve;
        fs.rmSync(await Promise.resolve(process.env.HOME + '/promise'));
        fetch(await Promise.resolve(process.env.API_BASE + '/promise'));
        globalThis.String = globalThis.convert;
        fs.rmSync(String(process.env.HOME + '/string'));
        fetch(String(process.env.API_BASE + '/string'));
    "#;
    for plan in [js(source), ts(source)] {
        let sinks = plan.effects.iter().filter(|effect| {
            matches!(
                effect.operation.0.as_str(),
                "filesystem.delete" | "network.request"
            )
        });
        assert_eq!(sinks.clone().count(), 4);
        assert!(sinks.into_iter().all(|effect| {
            matches!(&effect.resource, ResourceExpr::Unresolved { family }
            if family.0 == if effect.operation.0 == "filesystem.delete" {
                "filesystem"
            } else {
                "network"
            })
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            4
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn global_this_alias_builtin_reassignments_keep_sink_concatenations_unbounded() {
    let source = r#"
        const fs = require('fs');
        const root = globalThis;
        root.String = root.convert;
        fs.rmSync(String(process.env.HOME + '/alias-string'));
        const promises = root.Promise;
        promises.resolve = root.convert;
        fetch(await Promise.resolve(process.env.API_BASE + '/alias-promise'));
    "#;
    for plan in [js(source), ts(source)] {
        let sinks = plan.effects.iter().filter(|effect| {
            matches!(
                effect.operation.0.as_str(),
                "filesystem.delete" | "network.request"
            )
        });
        assert_eq!(sinks.clone().count(), 2);
        assert!(sinks.into_iter().all(|effect| {
            matches!(&effect.resource, ResourceExpr::Unresolved { family }
            if family.0 == if effect.operation.0 == "filesystem.delete" {
                "filesystem"
            } else {
                "network"
            })
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn global_object_mutations_keep_transparent_builtin_concatenations_unbounded() {
    let sources = [
        r#"
            const fs = require('fs');
            Object.defineProperty(globalThis, 'String', { value: globalThis.convert });
            Object.defineProperty(globalThis, 'Promise', {
                value: { resolve: globalThis.convert }
            });
            fs.rmSync(String(process.env.HOME + '/mutated-string'));
            fetch(await Promise.resolve(process.env.API_BASE + '/mutated-promise'));
        "#,
        r#"
            const fs = require('fs');
            Object.assign(globalThis, {
                String: globalThis.convert,
                Promise: { resolve: globalThis.convert }
            });
            fs.rmSync(String(process.env.HOME + '/assigned-string'));
            fetch(await Promise.resolve(process.env.API_BASE + '/assigned-promise'));
        "#,
        r#"
            const fs = require('fs');
            Object.defineProperties(globalThis, {
                String: { value: globalThis.convert },
                Promise: { value: { resolve: globalThis.convert } }
            });
            fs.rmSync(String(process.env.HOME + '/defined-string'));
            fetch(await Promise.resolve(process.env.API_BASE + '/defined-promise'));
        "#,
        r#"
            const fs = require('fs');
            const replacements = {
                String: globalThis.convert,
                Promise: { resolve: globalThis.convert }
            };
            Object.assign(globalThis, replacements);
            fs.rmSync(String(process.env.HOME + '/identifier-string'));
            fetch(await Promise.resolve(process.env.API_BASE + '/identifier-promise'));
        "#,
        r#"
            const fs = require('fs');
            const replacements = {
                String: globalThis.convert,
                Promise: { resolve: globalThis.convert }
            };
            Object.assign(globalThis, { ...replacements });
            fs.rmSync(String(process.env.HOME + '/spread-string'));
            fetch(await Promise.resolve(process.env.API_BASE + '/spread-promise'));
        "#,
        r#"
            const fs = require('fs');
            const stringName = 'String';
            const promiseName = 'Promise';
            Object.defineProperties(globalThis, {
                [stringName]: { value: globalThis.convert },
                [promiseName]: { value: { resolve: globalThis.convert } }
            });
            fs.rmSync(String(process.env.HOME + '/computed-string'));
            fetch(await Promise.resolve(process.env.API_BASE + '/computed-promise'));
        "#,
        r#"
            const fs = require('fs');
            Object.assign(globalThis, {}, {
                String: globalThis.convert,
                Promise: { resolve: globalThis.convert }
            });
            fs.rmSync(String(process.env.HOME + '/multi-source-string'));
            fetch(await Promise.resolve(process.env.API_BASE + '/multi-source-promise'));
        "#,
        r#"
            const fs = require('fs');
            Object.assign.call(Object, globalThis, {}, {
                String: globalThis.convert,
                Promise: { resolve: globalThis.convert }
            });
            fs.rmSync(String(process.env.HOME + '/call-string'));
            fetch(await Promise.resolve(process.env.API_BASE + '/call-promise'));
        "#,
        r#"
            const fs = require('fs');
            Object.defineProperties.apply(Object, [globalThis, {
                String: { value: globalThis.convert },
                Promise: { value: { resolve: globalThis.convert } }
            }]);
            fs.rmSync(String(process.env.HOME + '/apply-string'));
            fetch(await Promise.resolve(process.env.API_BASE + '/apply-promise'));
        "#,
        r#"
            const fs = require('fs');
            const key = process.env.KEY;
            Object.defineProperty(globalThis, key, { value: globalThis.convert });
            fs.rmSync(String(process.env.HOME + '/dynamic-key-string'));
            fetch(await Promise.resolve(process.env.API_BASE + '/dynamic-key-promise'));
        "#,
    ];
    for source in sources {
        for plan in [js(source), ts(source)] {
            let sinks = plan.effects.iter().filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            });
            assert_eq!(sinks.clone().count(), 2);
            assert!(sinks.into_iter().all(|effect| {
                matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == if effect.operation.0 == "filesystem.delete" {
                    "filesystem"
                } else {
                    "network"
                })
            }));
            assert_eq!(
                plan.boundaries
                    .iter()
                    .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                    .count(),
                2
            );
            assert!(!all_full(&plan));
        }
    }
}

#[test]
fn unresolved_network_host_concatenation_keeps_symbolic_resource_and_boundary() {
    let plans = [
        js(r#"
            fetch('https://' + process.env.HOST + '/meta');
        "#),
        ts(r#"
            fetch('https://' + process.env.HOST + '/meta');
        "#),
    ];
    for plan in plans {
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(
            &request.resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn unbounded_concatenation_keeps_symbolic_resource_and_boundary() {
    let plan = js(r#"
        const fs = require('fs');
        fs.rmSync(1 + '/cache');
        fs.rmSync(buildPath() + '/cache');
    "#);
    let deletes: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 2);
    assert!(deletes.iter().all(|effect| matches!(
        &effect.resource,
        ResourceExpr::Unresolved { family } if family.0 == "filesystem"
    )));
    assert!(has_boundary(&plan, "unmodeled_dynamic"));
    assert!(!all_full(&plan));
}

#[test]
fn assigned_unbounded_concatenations_keep_symbolic_resources_and_boundaries() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let target;
            target = process.env.HOME + 1;
            fs.rmSync(target);
            const url = 'https://api.example' + 1;
            fetch(url);
            const dynamicUrl = `https://${buildHost()}/meta`;
            fetch(dynamicUrl);
        "#),
        ts(r#"
            const fs = require('fs');
            let target: string;
            target = process.env.HOME + 1;
            fs.rmSync(target);
            const url: string = 'https://api.example' + 1;
            fetch(url);
            const dynamicUrl: string = `https://${buildHost()}/meta`;
            fetch(dynamicUrl);
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        let requests: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.request")
            .collect();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        )));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            3
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn unbounded_concatenation_arguments_keep_symbolic_resources_and_boundaries() {
    let plans = [
        js(r#"
            const fs = require('fs');
            ((target) => fs.rmSync(target))(1 + '/inline-cache');
            function clear(target) { fs.rmSync(target); }
            clear(1 + '/named-cache');
            ((target) => fetch(target))(1 + '/inline-meta');
            function request(target) { fetch(target); }
            request(1 + '/named-meta');
        "#),
        ts(r#"
            const fs = require('fs');
            ((target: string) => fs.rmSync(target))(1 + '/inline-cache');
            function clear(target: string) { fs.rmSync(target); }
            clear(1 + '/named-cache');
            ((target: string) => fetch(target))(1 + '/inline-meta');
            function request(target: string) { fetch(target); }
            request(1 + '/named-meta');
        "#),
    ];
    for plan in plans {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        let requests: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.request")
            .collect();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        )));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            4
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn node_dash_e_model_reaches_js() {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: vec![
                "node".into(),
                "-e".into(),
                "require('fs').rmSync('/tmp/a',{recursive:true})".into(),
            ],
            cwd: Some("/app".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(has(&plan, "filesystem.delete", "/tmp/a"));
}

#[test]
fn node_script_path_is_unavailable() {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: vec!["node".into(), "server.js".into()],
            cwd: Some("/app".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unrecoverable_source")
    );
}

#[test]
fn node_stdin_program_is_unavailable() {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: vec!["node".into(), "-".into(), "data.js".into()],
            cwd: Some("/app".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unrecoverable_source")
    );
    assert!(
        plan.effects
            .iter()
            .all(|effect| effect.operation.0 != "filesystem.read")
    );
}

fn has_boundary(plan: &Plan, reason: &str) -> bool {
    plan.boundaries.iter().any(|b| b.reason.as_str() == reason)
}

fn all_full(plan: &Plan) -> bool {
    plan.coverage
        .0
        .values()
        .all(|c| c.level == effinterp_proto::CoverageLevel::Full)
}

#[test]
fn uncalled_function_is_not_in_execution() {
    // neverCalled defines a delete but is never invoked: executing the module
    // must NOT report it.
    let plan = js(r#"
        const fs = require('fs');
        function neverCalled(){ fs.rmSync('/important', { recursive: true }); }
        console.log('hi');
    "#);
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0.starts_with("filesystem")),
        "uncalled function leaked a filesystem effect: {:?}",
        ops(&plan)
    );
    // console.log is inert, fs bound but unused: no unresolved-call noise.
    assert!(!has_boundary(&plan, "unresolved_call"));
}

#[test]
fn called_function_is_in_execution() {
    let plan = js(r#"
        const fs = require('fs');
        function doDelete(){ fs.rmSync('/important', { recursive: true }); }
        doDelete();
    "#);
    assert!(has(&plan, "filesystem.delete", "/important"));
}

#[test]
fn transitively_called_function_is_reached() {
    let plan = js(r#"
        const fs = require('fs');
        function inner(){ fs.unlinkSync('/deep'); }
        function outer(){ inner(); }
        outer();
    "#);
    assert!(has(&plan, "filesystem.delete", "/deep"));
}

#[test]
fn call_arguments_update_source_strings_before_entering_the_callee() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/old';
            function remove(value) { fs.rmSync(value); }
            remove(path = process.env.TMPDIR + '/new');
            fs.rmSync(path);
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/old';
            function remove(value: string) { fs.rmSync(value); }
            remove(path = process.env.TMPDIR + '/new');
            fs.rmSync(path);
        "#),
    ];
    for plan in plans {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|effect| is_joined_env_path(
            &effect.resource,
            "TMPDIR",
            "/new"
        )));
    }
}

#[test]
fn parameter_defaults_execute_only_for_missing_arguments() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/start';
            function unused(value = (path = process.env.TMPDIR + '/unused')) {}
            function supplied(value = (path = process.env.TMPDIR + '/supplied')) {}
            supplied('provided');
            fs.rmSync(path);
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/start';
            function unused(value = (path = process.env.TMPDIR + '/unused')) {}
            function supplied(value = (path = process.env.TMPDIR + '/supplied')) {}
            supplied('provided');
            fs.rmSync(path);
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/start"));
    }
}

#[test]
fn selected_parameter_destructuring_defaults_are_evaluated() {
    let source = r#"
        const fs = require('fs');
        let namedBase = process.env.HOME;
        function select({ selected = (namedBase = process.env.TMPDIR) }) {}
        select({});
        fs.rmSync(namedBase + '/named');

        let inlineBase = process.env.HOME;
        (({ selected = (inlineBase = process.env.USERPROFILE) }) => {})({});
        fs.rmSync(inlineBase + '/inline');
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().any(|effect| is_joined_env_path(
            &effect.resource,
            "TMPDIR",
            "/named"
        )));
        assert!(deletes.iter().any(|effect| is_joined_env_path(
            &effect.resource,
            "USERPROFILE",
            "/inline"
        )));
    }
}

#[test]
fn selected_destructuring_defaults_capture_values_in_evaluation_order() {
    let source = r#"
        const fs = require('fs');

        let localBase = process.env.HOME;
        const {
            localFirst = localBase,
            localSecond = (localBase = process.env.TMPDIR),
        } = {};
        fs.rmSync(localFirst + '/local-first');
        fs.rmSync(localSecond + '/local-second');

        let namedBase = process.env.HOME;
        function select({
            namedFirst = namedBase,
            namedSecond = (namedBase = process.env.USERPROFILE),
        }) {
            fs.rmSync(namedFirst + '/named-first');
            fs.rmSync(namedSecond + '/named-second');
        }
        select({});

        let inlineBase = process.env.HOME;
        (({
            inlineFirst = inlineBase,
            inlineSecond = (inlineBase = process.env.CACHE_DIR),
        }) => {
            fs.rmSync(inlineFirst + '/inline-first');
            fs.rmSync(inlineSecond + '/inline-second');
        })({});
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 6);
        for (environment, suffix) in [
            ("HOME", "/local-first"),
            ("TMPDIR", "/local-second"),
            ("HOME", "/named-first"),
            ("USERPROFILE", "/named-second"),
            ("HOME", "/inline-first"),
            ("CACHE_DIR", "/inline-second"),
        ] {
            assert!(
                deletes.iter().any(|effect| is_joined_env_path(
                    &effect.resource,
                    environment,
                    suffix
                )),
                "missing {environment}{suffix} resource in {deletes:#?}"
            );
        }
    }
}

#[test]
fn early_return_source_string_writes_join_function_exits() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/start';
            function rewrite(flag) {
                if (flag) {
                    path = process.env.TMPDIR + '/returned';
                    return;
                }
                path = process.env.USERPROFILE + '/continued';
            }
            rewrite(flag);
            fs.rmSync(path);
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/start';
            function rewrite(flag: boolean) {
                if (flag) {
                    path = process.env.TMPDIR + '/returned';
                    return;
                }
                path = process.env.USERPROFILE + '/continued';
            }
            rewrite(flag);
            fs.rmSync(path);
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn finally_includes_source_string_state_at_modeled_calls() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/same';
            try {
                path = process.env.TMPDIR + '/intermediate';
                fs.readFileSync('/input');
                path = process.env.HOME + '/same';
            } finally {
                fs.rmSync(path);
            }
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/same';
            try {
                path = process.env.TMPDIR + '/intermediate';
                fs.readFileSync('/input');
                path = process.env.HOME + '/same';
            } finally {
                fs.rmSync(path);
            }
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn catch_includes_source_string_state_at_quiet_calls() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME;
            try {
                path = process.env.TMPDIR;
                JSON.parse(process.argv[2]);
                path = process.env.HOME;
            } catch (_) {}
            fs.rmSync(path + '/x');
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME;
            try {
                path = process.env.TMPDIR;
                JSON.parse(process.argv[2]);
                path = process.env.HOME;
            } catch (_) {}
            fs.rmSync(path + '/x');
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn catch_includes_source_string_state_at_unresolved_calls() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME;
        try {
            path = process.env.TMPDIR;
            unknown();
            path = process.env.HOME;
        } catch (_) {}
        fs.rmSync(path + '/probe');

        let url = process.env.API_BASE;
        try {
            url = process.env.ALT_BASE;
            unknownNetwork();
            url = process.env.API_BASE;
        } catch (_) {}
        fetch(url + '/probe');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().any(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        assert!(sinks.iter().any(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        )));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn finally_includes_source_string_state_at_catch_calls() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME;
        try {
            throw new Error('enter catch');
        } catch (_) {
            path = process.env.TMPDIR;
            JSON.parse(process.argv[2]);
            path = process.env.HOME;
        } finally {
            fs.rmSync(path + '/cache');
        }
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn catch_includes_source_string_state_at_new_expressions() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME;
            try {
                path = process.env.TMPDIR;
                new RegExp('[');
                path = process.env.HOME;
            } catch (_) {}
            fs.rmSync(path + '/cache/x');
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME;
            try {
                path = process.env.TMPDIR;
                new RegExp('[');
                path = process.env.HOME;
            } catch (_) {}
            fs.rmSync(path + '/cache/x');
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn catch_includes_source_string_state_at_member_expressions() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME;
        try {
            path = process.env.TMPDIR;
            null.value;
            path = process.env.HOME;
        } catch (_) {}
        fs.rmSync(path + '/cache/x');

        let url = process.env.API_BASE;
        try {
            url = process.env.ALT_BASE;
            null['value'];
            url = process.env.API_BASE;
        } catch (_) {}
        fetch(url + '/meta');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn catch_includes_source_string_state_at_binary_expressions() {
    let source = r#"
        const fs = require('fs');
        let path = '/home';
        try {
            path = '/tmp';
            1n + 1;
            path = '/home';
        } catch (_) {}
        fs.rmSync(path + '/cache/x');

        let url = 'https://home.example';
        try {
            url = 'https://alternate.example';
            1n + 1;
            url = 'https://home.example';
        } catch (_) {}
        fetch(url + '/meta');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn catch_includes_source_string_state_at_unary_expressions() {
    let source = r#"
        const fs = require('fs');
        let path = '/home';
        try {
            path = '/tmp';
            +1n;
            path = '/home';
        } catch (_) {}
        fs.rmSync(path + '/cache/x');

        let url = 'https://home.example';
        try {
            url = 'https://alternate.example';
            +1n;
            url = 'https://home.example';
        } catch (_) {}
        fetch(url + '/meta');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn catch_includes_source_string_state_at_assignment_update_template_and_await_expressions() {
    let source = r#"
        const fs = require('fs');
        const assignmentLocked = 0;
        let assignmentPath = '/home';
        try {
            assignmentLocked = (assignmentPath = '/tmp', 1);
            assignmentPath = '/home';
        } catch (_) {}
        fs.rmSync(assignmentPath + '/assignment');

        const updateLocked = 0;
        let updateUrl = 'https://home.example';
        try {
            updateUrl = 'https://alternate.example';
            updateLocked++;
            updateUrl = 'https://home.example';
        } catch (_) {}
        fetch(updateUrl + '/update');

        const symbol = Symbol();
        let templatePath = '/home';
        try {
            templatePath = '/tmp';
            `${symbol}`;
            templatePath = '/home';
        } catch (_) {}
        fs.rmSync(templatePath + '/template');

        const rejected = Promise.reject(new Error('rejected'));
        let awaitUrl = 'https://home.example';
        try {
            awaitUrl = 'https://alternate.example';
            await rejected;
            awaitUrl = 'https://home.example';
        } catch (_) {}
        fetch(awaitUrl + '/await');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 4);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            4
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn catch_includes_source_string_state_at_tagged_template_array_spread_and_class_extends() {
    let source = r#"
        const fs = require('fs');
        var taggedPath = '/home';
        try {
            var taggedPath = '/tmp';
            (() => { throw new Error('tagged'); })`value`;
            taggedPath = '/home';
        } catch (_) {}
        fs.rmSync(taggedPath + '/tagged');

        var spreadUrl = 'https://home.example';
        try {
            var spreadUrl = 'https://alternate.example';
            [...null];
            spreadUrl = 'https://home.example';
        } catch (_) {}
        fetch(spreadUrl + '/array-spread');

        var classPath = '/home';
        try {
            var classPath = '/tmp';
            class Invalid extends 1 {}
            classPath = '/home';
        } catch (_) {}
        fs.rmSync(classPath + '/class');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 3);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            3
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn catch_includes_source_string_state_at_destructuring_object_spread_and_for_of_iteration() {
    let source = r#"
        const fs = require('fs');
        var destructuredPath = '/home';
        try {
            var destructuredPath = '/tmp';
            const { value } = null;
            destructuredPath = '/home';
        } catch (_) {}
        fs.rmSync(destructuredPath + '/destructured');

        var spreadUrl = 'https://home.example';
        try {
            var spreadUrl = 'https://alternate.example';
            const source = { get value() { throw new Error('spread'); } };
            ({ ...source });
            spreadUrl = 'https://home.example';
        } catch (_) {}
        fetch(spreadUrl + '/object-spread');

        var iterationPath = '/home';
        try {
            var iterationPath = '/tmp';
            for (const value of null) {}
            iterationPath = '/home';
        } catch (_) {}
        fs.rmSync(iterationPath + '/for-of');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 3);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            3
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn catch_includes_source_string_state_at_call_spread_and_for_in_iteration() {
    let source = r#"
        const fs = require('fs');
        var spreadPath = '/home';
        try {
            var spreadPath = '/tmp';
            const badIterable = {
                [Symbol.iterator]() {
                    return { next() { throw new Error('spread'); } };
                }
            };
            consume(...badIterable, (spreadPath = '/home'));
        } catch (_) {}
        fs.rmSync(spreadPath + '/call-spread');

        var forInPath = '/home';
        try {
            var forInPath = '/tmp';
            const badKeys = new Proxy({}, {
                ownKeys() { throw new Error('for-in'); }
            });
            for (const key in badKeys) {}
            forInPath = '/home';
        } catch (_) {}
        fs.rmSync(forInPath + '/for-in');
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|effect| {
            matches!(&effect.resource,
                ResourceExpr::Unresolved { family } if family.0 == "filesystem")
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn catch_includes_source_string_state_at_identifier_references() {
    let source = r#"
        const fs = require('fs');
        var path = '/home';
        var base = 'https://home.example';
        try {
            var path = '/tmp';
            var base = 'https://tmp.example';
            missingGlobal;
            path = '/home';
            base = 'https://home.example';
        } catch (_) {}
        fs.rmSync(path + '/x');
        fetch(base + '/x');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn catch_includes_source_string_state_at_private_in() {
    let source = r#"
        const fs = require('fs');
        class Probe {
            #value;
            static {
                var path = '/home';
                var base = 'https://home.example';
                try {
                    var path = '/tmp';
                    var base = 'https://tmp.example';
                    #value in null;
                    path = '/home';
                    base = 'https://home.example';
                } catch (_) {}
                fs.rmSync(path + '/private-in');
                fetch(base + '/private-in');
            }
        }
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn catch_includes_source_string_state_at_each_template_interpolation() {
    let source = r#"
        const fs = require('fs');
        const token = Symbol.iterator;
        var path = '/home';
        try {
            var path = '/tmp';
            `${token}${path = '/home'}`;
        } catch (_) {}
        fs.rmSync(path + '/template-coercion');
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 1);
        assert!(matches!(
            &deletes[0].resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            1
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn catch_includes_source_string_state_at_computed_property_key_coercion() {
    let source = r#"
        const fs = require('fs');
        const key = {
            [Symbol.toPrimitive]() {
                throw new Error('computed property key coercion');
            }
        };
        var path = '/home';
        var base = 'https://home.example';
        try {
            var path = '/tmp';
            ({ [key]: (path = '/home') });
        } catch (_) {}
        try {
            var base = 'https://tmp.example';
            ({ [key]: (base = 'https://home.example') });
        } catch (_) {}
        fs.rmSync(path + '/computed-key');
        fetch(base + '/computed-key');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn catch_includes_source_string_state_at_computed_class_key_coercion() {
    let source = r#"
        const fs = require('fs');
        const key = {
            [Symbol.toPrimitive]() {
                throw new Error('computed class key coercion');
            }
        };
        var path = '/home';
        var base = 'https://home.example';
        try {
            var path = '/tmp';
            class FilesystemTarget {
                [key]() {}
                static reset = (path = '/home');
            }
        } catch (_) {}
        try {
            var base = 'https://tmp.example';
            class NetworkTarget {
                [key]() {}
                static reset = (base = 'https://home.example');
            }
        } catch (_) {}
        fs.rmSync(path + '/class-key');
        fetch(base + '/class-key');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn bound_identifier_reference_does_not_add_exception_source_state() {
    let source = r#"
        const fs = require('fs');
        var path = '/home';
        try {
            var path = '/tmp';
            path;
            path = '/home';
        } catch (_) {}
        fs.rmSync(path + '/declared-identifier');
    "#;
    for plan in [js(source), ts(source)] {
        assert!(has(&plan, "filesystem.delete", "/home/declared-identifier"));
        assert!(plan.boundaries.is_empty());
        assert!(all_full(&plan));
    }
}

#[test]
fn non_throwing_global_identifier_references_do_not_add_exception_source_state() {
    let filesystem_source = r#"
        const fs = require('fs');
        var path = '/home';
        try {
            var path = '/tmp';
            typeof missingGlobal;
            undefined;
            globalThis;
            Object;
            Array;
            Error;
            path = '/home';
        } catch (_) {}
        fs.rmSync(path + '/safe-global');
    "#;
    for plan in [js(filesystem_source), ts(filesystem_source)] {
        assert!(has(&plan, "filesystem.delete", "/home/safe-global"));
        assert!(plan.boundaries.is_empty());
        assert!(all_full(&plan));
    }

    let network_source = r#"
        var base = 'https://home.example';
        try {
            var base = 'https://tmp.example';
            typeof missingGlobal;
            undefined;
            globalThis;
            Object;
            Array;
            Error;
            base = 'https://home.example';
        } catch (_) {}
        fetch(base + '/safe-global');
    "#;
    for plan in [js(network_source), ts(network_source)] {
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "network.request"
                && matches!(&effect.resource,
                        ResourceExpr::Join { parts }
                            if matches!(parts.as_slice(), [
                                ResourceExpr::Concrete {
                                    identity: ResourceIdentity::NetworkEndpoint {
                                        host,
                                        scheme,
                                        ..
                                    }
                                },
                                ResourceExpr::Literal { value }
                            ] if host == "home.example"
                                && scheme.as_deref() == Some("https")
                                && value == "/safe-global"))
        }));
        assert!(plan.boundaries.is_empty());
        assert!(all_full(&plan));
    }
}

#[test]
fn typescript_ambient_identifier_reference_adds_exception_source_state() {
    let plan = ts(r#"
        import fs from 'node:fs';
        declare const runtimeMissing: unknown;
        var path = '/home';
        var base = 'https://home.example';
        try {
            var path = '/tmp';
            var base = 'https://tmp.example';
            runtimeMissing;
            path = '/home';
            base = 'https://home.example';
        } catch (_) {}
        fs.rmSync(path + '/ambient');
        fetch(base + '/ambient');
    "#);
    let sinks: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| {
            matches!(
                effect.operation.0.as_str(),
                "filesystem.delete" | "network.request"
            )
        })
        .collect();
    assert_eq!(sinks.len(), 2);
    assert!(sinks.iter().all(|effect| match &effect.resource {
        ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
            "filesystem.delete" => family.0 == "filesystem",
            "network.request" => family.0 == "network",
            _ => false,
        },
        _ => false,
    }));
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        2
    );
    assert!(!all_full(&plan));
}

#[test]
fn switch_fallthrough_does_not_evaluate_later_case_tests() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/start';
            switch (choice) {
                case 0:
                    path = process.env.TMPDIR + '/fallthrough';
                case (path = process.env.USERPROFILE + '/case-test', 1):
                    fs.rmSync(path);
            }
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/start';
            switch (choice) {
                case 0:
                    path = process.env.TMPDIR + '/fallthrough';
                case (path = process.env.USERPROFILE + '/case-test', 1):
                    fs.rmSync(path);
            }
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn nested_function_calls_resolve_in_their_lexical_scope() {
    let plans = [
        js(r#"
            const fs = require('fs');
            let path = process.env.HOME + '/start';
            function outer() {
                function rewrite() { path = process.env.TMPDIR + '/nested'; }
                rewrite();
            }
            function rewrite() { path = process.env.USERPROFILE + '/module'; }
            outer();
            fs.rmSync(path);
        "#),
        ts(r#"
            import fs from 'node:fs';
            let path = process.env.HOME + '/start';
            function outer() {
                function rewrite() { path = process.env.TMPDIR + '/nested'; }
                rewrite();
            }
            function rewrite() { path = process.env.USERPROFILE + '/module'; }
            outer();
            fs.rmSync(path);
        "#),
    ];
    for plan in plans {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "TMPDIR", "/nested"));
    }
}

#[test]
fn call_arguments_keep_source_string_state_from_their_evaluation_order() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME + '/first';
        fs.renameSync(path, path = process.env.TMPDIR + '/second');
        path = process.env.HOME + '/third';
        function rename(source, destination) {
            fs.renameSync(source, destination);
        }
        rename(path, path = process.env.USERPROFILE + '/fourth');
    "#;
    for plan in [js(source), ts(source)] {
        let writes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.write")
            .collect();
        let moves: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.move")
            .collect();
        assert_eq!(writes.len(), 2);
        assert_eq!(moves.len(), 2);
        // A rename moves its source entry and writes its destination entry.
        assert!(is_joined_env_path(&moves[0].resource, "HOME", "/first"));
        assert!(is_joined_env_path(&writes[0].resource, "TMPDIR", "/second"));
        assert!(is_joined_env_path(&moves[1].resource, "HOME", "/third"));
        assert!(is_joined_env_path(
            &writes[1].resource,
            "USERPROFILE",
            "/fourth"
        ));
    }
}

#[test]
fn finally_updates_source_string_state_reaching_return() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME + '/start';
        function rewrite() {
            try {
                return;
            } finally {
                path = process.env.TMPDIR + '/final';
            }
        }
        rewrite();
        fs.rmSync(path);
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "TMPDIR", "/final"));
    }
}

#[test]
fn switch_fallthrough_exits_only_after_the_terminal_case() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.USERPROFILE + '/start';
        switch (choice) {
            case 0:
                path = process.env.TMPDIR + '/intermediate';
            default:
                path = process.env.HOME + '/final';
        }
        fs.rmSync(path);
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/final"));
    }
}

#[test]
fn declarator_source_string_observes_initializer_side_effects() {
    let source = r#"
        const fs = require('fs');
        let root = process.env.HOME + '/old';
        const path = (root = process.env.TMPDIR + '/new') + root;
        fs.rmSync(path);
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(&delete.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Literal { value: marker },
                ResourceExpr::Environment { name: first_name },
                ResourceExpr::Literal { value: first_path },
                ResourceExpr::Environment { name: second_name },
                ResourceExpr::Literal { value: second_path },
            ] if marker.is_empty() && first_name == "TMPDIR"
                && first_path == "/new"
                && second_name == "TMPDIR"
                && second_path == "/new")));
    }
}

#[test]
fn const_arrow_only_runs_when_called() {
    let uncalled = js(r#"
        const fs = require('fs');
        const wipe = () => fs.rmSync('/x', { recursive: true });
    "#);
    assert!(
        !uncalled
            .effects
            .iter()
            .any(|e| e.operation.0.starts_with("filesystem"))
    );
    let called = js(r#"
        const fs = require('fs');
        const wipe = () => fs.rmSync('/x', { recursive: true });
        wipe();
    "#);
    assert!(has(&called, "filesystem.delete", "/x"));
}

#[test]
fn iife_executes() {
    let plan = js(r#"
        const fs = require('fs');
        (function(){ fs.writeFileSync('/tmp/iife', 'x'); })();
    "#);
    assert!(has(&plan, "filesystem.write", "/tmp/iife"));
}

#[test]
fn callback_argument_is_followed() {
    let plan = js(r#"
        const fs = require('fs');
        [1,2].forEach(() => fs.unlinkSync('/cb'));
    "#);
    assert!(has(&plan, "filesystem.delete", "/cb"));
}

#[test]
fn named_callback_and_evidence_backed_promise_chain_are_followed() {
    let plan = js(r#"
        const fs = require('fs/promises');
        function cleanup() { return fs.unlink('/tmp/cleanup'); }
        async function run() {
            const data = await fs.readFile('/input').finally(cleanup);
            await fetch('https://example.test', { method: 'POST', body: data });
        }
        run();
    "#);
    assert!(has(&plan, "filesystem.read", "/input"));
    assert!(has(&plan, "filesystem.delete", "/tmp/cleanup"));
    assert!(ops(&plan).contains(&"network.upload"));
    assert!(!has_boundary(&plan, "unresolved_call"));
}

#[test]
fn unresolved_promise_handlers_are_boundaries() {
    let plan = js(r#"
        const fs = require('fs/promises');
        const logger = require('external-logger');
        fs.readFile('/x').then(logger.handle);
        fs.readFile('/y').then(unknownCallback);
    "#);
    assert!(has(&plan, "filesystem.read", "/x"));
    assert!(has(&plan, "filesystem.read", "/y"));
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unresolved_call")
            .count(),
        2
    );
}

#[test]
fn function_local_shadow_does_not_erase_a_module_import() {
    let source = r#"
        import { rmSync } from 'fs';
        function run() { rmSync('/shadow'); }
        function helper() { const rmSync = 0; return rmSync; }
        run();
    "#;
    for plan in [js(source), ts(source)] {
        assert!(has(&plan, "filesystem.delete", "/shadow"));
    }
}

#[test]
fn unknown_call_is_a_boundary_not_silence() {
    let plan = js(r#"thirdParty.doSomething();"#);
    assert!(
        has_boundary(&plan, "unresolved_call"),
        "unknown call must record an unresolved_call boundary"
    );
    assert!(
        !all_full(&plan),
        "coverage must not stay Full past an unresolved call"
    );
    assert!(plan.effects.is_empty(), "must not invent an effect");
}

#[test]
fn recursion_terminates() {
    let plan = js(r#"
        function a(){ b(); }
        function b(){ a(); }
        a();
    "#);
    // Bounded, valid, deterministic — the point is no hang/panic.
    validate_plan(&plan).unwrap();
    let again = js(r#"
        function a(){ b(); }
        function b(){ a(); }
        a();
    "#);
    assert_eq!(
        effinterp_proto::canonical_json(&plan),
        effinterp_proto::canonical_json(&again)
    );
}

#[test]
fn deterministic() {
    let src = r#"const fs=require('fs'); fs.writeFileSync('/a','x'); fs.readFileSync('/b');"#;
    let a = effinterp_proto::canonical_json(&js(src));
    let b = effinterp_proto::canonical_json(&js(src));
    assert_eq!(a, b);
}

/// A helper that returns a path built from a module constant and its parameter,
/// assigned to a local and then deleted: the returned resource must flow into
/// the delete (return-value summary + caller-side tracking).
#[test]
fn return_value_flows_into_a_later_effect() {
    let plan = js(r#"
        const path = require('path');
        const fs = require('fs');
        const BASE = '/var/cache';
        function cachePath(t) { return path.join(BASE, t); }
        const p = cachePath(name);
        fs.rmSync(p);
    "#);
    let delete = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .expect("a delete effect");
    let ResourceExpr::Join { parts } = &delete.resource else {
        panic!("expected Join, got {:?}", delete.resource);
    };
    assert!(
        parts.iter().any(|p| matches!(
            p,
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/var/cache"
        )),
        "BASE resolved to /var/cache through the return: {parts:?}"
    );
}

/// A literal local path assignment also flows to a later use.
#[test]
fn literal_local_assignment_flows() {
    let plan = js(r#"
        const fs = require('fs');
        const p = '/tmp/target';
        fs.rmSync(p);
    "#);
    assert!(has(&plan, "filesystem.delete", "/tmp/target"));
}

/// A helper whose return is not a resolvable resource yields a symbolic delete,
/// never a crash or a fabricated path.
#[test]
fn nonresolvable_return_stays_symbolic() {
    let plan = js(r#"
        const fs = require('fs');
        function mk() { return compute(); }
        const p = mk();
        fs.rmSync(p);
    "#);
    if let Some(d) = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
    {
        assert!(
            !matches!(&d.resource, ResourceExpr::Concrete { .. }),
            "no fabricated concrete path: {:?}",
            d.resource
        );
    }
}

/// Return tracking stays deterministic.
#[test]
fn return_tracking_is_deterministic() {
    let src = r#"
        const path = require('path');
        const fs = require('fs');
        const ROOT = '/c';
        function cp(t) { return path.join(ROOT, t); }
        const p = cp(x);
        fs.rmSync(p);
    "#;
    let a = effinterp_proto::canonical_json(&js(src));
    let b = effinterp_proto::canonical_json(&js(src));
    assert_eq!(a, b);
}

#[test]
fn concatenation_operands_keep_source_string_evaluation_order() {
    let sources = [
        r#"
            const fs = require('fs');
            let root = process.env.HOME + '/old';
            fs.rmSync(root + (root = process.env.TMPDIR + '/new'));
        "#,
        r#"
            const fs = require('fs');
            let root = process.env.HOME + '/old';
            fs.rmSync(`${root}${root = process.env.TMPDIR + '/new'}`);
        "#,
    ];
    for source in sources {
        for plan in [js(source), ts(source)] {
            let delete = plan
                .effects
                .iter()
                .find(|effect| effect.operation.0 == "filesystem.delete")
                .expect("filesystem delete effect");
            assert!(matches!(&delete.resource, ResourceExpr::Join { parts }
                if matches!(parts.as_slice(), [
                    ResourceExpr::Literal { value: marker },
                    ResourceExpr::Environment { name: first_name },
                    ResourceExpr::Literal { value: first_path },
                    ResourceExpr::Environment { name: second_name },
                    ResourceExpr::Literal { value: second_path },
                ] if marker.is_empty() && first_name == "HOME"
                    && first_path == "/old"
                    && second_name == "TMPDIR"
                    && second_path == "/new")));
        }
    }
}

#[test]
fn switch_case_tests_preserve_prior_failed_test_writes() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME + '/start';
        switch (choice) {
            case (path = process.env.TMPDIR + '/failed-test', 0):
                break;
            case 1:
                fs.rmSync(path);
        }
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(
            &delete.resource,
            "TMPDIR",
            "/failed-test"
        ));
    }
}

#[test]
fn block_local_function_bindings_resolve_in_their_lexical_scope() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME + '/start';
        {
            const rewrite = () => { path = process.env.TMPDIR + '/block'; };
            rewrite();
        }
        const rewrite = () => { path = process.env.USERPROFILE + '/outer'; };
        fs.rmSync(path);
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "TMPDIR", "/block"));
    }
}

#[test]
fn loop_test_writes_widen_later_iteration_source_strings() {
    let sources = [
        r#"
            const fs = require('fs');
            let base = process.env.HOME;
            let next = process.env.HOME;
            while ((base = next, next = process.env.TMPDIR, again)) {}
            fs.rmSync(base + '/x');
        "#,
        r#"
            const fs = require('fs');
            let base = process.env.HOME;
            let next = process.env.HOME;
            for (; (base = next, next = process.env.TMPDIR, again);) {}
            fs.rmSync(base + '/x');
        "#,
        r#"
            const fs = require('fs');
            let path = process.env.HOME + '/first';
            do {
                fs.rmSync(path);
            } while ((path = process.env.TMPDIR + '/later', again));
        "#,
    ];
    for plan in sources
        .into_iter()
        .flat_map(|source| [js(source), ts(source)])
    {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn function_valued_bindings_follow_initializer_execution_order() {
    let source = r#"
        const fs = require('fs');
        var root = () => process.env.HOME;
        fs.rmSync(root() + '/before');
        var root = () => process.env.TMPDIR;
        fs.rmSync(root() + '/after');
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(is_joined_env_path(&deletes[0].resource, "HOME", "/before"));
        assert!(is_joined_env_path(&deletes[1].resource, "TMPDIR", "/after"));
    }
}

#[test]
fn conditional_function_declarators_widen_callable_state() {
    let source = r#"
        const fs = require('fs');
        if (flag) {
            var pick = () => process.env.HOME;
        } else {
            var pick = () => process.env.TMPDIR;
        }
        fs.rmSync(pick() + '/cache');

        if (flag) {
            var endpoint = () => 'https://api.example';
        } else {
            var endpoint = () => process.env.ALT_BASE;
        }
        fetch(endpoint() + '/meta');
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(
            &request.resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn function_declarators_widen_across_conditional_control_flow() {
    let sources = [
        r#"
            const fs = require('fs');
            var pick = () => process.env.HOME;
            while (flag) {
                var pick = () => process.env.TMPDIR;
            }
            fs.rmSync(pick() + '/cache');
        "#,
        r#"
            const fs = require('fs');
            switch (choice) {
                case 0:
                    var pick = () => process.env.HOME;
                    break;
                default:
                    var pick = () => process.env.TMPDIR;
            }
            fs.rmSync(pick() + '/cache');
        "#,
        r#"
            const fs = require('fs');
            var pick = () => process.env.HOME;
            try {
                if (flag) throw new Error('failed');
            } catch {
                var pick = () => process.env.TMPDIR;
            }
            fs.rmSync(pick() + '/cache');
        "#,
    ];
    for plan in sources
        .into_iter()
        .flat_map(|source| [js(source), ts(source)])
    {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn loop_carried_callable_reassignments_are_unbounded() {
    let source = r#"
        const fs = require('fs');

        let whilePath = () => process.env.HOME;
        while (again) {
            fs.rmSync(whilePath() + '/while-cache');
            whilePath = () => process.env.TMPDIR;
        }

        let forEndpoint = () => 'https://home.example';
        for (; again; forEndpoint = () => process.env.ALT_BASE) {
            fetch(forEndpoint() + '/for-meta');
        }

        let doPath = () => process.env.HOME;
        do {
            fs.rmSync(doPath() + '/do-cache');
        } while ((doPath = () => process.env.TMPDIR, again));
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(
            &request.resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn local_function_writes_are_loop_carried() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME;
        let target = () => process.env.HOME;

        function applyRotation() {
            [0].forEach(() => {
                path = process.env.TMPDIR;
                target = () => process.env.TMPDIR;
            });
        }
        function rotate() {
            applyRotation();
        }

        while (again) {
            fs.rmSync(path + '/path-cache');
            fs.rmSync(target() + '/callable-cache');
            rotate();
        }
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn callable_reassignments_supersede_collected_functions() {
    let precise = r#"
        const fs = require('fs');
        let root = () => process.env.HOME;
        root = () => process.env.TMPDIR;
        fs.rmSync(root() + '/cache');
        let endpoint = () => 'https://good.example';
        endpoint = () => 'https://evil.example';
        fetch(endpoint() + '/meta');
    "#;
    for plan in [js(precise), ts(precise)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "TMPDIR", "/cache"));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                },
                ResourceExpr::Literal { value }
            ] if host == "evil.example"
                && scheme.as_deref() == Some("https")
                && value == "/meta")));
    }

    let unbounded = r#"
        const fs = require('fs');
        function root() { return process.env.HOME; }
        root = replacement;
        fs.rmSync(root() + '/cache');
    "#;
    for plan in [js(unbounded), ts(unbounded)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn repeated_call_executions_clear_stale_source_returns() {
    let source = r#"
        const fs = require('fs');
        let root = () => process.env.HOME;
        function remove() {
            const value = root();
            fs.rmSync(value + '/cache');
        }
        remove();
        root = replacement;
        remove();

        let endpoint = () => 'https://good.example';
        function request() {
            const value = endpoint();
            fetch(value + '/meta');
        }
        request();
        endpoint = replacement;
        request();
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(is_joined_env_path(&deletes[0].resource, "HOME", "/cache"));
        assert!(matches!(
            &deletes[1].resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));

        let requests: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.request")
            .collect();
        assert_eq!(requests.len(), 2);
        assert!(matches!(&requests[0].resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                },
                ResourceExpr::Literal { value }
            ] if host == "good.example"
                && scheme.as_deref() == Some("https")
                && value == "/meta")));
        assert!(matches!(
            &requests[1].resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn shadowed_undefined_arguments_skip_parameter_defaults() {
    let source = r#"
        const fs = require('fs');
        const undefined = process.env.USERPROFILE;
        let named = process.env.HOME;
        function ignore(value = (named = process.env.TMPDIR)) {}
        ignore(undefined);
        let inline = process.env.HOME;
        ((value = (inline = process.env.TMPDIR)) => {})(undefined);
        fs.rmSync(named + '/named');
        fs.rmSync(inline + '/inline');
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(is_joined_env_path(&deletes[0].resource, "HOME", "/named"));
        assert!(is_joined_env_path(&deletes[1].resource, "HOME", "/inline"));
        assert!(!plan.effects.iter().any(|effect| {
            effect.operation.0 == "environment.read"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name }
                } if name == "TMPDIR")
        }));
    }
}

#[test]
fn aggregate_members_and_spreads_preserve_sink_concatenations() {
    let source = r#"
        const fs = require('fs');
        fs.rmSync(({ path: process.env.HOME + '/member' }).path);
        fetch((['https://member.example' + '/index'])[0]);
        fs.rmSync(...[process.env.TMPDIR + '/spread']);
        fetch(...['https://spread.example' + '/index']);
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(is_joined_env_path(&deletes[0].resource, "HOME", "/member"));
        assert!(is_joined_env_path(
            &deletes[1].resource,
            "TMPDIR",
            "/spread"
        ));

        let requests: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.request")
            .collect();
        assert_eq!(requests.len(), 2);
        for (request, expected_host) in requests.iter().zip(["member.example", "spread.example"]) {
            assert!(matches!(&request.resource, ResourceExpr::Join { parts }
                if matches!(parts.as_slice(), [
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                    },
                    ResourceExpr::Literal { value }
                ] if host == expected_host
                    && scheme.as_deref() == Some("https")
                    && value == "/index")));
        }
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
        assert!(all_full(&plan));
    }
}

#[test]
fn aggregate_bindings_preserve_member_sink_concatenations() {
    let source = r#"
        const fs = require('fs');
        const paths = { cache: process.env.HOME + '/.cache/x' };
        const urls = ['https://api.example' + '/meta'];
        fs.rmSync(paths.cache);
        fetch(urls[0]);
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/.cache/x"));

        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                },
                ResourceExpr::Literal { value }
            ] if host == "api.example"
                && scheme.as_deref() == Some("https")
                && value == "/meta")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
        assert!(all_full(&plan));
    }
}

#[test]
fn aggregate_member_bindings_follow_lexical_scope() {
    let source = r#"
        const fs = require('fs');
        const paths = { cache: process.env.HOME + '/outer' };
        {
            const paths = { cache: process.env.TMPDIR + '/inner' };
            fs.rmSync(paths.cache);
        }
        function remove() {
            const paths = { cache: process.env.USERPROFILE + '/function' };
            fs.rmSync(paths.cache);
        }
        remove();
        fs.rmSync(paths.cache);
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 3);
        assert!(is_joined_env_path(&deletes[0].resource, "TMPDIR", "/inner"));
        assert!(is_joined_env_path(
            &deletes[1].resource,
            "USERPROFILE",
            "/function"
        ));
        assert!(is_joined_env_path(&deletes[2].resource, "HOME", "/outer"));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
        assert!(all_full(&plan));
    }
}

#[test]
fn dynamic_aggregate_members_keep_concatenation_boundaries() {
    let source = r#"
        const fs = require('fs');
        fs.rmSync(({ home: process.env.HOME + '/x' })[process.env.KEY]);
        fetch(({ url: 'https://api.example' + '/meta' })?.[process.env.KEY]);
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(
            &request.resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        ));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn optional_chain_members_preserve_sink_concatenations() {
    let source = r#"
        const fs = require('fs');
        fs.rmSync(({ path: process.env.HOME + '/optional.js' })?.path);
        fetch(({ url: 'https://optional.example' + '/meta' })?.['url']);
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/optional.js"));

        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                },
                ResourceExpr::Literal { value }
            ] if host == "optional.example"
                && scheme.as_deref() == Some("https")
                && value == "/meta")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
        assert!(all_full(&plan));
    }
}

#[test]
fn nullish_optional_computed_members_skip_keys() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME;
        let url = process.env.API_BASE;
        let maybe;
        maybe?.[path = process.env.TMPDIR];
        maybe?.[url = process.env.ALT_BASE];
        fs.rmSync(path + '/x');
        fetch(url + '/meta');
    "#;
    for plan in [js(source), ts(source)] {
        let environment_reads: Vec<_> = plan
            .effects
            .iter()
            .filter_map(|effect| {
                (effect.operation.0 == "environment.read").then_some(&effect.resource)
            })
            .collect();
        assert!(matches!(environment_reads.as_slice(), [
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name: home }
            },
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name: api_base }
            }
        ] if home == "HOME" && api_base == "API_BASE"));

        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/x"));

        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Environment { name },
                ResourceExpr::Literal { value }
            ] if name == "API_BASE" && value == "/meta")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
        assert!(all_full(&plan));
    }
}

#[test]
fn nullish_optional_calls_and_nested_chains_skip_operands() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME;
        let url = process.env.API_BASE;
        let maybe;
        maybe?.(path = process.env.TMPDIR);
        maybe?.(url = process.env.ALT_BASE);
        maybe?.value[path = process.env.TMPDIR];
        maybe?.value[url = process.env.ALT_BASE];
        fs.rmSync(path + '/x');
        fetch(url + '/meta');
    "#;
    for plan in [js(source), ts(source)] {
        let environment_reads: Vec<_> = plan
            .effects
            .iter()
            .filter_map(|effect| {
                (effect.operation.0 == "environment.read").then_some(&effect.resource)
            })
            .collect();
        assert!(matches!(environment_reads.as_slice(), [
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name: home }
            },
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name: api_base }
            }
        ] if home == "HOME" && api_base == "API_BASE"));

        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/x"));

        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Environment { name },
                ResourceExpr::Literal { value }
            ] if name == "API_BASE" && value == "/meta")));
        assert!(plan.boundaries.is_empty());
        assert!(all_full(&plan));
    }
}

#[test]
fn object_property_values_use_evaluation_state() {
    let source = r#"
        const fs = require('fs');
        let base = process.env.HOME;
        fs.rmSync(({
            path: base,
            mutate: (base = process.env.TMPDIR)
        }).path + '/cache/x');
        let url = 'https://home.example';
        fetch(({
            url,
            mutate: (url = 'https://tmp.example')
        }).url + '/meta');
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(&delete.resource, "HOME", "/cache/x"));

        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                },
                ResourceExpr::Literal { value }
            ] if host == "home.example"
                && scheme.as_deref() == Some("https")
                && value == "/meta")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
        assert!(all_full(&plan));
    }
}

#[test]
fn unbounded_aggregate_member_and_spread_concatenations_keep_boundaries() {
    let source = r#"
        const fs = require('fs');
        fs.rmSync(({ path: externalPath + '/member' }).path);
        fetch(...[globalThis.endpoint + '/index']);
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(
            &request.resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        ));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn uncertain_aggregate_spreads_keep_concatenation_boundaries() {
    let source = r#"
        const fs = require('fs');
        const extra = {};
        const empty = [];
        fs.rmSync(({ path: process.env.HOME + '/member', ...extra }).path);
        fetch(({ url: 'https://spread.example' + '/meta', ...extra }).url);
        fs.rmSync(...[...empty, process.env.TMPDIR + '/spread']);
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 3);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            3
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn bound_uncertain_aggregate_spreads_keep_concatenation_boundaries() {
    let source = r#"
        const fs = require('fs');
        const extra = {};
        const empty = [];
        const path = { path: process.env.HOME + '/member', ...extra };
        const exact = { ...extra, path: process.env.TMPDIR + '/exact' };
        const endpoint = { url: 'https://spread.example' + '/meta', ...extra };
        const paths = [...empty, process.env.TMPDIR + '/spread'];
        const exactPrefix = [process.env.HOME + '/prefix', ...empty];
        fs.rmSync(path.path);
        fs.rmSync(exact.path);
        fetch(endpoint.url);
        fs.rmSync(paths[0]);
        fs.rmSync(exactPrefix[0]);
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 4);
        assert!(matches!(
            &deletes[0].resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(is_joined_env_path(&deletes[1].resource, "TMPDIR", "/exact"));
        assert!(matches!(
            &deletes[2].resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(is_joined_env_path(&deletes[3].resource, "HOME", "/prefix"));

        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(
            &request.resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        ));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            3
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn spread_arguments_use_logical_sink_positions() {
    let source = r#"
        const fs = require('fs');
        fs.rmSync(...[], process.env.HOME + '/empty-spread');
        fs.renameSync(...[
            process.env.HOME + '/spread-source',
            process.env.TMPDIR + '/spread-destination'
        ]);
        fetch(...[], 'https://spread-position.example' + '/index');
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(is_joined_env_path(
            &delete.resource,
            "HOME",
            "/empty-spread"
        ));

        let source = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.move")
            .expect("filesystem rename source effect");
        assert!(is_joined_env_path(
            &source.resource,
            "HOME",
            "/spread-source"
        ));
        let destination = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.write")
            .expect("filesystem rename destination effect");
        assert!(is_joined_env_path(
            &destination.resource,
            "TMPDIR",
            "/spread-destination"
        ));

        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                },
                ResourceExpr::Literal { value }
            ] if host == "spread-position.example"
                && scheme.as_deref() == Some("https")
                && value == "/index")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
        assert!(all_full(&plan));
    }
}

#[test]
fn spread_argument_elements_use_evaluation_state() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME + '/spread-source';
        fs.copyFileSync(...[
            path,
            path = process.env.TMPDIR + '/spread-destination'
        ]);
        let url = 'https://first.example' + '/before';
        fetch(...[
            url,
            url = 'https://second.example' + '/after'
        ]);
    "#;
    for plan in [js(source), ts(source)] {
        let source = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.read")
            .expect("filesystem copy source effect");
        assert!(is_joined_env_path(
            &source.resource,
            "HOME",
            "/spread-source"
        ));
        let destination = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.write")
            .expect("filesystem copy destination effect");
        assert!(is_joined_env_path(
            &destination.resource,
            "TMPDIR",
            "/spread-destination"
        ));

        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                },
                ResourceExpr::Literal { value }
            ] if host == "first.example"
                && scheme.as_deref() == Some("https")
                && value == "/before")));
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
        assert!(all_full(&plan));
    }
}

#[test]
fn spread_arguments_bind_to_local_function_parameters() {
    let source = r#"
        const fs = require('fs');
        function remove(target) { fs.rmSync(target); }
        remove(...[process.env.HOME + '/named-spread']);
        ((target) => fs.rmSync(target))(...[
            process.env.TMPDIR + '/inline-spread'
        ]);
        function load(target) { fetch(target); }
        load(...['https://named-spread.example' + '/meta']);
        function request(...targets) { fetch(targets[0]); }
        request(...['https://rest-spread.example' + '/index']);
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(is_joined_env_path(
            &deletes[0].resource,
            "HOME",
            "/named-spread"
        ));
        assert!(is_joined_env_path(
            &deletes[1].resource,
            "TMPDIR",
            "/inline-spread"
        ));

        let requests: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.request")
            .collect();
        assert_eq!(requests.len(), 2);
        for (request, expected_host, expected_path) in [
            (requests[0], "named-spread.example", "/meta"),
            (requests[1], "rest-spread.example", "/index"),
        ] {
            assert!(matches!(&request.resource, ResourceExpr::Join { parts }
                if matches!(parts.as_slice(), [
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                    },
                    ResourceExpr::Literal { value }
                ] if host == expected_host
                    && scheme.as_deref() == Some("https")
                    && value == expected_path)));
        }
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
        assert!(all_full(&plan));
    }
}

#[test]
fn unbounded_spread_arguments_keep_local_function_boundaries() {
    let source = r#"
        const fs = require('fs');
        function remove(target) { fs.rmSync(target); }
        remove(...[externalPath + '/named-spread']);
        ((target) => fetch(target))(...[
            globalThis.endpoint + '/inline-spread'
        ]);
        function clear(...targets) { fs.rmSync(targets[0]); }
        clear(...[externalRoot + '/rest-spread']);
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(
            &request.resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        ));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            3
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn rest_member_assignments_invalidate_source_strings() {
    let source = r#"
        const fs = require('fs');
        function remove(...targets) {
            targets[0] = 42;
            fs.rmSync(targets[0] + '/.cache/x');
        }
        remove(process.env.HOME);
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn rest_member_updates_invalidate_source_strings() {
    let source = r#"
        const fs = require('fs');
        function update(...targets) {
            targets[0]++;
            fs.rmSync(targets[0] + '/after-update');
            ++targets[1];
            fetch(targets[1] + '/after-update');
        }
        update(process.env.HOME, 'https://before.example');
        function repeat(...targets) {
            while (globalThis.again) {
                fs.rmSync(targets[0] + '/loop-update');
                targets[0]++;
            }
        }
        repeat(process.env.TMPDIR);
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 3);
        assert!(
            sinks
                .iter()
                .all(|effect| matches!(&effect.resource, ResourceExpr::Unresolved { .. }))
        );
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            3
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn computed_rest_member_assignments_invalidate_source_strings() {
    let source = r#"
        const fs = require('fs');
        function indexed(index, ...targets) {
            targets[index] = 42;
            fs.rmSync(targets[0] + '/after-indexed-assignment');
        }
        indexed(0, process.env.HOME);
        function templated(...targets) {
            targets[`0`] = 42;
            fs.rmSync(targets[0] + '/after-template-assignment');
        }
        templated(process.env.TMPDIR);
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn deleted_rest_members_invalidate_source_strings() {
    let source = r#"
        const fs = require('fs');
        function remove(...targets) {
            delete targets[0];
            fs.rmSync(targets[0] + '/after-delete');
            delete targets[1];
            fetch(targets[1] + '/after-delete');
        }
        remove(process.env.HOME, 'https://before.example');
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(
            &request.resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        ));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn aggregate_writes_invalidate_rest_member_source_strings() {
    let source = r#"
        const fs = require('fs');
        function replace(...targets) {
            targets = [];
            fs.rmSync(targets[0] + '/after-replacement');
        }
        replace(process.env.HOME);
        function truncate(...targets) {
            targets.length = 0;
            fs.rmSync(targets[0] + '/after-truncation');
        }
        truncate(process.env.TMPDIR);
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn object_assign_invalidates_aggregate_member_source_strings() {
    let source = r#"
        const fs = require('fs');
        function remove(...targets) {
            Object.assign(targets, { 0: process.env.TMPDIR });
            fs.rmSync(targets[0] + '/after-assign');
        }
        remove(process.env.HOME);
        function request(...targets) {
            Object.assign(targets, { 0: 'https://new.example' });
            fetch(targets[0] + '/after-assign');
        }
        request('https://old.example');
        function repeat(...targets) {
            while (globalThis.again) {
                fs.rmSync(targets[0] + '/loop-assign');
                Object.assign(targets, { 0: process.env.TMPDIR });
            }
        }
        repeat(process.env.HOME);
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 3);
        assert!(
            sinks
                .iter()
                .all(|effect| matches!(&effect.resource, ResourceExpr::Unresolved { .. }))
        );
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            3
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn object_define_property_invalidates_aggregate_member_source_strings() {
    let source = r#"
        const fs = require('fs');
        function remove(...targets) {
            Object.defineProperty(targets, '0', { value: process.env.TMPDIR });
            fs.rmSync(targets[0] + '/after-define-property');
        }
        remove(process.env.HOME);
        function request(...targets) {
            Object.defineProperty(targets, '0', { value: 'https://new.example' });
            fetch(targets[0] + '/after-define-property');
        }
        request('https://old.example');
        function repeat(...targets) {
            while (globalThis.again) {
                fs.rmSync(targets[0] + '/loop-define-property');
                Object.defineProperty(targets, '0', { value: process.env.TMPDIR });
            }
        }
        repeat(process.env.HOME);
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 3);
        assert!(
            sinks
                .iter()
                .all(|effect| matches!(&effect.resource, ResourceExpr::Unresolved { .. }))
        );
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            3
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn object_mutation_call_forms_invalidate_aggregate_member_source_strings() {
    let source = r#"
        const fs = require('fs');
        function assign(...targets) {
            Object['assign'](targets, { 0: process.env.TMPDIR });
            fs.rmSync(targets[0] + '/after-computed-assign');
        }
        assign(process.env.HOME);
        function defineProperty(...targets) {
            Object['defineProperty'](targets, '0', { value: 'https://new.example' });
            fetch(targets[0] + '/after-computed-define-property');
        }
        defineProperty('https://old.example');
        function defineProperties(...targets) {
            Object.defineProperties(targets, {
                0: { value: process.env.TMPDIR }
            });
            fs.rmSync(targets[0] + '/after-define-properties');
        }
        defineProperties(process.env.HOME);
        function repeat(...targets) {
            while (globalThis.again) {
                fetch(targets[0] + '/loop-computed-define-properties');
                Object['defineProperties'](targets, {
                    0: { value: 'https://new.example' }
                });
            }
        }
        repeat('https://old.example');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 4);
        assert!(
            sinks
                .iter()
                .all(|effect| matches!(&effect.resource, ResourceExpr::Unresolved { .. }))
        );
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            4
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn object_assign_call_invalidates_aggregate_member_source_strings() {
    let source = r#"
        const fs = require('fs');
        function remove(...targets) {
            Object.assign.call(Object, targets, { 0: process.env.TMPDIR });
            fs.rmSync(targets[0] + '/after-assign-call');
        }
        remove(process.env.HOME);
        function request(...targets) {
            Object.assign.call(Object, targets, { 0: 'https://new.example' });
            fetch(targets[0] + '/after-assign-call');
        }
        request('https://old.example');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| {
            match (effect.operation.0.as_str(), &effect.resource) {
                ("filesystem.delete", ResourceExpr::Unresolved { family }) => {
                    family.0 == "filesystem"
                }
                ("network.request", ResourceExpr::Unresolved { family }) => family.0 == "network",
                _ => false,
            }
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn object_assign_apply_invalidates_aggregate_member_source_strings() {
    let source = r#"
        const fs = require('fs');
        function remove(...targets) {
            Object.assign.apply(Object, [targets, { 0: process.env.TMPDIR }]);
            fs.rmSync(targets[0] + '/after-assign-apply');
        }
        remove(process.env.HOME);
        function request(...targets) {
            Object.assign.apply(Object, [targets, { 0: 'https://new.example' }]);
            fetch(targets[0] + '/after-assign-apply');
        }
        request('https://old.example');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| {
            match (effect.operation.0.as_str(), &effect.resource) {
                ("filesystem.delete", ResourceExpr::Unresolved { family }) => {
                    family.0 == "filesystem"
                }
                ("network.request", ResourceExpr::Unresolved { family }) => family.0 == "network",
                _ => false,
            }
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn borrowed_object_mutators_invalidate_aggregate_member_source_strings() {
    let source = r#"
        const fs = require('fs');
        function definePropertyCall(...targets) {
            Object.defineProperty.call(Object, targets, '0', { value: process.env.TMPDIR });
            fs.rmSync(targets[0] + '/after-define-property-call');
            fetch(targets[0] + '/after-define-property-call');
        }
        definePropertyCall(process.env.HOME + '/before');
        function definePropertyApply(...targets) {
            Object.defineProperty.apply(Object, [targets, '0', { value: process.env.TMPDIR }]);
            fs.rmSync(targets[0] + '/after-define-property-apply');
            fetch(targets[0] + '/after-define-property-apply');
        }
        definePropertyApply(process.env.HOME + '/before');
        function definePropertiesCall(...targets) {
            Object.defineProperties.call(Object, targets, {
                0: { value: process.env.TMPDIR }
            });
            fs.rmSync(targets[0] + '/after-define-properties-call');
            fetch(targets[0] + '/after-define-properties-call');
        }
        definePropertiesCall(process.env.HOME);
        function definePropertiesApply(...targets) {
            Object.defineProperties.apply(Object, [targets, {
                0: { value: process.env.TMPDIR }
            }]);
            fs.rmSync(targets[0] + '/after-define-properties-apply');
            fetch(targets[0] + '/after-define-properties-apply');
        }
        definePropertiesApply(process.env.HOME);
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 8);
        assert!(sinks.iter().all(|effect| {
            match (effect.operation.0.as_str(), &effect.resource) {
                ("filesystem.delete", ResourceExpr::Unresolved { family }) => {
                    family.0 == "filesystem"
                }
                ("network.request", ResourceExpr::Unresolved { family }) => family.0 == "network",
                _ => false,
            }
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            8
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn borrowed_object_mutator_argument_arrays_invalidate_aggregate_member_source_strings() {
    let source = r#"
        const fs = require('fs');
        function definePropertyCall(...targets) {
            const args = [Object, targets, '0', { value: process.env.TMPDIR + '/call-new' }];
            Object.defineProperty.call(...args);
            fs.rmSync(targets[0] + '/after-argument-array-call');
            fetch(targets[0] + '/after-argument-array-call');
        }
        definePropertyCall(process.env.HOME + '/before');
        function definePropertyApply(...targets) {
            const args = [targets, '0', { value: process.env.TMPDIR + '/apply-new' }];
            Object.defineProperty.apply(Object, args);
            fs.rmSync(targets[0] + '/after-argument-array-apply');
            fetch(targets[0] + '/after-argument-array-apply');
        }
        definePropertyApply(process.env.HOME + '/before');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 4);
        assert!(sinks.iter().all(|effect| {
            match (effect.operation.0.as_str(), &effect.resource) {
                ("filesystem.delete", ResourceExpr::Unresolved { family }) => {
                    family.0 == "filesystem"
                }
                ("network.request", ResourceExpr::Unresolved { family }) => family.0 == "network",
                _ => false,
            }
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            4
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn split_spread_borrowed_object_mutators_invalidate_aggregate_member_source_strings() {
    let source = r#"
        const fs = require('fs');
        function definePropertyCall(...targets) {
            const receiver = [Object];
            Object.defineProperty.call(
                ...receiver,
                targets,
                '0',
                { value: process.env.TMPDIR + '/call-new' }
            );
            fs.rmSync(targets[0] + '/after-split-spread-call');
            fetch(targets[0] + '/after-split-spread-call');
        }
        definePropertyCall(process.env.HOME + '/before');
        function definePropertyApply(...targets) {
            const receiver = [Object];
            const args = [targets, '0', { value: process.env.TMPDIR + '/apply-new' }];
            Object.defineProperty.apply(...receiver, args);
            fs.rmSync(targets[0] + '/after-split-spread-apply');
            fetch(targets[0] + '/after-split-spread-apply');
        }
        definePropertyApply(process.env.HOME + '/before');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 4);
        assert!(sinks.iter().all(|effect| {
            match (effect.operation.0.as_str(), &effect.resource) {
                ("filesystem.delete", ResourceExpr::Unresolved { family }) => {
                    family.0 == "filesystem"
                }
                ("network.request", ResourceExpr::Unresolved { family }) => family.0 == "network",
                _ => false,
            }
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            4
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn array_fill_invocations_invalidate_aggregate_member_source_strings() {
    let source = r#"
        const fs = require('fs');
        function replaceDirectly(...targets) {
            targets.fill(process.env.QA_NEXT + '/changed');
            fs.rmSync(targets[0]);
            fetch(targets[0]);
        }
        function replaceWithCall(...targets) {
            Array.prototype.fill.call(
                targets,
                process.env.QA_NEXT + '/changed'
            );
            fs.rmSync(targets[0]);
            fetch(targets[0]);
        }
        function replaceWithApply(...targets) {
            Array.prototype.fill.apply(
                targets,
                [process.env.QA_NEXT + '/changed']
            );
            fs.rmSync(targets[0]);
            fetch(targets[0]);
        }
        replaceDirectly(process.env.QA_ORIG + '/original');
        replaceWithCall(process.env.QA_ORIG + '/original');
        replaceWithApply(process.env.QA_ORIG + '/original');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 6);
        assert!(
            sinks
                .iter()
                .all(|effect| matches!(&effect.resource, ResourceExpr::Unresolved { .. }))
        );
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            6
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn array_in_place_mutators_invalidate_aggregate_member_source_strings() {
    let source = r#"
        const fs = require('fs');
        function reverseTargets(...targets) {
            targets.reverse();
            fs.rmSync(targets[0] + '/after-reverse');
        }
        reverseTargets(process.env.HOME + '/first', process.env.TMPDIR + '/second');
        function copyTargets(...targets) {
            targets.copyWithin(0, 1);
            fs.rmSync(targets[0] + '/after-copy-within');
        }
        copyTargets(process.env.HOME + '/first', process.env.TMPDIR + '/second');
        function spliceTargets(...targets) {
            targets.splice(0, 1, process.env.QA_NEXT + '/replacement');
            fs.rmSync(targets[0] + '/after-splice');
        }
        spliceTargets(process.env.HOME + '/first', process.env.TMPDIR + '/second');
        function shiftTargets(...targets) {
            targets.shift();
            fs.rmSync(targets[0] + '/after-shift');
        }
        shiftTargets(process.env.HOME + '/first', process.env.TMPDIR + '/second');
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 4);
        assert!(
            deletes
                .iter()
                .all(|effect| matches!(&effect.resource, ResourceExpr::Unresolved { .. }))
        );
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            4
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn computed_array_mutators_invalidate_aggregate_member_source_strings() {
    let source = r#"
        const fs = require('fs');
        function reverseTargets(...targets) {
            targets['reverse']();
            fs.rmSync(targets[0] + '/after-reverse');
            fetch(targets[0] + '/after-reverse');
        }
        reverseTargets(process.env.HOME + '/first', process.env.TMPDIR + '/second');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| {
            match (effect.operation.0.as_str(), &effect.resource) {
                ("filesystem.delete", ResourceExpr::Unresolved { family }) => {
                    family.0 == "filesystem"
                }
                ("network.request", ResourceExpr::Unresolved { family }) => family.0 == "network",
                _ => false,
            }
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn unshift_sort_pop_and_reverse_call_apply_invalidate_aggregate_member_source_strings() {
    let source = r#"
        const fs = require('fs');
        function unshiftTargets(...targets) {
            targets.unshift(process.env.QA_NEXT + '/replacement');
            fs.rmSync(targets[0] + '/after-unshift');
            fetch(targets[0] + '/after-unshift');
        }
        unshiftTargets(process.env.QA_ORIG + '/first');
        function sortTargets(...targets) {
            targets.sort();
            fs.rmSync(targets[0] + '/after-sort');
            fetch(targets[0] + '/after-sort');
        }
        sortTargets(
            process.env.QA_Z + '/z',
            process.env.QA_A + '/a'
        );
        function popTargets(...targets) {
            targets.pop();
            fs.rmSync(targets[1] + '/after-pop');
            fetch(targets[1] + '/after-pop');
        }
        popTargets(
            process.env.QA_ORIG + '/first',
            process.env.QA_OTHER + '/second'
        );
        function reverseWithCall(...targets) {
            Array.prototype.reverse.call(targets);
            fs.rmSync(targets[0] + '/after-reverse-call');
            fetch(targets[0] + '/after-reverse-call');
        }
        reverseWithCall(
            process.env.QA_ORIG + '/first',
            process.env.QA_OTHER + '/second'
        );
        function reverseWithApply(...targets) {
            Array.prototype.reverse.apply(targets);
            fs.rmSync(targets[0] + '/after-reverse-apply');
            fetch(targets[0] + '/after-reverse-apply');
        }
        reverseWithApply(
            process.env.QA_ORIG + '/first',
            process.env.QA_OTHER + '/second'
        );
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 10);
        assert!(sinks.iter().all(|effect| {
            match (effect.operation.0.as_str(), &effect.resource) {
                ("filesystem.delete", ResourceExpr::Unresolved { family }) => {
                    family.0 == "filesystem"
                }
                ("network.request", ResourceExpr::Unresolved { family }) => family.0 == "network",
                _ => false,
            }
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            10
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn splice_call_apply_invalidate_aggregate_member_source_strings() {
    let source = r#"
        const fs = require('fs');
        function spliceWithCall(...targets) {
            Array.prototype.splice.call(targets, 0, 1);
            fs.rmSync(targets[0] + '/after-splice-call');
            fetch(targets[0] + '/after-splice-call');
        }
        spliceWithCall(
            process.env.HOME + '/first',
            process.env.TMPDIR + '/second'
        );
        function spliceWithApply(...targets) {
            Array.prototype.splice.apply(targets, [0, 1]);
            fs.rmSync(targets[0] + '/after-splice-apply');
            fetch(targets[0] + '/after-splice-apply');
        }
        spliceWithApply(
            process.env.HOME + '/first',
            process.env.TMPDIR + '/second'
        );
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 4);
        assert!(sinks.iter().all(|effect| {
            match (effect.operation.0.as_str(), &effect.resource) {
                ("filesystem.delete", ResourceExpr::Unresolved { family }) => {
                    family.0 == "filesystem"
                }
                ("network.request", ResourceExpr::Unresolved { family }) => family.0 == "network",
                _ => false,
            }
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            4
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn borrowed_array_mutators_invalidate_aggregate_member_source_strings() {
    let source = r#"
        const fs = require('fs');
        function copyWithinWithCall(...targets) {
            Array.prototype.copyWithin.call(targets, 0, 1);
            fs.rmSync(targets[0] + '/after-copy-within-call');
            fetch(targets[0] + '/after-copy-within-call');
        }
        copyWithinWithCall(process.env.HOME + '/first', process.env.TMPDIR + '/second');
        function copyWithinWithApply(...targets) {
            Array.prototype.copyWithin.apply(targets, [0, 1]);
            fs.rmSync(targets[0] + '/after-copy-within-apply');
            fetch(targets[0] + '/after-copy-within-apply');
        }
        copyWithinWithApply(process.env.HOME + '/first', process.env.TMPDIR + '/second');
        function shiftWithCall(...targets) {
            Array.prototype.shift.call(targets);
            fs.rmSync(targets[0] + '/after-shift-call');
            fetch(targets[0] + '/after-shift-call');
        }
        shiftWithCall(process.env.HOME + '/first', process.env.TMPDIR + '/second');
        function shiftWithApply(...targets) {
            Array.prototype.shift.apply(targets);
            fs.rmSync(targets[0] + '/after-shift-apply');
            fetch(targets[0] + '/after-shift-apply');
        }
        shiftWithApply(process.env.HOME + '/first', process.env.TMPDIR + '/second');
        function unshiftWithCall(...targets) {
            Array.prototype.unshift.call(targets, process.env.QA_NEXT + '/replacement');
            fs.rmSync(targets[0] + '/after-unshift-call');
            fetch(targets[0] + '/after-unshift-call');
        }
        unshiftWithCall(process.env.HOME + '/first');
        function unshiftWithApply(...targets) {
            Array.prototype.unshift.apply(targets, [process.env.QA_NEXT + '/replacement']);
            fs.rmSync(targets[0] + '/after-unshift-apply');
            fetch(targets[0] + '/after-unshift-apply');
        }
        unshiftWithApply(process.env.HOME + '/first');
        function sortWithCall(...targets) {
            Array.prototype.sort.call(targets);
            fs.rmSync(targets[0] + '/after-sort-call');
            fetch(targets[0] + '/after-sort-call');
        }
        sortWithCall(process.env.QA_Z + '/z', process.env.QA_A + '/a');
        function sortWithApply(...targets) {
            Array.prototype.sort.apply(targets);
            fs.rmSync(targets[0] + '/after-sort-apply');
            fetch(targets[0] + '/after-sort-apply');
        }
        sortWithApply(process.env.QA_Z + '/z', process.env.QA_A + '/a');
        function popWithCall(...targets) {
            Array.prototype.pop.call(targets);
            fs.rmSync(targets[1] + '/after-pop-call');
            fetch(targets[1] + '/after-pop-call');
        }
        popWithCall(process.env.HOME + '/first', process.env.TMPDIR + '/second');
        function popWithApply(...targets) {
            Array.prototype.pop.apply(targets);
            fs.rmSync(targets[1] + '/after-pop-apply');
            fetch(targets[1] + '/after-pop-apply');
        }
        popWithApply(process.env.HOME + '/first', process.env.TMPDIR + '/second');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 20);
        assert!(sinks.iter().all(|effect| {
            match (effect.operation.0.as_str(), &effect.resource) {
                ("filesystem.delete", ResourceExpr::Unresolved { family }) => {
                    family.0 == "filesystem"
                }
                ("network.request", ResourceExpr::Unresolved { family }) => family.0 == "network",
                _ => false,
            }
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            20
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn aggregate_alias_mutations_invalidate_source_strings() {
    let source = r#"
        const fs = require('fs');
        function assign(...targets) {
            const alias = targets;
            alias[0] = process.env.TMPDIR;
            fs.rmSync(targets[0] + '/after-alias-assignment');
        }
        assign(process.env.HOME);
        function mutate(...targets) {
            const alias = targets;
            Object.assign(alias, { 0: 'https://new.example' });
            fetch(targets[0] + '/after-alias-mutation');
        }
        mutate('https://old.example');
        function repeat(...targets) {
            const alias = targets;
            while (globalThis.again) {
                fs.rmSync(targets[0] + '/loop-alias-mutation');
                alias[0] = process.env.TMPDIR;
            }
        }
        repeat(process.env.HOME);
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 3);
        assert!(
            sinks
                .iter()
                .all(|effect| matches!(&effect.resource, ResourceExpr::Unresolved { .. }))
        );
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            3
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn parameter_alias_mutations_invalidate_caller_source_strings() {
    let source = r#"
        const fs = require('fs');
        function mutate(values) {
            values[0] = process.env.TMPDIR;
        }
        function remove(...targets) {
            mutate(targets);
            fs.rmSync(targets[0] + '/after-callee-mutation');
        }
        remove(process.env.HOME);
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 1);
        assert!(matches!(
            &deletes[0].resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            1
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn destructured_aggregate_aliases_invalidate_source_strings() {
    let source = r#"
        const fs = require('fs');
        function mutateParameter({ items }) {
            items[0] = 42;
        }
        function parameter(...targets) {
            mutateParameter({ items: targets });
            fs.rmSync(targets[0] + '/after-destructured-parameter');
        }
        parameter(process.env.HOME);
        function declaration(...targets) {
            const { items } = { items: targets };
            items[0] = 42;
            fs.rmSync(targets[0] + '/after-destructured-declaration');
        }
        declaration(process.env.HOME);
        function assignment(...targets) {
            let items;
            ({ items } = { items: targets });
            items[0] = 42;
            fs.rmSync(targets[0] + '/after-destructured-assignment');
        }
        assignment(process.env.HOME);
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 3);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            3
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn destructuring_rest_aggregate_aliases_invalidate_source_strings() {
    let source = r#"
        const fs = require('fs');
        function objectDeclaration(...targets) {
            const { skip, ...rest } = { skip: 0, inner: targets };
            rest.inner[0] = 'changed';
            fs.rmSync(targets[0] + '/after-object-rest-declaration');
        }
        objectDeclaration(process.env.HOME);
        function arrayDeclaration(...targets) {
            const [skip, ...rest] = [0, targets];
            rest[0][0] = 'https://changed.example';
            fetch(targets[0] + '/after-array-rest-declaration');
        }
        arrayDeclaration('https://before.example');
        function objectAssignment(...targets) {
            let skip, rest;
            ({ skip, ...rest } = { skip: 0, inner: targets });
            rest.inner[0] = 'changed';
            fs.rmSync(targets[0] + '/after-object-rest-assignment');
        }
        objectAssignment(process.env.HOME);
        function arrayAssignment(...targets) {
            let skip, rest;
            [skip, ...rest] = [0, targets];
            rest[0][0] = 'https://changed.example';
            fetch(targets[0] + '/after-array-rest-assignment');
        }
        arrayAssignment('https://before.example');
        function mutateObjectRest({ skip, ...rest }) {
            rest.inner[0] = 'changed';
        }
        function objectParameter(...targets) {
            mutateObjectRest({ skip: 0, inner: targets });
            fs.rmSync(targets[0] + '/after-object-rest-parameter');
        }
        objectParameter(process.env.HOME);
        function mutateArrayRest([skip, ...rest]) {
            rest[0][0] = 'https://changed.example';
        }
        function arrayParameter(...targets) {
            mutateArrayRest([0, targets]);
            fetch(targets[0] + '/after-array-rest-parameter');
        }
        arrayParameter('https://before.example');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 6);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            6
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn empty_prefix_concatenation_does_not_resolve_against_cwd() {
    let source = r#"
        const fs = require('fs');
        fs.rmSync('' + process.env.HOME + '/x');
        fs.rmSync('' + '/tmp/x');
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(is_joined_env_path(&deletes[0].resource, "HOME", "/x"));
        assert!(has(&plan, "filesystem.delete", "/tmp/x"));
    }
}

#[test]
fn captured_aggregate_aliases_invalidate_source_strings() {
    let source = r#"
        const fs = require('fs');
        function clear(...targets) {
            let alias;
            function link() {
                alias = targets;
            }
            link();
            alias[0] = 42;
            fs.rmSync(targets[0] + '/after-captured-alias');
        }
        clear(process.env.HOME);
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 1);
        assert!(matches!(
            &deletes[0].resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            1
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn returned_aggregate_aliases_invalidate_source_strings() {
    let source = r#"
        const fs = require('fs');
        function identity(value) {
            return value;
        }
        function named(...targets) {
            const alias = identity(targets);
            alias[0] = 42;
            fs.rmSync(targets[0] + '/after-named-return');
        }
        named(process.env.HOME);
        function inline(...targets) {
            const alias = ((value) => value)(targets);
            Object.assign(alias, { 0: 42 });
            fetch(targets[0] + '/after-inline-return');
        }
        inline('https://before.example');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(
            sinks
                .iter()
                .all(|effect| matches!(&effect.resource, ResourceExpr::Unresolved { .. }))
        );
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn wrapped_returned_aggregate_aliases_invalidate_source_strings() {
    let source = r#"
        const fs = require('fs');
        function objectWrapper(value) {
            return { inner: value };
        }
        function remove(...targets) {
            const box = objectWrapper(targets);
            box.inner[0] = 42;
            fs.rmSync(targets[0] + '/after-wrapped-object-return');
        }
        remove(process.env.HOME);
        function arrayWrapper(value) {
            return [value];
        }
        function request(...targets) {
            const box = arrayWrapper(targets);
            box[0][0] = 42;
            fetch(targets[0] + '/after-wrapped-array-return');
        }
        request('https://before.example');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn expression_wrapped_aggregate_aliases_invalidate_source_strings() {
    let source = r#"
        const fs = require('fs');
        function conditional(...targets) {
            const alias = globalThis.pick ? targets : targets;
            alias[0] = 42;
            fs.rmSync(targets[0] + '/after-conditional-alias');
        }
        conditional(process.env.HOME);
        function logical(...targets) {
            const alias = targets && targets;
            alias[0] = 42;
            fetch(targets[0] + '/after-logical-alias');
        }
        logical('https://before.example');
        function sequence(...targets) {
            const alias = (0, targets);
            alias[0] = 42;
            fs.rmSync(targets[0] + '/after-sequence-alias');
        }
        sequence(process.env.HOME);
        function assignment(...targets) {
            let selected;
            const alias = (selected = targets);
            alias[0] = 42;
            fetch(targets[0] + '/after-assignment-alias');
        }
        assignment('https://before.example');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 4);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            4
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn logical_assignment_aggregate_aliases_invalidate_source_strings() {
    let source = r#"
        const fs = require('fs');
        function orAssignment(...targets) {
            let selected = targets;
            const alias = (selected ||= []);
            alias[0] = 42;
            fs.rmSync(targets[0] + '/after-or-assignment-alias');
        }
        orAssignment(process.env.HOME);
        function andAssignment(...targets) {
            let selected = true;
            selected &&= targets;
            selected[0] = 42;
            fetch(targets[0] + '/after-and-assignment-alias');
        }
        andAssignment('https://before.example');
        function nullishAssignment(...targets) {
            let selected = null;
            const alias = (selected ??= targets);
            Object.assign(alias, { 0: 42 });
            fs.rmSync(targets[0] + '/after-nullish-assignment-alias');
        }
        nullishAssignment(process.env.HOME);
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 3);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            3
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn member_assignment_aggregate_aliases_invalidate_source_strings() {
    let source = r#"
        const fs = require('fs');
        function plainStaticMember(...targets) {
            const holder = {};
            holder.slot = targets;
            holder.slot[0] = 42;
            fs.rmSync(targets[0] + '/after-plain-static-member');
        }
        plainStaticMember(process.env.HOME);
        function plainComputedMember(...targets) {
            const holder = {};
            holder['slot'] = targets;
            Object.assign(holder['slot'], { 0: 42 });
            fetch(targets[0] + '/after-plain-computed-member');
        }
        plainComputedMember('https://before.example');
        function logicalStaticMember(...targets) {
            const holder = {};
            holder.slot ??= targets;
            holder.slot[0] = 42;
            fs.rmSync(targets[0] + '/after-logical-static-member');
        }
        logicalStaticMember(process.env.HOME);
        function logicalComputedMember(...targets) {
            const holder = {};
            holder['slot'] ??= targets;
            Object.assign(holder['slot'], { 0: 42 });
            fetch(targets[0] + '/after-logical-computed-member');
        }
        logicalComputedMember('https://before.example');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 4);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            4
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn typescript_wrapped_member_assignment_preserves_aggregate_aliases() {
    let plan = ts(r#"
        const fs = require('fs');
        function wrappedMember(...targets: string[]) {
            const holder: { slot?: string[] } = {};
            (holder.slot as string[]) = targets;
            holder.slot[0] = 'changed';
            fs.rmSync(targets[0] + '/after-wrapped-member');
        }
        wrappedMember(process.env.HOME);
    "#);
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Unresolved { family } if family.0 == "filesystem"
    ));
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
    );
    assert!(!all_full(&plan));
}

#[test]
fn optional_chain_aggregate_aliases_invalidate_source_strings() {
    let source = r#"
        const fs = require('fs');
        function staticMember(...targets) {
            const holder = { inner: targets };
            const alias = holder?.inner;
            alias[0] = 42;
            fs.rmSync(targets[0] + '/after-optional-chain');
        }
        staticMember(process.env.HOME);
        function computedMember(...targets) {
            const holder = { inner: targets };
            const alias = holder?.['inner'];
            Object.assign(alias, { 0: 42 });
            fetch(targets[0] + '/after-computed-optional-chain');
        }
        computedMember('https://before.example');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn implicit_plus_coercion_widens_source_string_state() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME;
        '' + { toString() { path = process.env.TMPDIR; return ''; } };
        fs.rmSync(path + '/after-coercion');
        let url = process.env.API_BASE;
        '' + { valueOf() { url = process.env.ALT_BASE; return ''; } };
        fetch(url + '/after-coercion');
        let boundPath = process.env.HOME;
        const primitive = {
            valueOf() { boundPath = process.env.TMPDIR; return ''; }
        };
        '' + primitive;
        fs.rmSync(boundPath + '/after-bound-coercion');
        let symbolUrl = process.env.API_BASE;
        const symbolPrimitive = {
            [Symbol.toPrimitive]() { symbolUrl = process.env.ALT_BASE; return ''; }
        };
        '' + symbolPrimitive;
        fetch(symbolUrl + '/after-symbol-coercion');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 4);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            4
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn getter_returned_plus_coercion_callback_widens_source_string_state() {
    let source = r#"
        const fs = require('fs');
        let base = process.env.HOME;
        const primitive = {
            get [Symbol.toPrimitive]() {
                return function () {
                    base = process.env.TMPDIR;
                    return '';
                };
            }
        };
        '' + primitive;
        fs.rmSync(base + '/after-getter-coercion');
    "#;
    for plan in [js(source), ts(source)] {
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "environment.read"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable { name }
                    } if name == "TMPDIR"
                )
        }));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn function_valued_declarators_collect_nested_plus_coercion_callbacks() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME;
        const remove = () => {
            const primitive = {
                valueOf() { path = process.env.TMPDIR; return ''; }
            };
            '' + primitive;
        };
        remove();
        fs.rmSync(path + '/after-arrow-coercion');
        let url = process.env.API_BASE;
        const request = function() {
            const primitive = {
                [Symbol.toPrimitive]() { url = process.env.ALT_BASE; return ''; }
            };
            '' + primitive;
        };
        request();
        fetch(url + '/after-function-coercion');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn plus_coercion_callbacks_flow_through_parameters() {
    let source = r#"
        const fs = require('fs');
        let namedPath = process.env.HOME;
        const namedPrimitive = {
            valueOf() { namedPath = process.env.TMPDIR; return ''; }
        };
        function coerce(value) { '' + value; }
        coerce(namedPrimitive);
        fs.rmSync(namedPath + '/after-named-parameter-coercion');
        let inlinePath = process.env.HOME;
        const inlinePrimitive = {
            [Symbol.toPrimitive]() { inlinePath = process.env.TMPDIR; return ''; }
        };
        ((value) => { '' + value; })(inlinePrimitive);
        fs.rmSync(inlinePath + '/after-inline-parameter-coercion');
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|effect| {
            matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "filesystem")
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn plus_coercion_callbacks_flow_through_parameter_patterns() {
    let source = r#"
        const fs = require('fs');
        let destructuredPath = process.env.HOME;
        const destructuredPrimitive = {
            valueOf() { destructuredPath = process.env.TMPDIR; return ''; }
        };
        function destructured({ value }) { '' + value; }
        destructured({ value: destructuredPrimitive });
        fs.rmSync(destructuredPath + '/after-destructured-parameter-coercion');
        let defaultPath = process.env.HOME;
        const defaultPrimitive = {
            valueOf() { defaultPath = process.env.TMPDIR; return ''; }
        };
        function defaulted(value = defaultPrimitive) { '' + value; }
        defaulted();
        fs.rmSync(defaultPath + '/after-default-parameter-coercion');
        let restPath = process.env.HOME;
        const restPrimitive = {
            [Symbol.toPrimitive]() { restPath = process.env.TMPDIR; return ''; }
        };
        function rest(...values) { '' + values[0]; }
        rest(restPrimitive);
        fs.rmSync(restPath + '/after-rest-parameter-coercion');
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 3);
        assert!(deletes.iter().all(|effect| {
            matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "filesystem")
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            3
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn plus_coercion_callbacks_flow_through_identifier_bound_parameter_patterns() {
    let source = r#"
        const fs = require('fs');
        let objectPath = process.env.HOME;
        const objectPrimitive = {
            valueOf() { objectPath = process.env.TMPDIR; return ''; }
        };
        const payload = { value: objectPrimitive };
        function coerceObject({ value }) { '' + value; }
        coerceObject(payload);
        fs.rmSync(objectPath + '/after-identifier-object-coercion');
        let arrayPath = process.env.HOME;
        const arrayPrimitive = {
            [Symbol.toPrimitive]() { arrayPath = process.env.TMPDIR; return ''; }
        };
        const values = [arrayPrimitive];
        function coerceArray([value]) { '' + value; }
        coerceArray(values);
        fs.rmSync(arrayPath + '/after-identifier-array-coercion');
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(deletes.iter().all(|effect| {
            matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "filesystem")
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn template_interpolation_follows_plus_coercion_callbacks() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME;
        const pathPrimitive = {
            toString() { path = process.env.TMPDIR; return ''; }
        };
        `${pathPrimitive}`;
        fs.rmSync(path + '/after-template-coercion');
        let url = process.env.API_BASE;
        const urlPrimitive = {
            [Symbol.toPrimitive]() { url = process.env.ALT_BASE; return ''; }
        };
        `${urlPrimitive}`;
        fetch(url + '/after-template-coercion');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn assigned_plus_coercion_callbacks_widen_source_string_state() {
    let source = r#"
        const fs = require('fs');
        let valueOfPath = process.env.HOME;
        const valueOfPrimitive = {};
        valueOfPrimitive.valueOf = () => {
            valueOfPath = process.env.TMPDIR;
            return '';
        };
        '' + valueOfPrimitive;
        fs.rmSync(valueOfPath + '/after-assigned-value-of');
        let toStringUrl = process.env.API_BASE;
        const toStringPrimitive = {};
        toStringPrimitive['toString'] = () => {
            toStringUrl = process.env.ALT_BASE;
            return '';
        };
        `${toStringPrimitive}`;
        fetch(toStringUrl + '/after-assigned-to-string');
        let symbolPath = process.env.HOME;
        const symbolPrimitive = {};
        symbolPrimitive[Symbol.toPrimitive] = () => {
            symbolPath = process.env.TMPDIR;
            return '';
        };
        '' + symbolPrimitive;
        fs.rmSync(symbolPath + '/after-assigned-symbol-coercion');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 3);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            3
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn plus_coercion_callbacks_follow_aggregate_alias_wrappers() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME;
        const pathPrimitive = {
            valueOf() { path = process.env.TMPDIR; return 1; }
        };
        const pathAlias = true ? pathPrimitive : pathPrimitive;
        pathAlias + 1;
        fs.rmSync(path + '/after-wrapper-coercion');
        let url = process.env.API_BASE;
        const urlPrimitive = {
            [Symbol.toPrimitive]() { url = process.env.ALT_BASE; return ''; }
        };
        const urlAlias = true ? urlPrimitive : urlPrimitive;
        `${urlAlias}`;
        fetch(url + '/after-wrapper-coercion');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn assigned_plus_coercion_callbacks_update_aggregate_aliases() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME;
        const pathPrimitive = {};
        const pathAlias = pathPrimitive;
        pathAlias.valueOf = function () {
            path = process.env.TMPDIR;
            return 1;
        };
        pathPrimitive + 1;
        fs.rmSync(path + '/after-alias-assignment');
        let url = process.env.API_BASE;
        const urlPrimitive = {};
        const urlAlias = urlPrimitive;
        urlAlias[Symbol.toPrimitive] = () => {
            url = process.env.ALT_BASE;
            return '';
        };
        `${urlPrimitive}`;
        fetch(url + '/after-alias-assignment');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn class_instance_plus_coercion_callbacks_widen_source_string_state() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME;
        class Box {
            valueOf() { path = process.env.TMPDIR; return 1; }
        }
        const box = new Box();
        box + 1;
        fs.rmSync(path + '/after-class-coercion');
        let url = process.env.API_BASE;
        class Endpoint {
            [Symbol.toPrimitive]() { url = process.env.ALT_BASE; return ''; }
        }
        const endpoint = new Endpoint();
        `${endpoint}`;
        fetch(url + '/after-class-coercion');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        assert!(!all_full(&plan));
    }
}

#[test]
fn constructor_return_plus_coercion_callbacks_widen_source_string_state() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME;
        class Box {
            constructor() {
                return {
                    [Symbol.toPrimitive]() {
                        path = process.env.TMPDIR;
                        return 1;
                    }
                };
            }
        }
        const box = new Box();
        box + 1;
        fs.rmSync(path + '/after-constructor-return-coercion');
        let url = process.env.API_BASE;
        class Endpoint {
            constructor() {
                return {
                    valueOf() {
                        url = process.env.ALT_BASE;
                        return '';
                    }
                };
            }
        }
        const endpoint = new Endpoint();
        `${endpoint}`;
        fetch(url + '/after-constructor-return-coercion');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        for expected in ["TMPDIR", "ALT_BASE"] {
            assert!(plan.effects.iter().any(|effect| {
                effect.operation.0 == "environment.read"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::EnvironmentVariable { name }
                        } if name == expected
                    )
            }));
        }
        assert!(!all_full(&plan));
    }
}

#[test]
fn constructor_identifier_return_plus_coercion_callbacks_widen_source_string_state() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.QA_HOME;
        const boxValue = {
            valueOf() {
                path = process.env.QA_TMP;
                return 1;
            }
        };
        class Box {
            constructor() { return boxValue; }
        }
        const box = new Box();
        box + 1;
        fs.rmSync(path + '/after-constructor-identifier-return');
        let url = process.env.QA_API;
        const endpointValue = {
            [Symbol.toPrimitive]() {
                url = process.env.QA_ALT;
                return '';
            }
        };
        class Endpoint {
            constructor() { return endpointValue; }
        }
        const endpoint = new Endpoint();
        `${endpoint}`;
        fetch(url + '/after-constructor-identifier-return');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        for expected in ["QA_TMP", "QA_ALT"] {
            assert!(plan.effects.iter().any(|effect| {
                effect.operation.0 == "environment.read"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::EnvironmentVariable { name }
                        } if name == expected
                    )
            }));
        }
        assert!(!all_full(&plan));
    }
}

#[test]
fn nested_local_and_instance_field_coercion_callbacks_widen_source_string_state() {
    let source = r#"
        const fs = require('fs');
        let nestedPath = process.env.NESTED_HOME;
        class NestedBox {
            constructor() {
                if (true) {
                    return {
                        valueOf() {
                            nestedPath = process.env.NESTED_TMP;
                            return 1;
                        }
                    };
                }
            }
        }
        new NestedBox() + 1;
        fs.rmSync(nestedPath + '/after-nested-constructor-return');

        let localPath = process.env.LOCAL_HOME;
        class LocalBox {
            constructor() {
                const replacement = {
                    valueOf() {
                        localPath = process.env.LOCAL_TMP;
                        return 1;
                    }
                };
                return replacement;
            }
        }
        new LocalBox() + 1;
        fs.rmSync(localPath + '/after-local-constructor-return');

        let fieldPath = process.env.FIELD_HOME;
        class FieldBox {
            valueOf = function() {
                fieldPath = process.env.FIELD_TMP;
                return 1;
            };
        }
        new FieldBox() + 1;
        fs.rmSync(fieldPath + '/after-instance-field');
    "#;
    for plan in [js(source), ts(source)] {
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 3);
        assert!(deletes.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            3
        );
        for expected in ["NESTED_TMP", "LOCAL_TMP", "FIELD_TMP"] {
            assert!(plan.effects.iter().any(|effect| {
                effect.operation.0 == "environment.read"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::EnvironmentVariable { name }
                        } if name == expected
                    )
            }));
        }
        assert!(!all_full(&plan));
    }
}

#[test]
fn no_substitution_templates_use_cooked_values() {
    let source = r#"
        const fs = require('fs');
        fs.rmSync(`/tmp/a\nb`);
        fetch(`https://example.com/a\u0062`);
    "#;
    for plan in [js(source), ts(source)] {
        assert!(has(&plan, "filesystem.delete", "/tmp/a\nb"));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(matches!(&request.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint { host, path, .. }
            } if host == "example.com" && path.as_deref() == Some("/ab")));
        assert!(plan.boundaries.is_empty());
        assert!(all_full(&plan));
    }
}

#[test]
fn class_plus_coercion_callbacks_are_inherited() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME;
        class Base {
            valueOf() { path = process.env.TMPDIR; return 1; }
        }
        class Child extends Base {
            toString() { return ''; }
        }
        new Child() + '';
        fs.rmSync(path + '/after-inherited-coercion');
        let url = process.env.API_BASE;
        class EndpointBase {
            [Symbol.toPrimitive]() { url = process.env.ALT_BASE; return ''; }
        }
        class Endpoint extends EndpointBase {
            valueOf() { return 1; }
        }
        `${new Endpoint()}`;
        fetch(url + '/after-inherited-coercion');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        for expected in ["TMPDIR", "ALT_BASE"] {
            assert!(plan.effects.iter().any(|effect| {
                effect.operation.0 == "environment.read"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::EnvironmentVariable { name }
                        } if name == expected
                    )
            }));
        }
        assert!(!all_full(&plan));
    }
}

#[test]
fn prototype_installed_plus_coercion_callbacks_widen_source_string_state() {
    let source = r#"
        const fs = require('fs');
        let path = process.env.HOME;
        class Box {}
        Box.prototype[Symbol.toPrimitive] = function () {
            path = process.env.TMPDIR;
            return '';
        };
        new Box() + '';
        fs.rmSync(path + '/after-prototype-coercion');
        let url = process.env.API_BASE;
        class Endpoint {}
        Endpoint.prototype.toString = function () {
            url = process.env.ALT_BASE;
            return '';
        };
        `${new Endpoint()}`;
        fetch(url + '/after-prototype-coercion');
    "#;
    for plan in [js(source), ts(source)] {
        let sinks: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "filesystem.delete" | "network.request"
                )
            })
            .collect();
        assert_eq!(sinks.len(), 2);
        assert!(sinks.iter().all(|effect| match &effect.resource {
            ResourceExpr::Unresolved { family } => match effect.operation.0.as_str() {
                "filesystem.delete" => family.0 == "filesystem",
                "network.request" => family.0 == "network",
                _ => false,
            },
            _ => false,
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            2
        );
        for expected in ["TMPDIR", "ALT_BASE"] {
            assert!(plan.effects.iter().any(|effect| {
                effect.operation.0 == "environment.read"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::EnvironmentVariable { name }
                        } if name == expected
                    )
            }));
        }
        assert!(!all_full(&plan));
    }
}

#[test]
fn http_create_server_is_a_listener_not_a_request() {
    for source in [
        r#"const http = require('http'); http.createServer(h).listen(8080);"#,
        r#"const http = require('http'); const s = http.createServer(h); s.listen(8080);"#,
        r#"const https = require('https'); https.createServer(opts, h).listen(443);"#,
    ] {
        let plan = js(source);
        assert_eq!(
            ops(&plan)
                .iter()
                .filter(|operation| **operation == "network.listen")
                .count(),
            1
        );
        assert!(!ops(&plan).contains(&"network.request"));
    }

    let requests = js(r#"
        const http = require('http');
        const https = require('https');
        https.get('https://example.com/x');
        http.request({host: 'example.com'});
    "#);
    assert_eq!(
        ops(&requests)
            .iter()
            .filter(|operation| **operation == "network.request")
            .count(),
        2
    );
}

#[test]
fn local_fetch_bindings_shadow_the_global() {
    for source in [
        "function fetch(){ return 1 } fetch();",
        "function f(fetch){ fetch() } f(g);",
    ] {
        assert!(!ops(&js(source)).contains(&"network.request"));
    }

    let local_callable = js(r#"
        const fs = require('fs');
        const fetch = async () => fs.rmSync('/tmp/x');
        fetch();
    "#);
    assert!(!ops(&local_callable).contains(&"network.request"));
    assert!(has(&local_callable, "filesystem.delete", "/tmp/x"));

    for source in [
        "fetch('https://example.com/a');",
        "import fetch from 'node-fetch'; fetch('https://example.com/a');",
    ] {
        assert_eq!(
            ops(&js(source))
                .iter()
                .filter(|operation| **operation == "network.request")
                .count(),
            1
        );
    }
}

#[test]
fn rm_options_through_bindings_and_spreads_keep_recursive() {
    let plan = js(r#"
        const fs = require('fs');
        const RM_OPTS = {recursive: true};
        fs.rmSync('/tmp/bound', RM_OPTS);
        const base = {recursive: true};
        fs.rmSync('/tmp/spread', {...base, force: true});
        fs.rmSync('/tmp/overridden', {...base, recursive: false});
        let reassigned = {recursive: true};
        reassigned = {};
        fs.rmSync('/tmp/reassigned', reassigned);
    "#);
    for path in ["/tmp/bound", "/tmp/spread"] {
        let effect = plan
            .effects
            .iter()
            .find(|effect| has_effect(effect, "filesystem.delete", path))
            .expect("recursive delete");
        assert_eq!(
            effect.attributes.get("recursive"),
            Some(&effinterp_proto::AttrValue::Bool(true))
        );
    }
    for path in ["/tmp/overridden", "/tmp/reassigned"] {
        let effect = plan
            .effects
            .iter()
            .find(|effect| has_effect(effect, "filesystem.delete", path))
            .expect("non-recursive delete");
        assert!(!effect.attributes.contains_key("recursive"));
    }
}

#[test]
fn spawn_with_shell_true_nests_the_command_string() {
    let command = js(r#"
        const {spawn} = require('child_process');
        spawn('rm -rf /tmp/z', {shell: true});
    "#);
    let delete = command
        .effects
        .iter()
        .find(|effect| has_effect(effect, "filesystem.delete", "/tmp/z"))
        .expect("shell-nested delete");
    assert_eq!(
        delete.attributes.get("recursive"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    assert_eq!(
        delete.attributes.get("force"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    assert!(!has_boundary(&command, "unmodeled_command"));
    assert!(all_full(&command));

    let argv = js(r#"
        const {spawn} = require('child_process');
        spawn('rm', ['-rf', '/tmp/argv'], {shell: true});
    "#);
    assert!(has(&argv, "filesystem.delete", "/tmp/argv"));

    let pipeline = js(r#"
        const {spawn} = require('child_process');
        spawn('npm run build && npm publish', {shell: true});
    "#);
    assert_eq!(
        pipeline
            .execution_graph
            .nodes
            .iter()
            .filter(|node| matches!(&node.subject, Subject::Exec { argv, .. }
                if argv.first().is_some_and(|word| word == "npm")))
            .count(),
        2
    );

    let dynamic = js(r#"
        const {spawnSync} = require('child_process');
        spawnSync(cmd, {shell: '/bin/bash'});
    "#);
    assert!(has_boundary(&dynamic, "unmodeled_dynamic_code"));
    assert!(!ops(&dynamic).contains(&"process.exec"));

    // A tracked argv array joins the command the shell runs.
    let push = js(r#"
        const {execFileSync} = require('child_process');
        const args = ['push', '--force'];
        execFileSync('git', args, {shell: true});
    "#);
    let sync = push
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.remote_sync")
        .expect("shell-nested git push --force");
    assert_eq!(
        sync.attributes.get("force"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    let reset = js(r#"
        const {execFileSync} = require('child_process');
        const args = ['reset', '--hard'];
        execFileSync('git', args, {shell: true});
    "#);
    assert!(ops(&reset).contains(&"git.worktree_discard"));

    // An unset shell option runs no shell, so the argument stays one word.
    for source in [
        "const {spawn} = require('child_process'); const o = {shell: undefined}; spawn('echo', ['; cat /home/test/.ssh/id_rsa'], o);",
        "const {spawn} = require('child_process'); spawn('echo', ['; cat /home/test/.ssh/id_rsa'], {shell: undefined});",
        "const {spawn} = require('child_process'); const o = {shell: null}; spawn('echo', ['; cat /home/test/.ssh/id_rsa'], o);",
    ] {
        let plan = js(source);
        assert!(
            !has(&plan, "filesystem.read", "/home/test/.ssh/id_rsa"),
            "{source}"
        );
    }
}

#[test]
fn path_join_is_anchored_once() {
    let plan = js(r#"
        const fs = require('fs');
        const path = require('path');
        fs.writeFileSync(path.join('/var/data', 'part.json'), 'x');
        fs.writeFileSync(path.join('dist', 'part.json'), 'x');
        const ROOT = '/srv';
        fs.rmSync(path.join(ROOT, 'cache'));
        function f(d) { fs.rmSync(path.join(d, 'nested')); }
        f('/srv');
        fs.rmSync(path.join(x, 'cache'));
        fs.writeFileSync(path.resolve('dist', 'a.json'), 'x');
    "#);
    for (operation, path) in [
        ("filesystem.write", "/var/data/part.json"),
        ("filesystem.write", "/app/dist/part.json"),
        ("filesystem.delete", "/srv/cache"),
        ("filesystem.delete", "/srv/nested"),
        ("filesystem.write", "/app/dist/a.json"),
    ] {
        assert!(has(&plan, operation, path), "missing {operation} {path}");
    }
    let unresolved = plan
        .effects
        .iter()
        .find(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Join { parts }
                    if matches!(parts.as_slice(), [
                        ResourceExpr::Unresolved { family },
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path }
                        }
                    ] if family.0 == "filesystem" && path == "cache"))
        })
        .expect("unbound join stays symbolic");
    assert!(!resource_has_parameter(&unresolved.resource));
}

#[test]
fn copy_recursive_attribute_is_on_the_destination() {
    let plan = js(r#"
        const fs = require('fs');
        fs.cpSync('/src', '/dest', {recursive: true});
    "#);
    let read = plan
        .effects
        .iter()
        .find(|effect| has_effect(effect, "filesystem.read", "/src"))
        .expect("copy source read");
    assert!(!read.attributes.contains_key("recursive"));
    let write = plan
        .effects
        .iter()
        .find(|effect| has_effect(effect, "filesystem.write", "/dest"))
        .expect("copy destination write");
    assert_eq!(
        write.attributes.get("recursive"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
}

#[test]
fn const_urls_and_named_path_imports_lower() {
    let network = js(r#"
        const BASE = 'https://api.example.com';
        const U = 'https://api.example.com/v1';
        const NOT_A_URL = 'local-resource';
        const https = require('https');
        fetch(BASE);
        https.get(U);
        fetch(`${BASE}/v1/items`);
        fetch(NOT_A_URL);
    "#);
    assert_eq!(
        network
            .effects
            .iter()
            .filter(|effect| matches!(&effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                } if host == "api.example.com" && scheme.as_deref() == Some("https")))
            .count(),
        2
    );
    assert!(network.effects.iter().any(|effect| {
        effect.operation.0 == "network.request"
            && matches!(&effect.resource, ResourceExpr::Join { parts }
                if matches!(parts.as_slice(), [
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::NetworkEndpoint { host, .. }
                    },
                    ResourceExpr::Literal { value }
                ] if host == "api.example.com" && value == "/v1/items"))
    }));
    assert!(network.effects.iter().any(|effect| {
        effect.operation.0 == "network.request"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "network")
    }));

    for source in [
        "const fs=require('fs'); const {join}=require('path'); fs.rmSync(join('/srv','cache'));",
        "import fs from 'fs'; import {join} from 'node:path'; fs.rmSync(join('/srv','cache'));",
        "const fs=require('fs'); const path=require('path'); fs.rmSync(path.posix.join('/srv','cache'));",
        "const fs=require('fs'); const p=require('path'); fs.rmSync(p.join('/srv','cache'));",
        "import fs from 'fs'; import * as p from 'path'; fs.rmSync(p.resolve('/srv','cache'));",
    ] {
        assert!(
            has(&js(source), "filesystem.delete", "/srv/cache"),
            "{source}"
        );
    }

    let win32 = js(r#"
        const fs = require('fs');
        const path = require('path');
        fs.rmSync(path.win32.join('/srv', 'cache'));
    "#);
    assert!(win32.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "filesystem")
    }));
}

fn has_effect(effect: &effinterp_proto::Effect, operation: &str, path: &str) -> bool {
    effect.operation.0 == operation
        && matches!(&effect.resource,
            ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: actual } }
                if actual == path)
}

#[test]
fn environment_mutations_are_writes_without_target_reads() {
    let source = r#"
        const values = { B: "2" };
        delete process.env.DEBUG;
        delete process.env[key];
        Object.assign(process.env, { A: "1", "C": "3", [key]: "dynamic" }, values, source);
    "#;
    for plan in [js(source), ts(source)] {
        let is_env_name = |effect: &effinterp_proto::Effect, expected: &str| {
            matches!(&effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name },
                } | ResourceExpr::Environment { name } if name == expected)
        };
        for name in ["DEBUG", "A", "B", "C"] {
            assert!(plan.effects.iter().any(|effect| {
                effect.operation.0 == "environment.write" && is_env_name(effect, name)
            }));
        }
        let deleted = plan
            .effects
            .iter()
            .find(|effect| is_env_name(effect, "DEBUG"))
            .unwrap();
        assert_eq!(
            deleted.attributes.get("unset"),
            Some(&effinterp_proto::AttrValue::Bool(true))
        );
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "environment.write"
                && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                    if family.0 == "environment")
                && effect.attributes.get("unset") == Some(&effinterp_proto::AttrValue::Bool(true))
        }));
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "environment.read")
        );
    }

    let shadowed = js(
        "function configure(process) { delete process.env.X; Object.assign(process.env, {Y: '1'}); } configure(fake);",
    );
    assert!(
        shadowed
            .effects
            .iter()
            .all(|effect| effect.operation.0 != "environment.write")
    );
    assert!(has_boundary(&shadowed, "partial_analysis"));
}

fn resource_has_parameter(resource: &ResourceExpr) -> bool {
    match resource {
        ResourceExpr::Parameter { .. } => true,
        ResourceExpr::Join { parts } => parts.iter().any(resource_has_parameter),
        _ => false,
    }
}

#[test]
fn in_function_git_push_composes_remote_sync() {
    let plan = js(
        "const { execFileSync } = require('child_process');\nfunction push(){ execFileSync('git', ['push', '--force', 'origin', 'main']); }\npush();\n",
    );
    let sync = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.remote_sync")
        .expect("in-function git push composes");
    assert_eq!(
        sync.attributes.get("force"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    assert_eq!(
        sync.attributes.get("push"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
}

#[test]
fn spawn_sync_bound_dir_deletes_path() {
    let plan = js(
        "const { spawnSync } = require('child_process');\nfunction rm(dir){ spawnSync('rm', ['-rf', dir]); }\nrm('/tmp/z');\n",
    );
    assert!(has(&plan, "filesystem.delete", "/tmp/z"));
}

#[test]
fn exec_sync_template_literal_nests() {
    let plan = js(
        "const { execSync } = require('child_process');\nexecSync(`git push --force origin main`);\n",
    );
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "git.remote_sync")
    );
}

#[test]
fn rest_wrapper_and_args_ident_compose() {
    for source in [
        "const { execFileSync } = require('child_process');\nconst git = (...a) => execFileSync('git', a);\ngit('push', '--force');\n",
        "const { execFileSync } = require('child_process');\nconst args = ['push', '--force'];\nexecFileSync('git', args);\n",
    ] {
        let plan = js(source);
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "git.remote_sync"),
            "{source}"
        );
    }
}

#[test]
fn dropped_argv_never_claims_git_full() {
    let plan = js("const { execFileSync } = require('child_process');
execFileSync('git', unknownArgs);
");
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "process.exec")
    );
    assert_ne!(
        plan.coverage
            .0
            .get(&Domain::new("git"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Full)
    );
}

#[test]
fn tracked_argv_past_index_limit_does_not_drop_tail_silently() {
    let mut files = vec!["'-rf'".to_string()];
    for i in 0..40 {
        files.push(format!("'/data/keep{i}'"));
    }
    let source = format!(
        "const {{ execFileSync }} = require('child_process');\nconst files = [{}];\nexecFileSync('rm', files);\n",
        files.join(", ")
    );
    let plan = js(&source);
    assert!(has(&plan, "filesystem.delete", "/data/keep0"));
    assert!(
        plan.effects.iter().any(|effect| {
            effect.operation.0 == "process.exec"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::Process { argv, .. }
                    } if argv.iter().any(|word| {
                        matches!(word, ResourceExpr::Unresolved { .. })
                    })
                )
        }),
        "oversized tracked argv must keep an Unknown tail"
    );
    assert!(
        plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(effect.resource, ResourceExpr::Unresolved { .. })
        }),
        "truncated argv tail must surface as an unknown delete"
    );
}

fn exec_argv_has_unresolved(plan: &Plan) -> bool {
    plan.effects.iter().any(|effect| {
        effect.operation.0 == "process.exec"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { argv, .. }
                } if argv.iter().any(|word| matches!(word, ResourceExpr::Unresolved { .. }))
            )
    })
}

#[test]
fn spread_argv_words_are_not_dropped() {
    let force = js("const { execFileSync } = require('child_process');
const extra = ['--force'];
const args = ['push', ...extra];
execFileSync('git', args);
");
    let sync = force
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.remote_sync")
        .expect("tracked array spread should compose git push --force");
    assert_eq!(
        sync.attributes.get("force"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );

    let rest = js("const { execFileSync } = require('child_process');
function run(...extra){ execFileSync('rm', ['-rf', ...extra]); }
run('/tmp/a');
");
    assert!(has(&rest, "filesystem.delete", "/tmp/a"));

    let after_spread = js("const { execFileSync } = require('child_process');
const args = ['-rf', ...process.argv.slice(2), '/tmp/keep'];
execFileSync('rm', args);
");
    assert!(has(&after_spread, "filesystem.delete", "/tmp/keep"));
    assert!(
        exec_argv_has_unresolved(&after_spread),
        "unknown-length spread must leave an Unknown argv word"
    );

    let unknown = js("const { execFileSync } = require('child_process');
const args = ['push', '--force', ...unknownList];
execFileSync('git', args);
");
    assert!(
        exec_argv_has_unresolved(&unknown),
        "unknown spread must not truncate argv without a trace"
    );
}

#[test]
fn sibling_function_block_captures_do_not_expand_aliases_without_bound() {
    let plan = js(r#"
import { readFileSync } from "node:fs";
{
    const file = "a.ts";
    const sourceFile = readFileSync(file, "utf8");
    const failures = [];
    function checkSpecifier(node) {
        if (node.text) failures.push(sourceFile);
    }
    function visit(node) {
        if (node.moduleSpecifier) checkSpecifier(node.moduleSpecifier);
    }
    visit(sourceFile);
}
"#);
    validate_plan(&plan).unwrap();
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.read")
    );
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "limit_saturated")
    );
}

#[test]
fn reachable_unknown_members_keep_callbacks_and_modeled_effects() {
    for source in [
        "require('fs').unmodeledMember(() => require('fs').unlinkSync('/callback'));",
        "require('net').connect(80); require('fs').unlinkSync('/callback');",
        "process.on('exit', () => require('fs').unlinkSync('/callback'));",
        "try { unknown(); } catch (e) { require('fs').unlinkSync('/callback'); } finally { require('fs').writeFileSync('/cleanup', 'x'); }",
        "const path = unknown; path.join(); require('fs').unlinkSync('/callback');",
        "require('child_process').unknownMember(); require('fs').unlinkSync('/callback');",
        "require('path').unknownMember(); require('fs').unlinkSync('/callback');",
        "require('fs').writeFileSync('/missing-data'); require('fs').unlinkSync('/callback');",
        "require('util').unknownMember(); require('fs').unlinkSync('/callback');",
        "using cleanup = resource; require('fs').unlinkSync('/callback');",
        "Math[operation](); require('fs').unlinkSync('/callback');",
    ] {
        let plan = js(source);
        assert!(
            has(&plan, "filesystem.delete", "/callback"),
            "{source}: {plan:?}"
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unresolved_call" && !b.provenance.is_empty()),
            "{source}: {plan:?}"
        );
        assert!(!plan.coverage.is_full(&Domain::new("filesystem")));
        assert!(!ops(&plan).contains(&"process.exec"));
    }
    for (source, module, symbol) in [
        (
            "const fs = require('fs'); fs.readdirSync('/a');",
            "fs",
            "readdirSync",
        ),
        (
            "require('child_process').fork('/x');",
            "child_process",
            "fork",
        ),
        (
            "const cp = require('child_process'); cp.fork('/x');",
            "child_process",
            "fork",
        ),
        ("require('net').connect(80);", "net", "connect"),
        ("require('fs')['realpathSync']('/a');", "fs", "realpathSync"),
        (
            "const fs = require('node:fs'); fs['unknownMember']();",
            "fs",
            "unknownMember",
        ),
        (
            "import fs from 'fs'; fs.readdirSync('/a');",
            "fs",
            "default.readdirSync",
        ),
        (
            "import { readdirSync } from 'fs'; readdirSync('/a');",
            "fs",
            "readdirSync",
        ),
    ] {
        let plan = js(source);
        validate_plan(&plan).unwrap();
        assert!(
            plan.boundaries.iter().any(|boundary| {
                boundary.reason.as_str() == "unresolved_call"
                    && boundary
                        .callee
                        .as_ref()
                        .is_some_and(|callee| callee.module == module && callee.symbol == symbol)
                    && !boundary.provenance.is_empty()
                    && boundary
                        .domains
                        .iter()
                        .any(|domain| domain.0 == "filesystem")
                    && boundary.domains.iter().any(|domain| domain.0 == "network")
            }),
            "{source}: {plan:?}"
        );
    }
    for source in [
        "require('fs')[operation]('/a');",
        "const fs = require('fs'); fs.readdirSync = unknown; fs.readdirSync('/a');",
        "const require = loader; require('fs').unmodeledMember();",
    ] {
        let plan = js(source);
        validate_plan(&plan).unwrap();
        assert!(has_boundary(&plan, "unresolved_call"));
        assert!(
            plan.boundaries
                .iter()
                .all(|boundary| boundary.callee.is_none()),
            "{source}: {plan:?}"
        );
    }
    let shadowed = js(
        "const fs = require('fs'); function run(fs) { fs.unlinkSync('/false'); } run(receiver);",
    );
    assert!(!has(&shadowed, "filesystem.delete", "/false"));
    assert!(has_boundary(&shadowed, "unresolved_call"));
    assert!(
        shadowed
            .boundaries
            .iter()
            .all(|boundary| boundary.callee.is_none())
    );
    let fork = js("require('child_process').fork('/child.js');");
    assert!(ops(&fork).contains(&"process.exec"));
    assert!(
        fork.boundaries
            .iter()
            .any(|b| b.domains.iter().any(|d| d.0 == "filesystem"))
    );
    let plan = js(
        "require('fs').unlinkSync('/modeled'); export function unused() { require('fs').unlinkSync('/uncalled'); }",
    );
    assert!(has(&plan, "filesystem.delete", "/modeled"));
    assert!(!has(&plan, "filesystem.delete", "/uncalled"));
    assert!(plan.coverage.is_full(&Domain::new("filesystem")));
}

#[test]
fn fs_link_symlink_and_truncate_sync() {
    let plan = js(r#"
        const fs = require('fs');
        fs.linkSync('/home/u/.ssh/id_rsa', '/tmp/key');
        fs.symlinkSync('/tmp/target', '/home/u/.bashrc');
        fs.truncateSync('/home/u/.profile');
        fs.promises.link('/srv/a', '/srv/b');
        fs.promises.symlink('/srv/c', '/srv/d');
    "#);
    assert!(has(&plan, "filesystem.create", "/tmp/key"));
    assert!(has(&plan, "filesystem.read", "/home/u/.ssh/id_rsa"));
    assert!(has(&plan, "filesystem.create", "/home/u/.bashrc"));
    assert!(!has(&plan, "filesystem.read", "/tmp/target"));
    assert!(has(&plan, "filesystem.write", "/home/u/.profile"));
    assert!(has(&plan, "filesystem.create", "/srv/b"));
    assert!(has(&plan, "filesystem.create", "/srv/d"));
    assert!(
        plan.effects
            .iter()
            .filter(|effect| effect.attributes.contains_key("symlink"))
            .count()
            == 2
    );
    assert!(plan.coverage.is_full(&Domain::new("filesystem")));
}

#[test]
fn shadowed_require_is_not_the_node_loader() {
    for source in [
        "const require = () => ({ rmSync() {} }); require('fs').rmSync('/', { recursive: true });",
        "function require() { return { rmSync() {} }; } const fs = require('fs'); fs.rmSync('/etc');",
        "const require = loader; const { rmSync } = require('fs'); rmSync('/etc');",
    ] {
        let plan = js(source);
        assert!(
            !ops(&plan).contains(&"filesystem.delete"),
            "{source}: {plan:?}"
        );
    }
    let plan = js("function load(require) { return require; } require('fs').rmSync('/etc');");
    assert!(has(&plan, "filesystem.delete", "/etc"));
}

#[test]
fn process_chdir_sets_the_child_cwd() {
    let plan = js(
        "process.chdir('/'); require('child_process').execSync('rm -rf etc'); require('fs').rmSync('var', { recursive: true });",
    );
    assert!(has(&plan, "filesystem.delete", "/etc"), "{plan:?}");
    assert!(has(&plan, "filesystem.delete", "/var"), "{plan:?}");
    assert!(!has_boundary(&plan, "unresolved_call"), "{plan:?}");

    let plan = js(
        "const target = 'etc'; process.chdir('/srv'); process.chdir('..'); require('fs').rmSync(target, { recursive: true });",
    );
    assert!(has(&plan, "filesystem.delete", "/etc"), "{plan:?}");

    // A chdir the walk cannot pin to one directory stays unresolved.
    for source in [
        "if (flag) process.chdir('/'); require('child_process').execSync('rm -rf etc');",
        "for (const d of dirs) process.chdir(d); require('child_process').execSync('rm -rf etc');",
        "function enter() { process.chdir('/'); } enter(); require('child_process').execSync('rm -rf etc');",
        "process.chdir(dir); require('child_process').execSync('rm -rf etc');",
    ] {
        let plan = js(source);
        assert!(has_boundary(&plan, "unresolved_call"), "{source}: {plan:?}");
        assert!(
            !has(&plan, "filesystem.delete", "/etc"),
            "{source}: {plan:?}"
        );
    }
}

/// Whether a path leaves its environment value unknown: some part is
/// unresolved and no part is a variable the host would fill in.
fn leaves_environment_unknown(resource: &ResourceExpr) -> bool {
    match resource {
        ResourceExpr::Unresolved { .. } => true,
        ResourceExpr::Join { parts } => {
            parts
                .iter()
                .any(|part| matches!(part, ResourceExpr::Unresolved { .. }))
                && !parts
                    .iter()
                    .any(|part| matches!(part, ResourceExpr::Environment { .. }))
        }
        _ => false,
    }
}

/// `atob` is the base64 decoder only while the program has not bound the name
/// itself. A block's own binding hides the global inside that block and inside
/// functions the block defines, and nowhere else.
#[test]
fn block_scoped_atob_is_not_the_base64_decoder() {
    let decodes = |source: &str| {
        js(source)
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "process.stream_transform")
    };
    for local in [
        r#"{ const atob = (text) => text; eval(atob("console.log(1)")) }"#,
        r#"function f() { { const atob = (t) => t; eval(atob("console.log(1)")) } } f()"#,
        r#"{ const atob = (t) => t; function g() { eval(atob("console.log(1)")) } g() }"#,
    ] {
        assert!(!decodes(local), "{local}");
    }
    for global in [
        r#"{ const x = 1; eval(atob("Y29uc29sZS5sb2coMSk=")) }"#,
        r#"{ const atob = (t) => t; } eval(atob("Y29uc29sZS5sb2coMSk="))"#,
        r#"function g() { eval(atob("Y29uc29sZS5sb2coMSk=")) } { const atob = (t) => t; g() }"#,
    ] {
        assert!(decodes(global), "{global}");
    }
}
