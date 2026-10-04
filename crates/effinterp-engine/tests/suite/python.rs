use effinterp_engine::{Engine, ValueArgument, default_limits, python_external_method_effects};
use effinterp_proto::{
    AttrValue, BoundaryClass, CoverageLevel, Domain, Plan, ResourceExpr, ResourceIdentity, Subject,
    validate_plan,
};

fn py(source: &str) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Source {
            dialect: None,
            language: "python".into(),
            source: source.to_string(),
            cwd: Some("/work".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));
    plan
}

fn py_with_causality(source: &str) -> Plan {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Source {
            dialect: None,
            language: "python".into(),
            source: source.to_string(),
            cwd: Some("/work".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));
    plan
}

fn pyexec(source: &str) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: vec!["python3".to_string(), "-c".to_string(), source.to_string()],
            cwd: Some("/work".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));
    plan
}

fn ops(plan: &Plan) -> Vec<(&str, String)> {
    plan.effects
        .iter()
        .map(|e| (e.operation.0.as_str(), render(&e.resource)))
        .collect()
}

fn render(expr: &ResourceExpr) -> String {
    match expr {
        ResourceExpr::Concrete { identity } => match identity {
            ResourceIdentity::FsPath { path } => path.clone(),
            ResourceIdentity::Process { executable, .. } => executable.clone(),
            ResourceIdentity::NetworkEndpoint { host, .. } => host.clone(),
            ResourceIdentity::EnvironmentVariable { name } => format!("${name}"),
            _ => "concrete".to_string(),
        },
        ResourceExpr::Parameter { name } => format!("<{name}>"),
        ResourceExpr::Environment { name } => format!("${name}"),
        ResourceExpr::Join { .. } => "join".to_string(),
        ResourceExpr::Unresolved { family } => format!("?{}", family.0),
        other => format!("{other:?}"),
    }
}

fn has(plan: &Plan, op: &str, resource: &str) -> bool {
    ops(plan).iter().any(|(o, r)| *o == op && r == resource)
}

fn code_source(plan: &Plan) -> Option<&str> {
    plan.effects
        .iter()
        .find(|effect| effect.operation.0 == "process.code_execution")
        .and_then(|effect| effect.attributes.get("source"))
        .and_then(|value| match value {
            effinterp_proto::AttrValue::String(value) => Some(value.as_str()),
            _ => None,
        })
}

fn has_boundary(plan: &Plan, reason: &str) -> bool {
    plan.boundaries.iter().any(|b| b.reason.as_str() == reason)
}

fn process_cwd<'a>(plan: &'a Plan, executable: &str) -> Option<&'a ResourceExpr> {
    plan.effects
        .iter()
        .find_map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable: name,
                        cwd,
                        ..
                    },
            } if name == executable => cwd.as_deref(),
            _ => None,
        })
}

fn is_fs_path(resource: Option<&ResourceExpr>, expected: &str) -> bool {
    matches!(
        resource,
        Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        }) if path == expected
    )
}

fn one_effect<'a>(plan: &'a Plan, operation: &str) -> &'a effinterp_proto::Effect {
    let effects: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == operation)
        .collect();
    assert_eq!(effects.len(), 1, "{operation}: {:?}", plan.effects);
    effects[0]
}

fn assert_no_untyped_resource(plan: &Plan) {
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "untyped_resource")
    );
}

#[test]
fn relative_and_empty_http_urls_are_unresolved_network_resources() {
    for source in [
        "import requests\nrequests.get(\"/api/x\")",
        "import requests\nrequests.get(\"\")",
        "from urllib.request import urlopen\nurlopen(\"/x\")",
        "import httpx\nc = httpx.Client(base_url=\"https://api.example.com\")\nc.get(\"/health\")",
    ] {
        let plan = py(source);
        assert!(matches!(
            &one_effect(&plan, "network.request").resource,
            ResourceExpr::Unresolved { family } if family.0 == "network"
        ));
        assert_no_untyped_resource(&plan);
    }
}

#[test]
fn unix_socket_connect_uses_the_path_as_a_unix_endpoint() {
    for source in [
        "import socket\ns=socket.socket(socket.AF_UNIX); s.connect(\"/tmp/x.sock\")",
        "from socket import socket, AF_UNIX\ns=socket(family=AF_UNIX); s.connect(\"/tmp/x.sock\")",
    ] {
        let plan = py(source);
        assert!(matches!(
            &one_effect(&plan, "network.request").resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint {
                    host,
                    scheme: Some(scheme),
                    port: None,
                    path: None,
                },
            } if host == "/tmp/x.sock" && scheme == "unix"
        ));
        assert_no_untyped_resource(&plan);
    }

    let inet = py("import socket\ns=socket.socket(socket.AF_INET); s.connect((\"h\", 80))");
    assert!(matches!(
        &one_effect(&inet, "network.request").resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                host,
                scheme: None,
                port: Some(80),
                path: None,
            },
        } if host == "h"
    ));
    assert_no_untyped_resource(&inet);
}

#[test]
fn no_entry_point_distinguishes_unreached_python_callables() {
    let declarations = "import shutil\nclass Storage:\n    def __init__(self, root):\n        self.root = root\n        self.purge(root)\n    def purge(self, root):\n        shutil.rmtree(root)\n";
    let plan = py(declarations);
    let boundary = plan
        .boundaries
        .iter()
        .find(|boundary| boundary.reason.as_str() == "no_entry_point")
        .expect("declaration-only Python has no execution root");
    assert_eq!(boundary.class, BoundaryClass::Unresolved);
    assert_eq!(
        boundary.detail.as_deref(),
        Some(
            "no execution root reached; declared callables not executed: Storage.__init__, Storage.purge"
        )
    );
    assert!(boundary.callee.is_none());
    for domain in ["environment", "filesystem", "network", "process"] {
        assert_eq!(
            plan.coverage.0[&Domain::new(domain)].level,
            CoverageLevel::Partial
        );
    }
    assert!(has_boundary(&pyexec(declarations), "no_entry_point"));

    let reached = py(&format!("{declarations}\nStorage('/tmp/cache')\n"));
    assert!(has(&reached, "filesystem.delete", "/tmp/cache"));
    assert!(!has_boundary(&reached, "no_entry_point"));

    // Uncalled bodies must not spend the invocation budget before main runs.
    let mut large = String::from("import os\ndef giant():\n");
    large.push_str(&"    x = 1\n".repeat(5000));
    for index in 0..20_000 {
        large.push_str(&format!(
            "def unused_{index}():\n    x = 1\n    return x\n\n"
        ));
    }
    large.push_str("def main():\n    os.remove('/root-reached')\nmain()\n");
    let reached = py(&large);
    assert!(has(&reached, "filesystem.delete", "/root-reached"));
    assert!(!has_boundary(&reached, "no_entry_point"));
    assert!(!has_boundary(&reached, "limit_saturated"));

    // A called giant body gets a local cap, leaving the following call reachable.
    let called = large.replace("main()\n", "giant()\nmain()\n").replacen(
        &"    x = 1\n".repeat(5000),
        &"    unknown()\n".repeat(5000),
        1,
    );
    let reached = py(&called);
    assert!(has(&reached, "filesystem.delete", "/root-reached"));
    assert!(!has_boundary(&reached, "no_entry_point"));
    let limit = reached
        .boundaries
        .iter()
        .find(|boundary| boundary.limit.as_deref() == Some("max_python_nodes"))
        .unwrap();
    assert_eq!(limit.detail.as_deref(), Some("giant"));
    assert!(!limit.provenance.is_empty());

    // Passing a callable to an unmodeled external API does not prove invocation.
    let external = py(&large.replace("main()\n", "import external\nexternal.register(main)\n"));
    assert!(!has_boundary(&external, "limit_saturated"));
    assert!(!has(&external, "filesystem.delete", "/root-reached"));
    assert!(external.boundaries.iter().any(|boundary| {
        boundary
            .callee
            .as_ref()
            .is_some_and(|callee| callee.module == "external" && callee.symbol == "register")
    }));

    let top_level = py("import os\ndef clean():\n    os.remove('/unreached')\nos.remove('/top')\n");
    assert!(has(&top_level, "filesystem.delete", "/top"));
    assert!(!has_boundary(&top_level, "no_entry_point"));
    assert!(!has_boundary(&py(""), "no_entry_point"));
}

// Regression: framework-owned handlers are execution roots even when no
// source-written call reaches them; lookalike declarations remain dormant.
#[test]
fn framework_handlers_are_import_grounded_roots() {
    let cases = [
        (
            "from django.core.management.base import BaseCommand\nimport os\nclass Command(BaseCommand):\n    def handle(self, *args):\n        os.remove('/django')\n",
            "/django",
        ),
        (
            "import click, os\n@click.command()\ndef clean(path):\n    os.remove(path)\n",
            "<path>",
        ),
        (
            "from typer import Typer\nimport os\napp = Typer()\n@app.command()\ndef clean():\n    os.remove('/typer')\n",
            "/typer",
        ),
        (
            "from flask import Flask\nimport os\napp = Flask(__name__)\n@app.route('/clean')\ndef clean():\n    os.remove('/flask')\n",
            "/flask",
        ),
        (
            "from fastapi import FastAPI\nimport os\napp = FastAPI()\n@app.get('/clean')\ndef clean():\n    os.remove('/fastapi')\n",
            "/fastapi",
        ),
        (
            "from fastapi import APIRouter as Router\nimport os\nrouter = Router()\ndef clean(): os.remove('/fastapi-direct')\nrouter.add_api_route('/clean', clean, methods=['DELETE'])\n",
            "/fastapi-direct",
        ),
        (
            "from fastapi import APIRouter as Router\nimport os\nrouter = Router()\nclass Routes:\n    @router.get('/class')\n    def clean(self): os.remove('/fastapi-class')\n",
            "/fastapi-class",
        ),
        (
            "from fastapi import FastAPI\nimport os\napp = FastAPI()\nif os.environ.get('ENABLED'):\n    @app.get('/conditional')\n    async def clean(): os.remove('/fastapi-conditional')\n",
            "/fastapi-conditional",
        ),
        (
            "import os\ntry:\n    from fastapi import FastAPI\nexcept ImportError:\n    FastAPI = None\napp = FastAPI()\n@app.get('/clean')\ndef clean(): os.remove('/fastapi-try-import')\n",
            "/fastapi-try-import",
        ),
        (
            "import os\nif True:\n    from fastapi import APIRouter as Router\napp = Router()\n@app.get('/clean')\ndef clean(): os.remove('/fastapi-if-import')\n",
            "/fastapi-if-import",
        ),
        (
            "import os\nwith context():\n    import fastapi as api\napp = api.FastAPI()\n@app.get('/clean')\ndef clean(): os.remove('/fastapi-with-import')\n",
            "/fastapi-with-import",
        ),
        (
            "from fastapi import FastAPI\nimport os\napp = FastAPI()\napp.state.ready = True\napp.dependency_overrides[object] = None\n@app.delete('/clean')\ndef clean(): os.remove('/fastapi-members')\n",
            "/fastapi-members",
        ),
        (
            "from fastapi import APIRouter\nimport os\nrouter = APIRouter(prefix='/local')\nrouter.prefix = unknown\n@router.delete('/clean')\ndef clean(): os.remove('/fastapi-prefix-write')\n",
            "/fastapi-prefix-write",
        ),
        (
            "import click, os\n@click.group()\ndef cli(): pass\n@cli.command()\ndef clean():\n    os.remove('/click-group')\n",
            "/click-group",
        ),
    ];
    for (source, path) in cases {
        let plan = py(source);
        assert!(has(&plan, "filesystem.delete", path), "{source}");
        assert!(!has_boundary(&plan, "no_entry_point"), "{source}");
    }

    let lookalike = py(
        "import os\nclass BaseCommand: pass\nclass Command(BaseCommand):\n    def handle(self):\n        os.remove('/dormant')\n",
    );
    assert!(!has(&lookalike, "filesystem.delete", "/dormant"));
    assert!(has_boundary(&lookalike, "no_entry_point"));
}

#[test]
fn os_remove_end_to_end_via_pyexec() {
    let plan = pyexec("import os\nos.remove('/tmp/x')");
    assert!(has(&plan, "process.exec", "python3"));
    assert!(has(&plan, "filesystem.delete", "/tmp/x"));
    // Python startup configuration affects only the environment domain.
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Full
    );
    assert_eq!(
        plan.coverage.0[&Domain::new("environment")].level,
        CoverageLevel::Partial
    );
    assert!(!has_boundary(&plan, "frontend_partial"));

    let source = py("import os\nos.remove('/tmp/x')");
    assert!(has_boundary(&source, "frontend_partial"));
    assert_eq!(
        source.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Partial
    );

    let unbound = pyexec("import os\nos.remove(target)");
    assert!(has_boundary(&unbound, "frontend_partial"));
    assert_eq!(
        unbound.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Partial
    );
}

/// A summary that reaches its effect cap must say so at the call site: the
/// effects it left out would otherwise read as a fully covered function.
#[test]
fn summary_past_its_effect_cap_leaves_a_limit_boundary() {
    let mut source = String::from("import os, shutil\ndef clean():\n");
    for index in 0..1024 {
        source.push_str(&format!("    os.remove('/tmp/cache/f{index}')\n"));
    }
    source.push_str("    shutil.rmtree('/etc')\nclean()\n");
    let plan = py(&source);
    assert!(has(&plan, "filesystem.delete", "/tmp/cache/f1023"));
    assert!(!has(&plan, "filesystem.delete", "/etc"));
    let limit = plan
        .boundaries
        .iter()
        .find(|boundary| boundary.limit.as_deref() == Some("max_summary_effects"))
        .unwrap();
    assert_eq!(limit.class, BoundaryClass::Limit);
    assert_eq!(limit.domains, vec![Domain::new("filesystem")]);
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Partial
    );
}

#[test]
fn open_modes_map_to_read_write_append() {
    assert!(has(&py("open('/a')"), "filesystem.read", "/a"));
    assert!(has(&py("open('/a','w')"), "filesystem.write", "/a"));
    // A mode whose every part is known is that mode, however it is spelled.
    for source in [
        "mode = 'w'\nopen('/a', mode)",
        "open('/a', f'w')",
        "open('/a', 'w' + 'b')",
        "mode = f'w'\nopen('/a', mode)",
        "mode = 'w' + 'b'\nopen('/a', mode)",
        "kind = 'w'\nopen('/a', kind + 'b')",
    ] {
        let known = py(source);
        assert!(has(&known, "filesystem.write", "/a"), "{source}");
        assert!(!has(&known, "filesystem.read", "/a"), "{source}");
    }
    // A mode with an unknown part decides nothing; it must not read as "r".
    for source in [
        "import sys\nopen('/a', sys.argv[1])",
        "import sys\nopen('/a', 'w' + sys.argv[1])",
    ] {
        let unknown = py(source);
        assert!(unknown.effects.is_empty(), "{source}");
        assert!(has_boundary(&unknown, "unmodeled_dynamic"), "{source}");
        assert_eq!(
            unknown.coverage.0[&Domain::new("filesystem")].level,
            CoverageLevel::Partial,
            "{source}"
        );
    }
    let append = py("open('/a','a')");
    assert!(has(&append, "filesystem.write", "/a"));
    assert!(
        append
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.write" && e.attributes.contains_key("append"))
    );
    let plus = py("open('/a','r+')");
    assert!(has(&plus, "filesystem.read", "/a"));
    assert!(has(&plus, "filesystem.write", "/a"));
    assert_eq!(
        plus.effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.read")
            .unwrap()
            .attributes
            .get("access_purpose"),
        Some(&AttrValue::String("program_input".into()))
    );
    // mode via keyword.
    assert!(has(&py("open('/a', mode='w')"), "filesystem.write", "/a"));
}

#[test]
fn relative_path_resolves_against_cwd() {
    assert!(has(
        &py("open('out.txt','w')"),
        "filesystem.write",
        "/work/out.txt"
    ));
}

#[test]
fn generic_source_without_cwd_keeps_relative_paths_symbolic() {
    let plan = Engine::new()
        .analyze(&Subject::Source {
            dialect: None,
            language: "python".to_string(),
            source: "import os\nos.remove('data/x.txt')".to_string(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .expect("a delete effect");
    let ResourceExpr::Join { parts } = &delete.resource else {
        panic!("expected symbolic cwd join, got {:?}", delete.resource);
    };
    assert!(matches!(
        parts.as_slice(),
        [
            ResourceExpr::Parameter { name },
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            }
        ] if name == "cwd" && path == "data/x.txt"
    ));
}

#[test]
fn non_literal_path_stays_symbolic() {
    let plan = py("import os\np = input()\nos.remove(p)");
    assert!(has(&plan, "filesystem.delete", "<p>"));
}

#[test]
fn aliased_import_is_owned() {
    let plan = py("import subprocess as sp\nsp.run(['rm','/x'])");
    assert!(has(&plan, "process.exec", "rm"));
    assert!(has(&plan, "filesystem.delete", "/x"));
}

#[test]
fn from_import_is_owned() {
    let plan = py("from os import remove\nremove('/x')");
    assert!(has(&plan, "filesystem.delete", "/x"));
}

#[test]
fn shadowing_removes_ownership() {
    // `os` rebound to something else: os.remove is no longer the stdlib call.
    let plan = py("import os\nos = object()\nos.remove('/x')");
    assert!(!has(&plan, "filesystem.delete", "/x"));
}

#[test]
fn unknown_object_attribute_is_not_an_effect() {
    // A matching method name on an untracked object establishes nothing.
    let plan = py("thing.remove('/x')");
    assert!(plan.effects.is_empty());
}

#[test]
fn subprocess_list_nests_exec() {
    let plan = py("import subprocess\nsubprocess.run(['rm','-rf','/data'])");
    assert!(has(&plan, "process.exec", "rm"));
    assert!(has(&plan, "filesystem.delete", "/data"));
    assert!(plan.execution_graph.nodes.iter().any(|n| matches!(
        &n.subject,
        Subject::Exec { argv, .. } if argv.first().map(String::as_str) == Some("rm")
    )));
}

#[test]
fn subprocess_shell_true_nests_shell() {
    let plan = py("import subprocess\nsubprocess.run('rm -rf /data', shell=True)");
    assert!(has(&plan, "filesystem.delete", "/data"));
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .any(|n| matches!(&n.subject, Subject::Shell { .. }))
    );
}

#[test]
fn subprocess_shell_executable_replaces_the_shell() {
    let plan =
        py("import subprocess\nsubprocess.run('rm -rf /data', shell=True, executable='/bin/echo')");
    assert!(!has(&plan, "filesystem.delete", "/data"));
    assert!(plan.execution_graph.nodes.iter().any(|n| matches!(
        &n.subject,
        Subject::Exec { argv, .. } if argv == &["/bin/echo", "-c", "rm -rf /data"]
    )));
    let plan =
        py("import subprocess\nsubprocess.run('rm -rf /data', shell=True, executable='/bin/bash')");
    assert!(has(&plan, "filesystem.delete", "/data"));
}

#[test]
fn posix_spawn_file_actions_stay_bounded_through_keyword_expansion() {
    let bounded = |source: &str| {
        py(source).boundaries.iter().any(|boundary| {
            boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("file_actions"))
        })
    };
    let actions = "[(os.POSIX_SPAWN_OPEN, 1, '/etc/passwd', os.O_WRONLY | os.O_TRUNC, 0)]";
    for call in [
        format!("file_actions={actions}"),
        format!("**{{'file_actions': {actions}}}"),
        "**options".to_string(),
    ] {
        assert!(
            bounded(&format!(
                "import os\nos.posix_spawn('/usr/bin/true', ['true'], {{}}, {call})"
            )),
            "{call}"
        );
    }
    assert!(!bounded(
        "import os\nos.posix_spawn('/usr/bin/true', ['true'], {}, **{'setsid': True})"
    ));
}

#[test]
fn asyncio_subprocess_cwd_is_inherited_when_the_coroutine_runs() {
    // Each coroutine is made in /work but runs after `os.chdir('/etc')`, so
    // its relative operand must not resolve against the creation directory.
    // A relative `cwd=` joins onto that later directory, and a scheduled
    // coroutine runs only once the caller yields.
    let scheduled = |schedule: &str| {
        format!(
            "import asyncio, os\nasync def main():\n    t = {schedule}(asyncio.create_subprocess_exec('rm', '-f', 'passwd'))\n    os.chdir('/etc')\n    await t\nasyncio.run(main())"
        )
    };
    for source in [
        "import asyncio, os\nc = asyncio.create_subprocess_exec('rm', '-f', 'passwd')\nos.chdir('/etc')\nasyncio.run(c)".to_string(),
        "import asyncio, os\nc = asyncio.create_subprocess_shell('rm -f passwd')\nos.chdir('/etc')\nasyncio.run(c)".to_string(),
        "import asyncio, os\nc = asyncio.create_subprocess_exec('rm', '-f', 'passwd', cwd='.')\nos.chdir('/etc')\nasyncio.run(c)".to_string(),
        "import asyncio, os\nc = asyncio.create_subprocess_shell('rm -f passwd', cwd='.')\nos.chdir('/etc')\nasyncio.run(c)".to_string(),
        scheduled("asyncio.create_task"),
        scheduled("asyncio.ensure_future"),
        scheduled("asyncio.gather"),
        // A bound path was resolved when it was bound, not when the child
        // launches.
        "import asyncio, os\nfrom pathlib import Path\nd = Path('.')\nc = asyncio.create_subprocess_exec('rm', '-f', 'passwd', cwd=d)\nos.chdir('/etc')\nasyncio.run(c)".to_string(),
        "import asyncio, os\nd = '.'\nc = asyncio.create_subprocess_exec('rm', '-f', 'passwd', cwd=d)\nos.chdir('/etc')\nasyncio.run(c)".to_string(),
        "import asyncio, os\nfrom pathlib import Path\nc = asyncio.create_subprocess_exec('rm', '-f', 'passwd', cwd=Path('.'))\nos.chdir('/etc')\nasyncio.run(c)".to_string(),
    ] {
        let plan = py(&source);
        assert!(has_op(&plan, "filesystem.delete"), "{source}");
        assert!(!has(&plan, "filesystem.delete", "/work/passwd"), "{source}");
        assert!(
            plan.boundaries.iter().any(|boundary| boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("directory it inherits is unresolved"))),
            "{source}"
        );
    }
    for cwd in ["'/etc'", "Path('/etc')"] {
        let plan = py(&format!(
            "import asyncio, os\nfrom pathlib import Path\nc = asyncio.create_subprocess_exec('rm', '-f', 'passwd', cwd={cwd})\nos.chdir('/tmp')\nasyncio.run(c)"
        ));
        assert!(has(&plan, "filesystem.delete", "/etc/passwd"), "{cwd}");
    }
}

#[test]
fn subprocess_explicit_cwd_controls_processes_and_nested_effects() {
    for source in [
        "import subprocess\nsubprocess.run(['rm', 'relative'], cwd='/repo')",
        "import subprocess\nsubprocess.run('rm relative', shell=True, cwd='/repo')",
    ] {
        let plan = py(source);
        assert!(is_fs_path(process_cwd(&plan, "rm"), "/repo"));
        assert!(has(&plan, "filesystem.delete", "/repo/relative"));
        assert!(!has(&plan, "filesystem.delete", "/work/relative"));
    }
}

#[test]
fn every_subprocess_api_honors_explicit_cwd() {
    // `getoutput` and `getstatusoutput` take no `cwd=`.
    for api in ["run", "call", "check_call", "check_output", "Popen"] {
        let plan = py(&format!(
            "import subprocess\nsubprocess.{api}(['rm', 'relative'], cwd='/repo')"
        ));
        assert!(
            is_fs_path(process_cwd(&plan, "rm"), "/repo"),
            "{api} did not retain cwd"
        );
        assert!(
            has(&plan, "filesystem.delete", "/repo/relative"),
            "{api} did not use cwd for its nested effect"
        );
    }
}

#[test]
fn subprocess_cwd_resolves_str_path_values_and_summaries() {
    let path = py(
        "from pathlib import Path\nimport subprocess\nROOT = Path('/repo')\nsubprocess.run(['rm', 'relative'], cwd=str(ROOT))",
    );
    assert!(is_fs_path(process_cwd(&path, "rm"), "/repo"));
    assert!(has(&path, "filesystem.delete", "/repo/relative"));

    let summary = py(
        "import subprocess\ndef launch(root):\n    subprocess.run(['rm', 'relative'], cwd=root)\nlaunch('/repo')",
    );
    assert!(is_fs_path(process_cwd(&summary, "rm"), "/repo"));
}

#[test]
fn pathlib_multi_segment_paths_retain_every_component() {
    let plan = py(
        "from pathlib import Path\nimport subprocess\nopen(Path('/srv', 'data', 'in.txt'))\nsubprocess.run(['rm', 'relative'], cwd=Path('/repo', 'sub'))",
    );
    assert!(has(&plan, "filesystem.read", "/srv/data/in.txt"));
    assert!(is_fs_path(process_cwd(&plan, "rm"), "/repo/sub"));
    assert!(has(&plan, "filesystem.delete", "/repo/sub/relative"));
    assert!(!has(&plan, "filesystem.delete", "/repo/relative"));
}

#[test]
fn subprocess_cwd_negative_pairs_preserve_existing_behavior() {
    for source in [
        "import subprocess\nsubprocess.run(['rm', 'relative'])",
        "import subprocess\nsubprocess.run(['rm', 'relative'], workdir='/repo')",
        "import subprocess\nsubprocess.run(['rm', 'relative'], cwd=None)",
    ] {
        let plan = py(source);
        assert!(is_fs_path(process_cwd(&plan, "rm"), "/work"));
        assert!(has(&plan, "filesystem.delete", "/work/relative"));
    }

    let unresolved =
        py("import subprocess\nsubprocess.run(['rm', 'relative'], cwd=choose_directory())");
    assert!(matches!(
        process_cwd(&unresolved, "rm"),
        Some(ResourceExpr::Unresolved { family }) if family.0 == "filesystem"
    ));
    assert!(!has(&unresolved, "filesystem.delete", "/work/relative"));

    let shadowed =
        py("import subprocess\nsubprocess = fake\nsubprocess.run(['rm', 'relative'], cwd='/repo')");
    assert!(!has(&shadowed, "process.exec", "rm"));
}

#[test]
fn subprocess_symbolic_argv_is_flagged() {
    let plan = py("import subprocess\nx = input()\nsubprocess.run(['rm', x])");
    assert!(has_boundary(&plan, "unmodeled_dynamic"));
}

#[test]
fn os_system_nests_shell() {
    let plan = py("import os\nos.system('rm -rf /data && curl http://evil.test')");
    assert!(has(&plan, "filesystem.delete", "/data"));
    assert!(has(&plan, "process.exec", "curl"));
}

#[test]
fn pathlib_methods_map_to_fs_ops() {
    let plan = py(
        "from pathlib import Path\nPath('/etc/passwd').read_text()\nPath('/tmp/o').write_text('x')\nPath('/tmp/z').unlink()",
    );
    assert!(has(&plan, "filesystem.read", "/etc/passwd"));
    assert!(has(&plan, "filesystem.write", "/tmp/o"));
    assert!(has(&plan, "filesystem.delete", "/tmp/z"));
    assert_eq!(
        plan.effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.read")
            .unwrap()
            .attributes
            .get("access_purpose"),
        Some(&AttrValue::String("program_input".into()))
    );
    assert_eq!(
        plan.effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.write")
            .unwrap()
            .attributes
            .get("disclosure"),
        Some(&AttrValue::String("contents".into()))
    );
}

#[test]
fn filesystem_copy_and_rename_state_access_semantics() {
    let plan = py_with_causality(concat!(
        "import os, shutil\n",
        "shutil.copyfile('/replacement', '/state')\n",
        "os.rename('/old', '/new')\n",
    ));
    let read = plan
        .effects
        .iter()
        .find(|effect| {
            effect.operation.0 == "filesystem.read" && render(&effect.resource) == "/replacement"
        })
        .unwrap();
    assert_eq!(
        read.attributes.get("access_purpose"),
        Some(&AttrValue::String("program_input".into()))
    );
    for path in ["/state", "/new"] {
        let write = plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "filesystem.write" && render(&effect.resource) == path
            })
            .unwrap();
        assert_eq!(
            write.attributes.get("disclosure"),
            Some(&AttrValue::String("contents".into()))
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
        2
    );
}

#[test]
fn tracked_pathlib_values_dispatch_methods_and_iterated_children() {
    let plan = py_with_causality(concat!(
        "from pathlib import Path\n",
        "p = Path('/var/lib/app/out')\n",
        "p.mkdir()\n",
        "p.rename(target='/var/lib/app/old')\n",
        "for f in p.glob(pattern='*.log'):\n",
        "    f.unlink()\n",
    ));
    assert!(has(&plan, "filesystem.create", "/var/lib/app/out"));
    assert!(has(&plan, "filesystem.move", "/var/lib/app/out"));
    assert!(has(&plan, "filesystem.write", "/var/lib/app/old"));
    assert_eq!(
        plan.effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "filesystem.write"
                    && render(&effect.resource) == "/var/lib/app/old"
            })
            .unwrap()
            .attributes
            .get("disclosure"),
        Some(&AttrValue::String("contents".into()))
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
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && matches!(&effect.resource, ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern } }
                if effinterp_proto::glob_match(pattern, "/var/lib/app/out/.hidden.log") == Ok(true))
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Join { parts }
                if matches!(parts.as_slice(), [
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    },
                    ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob } }
                ] if path == "/var/lib/app/out" && glob == "*.log"))
    }));
}

#[test]
fn chained_pathlib_assignment_keeps_receiver_value_flow() {
    for source in [
        concat!(
            "from pathlib import Path\n",
            "q = r = Path('/a/b')\n",
            "r.unlink()\n",
        ),
        concat!(
            "from pathlib import Path\n",
            "p = Path('/a/b')\n",
            "q = r = p\n",
            "r.unlink()\n",
        ),
        concat!(
            "from pathlib import Path\n",
            "def go():\n",
            "    q = r = Path('/a/b')\n",
            "    r.unlink()\n",
            "go()\n",
        ),
        concat!(
            "from pathlib import Path\n",
            "values = {}\n",
            "q = values['path'] = Path('/a/b')\n",
            "q.unlink()\n",
        ),
        concat!(
            "from pathlib import Path\n",
            "values = {}\n",
            "values['path'] = q = Path('/a/b')\n",
            "q.unlink()\n",
        ),
        concat!(
            "from pathlib import Path\n",
            "class Cache:\n",
            "    def clear(self):\n",
            "        self.path = path = Path('/a/b')\n",
            "        path.unlink()\n",
            "Cache().clear()\n",
        ),
    ] {
        let plan = py(source);
        assert!(
            has(&plan, "filesystem.delete", "/a/b"),
            "{source:?} => {:#?}",
            plan.effects
        );
    }

    let widened = py(concat!(
        "from pathlib import Path\n",
        "p = Path('/a/b')\n",
        "values = {}\n",
        "p = values['path'] = Path('/x') if condition else Path('/y')\n",
        "p.unlink()\n",
    ));
    assert!(has(&widened, "filesystem.delete", "?filesystem"));
    assert!(!has(&widened, "filesystem.delete", "/a/b"));
    assert_eq!(
        widened
            .boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        1
    );
}

#[test]
fn boolean_arguments_stay_unresolved_in_resource_positions() {
    let plan = py("def read(flag):\n    open(flag).read()\nread(True)");
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "filesystem")
    }));

    let method = py(concat!(
        "class Reader:\n",
        "    def mkdir(self, parents):\n",
        "        open(parents).read()\n",
        "Reader().mkdir(parents=True)\n",
    ));
    assert!(has(&method, "filesystem.read", "?filesystem"));
    assert!(!has(&method, "filesystem.read", "/work/true"));
}

#[test]
fn pathlib_constructor_arguments_keep_concrete_local_bindings() {
    let plan = py(concat!(
        "from pathlib import Path\n",
        "def read(path):\n",
        "    open(path).read()\n",
        "read(Path('/srv/data'))\n",
    ));
    assert!(has(&plan, "filesystem.read", "/srv/data"));
    assert!(!has(&plan, "filesystem.read", "?filesystem"));
}

#[test]
fn pathlib_producers_keep_symbolic_and_environment_roots() {
    let symbolic = py(concat!(
        "from pathlib import Path\n",
        "CACHE = Path(__file__).resolve().parent / '.cache'\n",
        "CACHE.mkdir(parents=True)\n",
        "(CACHE / 'x.json').write_text('1')\n",
    ));
    let create = symbolic
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.create")
        .expect("CACHE.mkdir is modeled");
    assert!(matches!(&create.resource, ResourceExpr::Join { parts }
        if matches!(parts.as_slice(), [
            ResourceExpr::Property { base, name },
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            }
        ] if name == "parent"
            && matches!(base.as_ref(), ResourceExpr::Parameter { name } if name == "__file__")
            && path == ".cache")));
    assert_eq!(
        create.attributes.get("parents"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    assert!(!has_boundary(&symbolic, "external_unmodeled"));

    let environment = py(concat!(
        "import os\n",
        "from pathlib import Path\n",
        "BASE = Path(os.environ['APP_HOME']) / 'data'\n",
        "(BASE / 'db.sqlite').unlink()\n",
    ));
    assert!(environment.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Join { parts }
                if matches!(parts.as_slice(), [
                    ResourceExpr::Environment { name },
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path: data }
                    },
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path: database }
                    }
                ] if name == "APP_HOME" && data == "data" && database == "db.sqlite"))
    }));
}

#[test]
fn pathlib_path_transformers_feed_effect_receivers() {
    let plan = py(concat!(
        "from pathlib import Path\n",
        "Path('~/.cache').expanduser().mkdir()\n",
        "Path.cwd().joinpath('output', 'result.txt').touch()\n",
        "Path('/tmp/report.txt').with_suffix('.log').unlink()\n",
        "Path('/tmp/report.txt').with_name('summary.txt').exists()\n",
        "Path('/tmp/report.txt').chmod(0o600)\n",
        "source = Path('/tmp/original.txt')\n",
        "renamed = source.with_name('renamed.txt')\n",
        "source.rename(renamed)\n",
    ));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.create"
            && matches!(&effect.resource, ResourceExpr::Join { parts }
                if matches!(parts.as_slice(), [
                    ResourceExpr::Environment { name },
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    }
                ] if name == "HOME" && path == ".cache"))
    }));
    assert!(has(&plan, "filesystem.write", "/work/output/result.txt"));
    assert!(has(&plan, "filesystem.delete", "/tmp/report.log"));
    assert!(has(&plan, "filesystem.write", "/tmp/renamed.txt"));
    let metadata_read = plan
        .effects
        .iter()
        .find(|effect| {
            effect.operation.0 == "filesystem.read"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/tmp/summary.txt")
        })
        .expect("exists reads metadata");
    assert_eq!(
        metadata_read.attributes.get("metadata"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    assert!(has(&plan, "filesystem.metadata", "/tmp/report.txt"));
}

#[test]
fn tracked_path_expanduser_preserves_the_tilde_origin() {
    let plan = py(concat!(
        "from pathlib import Path\n",
        "p = Path('~/x')\n",
        "p.expanduser().touch()\n",
    ));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.write"
            && matches!(&effect.resource, ResourceExpr::Join { parts }
                if matches!(parts.as_slice(), [
                    ResourceExpr::Environment { name },
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    }
                ] if name == "HOME" && path == "x"))
    }));

    let unexpanded = py(concat!(
        "from pathlib import Path\n",
        "p = Path('~/x')\n",
        "p.touch()\n",
    ));
    assert!(has(&unexpanded, "filesystem.write", "/work/~/x"));
}

#[test]
fn pathlib_absolute_components_reset_the_receiver() {
    let plan = py(concat!(
        "from pathlib import Path\n",
        "absolute = '/etc/hosts'\n",
        "(Path('/a') / '/etc/passwd').unlink()\n",
        "Path('/a').joinpath('discarded', '/etc/shadow').unlink()\n",
        "(Path('/a') / absolute).unlink()\n",
    ));
    for path in ["/etc/passwd", "/etc/shadow", "/etc/hosts"] {
        assert!(has(&plan, "filesystem.delete", path), "{:#?}", plan.effects);
    }
    assert!(plan.effects.iter().all(|effect| {
        !matches!(&effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if path.starts_with("/a/"))
    }));
}

#[test]
fn requests_and_urllib_are_network() {
    let plan = py("import requests\nrequests.get('https://api.test/v1/data')");
    assert!(has(&plan, "network.request", "api.test"));
    let post = py("import requests\nrequests.post('https://api.test/upload')");
    assert!(
        post.effects
            .iter()
            .any(|e| e.operation.0 == "network.upload")
    );
}

#[test]
fn string_concatenation_is_typed_by_its_effect_sink() {
    let filesystem = py(
        "import os\nos.remove(os.environ['HOME'] + '/.cache/x')\nos.remove(f\"{os.environ['HOME']}/.cache/y\")",
    );
    let deletes: Vec<_> = filesystem
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 2);
    assert!(deletes.iter().all(|effect| {
        matches!(&effect.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Environment { name },
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                }
            ] if name == "HOME" && path.starts_with("/.cache/")))
    }));
    assert!(!has_boundary(&filesystem, "unmodeled_dynamic"));

    let unanchored_filesystem = py(
        "import os\nos.remove(left + right)\nos.remove(f'{left}{right}')\njoined_plus = left + right\njoined_fstring = f'{left}{right}'\nos.remove(joined_plus)\nos.remove(joined_fstring)",
    );
    let unanchored_deletes: Vec<_> = unanchored_filesystem
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect();
    assert_eq!(unanchored_deletes.len(), 4);
    assert!(unanchored_deletes.iter().all(|effect| {
        matches!(&effect.resource, ResourceExpr::Unresolved { family }
            if family.0 == "filesystem")
    }));
    assert!(!has_boundary(&unanchored_filesystem, "unmodeled_dynamic"));

    let network = py(
        "import requests\nbase = 'https://graph.example'\nrequests.post(base + '/meta/auth?api_token=' + tok)\nrequests.get(f'https://api.example/items/{tok}')",
    );
    for operation in ["network.upload", "network.request"] {
        let effect = network
            .effects
            .iter()
            .find(|effect| effect.operation.0 == operation)
            .expect("network concatenation effect");
        assert!(matches!(&effect.resource, ResourceExpr::Join { parts }
        if matches!(parts.first(), Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { scheme: Some(scheme), .. }
        }) if scheme == "https")
            && parts.iter().all(|part| !matches!(part, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { .. }
            }))));
    }

    let unanchored = py("import requests\nrequests.get(left + right)");
    assert!(unanchored.effects.iter().any(|effect| {
        effect.operation.0 == "network.request"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "network")
    }));
}

#[test]
fn string_bindings_are_anchored_after_filesystem_concatenation() {
    let absolute = py(
        "import os\nUSER = 'alice'\nos.remove('/home/' + USER + '/logs/app.log')\nos.remove(f'/home/{USER}/logs/app.log')",
    );
    let deletes: Vec<_> = absolute
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 2, "{:?}", absolute.effects);
    assert!(deletes.iter().all(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if path == "/home/alice/logs/app.log"
    )));

    let relative = py("import os\nname = 'x.log'\nos.remove('logs/' + name)");
    assert!(has(&relative, "filesystem.delete", "/work/logs/x.log"));
}

#[test]
fn network_concatenation_is_typed_after_local_call_substitution() {
    for source in [
        "import requests\ndef fetch(base, token):\n    requests.get(base + '/v1/' + token)\nfetch('https://api.example', 'secret')",
        "import requests\ndef fetch(base):\n    requests.get(base + '/v1')\nbase = 'https://api.example'\nfetch(base)",
        "import requests\ndef fetch(url):\n    requests.get(url)\nfetch('https://api.example/' + token)",
        "import requests\ndef fetch(base, token):\n    requests.get(base + '/v1/' + token)\ndef run(base, token):\n    fetch(base, token)\nrun('https://api.example', 'secret')",
    ] {
        let plan = py(source);
        let effect = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.request")
            .expect("network request effect");
        assert!(
            matches!(
                &effect.resource,
                ResourceExpr::Join { parts }
                    if matches!(
                        parts.first(),
                        Some(ResourceExpr::Concrete {
                            identity: ResourceIdentity::NetworkEndpoint { host, scheme, .. }
                        }) if host == "api.example" && scheme.as_deref() == Some("https")
                    )
            ),
            "specialized network resource: {:?}",
            effect.resource
        );
    }

    let unanchored = py(
        "import requests\ndef fetch(left, right):\n    requests.get(left + right)\nfetch(left, right)",
    );
    assert!(unanchored.effects.iter().any(|effect| {
        effect.operation.0 == "network.request"
            && matches!(
                &effect.resource,
                ResourceExpr::Unresolved { family } if family.0 == "network"
            )
    }));
}

#[test]
fn filesystem_concatenation_preserves_environment_after_local_call_substitution() {
    let plan = py(
        "import os\ndef wipe_plus(base):\n    os.remove(base + '/.cache/x')\ndef wipe_fstring(base):\n    os.remove(f'{base}/.cache/y')\nwipe_plus(os.environ['HOME'])\nwipe_fstring(os.environ['HOME'])",
    );
    let deletes: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 2);
    assert!(deletes.iter().all(|effect| {
        matches!(&effect.resource, ResourceExpr::Join { parts }
            if matches!(parts.as_slice(), [
                ResourceExpr::Environment { name },
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                }
            ] if name == "HOME" && path.starts_with("/.cache/")))
    }));
    assert!(!has_boundary(&plan, "unmodeled_dynamic"));
}

#[test]
fn empty_string_does_not_anchor_filesystem_concatenation() {
    let plan = py("import os\nos.remove(left + '')");
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Unresolved { family } if family.0 == "filesystem"
            )
    }));
    assert!(!has_boundary(&plan, "unmodeled_dynamic"));
}

#[test]
fn unbounded_string_concatenation_keeps_its_boundary() {
    for source in [
        "import os\nos.remove(1 + '/cache')",
        "import os\nos.remove(build_path() + '/cache')",
        "import os\ncount = 1\nos.remove(f'{count}/cache')",
        "import os\npath = build_path()\nos.remove(path + '/cache')",
        "import os\nos.remove(f\"{os.environ['HOME']!r}/cache\")",
        "import os\nos.remove(f\"{os.environ['HOME']:>40}/cache\")",
    ] {
        let plan = py(source);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                    if family.0 == "filesystem")
        }));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
    }
}

#[test]
fn augmented_string_concatenation_updates_or_invalidates_binding() {
    let network =
        py("import requests\nurl = 'https://api.example' + ''\nurl += '/v1'\nrequests.get(url)");
    assert!(network.effects.iter().any(|effect| {
        effect.operation.0 == "network.request"
            && matches!(&effect.resource, ResourceExpr::Join { parts }
                if matches!(parts.first(), Some(ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { scheme: Some(scheme), .. }
                }) if scheme == "https")
                    && parts.iter().any(|part| matches!(part,
                        ResourceExpr::Literal { value } if value == "/v1")))
    }));

    let filesystem =
        py("import os\npath = os.environ['HOME'] + '/safe'\npath += build_path()\nos.remove(path)");
    assert!(filesystem.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "filesystem")
    }));
    assert!(has_boundary(&filesystem, "unmodeled_dynamic"));
}

#[test]
fn augmented_path_reassignment_widens_without_silence() {
    for (source, operation) in [
        (
            "from pathlib import Path\np = Path('/a')\np /= 'sub'\np.unlink()",
            "filesystem.delete",
        ),
        (
            concat!(
                "from pathlib import Path\n",
                "def go(base):\n",
                "    p = Path(base)\n",
                "    p /= 'sub'\n",
                "    p.write_text('x')\n",
                "go('/srv')\n",
            ),
            "filesystem.write",
        ),
        (
            concat!(
                "from pathlib import Path\n",
                "p = Path('/a') if condition else Path('/b')\n",
                "p /= 'sub'\n",
                "p.unlink()\n",
            ),
            "filesystem.delete",
        ),
    ] {
        let plan = py(source);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == operation
                && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                    if family.0 == "filesystem")
        }));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
                .count(),
            1
        );
    }
}

#[test]
fn augmented_reassignment_clears_stale_constructor_bindings() {
    let path = py(concat!(
        "import os\n",
        "from pathlib import Path\n",
        "def use(path):\n",
        "    os.remove(path)\n",
        "p = Path('/a')\n",
        "p /= 'sub'\n",
        "use(p)\n",
    ));
    assert!(path.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "filesystem")
    }));
    assert!(!has(&path, "filesystem.delete", "/a"));

    let instance = py(concat!(
        "import shutil\n",
        "class Storage:\n",
        "    def __init__(self, root):\n",
        "        self.root = root\n",
        "    def purge(self):\n",
        "        shutil.rmtree(self.root)\n",
        "s = Storage('/a')\n",
        "s += 1\n",
        "s.purge()\n",
    ));
    assert!(!has(&instance, "filesystem.delete", "/a"));
}

#[test]
fn rebindings_and_branch_disagreement_drop_stale_constructor_bindings() {
    let storage = concat!(
        "import os, shutil\n",
        "class Storage:\n",
        "    def __init__(self, root): self.root = root\n",
        "    def purge(self): shutil.rmtree(self.root)\n",
    );
    for body in [
        concat!(
            "def pool(): return []\n",
            "s = Storage('/a')\n",
            "for s in pool(): s.purge()\n",
        ),
        "s = Storage('/a')\nwith open('/tmp/x') as s: pass\ns.purge()\n",
        "s = Storage('/a')\ndef s(): pass\ns.purge()\n",
        "s = Storage('/a')\ndel s\ns.purge()\n",
        concat!(
            "def fallback(): return None\n",
            "if os.environ.get('X'):\n",
            "    s = Storage('/a')\n",
            "else:\n",
            "    s = fallback()\n",
            "s.purge()\n",
        ),
        concat!(
            "s = Storage('/a')\n",
            "if os.environ.get('X'):\n",
            "    s = fallback()\n",
            "s.purge()\n",
        ),
    ] {
        let plan = py(&format!("{storage}{body}"));
        assert!(!has(&plan, "filesystem.delete", "/a"));
        assert!(
            plan.boundaries.iter().any(|boundary| {
                boundary.reason == effinterp_proto::BoundaryReason::DYNAMIC_DISPATCH
                    && boundary.domains.contains(&Domain::new("filesystem"))
            }),
            "{body}: {:?}",
            plan.boundaries
        );
    }
}

#[test]
fn same_file_receiver_dispatch_survives_annotations_factories_and_module_scope() {
    let store = concat!(
        "import os\n",
        "class Store:\n",
        "    def purge(self): os.remove('/var/data/cache.db')\n",
    );
    for body in [
        "def cleanup(store: Store): store.purge()\ncleanup(Store())\n",
        "STORE = Store()\ndef main(): STORE.purge()\nmain()\n",
        "def make(): return Store()\no = make()\no.purge()\n",
        "def make(): return Store()\nmake().purge()\n",
        "items = [Store()]\nfor it in items: it.purge()\n",
        "for it in [Store()]: it.purge()\n",
    ] {
        let plan = py(&format!("{store}{body}"));
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/var/data/cache.db")
            }),
            "{body}: {:?}",
            plan
        );
    }
    for body in [
        "STORE = Store()\ndef main(STORE): STORE.purge()\nmain(None)\n",
        "def helper(): item.purge()\ndef main():\n    item = Store()\n    helper()\nmain()\n",
        "from pathlib import Path\ndef helper(): p.unlink()\ndef main():\n    p = Path('/wrong')\n    helper()\nmain()\n",
        "items = [Store()]\nitems = []\nfor it in items: it.purge()\n",
        "item, unused = Store(), None\nfor it in unused: it.purge()\n",
        "items = [Store()]\nif os.getenv('X'): items = []\nfor it in items: it.purge()\n",
        "def make():\n    if os.getenv('X'): return\n    return Store()\no = make()\no.purge()\n",
    ] {
        let plan = py(&format!("{store}{body}"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| { effect.operation.0 == "filesystem.delete" }),
            "{body}: {:?}",
            plan.effects
        );
    }
}

#[test]
fn environ_read_and_write() {
    let getenv = py("import os\nos.getenv('SECRET')");
    assert!(has(&getenv, "environment.read", "$SECRET"));
    let setenv = py("import os\nos.environ['TOKEN'] = 'x'");
    assert!(has(&setenv, "environment.write", "$TOKEN"));
    let empty = py("import os\nos.getenv('')");
    assert!(empty.effects.iter().any(|effect| {
        effect.operation.0 == "environment.read"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "environment")
    }));
}

#[test]
fn environment_mutations_are_writes_and_removals_are_marked() {
    let plan = py(r#"import os
def mutate():
    del os.environ["DEBUG"]
    os.environ.pop("TRACE", None)
    os.environ.update({"A": "1", dynamic: "2"}, B="3", **values)
    os.environ.setdefault(key, "value")
    os.environ.clear()
    os.unsetenv("OLD")
mutate()"#);

    for name in ["DEBUG", "TRACE", "A", "B", "OLD"] {
        assert!(has(&plan, "environment.write", &format!("${name}")));
    }
    for name in ["DEBUG", "TRACE", "OLD"] {
        let effect = plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "environment.write"
                    && render(&effect.resource) == format!("${name}")
            })
            .unwrap();
        assert_eq!(
            effect.attributes.get("unset"),
            Some(&effinterp_proto::AttrValue::Bool(true))
        );
    }
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "environment.write"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "environment")
    }));
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

#[test]
fn shutil_rmtree_is_recursive_delete() {
    let plan = py("import shutil\nshutil.rmtree('/data')");
    assert!(
        plan.effects.iter().any(|e| e.operation.0 == "filesystem.delete"
            && e.attributes.contains_key("recursive"))
    );
}

#[test]
fn dynamic_calls_are_opaque() {
    for src in [
        "import os\neval(os.environ['X'])",
        "import os\nexec(os.environ['X'])",
        "import os\n__import__(os.environ['X'])",
        "import os\neval('os.remove(\"/a\")', {})",
    ] {
        let plan = py(src);
        assert!(
            has_boundary(&plan, "unmodeled_dynamic"),
            "no boundary for {src}"
        );
        assert!(!has(&plan, "filesystem.delete", "/a"), "invented {src}");
    }
}

#[test]
fn literal_source_and_selectors_resolve_to_the_call_they_name() {
    // A literal eval body is source, not unrecoverable code, and a literal
    // `__import__` names the module it imports.
    let evaluated = py(r#"eval('__import__("os").remove("/a")')"#);
    assert!(has(&evaluated, "filesystem.delete", "/a"));
    assert!(!has_boundary(&evaluated, "unmodeled_dynamic"));

    // `getattr` with a tracked receiver and a literal name selects the same
    // attribute as writing it out, including after a later rebinding.
    let selected = py("import os\ngetattr(os, 'chmod')('/a', 0)\nos = object()");
    assert!(has(&selected, "filesystem.metadata", "/a"));
    assert!(!has_boundary(&selected, "unresolved_call"));
    assert!(selected.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.metadata"
            && effect.attributes.get("action") == Some(&AttrValue::String("chmod".into()))
    }));
    let computed = py("import os\ngetattr(os, os.environ['NAME'])('/a', 0)");
    assert!(!has(&computed, "filesystem.metadata", "/a"));
    assert!(has_boundary(&computed, "dynamic_dispatch"));

    let reference = py("import os\ndict(os=1)\nprint(getattr(os, 'chmod'), '/a')");
    assert!(!has(&reference, "filesystem.metadata", "/a"));
    assert!(!has_boundary(&reference, "unresolved_call"));
}

#[test]
fn links_preserve_their_created_alias_evidence() {
    let hard = py_with_causality(
        "import os\nos.link('/home/test/.nah/trust.json', '/tmp/alias')\nopen('/tmp/alias', 'w')",
    );
    assert!(has(&hard, "filesystem.create", "/tmp/alias"));
    assert!(has(&hard, "filesystem.write", "/home/test/.nah/trust.json"));
    assert!(!has(&hard, "filesystem.write", "/tmp/alias"));
    let target = hard
        .effects
        .iter()
        .find(|effect| {
            effect.operation.0 == "filesystem.read"
                && render(&effect.resource) == "/home/test/.nah/trust.json"
        })
        .unwrap();
    assert_eq!(
        target.attributes.get("metadata"),
        Some(&AttrValue::Bool(true))
    );
    assert!(
        hard.causality
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

    let symbolic = py("import os\nos.symlink('/a', '/b')");
    let create = symbolic
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.create")
        .unwrap();
    assert_eq!(
        create.attributes.get("symlink"),
        Some(&AttrValue::Bool(true))
    );
    assert!(!has(&symbolic, "filesystem.read", "/a"));

    let unresolved = py("import os\nos.link(source, '/b')");
    assert!(has(&unresolved, "filesystem.create", "/b"));
    assert!(
        unresolved
            .effects
            .iter()
            .all(|effect| effect.operation.0 != "filesystem.read")
    );
}

#[test]
fn modeled_star_imports_bind_effect_apis() {
    let os = py("from os import *\nremove('/x')");
    assert!(has(&os, "filesystem.delete", "/x"));
    assert!(!has_boundary(&os, "unmodeled_import"));

    let shutil = py("from shutil import *\nrmtree('/tree')");
    assert!(has(&shutil, "filesystem.delete", "/tree"));
    assert!(!has_boundary(&shutil, "unmodeled_import"));
}

#[test]
fn unmodeled_star_import_remains_a_boundary() {
    let plan = py("from mylib import *\nremove('/x')");
    assert!(has_boundary(&plan, "unmodeled_import"));
}

#[test]
fn every_modeled_star_export_reaches_its_model() {
    let cases = [
        ("os", "remove('/remove')", "filesystem.delete"),
        ("os", "unlink('/unlink')", "filesystem.delete"),
        ("os", "rmdir('/rmdir')", "filesystem.delete"),
        ("os", "mkdir('/mkdir')", "filesystem.create"),
        ("os", "makedirs('/makedirs')", "filesystem.create"),
        ("os", "rename('/rename', '/to')", "filesystem.move"),
        ("os", "replace('/replace', '/to')", "filesystem.move"),
        ("os", "chmod('/chmod', 0)", "filesystem.metadata"),
        ("os", "chown('/chown', 0, 0)", "filesystem.metadata"),
        ("os", "stat('/stat')", "filesystem.read"),
        ("os", "lstat('/lstat')", "filesystem.read"),
        ("os", "listdir('/listdir')", "filesystem.read"),
        ("os", "scandir('/scandir')", "filesystem.read"),
        ("os", "truncate('/truncate', 0)", "filesystem.write"),
        ("os", "getenv('GETENV')", "environment.read"),
        ("os", "environ['ENVIRON']", "environment.read"),
        ("os", "putenv('PUTENV', 'x')", "environment.write"),
        ("os", "unsetenv('UNSETENV')", "environment.write"),
        ("os", "setenv('SETENV', 'x')", "environment.write"),
        ("os", "system('true')", "execution"),
        ("os", "popen('true')", "execution"),
        ("os", "exec('code')", "boundary:unmodeled_dynamic"),
        ("shutil", "rmtree('/rmtree')", "filesystem.delete"),
        ("shutil", "copy('/copy', '/to')", "filesystem.read"),
        ("shutil", "copy2('/copy2', '/to')", "filesystem.read"),
        ("shutil", "copyfile('/copyfile', '/to')", "filesystem.read"),
        ("shutil", "copytree('/copytree', '/to')", "filesystem.read"),
        ("shutil", "move('/move', '/to')", "filesystem.move"),
        ("subprocess", "run(['true'])", "process.exec"),
        ("subprocess", "call(['true'])", "process.exec"),
        ("subprocess", "check_call(['true'])", "process.exec"),
        ("subprocess", "check_output(['true'])", "process.exec"),
        ("subprocess", "Popen(['true'])", "process.exec"),
        ("subprocess", "getoutput('true')", "execution"),
        ("subprocess", "getstatusoutput('true')", "execution"),
        ("pathlib", "Path('/Path').read_text()", "filesystem.read"),
        (
            "pathlib",
            "PurePath('/PurePath').read_text()",
            "filesystem.read",
        ),
        (
            "pathlib",
            "PosixPath('/PosixPath').read_text()",
            "filesystem.read",
        ),
        (
            "pathlib",
            "PurePosixPath('/PurePosixPath').read_text()",
            "filesystem.read",
        ),
        ("requests", "get('https://example.com')", "network.request"),
        ("requests", "post('https://example.com')", "network.upload"),
        ("requests", "put('https://example.com')", "network.upload"),
        (
            "requests",
            "delete('https://example.com')",
            "network.request",
        ),
        ("requests", "patch('https://example.com')", "network.upload"),
        ("requests", "head('https://example.com')", "network.request"),
        (
            "requests",
            "options('https://example.com')",
            "network.request",
        ),
        (
            "requests",
            "request('GET', 'https://example.com')",
            "network.request",
        ),
        (
            "requests",
            "Session().get('https://example.com')",
            "network.request",
        ),
        (
            "requests",
            "session().get('https://example.com')",
            "network.request",
        ),
        ("httpx", "get('https://example.com')", "network.request"),
        ("httpx", "post('https://example.com')", "network.upload"),
        ("httpx", "put('https://example.com')", "network.upload"),
        ("httpx", "delete('https://example.com')", "network.request"),
        ("httpx", "patch('https://example.com')", "network.upload"),
        ("httpx", "head('https://example.com')", "network.request"),
        ("httpx", "options('https://example.com')", "network.request"),
        (
            "httpx",
            "request('GET', 'https://example.com')",
            "network.request",
        ),
        (
            "httpx",
            "stream('GET', 'https://example.com')",
            "network.request",
        ),
        (
            "httpx",
            "Client().get('https://example.com')",
            "network.request",
        ),
        (
            "httpx",
            "AsyncClient().get('https://example.com')",
            "network.request",
        ),
        (
            "urllib.request",
            "urlopen('https://example.com')",
            "network.request",
        ),
        (
            "urllib.request",
            "urlretrieve('https://example.com', '/download')",
            "network.download",
        ),
    ];
    for (module, call, expected) in cases {
        let plan = py(&format!("from {module} import *\n{call}"));
        assert!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unmodeled_import")
                .all(|boundary| boundary
                    .callee
                    .as_ref()
                    .is_some_and(|callee| callee.symbol == "__module_init__")),
            "{module}.{call}"
        );
        if let Some(reason) = expected.strip_prefix("boundary:") {
            assert!(has_boundary(&plan, reason), "{module}.{call}: {plan:?}");
        } else if expected == "execution" {
            assert!(
                plan.execution_graph.nodes.len() > 1,
                "{module}.{call}: {plan:?}"
            );
        } else {
            assert!(
                plan.effects
                    .iter()
                    .any(|effect| effect.operation.0 == expected),
                "{module}.{call}: {plan:?}"
            );
        }
    }
}

#[test]
fn effects_inside_control_flow_are_found() {
    let plan =
        py("import os\nif cond:\n    os.remove('/x')\nfor i in range(3):\n    os.mkdir('/d')");
    assert!(has(&plan, "filesystem.delete", "/x"));
    assert!(has(&plan, "filesystem.create", "/d"));
}

#[test]
fn malformed_source_is_a_boundary_not_a_panic() {
    let plan = py("def (:\n  this is not python !!!");
    assert!(has_boundary(&plan, "parse_error"));
}

#[test]
fn node_budget_saturates_gracefully() {
    let mut limits = default_limits();
    limits.insert("max_python_nodes".to_string(), 5);
    let src = (0..100)
        .map(|i| format!("os.remove('/f{i}')"))
        .collect::<Vec<_>>()
        .join("\n");
    let plan = Engine::with_limits(limits)
        .unwrap()
        .analyze(&Subject::Source {
            dialect: None,
            language: "python".into(),
            source: format!("import os\n{src}"),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.limit.as_deref() == Some("max_python_nodes"))
    );
}

#[test]
fn python_module_delegation_keeps_one_process() {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: ["python3.12", "-S", "-m", "pip", "install", "requests"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert_eq!(code_source(&plan), Some("file"));
    assert!(has(&plan, "network.download", "?network"));
    assert!(has(&plan, "filesystem.write", "?filesystem"));
    assert!(has_boundary(&plan, "package_scripts"));
    assert!(!has_boundary(&plan, "unrecoverable_source"));
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "process.exec")
            .count(),
        1
    );
    assert_eq!(plan.execution_graph.nodes.len(), 1);
}

#[test]
fn unknown_python_modules_and_script_paths_are_opaque() {
    for argv in [
        vec!["python3", "-m", "application.module"],
        vec!["python3", "-mapplication.module"],
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Exec {
                argv: argv.into_iter().map(str::to_string).collect(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert_eq!(code_source(&plan), Some("file"));
        assert!(has_boundary(&plan, "unrecoverable_source"));
        assert!(!has_boundary(&plan, "unmodeled_command"));
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "filesystem.read")
        );
    }

    let script = Engine::new()
        .analyze(&Subject::Exec {
            argv: vec!["python3".into(), "app.py".into()],
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&script).unwrap();
    assert_eq!(code_source(&script), Some("file"));
    assert!(has(&script, "filesystem.read", "/w/app.py"));
    assert!(has_boundary(&script, "unrecoverable_source"));
}

#[test]
fn python_launcher_emits_code_execution_for_each_source_shape() {
    for (argv, source) in [
        (vec!["python3", "-c", "print(1)"], "argument"),
        (vec!["python3", "-"], "stdin"),
        (vec!["python3"], "stdin"),
        (vec!["python3.12", "app.py"], "file"),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Exec {
                argv: argv.into_iter().map(str::to_string).collect(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert_eq!(code_source(&plan), Some(source));
    }

    // The program text follows `c` inside an option cluster, and the `py`
    // launcher takes the same arguments behind its version selector.
    for argv in [
        vec!["python", "-Ic", "import os; os.remove('/x')"],
        vec!["python", "-Icimport os; os.remove('/x')"],
        vec!["py", "-3", "-c", "import os; os.remove('/x')"],
        vec!["py", "-3.12", "-c", "import os; os.remove('/x')"],
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Exec {
                argv: argv.iter().map(|arg| arg.to_string()).collect(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert_eq!(code_source(&plan), Some("argument"), "{argv:?}");
        assert!(has(&plan, "filesystem.delete", "/x"), "{argv:?}");
    }
}

#[test]
fn deterministic_across_runs() {
    let src = "import os, subprocess\nos.remove('/a')\nsubprocess.run(['cp','/a','/b'])";
    let engine = Engine::new();
    let subject = Subject::Source {
        dialect: None,
        language: "python".into(),
        source: src.to_string(),
        cwd: Some("/w".to_string()),
        context: Default::default(),
    };
    let a = effinterp_proto::canonical_json(&engine.analyze(&subject).unwrap());
    let b = effinterp_proto::canonical_json(&engine.analyze(&subject).unwrap());
    assert_eq!(a, b);
}

// --- execution vs. source-surface semantics (advisor recommendation #2) ---

#[test]
fn uncalled_function_body_is_not_executed() {
    // never_called() is defined but never invoked: its delete must NOT appear
    // in the module's execution effects.
    let plan = py("import os\ndef never_called():\n    os.remove('/important')\nprint('hi')");
    assert!(
        !has(&plan, "filesystem.delete", "/important"),
        "uncalled function contributed an execution effect"
    );
}

#[test]
fn called_function_body_is_reached_via_call_graph() {
    let plan = py("import os\ndef f():\n    os.remove('/x')\nf()");
    assert!(
        has(&plan, "filesystem.delete", "/x"),
        "call to a local function was not followed"
    );
}

#[test]
fn transitive_calls_are_followed() {
    let plan = py("import os\ndef a():\n    os.remove('/a')\ndef b():\n    a()\nb()");
    assert!(has(&plan, "filesystem.delete", "/a"));
}

#[test]
fn only_reached_functions_execute() {
    // g() is called, h() is not; only g's effect executes.
    let plan = py("import os\ndef g():\n    os.remove('/g')\ndef h():\n    os.remove('/h')\ng()");
    assert!(has(&plan, "filesystem.delete", "/g"));
    assert!(!has(&plan, "filesystem.delete", "/h"));
}

#[test]
fn unknown_module_call_is_an_explicit_boundary() {
    let plan = py("import third_party\nthird_party.do_something()");
    assert!(has_boundary(&plan, "unresolved_call"));
    // No invented concrete effect for the unknown call.
    assert!(plan.effects.is_empty());
    // Coverage is not Full for any domain the unknown call could reach.
    assert!(
        plan.coverage
            .0
            .values()
            .all(|l| l.level != CoverageLevel::Full)
    );
}

#[test]
fn self_recursion_terminates() {
    let plan = py("import os\ndef loop():\n    os.remove('/r')\n    loop()\nloop()");
    validate_plan(&plan).unwrap();
    assert!(has(&plan, "filesystem.delete", "/r"));
}

#[test]
fn mutual_recursion_terminates() {
    let plan = py(
        "import os\ndef a():\n    os.remove('/a')\n    b()\ndef b():\n    os.remove('/b')\n    a()\na()",
    );
    validate_plan(&plan).unwrap();
    assert!(has(&plan, "filesystem.delete", "/a"));
    assert!(has(&plan, "filesystem.delete", "/b"));
}

#[test]
fn inert_external_calls_stay_quiet() {
    // os.getcwd and re.compile are on the curated inert list: no boundary, no
    // invented effect.
    for source in [
        "import os\nos.getcwd()",
        "import re\nre.compile('x')",
        r#"print('os.remove(\"/tmp/x\")')"#,
    ] {
        let plan = py(source);
        assert!(!has_boundary(&plan, "unresolved_call"), "{source}");
        assert!(!has_boundary(&plan, "external_unmodeled"), "{source}");
        assert!(plan.effects.is_empty(), "{source}");
    }

    let read = py(r#"print(open('/tmp/x', 'r').read(), 'w')"#);
    assert!(has(&read, "filesystem.read", "/tmp/x"));
    assert!(!has_boundary(&read, "unresolved_call"));
}

#[test]
fn unmodeled_effectful_stdlib_call_is_a_loud_boundary() {
    // An unmodeled method of an effectful stdlib module must not be silent:
    // shutil/socket live outside the repo AND perform effects, so a call no
    // model covered surfaces as an explicit external_unmodeled boundary.
    for source in [
        "import shutil\nshutil.chown('/var/data', 'app')",
        "import socket\nsocket.create_connection(('db.internal', 5432))",
        "import sqlite3\nsqlite3.connect('app.db')",
    ] {
        let plan = py(source);
        assert!(
            has_boundary(&plan, "external_unmodeled"),
            "no external_unmodeled boundary for {source}: {:?}",
            plan.boundaries
        );
        assert!(plan.effects.is_empty(), "{source}");
        let boundary = plan
            .boundaries
            .iter()
            .find(|boundary| boundary.reason.as_str() == "external_unmodeled")
            .unwrap();
        assert!(
            boundary
                .domains
                .iter()
                .all(|domain| { plan.coverage.0[domain].level == CoverageLevel::Partial })
        );
    }
}

#[test]
fn external_boundaries_affect_only_the_domains_their_member_reaches() {
    // Each of these calls is exactly identified, so its boundary names the
    // domains that member can reach and no others.
    for (source, expected) in [
        (
            "import socket\nsocket.create_connection(('db.internal', 5432))",
            vec!["network"],
        ),
        (
            "import shutil\nshutil.chown('/var/data', 'app')",
            vec!["filesystem"],
        ),
        (
            "import sqlite3\nsqlite3.connect('app.db')",
            vec!["database", "filesystem"],
        ),
    ] {
        let plan = py(source);
        let boundary = plan
            .boundaries
            .iter()
            .find(|b| b.reason.as_str() == "external_unmodeled")
            .unwrap_or_else(|| panic!("no external_unmodeled boundary for {source}"));
        let domains: Vec<&str> = boundary.domains.iter().map(|d| d.0.as_str()).collect();
        assert_eq!(domains, expected, "{source}");
    }
}

#[test]
fn unknown_programs_and_member_inexact_surfaces_reach_every_domain() {
    for source in [
        "import pty\npty.spawn(['curl', 'https://example.com'])",
        "import logging.handlers\nlogging.handlers.HTTPHandler('example.com', '/log')",
        "import multiprocessing\nmultiprocessing.Process().start()",
    ] {
        let plan = py(source);
        let boundaries: Vec<_> = plan
            .boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "external_unmodeled")
            .collect();
        assert!(!boundaries.is_empty(), "no external boundary for {source}");
        for boundary in boundaries {
            let domains: std::collections::BTreeSet<&str> = boundary
                .domains
                .iter()
                .map(|domain| domain.0.as_str())
                .collect();
            assert_eq!(
                domains,
                effinterp_proto::DOMAINS.into_iter().collect(),
                "{source}"
            );
        }
    }
}

#[test]
fn an_unknown_third_party_call_still_reaches_every_domain() {
    // Nothing bounds what a package we cannot see does, so its boundary must
    // stay broad rather than invent a precise negative answer.
    let plan = py("import vendorpkg\nvendorpkg.frob('/x')");
    let boundary = plan
        .boundaries
        .iter()
        .find(|b| b.reason.as_str() == "unresolved_call")
        .expect("an unrecognized module is a loud unresolved_call boundary");
    let domains: Vec<&str> = boundary.domains.iter().map(|d| d.0.as_str()).collect();
    for domain in effinterp_proto::DOMAINS {
        assert!(domains.contains(&domain), "missing {domain}: {domains:?}");
    }
}

#[test]
fn a_wrong_arity_call_does_not_inherit_the_inert_classification() {
    // `os.getcwd` takes no arguments; a same-named call that takes one is not
    // the stdlib function, so it loses the curated quiet classification.
    assert!(!has_boundary(
        &py("import os\nos.getcwd()"),
        "external_unmodeled"
    ));
    assert!(has_boundary(
        &py("import os\nos.getcwd('/somewhere')"),
        "external_unmodeled"
    ));
}

// --- function summaries with argument substitution ---

/// The effect's resource rendered structurally so a Join's parts are visible.
fn deep_render(expr: &ResourceExpr) -> String {
    match expr {
        ResourceExpr::Join { parts } => {
            let inner: Vec<String> = parts.iter().map(deep_render).collect();
            format!("join[{}]", inner.join(", "))
        }
        other => render(other),
    }
}

fn delete_resource(plan: &Plan) -> String {
    let e = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .expect("no filesystem.delete effect");
    deep_render(&e.resource)
}

#[test]
fn summary_substitutes_arguments_into_a_join() {
    // The key case: a helper builds a path from its params; the caller's
    // literal and symbol are substituted in.
    let plan = py(
        "import os, shutil\ndef wipe(root, t):\n    shutil.rmtree(os.path.join(root, t))\nwipe('/tmp/cache', name)",
    );
    assert_eq!(delete_resource(&plan), "join[/tmp/cache, <name>]");
}

#[test]
fn summary_not_applied_when_function_uncalled() {
    let plan =
        py("import os, shutil\ndef wipe(root, t):\n    shutil.rmtree(os.path.join(root, t))");
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.delete"),
        "uncalled helper contributed a delete"
    );
}

#[test]
fn summary_specializes_each_call_site() {
    let plan = py("import os\ndef rm(p):\n    os.remove(p)\nrm('/a')\nrm('/b')");
    assert!(has(&plan, "filesystem.delete", "/a"));
    assert!(has(&plan, "filesystem.delete", "/b"));
}

#[test]
fn summary_free_parameter_stays_symbolic() {
    // Called with fewer args than params: the unbound param stays symbolic.
    let plan = py("import os\ndef rm(a, b):\n    os.remove(os.path.join(a, b))\nrm('/root')");
    assert_eq!(delete_resource(&plan), "join[/root, <b>]");
}

#[test]
fn summary_transitive_substitution() {
    let plan =
        py("import os\ndef inner(p):\n    os.remove(p)\ndef outer(q):\n    inner(q)\nouter('/z')");
    assert!(has(&plan, "filesystem.delete", "/z"));

    // The first caller's guard must not become part of the cached summary,
    // even when its condition stack has widened at the depth cap.
    for depth in [1, 70] {
        let mut source = String::from("import os\ndef wipe(p): os.remove(p)\n");
        for level in 0..depth {
            source.push_str(&format!("{}if flag:\n", "    ".repeat(level)));
        }
        source.push_str(&format!(
            "{}wipe('/guarded')\nwipe('/always')",
            "    ".repeat(depth)
        ));
        let plan = py(&source);
        let always = plan
            .effects
            .iter()
            .find(|effect| render(&effect.resource) == "/always")
            .unwrap();
        assert!(always.condition.is_none());
    }
}

#[test]
fn summary_recursion_terminates_and_is_valid() {
    let plan = py("import os\ndef loop(p):\n    os.remove(p)\n    loop(p)\nloop('/r')");
    validate_plan(&plan).unwrap();
    assert!(has(&plan, "filesystem.delete", "/r"));

    // An acyclic call chain must also stop before exhausting the native stack.
    let mut source = String::from("import os\n");
    for index in 0..80 {
        source.push_str(&format!("def f{index}(): f{}()\n", index + 1));
    }
    source.push_str("def f80(): os.remove('/deep')\nf0()\nos.remove('/after')\n");
    let plan = py(&source);
    assert!(has(&plan, "filesystem.delete", "/after"));
    assert!(!has(&plan, "filesystem.delete", "/deep"));
    assert!(plan.boundaries.iter().any(
        |boundary| boundary.reason.as_str() == "partial_analysis" && boundary.callee.is_some()
    ));
}

#[test]
fn summary_analysis_is_deterministic() {
    let src = "import os, shutil\ndef wipe(root, t):\n    shutil.rmtree(os.path.join(root, t))\nwipe('/tmp', name)";
    let a = effinterp_proto::canonical_json(&py(src));
    let b = effinterp_proto::canonical_json(&py(src));
    assert_eq!(a, b);
}

/// A helper that returns a path built from a module constant and its parameter,
/// assigned to a local and then deleted: the returned resource must flow into
/// the delete (return-value summary + caller-side tracking).
#[test]
fn return_value_flows_into_a_later_effect() {
    let plan = py(
        "import os\nROOT=\"/var/cache\"\ndef cache_path(t): return os.path.join(ROOT, t)\np = cache_path(name)\nos.remove(p)",
    );
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
        "ROOT resolved to /var/cache: {parts:?}"
    );
    assert!(
        parts
            .iter()
            .any(|p| matches!(p, ResourceExpr::Parameter { name } if name == "name")),
        "the caller's argument survives symbolically: {parts:?}"
    );
}

/// A literal local path assignment also flows to a later use.
#[test]
fn literal_local_assignment_flows() {
    let plan = py("import os\np = \"/tmp/target\"\nos.remove(p)");
    assert!(has(&plan, "filesystem.delete", "/tmp/target"));
}

/// A helper whose return is not a resolvable resource yields a symbolic delete,
/// never a crash or a fabricated path.
#[test]
fn nonresolvable_return_stays_symbolic() {
    let plan = py("import os\ndef mk(): return compute()\np = mk()\nos.remove(p)");
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

#[test]
fn local_return_resources_flow_directly_into_sinks() {
    let literal = py(concat!(
        "import shutil\n",
        "def cache_dir():\n",
        "    path = '/var/cache/tool'\n",
        "    return path\n",
        "shutil.rmtree(cache_dir())\n",
    ));
    assert!(has(&literal, "filesystem.delete", "/var/cache/tool"));

    let home = py(concat!(
        "import shutil\n",
        "from pathlib import Path\n",
        "def cache_dir():\n",
        "    return Path.home() / '.cache' / 'tool'\n",
        "shutil.rmtree(cache_dir())\n",
    ));
    assert!(home.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Join { parts }
                if matches!(parts.as_slice(), [
                    ResourceExpr::Environment { name },
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path: cache }
                    },
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path: tool }
                    }
                ] if name == "HOME" && cache == ".cache" && tool == "tool"))
    }));

    let divergent = py(concat!(
        "import shutil\n",
        "def cache_dir(flag):\n",
        "    if flag:\n",
        "        return '/a'\n",
        "    return '/b'\n",
        "shutil.rmtree(cache_dir(flag))\n",
    ));
    assert!(has(&divergent, "filesystem.delete", "?filesystem"));
    assert!(has_boundary(&divergent, "unmodeled_dynamic"));
}

#[test]
fn literal_defaults_specialize_local_effects() {
    let defaulted = py(concat!(
        "def append_audit(line, path='/var/log/audit.log'):\n",
        "    open(path, 'a').write(line)\n",
        "append_audit('x')\n",
    ));
    let write = defaulted
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.write")
        .expect("append writes the default path");
    assert!(matches!(&write.resource, ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path }
    } if path == "/var/log/audit.log"));
    assert_eq!(
        write.attributes.get("append"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );

    let explicit = py(concat!(
        "def append_audit(line, path='/var/log/audit.log'):\n",
        "    open(path, 'a').write(line)\n",
        "append_audit('x', '/explicit')\n",
    ));
    assert!(has(&explicit, "filesystem.write", "/explicit"));

    let dynamic = py(concat!(
        "import os\n",
        "def append_audit(line, path=os.getenv('AUDIT_PATH')):\n",
        "    open(path, 'a').write(line)\n",
        "append_audit('x')\n",
    ));
    assert!(has(&dynamic, "filesystem.write", "<path>"));
}

#[test]
fn splatted_arguments_do_not_apply_literal_defaults() {
    let keyword = py(concat!(
        "def write(line, path='/var/log/audit.log'):\n",
        "    open(path, 'a').write(line)\n",
        "def outer(**kw):\n",
        "    write('x', **kw)\n",
        "outer(path='/tmp/other')\n",
    ));
    assert!(has(&keyword, "filesystem.write", "<path>"));
    assert!(!has(&keyword, "filesystem.write", "/var/log/audit.log"));

    let positional = py(concat!(
        "def write(first='/first', path='/second'):\n",
        "    open(path, 'w').write(first)\n",
        "def outer(*args):\n",
        "    write(*args)\n",
        "outer('/explicit')\n",
    ));
    assert!(has(&positional, "filesystem.write", "<path>"));
    assert!(!has(&positional, "filesystem.write", "/second"));
}

#[test]
fn varargs_do_not_bind_keyword_only_defaults_positionally() {
    let plan = py(concat!(
        "def emit(*paths, target='/tmp/target.log'):\n",
        "    open(target, 'w').write('x')\n",
        "emit('/etc/shadow')\n",
    ));
    assert!(has(&plan, "filesystem.write", "/tmp/target.log"));
    assert!(!has(&plan, "filesystem.write", "/etc/shadow"));
}

#[test]
fn constructor_attributes_specialize_method_effects() {
    let direct = py(concat!(
        "import shutil\n",
        "class Storage:\n",
        "    def __init__(self, root):\n",
        "        self.root = root\n",
        "    def purge(self):\n",
        "        shutil.rmtree(self.root)\n",
        "Storage('/var/lib/app/blobs').purge()\n",
    ));
    assert!(has(&direct, "filesystem.delete", "/var/lib/app/blobs"));

    let bound = py(concat!(
        "import shutil\n",
        "class Storage:\n",
        "    def __init__(self, root):\n",
        "        self.root = root\n",
        "    def purge(self):\n",
        "        shutil.rmtree(self.root)\n",
        "s = Storage(root='/var/lib/app/blobs')\n",
        "s.purge()\n",
    ));
    assert!(has(&bound, "filesystem.delete", "/var/lib/app/blobs"));

    let literal = py(concat!(
        "import shutil\n",
        "class Storage:\n",
        "    def __init__(self):\n",
        "        self.root = '/var/lib/app/blobs'\n",
        "    def purge(self):\n",
        "        shutil.rmtree(self.root)\n",
        "Storage().purge()\n",
    ));
    assert!(has(&literal, "filesystem.delete", "/var/lib/app/blobs"));

    let unresolved = py(concat!(
        "import shutil\n",
        "class Storage:\n",
        "    def __init__(self, root):\n",
        "        self.root = root\n",
        "    def purge(self):\n",
        "        shutil.rmtree(self.root)\n",
        "Storage(dynamic()).purge()\n",
    ));
    assert!(has(&unresolved, "filesystem.delete", "<self.root>"));

    let pathlib = py(concat!(
        "from pathlib import Path\n",
        "class Rel:\n",
        "    def __init__(self, path):\n",
        "        self.path = path\n",
        "    def go(self):\n",
        "        self.path.read_text()\n",
        "        self.path.write_text('updated')\n",
        "Rel(Path('CHANGES.md')).go()\n",
    ));
    assert!(
        has(&pathlib, "filesystem.read", "/work/CHANGES.md"),
        "{:#?}",
        pathlib.effects
    );
    assert!(
        has(&pathlib, "filesystem.write", "/work/CHANGES.md"),
        "{:#?}",
        pathlib.effects
    );
}

#[test]
fn constructor_parameters_shadow_module_constants_in_attribute_values() {
    for (assignment, expected) in [
        ("self.root = root", "/ctor/arg"),
        ("self.root = Path(root) / 'blobs'", "/ctor/arg/blobs"),
    ] {
        let plan = py(&format!(
            "import shutil\nfrom pathlib import Path\nroot = '/module/global'\nclass Storage:\n    def __init__(self, root):\n        {assignment}\n    def purge(self):\n        shutil.rmtree(self.root)\nStorage('/ctor/arg').purge()\n"
        ));
        assert!(has(&plan, "filesystem.delete", expected));
        assert!(!has(&plan, "filesystem.delete", "/module/global"));
        assert!(!has(&plan, "filesystem.delete", "/module/global/blobs"));
    }
}

#[test]
fn external_attribute_writes_invalidate_constructor_values() {
    let declarations = concat!(
        "import shutil\n",
        "class Storage:\n",
        "    def __init__(self, root='/var/lib/app/blobs'):\n",
        "        self.root = root\n",
        "    def purge(self):\n",
        "        shutil.rmtree(self.root)\n",
    );
    for statements in [
        "s = Storage('/one')\ns.root = '/other'\ns.purge()\n",
        "s = Storage()\ns.root = '/tmp/other'\ns.purge()\n",
        "def wire(value):\n    value.root = '/injected'\ns = Storage('/one')\nwire(s)\ns.purge()\n",
        "s = Storage('/one')\nt = s\nt.root = '/other'\ns.purge()\n",
        "s = Storage('/one')\nu = t = s\nu.root = '/other'\ns.purge()\n",
        "store = Storage('/one')\nbackup = Storage('/two')\nsrc, dst = store, backup\nsrc.root = '/other'\nstore.purge()\n",
        "s = Storage('/one')\n(t := s)\nt.root = '/other'\ns.purge()\n",
        "s = Storage('/one')\nfor t in [s]:\n    t.root = '/other'\ns.purge()\n",
        "s = Storage('/one')\ns.root = '/other'\nt = s\ns = Storage('/fresh')\nt.purge()\n",
        "def inner(value):\n    value.root = '/injected'\ndef outer(value):\n    inner(value)\ns = Storage('/one')\nouter(s)\ns.purge()\n",
        "def wire(value):\n    alias = value\n    alias.root = '/injected'\ns = Storage('/one')\nwire(s)\ns.purge()\n",
    ] {
        let plan = py(&format!("{declarations}{statements}"));
        assert!(has(&plan, "filesystem.delete", "<self.root>"));
        assert!(!has(&plan, "filesystem.delete", "/one"));
        assert!(!has(&plan, "filesystem.delete", "/var/lib/app/blobs"));
    }
}

#[test]
fn unpack_walrus_and_loop_aliases_share_constructor_identity() {
    let declarations = concat!(
        "import shutil\n",
        "class Storage:\n",
        "    def __init__(self, root):\n",
        "        self.root = root\n",
        "    def purge(self):\n",
        "        shutil.rmtree(self.root)\n",
    );
    for statements in [
        "store = Storage('/one')\nbackup = Storage('/two')\nsrc, dst = store, backup\nsrc.purge()\n",
        "s = Storage('/one')\n(t := s)\nt.purge()\n",
        "s = Storage('/one')\nfor t in [s]:\n    t.purge()\n",
    ] {
        let plan = py(&format!("{declarations}{statements}"));
        assert!(
            has(&plan, "filesystem.delete", "/one"),
            "{statements:?} => {:#?}",
            plan.effects
        );
        assert!(!has(&plan, "filesystem.delete", "<self.root>"));
        assert!(!has(&plan, "filesystem.delete", "/two"));
    }
}

#[test]
fn conditional_constructor_attributes_stay_symbolic() {
    let plan = py(concat!(
        "import shutil\n",
        "class Storage:\n",
        "    def __init__(self, flag):\n",
        "        self.root = '/safe'\n",
        "        if flag:\n",
        "            self.root = '/danger'\n",
        "    def purge(self):\n",
        "        shutil.rmtree(self.root)\n",
        "Storage(True).purge()\n",
    ));
    assert!(has(&plan, "filesystem.delete", "<self.root>"));
    assert!(!has(&plan, "filesystem.delete", "/safe"));
    assert!(!has(&plan, "filesystem.delete", "/danger"));
}

#[test]
fn match_and_try_star_reassignments_drop_constructor_attribute_values() {
    let reassignments = [
        concat!(
            "    def configure(self, value):\n",
            "        match value:\n",
            "            case 1:\n",
            "                self.root = compute()\n",
        ),
        concat!(
            "    def configure(self):\n",
            "        try:\n",
            "            pass\n",
            "        except* ValueError:\n",
            "            self.root = compute()\n",
        ),
    ];

    for reassignment in reassignments {
        let plan = py(&format!(
            concat!(
                "import shutil\n",
                "class Storage:\n",
                "    def __init__(self):\n",
                "        self.root = '/var/lib/app/blobs'\n",
                "{reassignment}",
                "    def purge(self):\n",
                "        shutil.rmtree(self.root)\n",
                "Storage().purge()\n",
            ),
            reassignment = reassignment
        ));
        assert!(has(&plan, "filesystem.delete", "<self.root>"));
        assert!(!has(&plan, "filesystem.delete", "/var/lib/app/blobs"));
    }
}

#[test]
fn match_reassignment_in_init_drops_the_prior_attribute_value() {
    let plan = py(concat!(
        "import shutil\n",
        "class Storage:\n",
        "    def __init__(self, value):\n",
        "        self.root = '/var/lib/app/blobs'\n",
        "        match value:\n",
        "            case 1:\n",
        "                self.root = compute()\n",
        "    def purge(self):\n",
        "        shutil.rmtree(self.root)\n",
        "Storage(1).purge()\n",
    ));
    assert!(has(&plan, "filesystem.delete", "<self.root>"));
    assert!(!has(&plan, "filesystem.delete", "/var/lib/app/blobs"));
}

#[test]
fn augmented_and_binding_reassignments_drop_constructor_attribute_values() {
    let reassignments = [
        "    def configure(self, value):\n        self.root += value\n",
        "    def configure(self, values):\n        for self.root in values:\n            pass\n",
        "    async def configure(self, values):\n        async for self.root in values:\n            pass\n",
        "    def configure(self, value):\n        with open(value) as self.root:\n            pass\n",
        "    async def configure(self, value):\n        async with value as self.root:\n            pass\n",
    ];

    for reassignment in reassignments {
        let plan = py(&format!(
            concat!(
                "import shutil\n",
                "class Storage:\n",
                "    def __init__(self):\n",
                "        self.root = '/var/lib/app/blobs'\n",
                "{reassignment}",
                "    def purge(self):\n",
                "        shutil.rmtree(self.root)\n",
                "Storage().purge()\n",
            ),
            reassignment = reassignment
        ));
        assert!(has(&plan, "filesystem.delete", "<self.root>"));
        assert!(!has(&plan, "filesystem.delete", "/var/lib/app/blobs"));
    }
}

#[test]
fn augmented_and_binding_reassignments_in_init_drop_prior_attribute_values() {
    let reassignments = [
        "        self.root += value\n",
        "        for self.root in values:\n            pass\n",
        "        with open(value) as self.root:\n            pass\n",
    ];

    for reassignment in reassignments {
        let plan = py(&format!(
            concat!(
                "import shutil\n",
                "class Storage:\n",
                "    def __init__(self, value, values):\n",
                "        self.root = '/var/lib/app/blobs'\n",
                "{reassignment}",
                "    def purge(self):\n",
                "        shutil.rmtree(self.root)\n",
                "Storage('x', ['y']).purge()\n",
            ),
            reassignment = reassignment
        ));
        assert!(has(&plan, "filesystem.delete", "<self.root>"));
        assert!(!has(&plan, "filesystem.delete", "/var/lib/app/blobs"));
    }
}

#[test]
fn unpack_chained_and_delete_reassignments_drop_constructor_attribute_values() {
    let method_reassignments = [
        "    def configure(self, value):\n        self.root, self.other = value, value\n",
        "    def configure(self):\n        del self.root\n",
    ];

    for reassignment in method_reassignments {
        let plan = py(&format!(
            concat!(
                "import shutil\n",
                "class Storage:\n",
                "    def __init__(self):\n",
                "        self.root = '/var/lib/app/blobs'\n",
                "{reassignment}",
                "    def purge(self):\n",
                "        shutil.rmtree(self.root)\n",
                "Storage().purge()\n",
            ),
            reassignment = reassignment
        ));
        assert!(has(&plan, "filesystem.delete", "<self.root>"));
        assert!(!has(&plan, "filesystem.delete", "/var/lib/app/blobs"));
    }

    let init_reassignments = [
        "        self.root, self.other = value, value\n",
        "        self.root = self.other = value\n",
        "        del self.root\n",
    ];

    for reassignment in init_reassignments {
        let plan = py(&format!(
            concat!(
                "import shutil\n",
                "class Storage:\n",
                "    def __init__(self, value):\n",
                "        self.root = '/var/lib/app/blobs'\n",
                "{reassignment}",
                "    def purge(self):\n",
                "        shutil.rmtree(self.root)\n",
                "Storage('x').purge()\n",
            ),
            reassignment = reassignment
        ));
        assert!(has(&plan, "filesystem.delete", "<self.root>"));
        assert!(!has(&plan, "filesystem.delete", "/var/lib/app/blobs"));
    }
}

#[test]
fn path_parameters_shadow_same_named_module_paths() {
    let plan = py(concat!(
        "from pathlib import Path\n",
        "CACHE = Path('/srv/cache')\n",
        "def replace(CACHE):\n",
        "    return CACHE.replace('x', 'y')\n",
        "replace('hello-x')\n",
    ));
    assert!(
        plan.effects
            .iter()
            .all(|effect| !effect.operation.0.starts_with("filesystem.")),
        "{:#?}",
        plan.effects
    );
}

#[test]
fn non_path_instance_attributes_do_not_dispatch_as_pathlib() {
    let plan = py(concat!(
        "import os\n",
        "class Release:\n",
        "    def __init__(self):\n",
        "        self.name = 'my-release'\n",
        "        self.tag = os.environ['TAG']\n",
        "    def go(self):\n",
        "        self.name.replace('-', '_')\n",
        "        self.tag.replace('-', '_')\n",
        "class Conn:\n",
        "    def open(self):\n",
        "        open('/var/run/conn').read()\n",
        "class Job:\n",
        "    def __init__(self, conn):\n",
        "        self.conn = conn\n",
        "    def go(self):\n",
        "        self.conn.open()\n",
        "Release().go()\n",
        "Job(Conn()).go()\n",
    ));
    assert!(
        plan.effects
            .iter()
            .all(|effect| !effect.operation.0.starts_with("filesystem.")),
        "{:#?}",
        plan.effects
    );
}

#[test]
fn chained_local_constructor_preserves_initializer_effects() {
    let plan = py(concat!(
        "class Config:\n",
        "    def __init__(self):\n",
        "        open('/init').read()\n",
        "    def load(self):\n",
        "        open('/load').read()\n",
        "Config().load()\n",
    ));
    let init = plan
        .effects
        .iter()
        .position(|effect| {
            effect.operation.0 == "filesystem.read"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/init")
        })
        .expect("initializer effect is retained");
    let load = plan
        .effects
        .iter()
        .position(|effect| {
            effect.operation.0 == "filesystem.read"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/load")
        })
        .expect("method effect is retained");
    assert!(init < load);
}

#[test]
fn local_context_manager_applies_enter_and_exit() {
    let plan = py(concat!(
        "import os\n",
        "class Lock:\n",
        "    def __init__(self, path):\n",
        "        self.path = path\n",
        "    def __enter__(self):\n",
        "        open(self.path, 'w')\n",
        "        return self.path\n",
        "    def __exit__(self, exc_type, exc, tb):\n",
        "        os.remove(self.path)\n",
        "with Lock('/tmp/app.lock') as p:\n",
        "    open(p).read()\n",
    ));
    assert!(has(&plan, "filesystem.write", "/tmp/app.lock"));
    assert!(has(&plan, "filesystem.read", "/tmp/app.lock"));
    assert!(has(&plan, "filesystem.delete", "/tmp/app.lock"));

    let unresolved = py(concat!(
        "import os\n",
        "class Lock:\n",
        "    def __init__(self, path):\n",
        "        self.path = path\n",
        "    def __enter__(self):\n",
        "        return dynamic()\n",
        "    def __exit__(self, exc_type, exc, tb):\n",
        "        os.remove(self.path)\n",
        "with Lock('/tmp/app.lock') as p:\n",
        "    open(p).read()\n",
    ));
    assert!(has(&unresolved, "filesystem.read", "?filesystem"));
    assert!(has(&unresolved, "filesystem.delete", "/tmp/app.lock"));
    assert!(has_boundary(&unresolved, "unmodeled_dynamic"));
}

#[test]
fn non_path_context_values_do_not_dispatch_as_pathlib() {
    let generator = py(concat!(
        "import contextlib, os\n",
        "@contextlib.contextmanager\n",
        "def temp_dir():\n",
        "    value = os.environ['TMPDIR']\n",
        "    yield value\n",
        "with temp_dir() as value:\n",
        "    value.replace('\\\\', '/')\n",
    ));
    assert!(has(&generator, "environment.read", "$TMPDIR"));
    assert!(!has_op(&generator, "filesystem.move"));
    assert!(!has_op(&generator, "filesystem.write"));

    let local = py(concat!(
        "class Value:\n",
        "    def __init__(self, value):\n",
        "        self.value = value\n",
        "    def __enter__(self):\n",
        "        return self.value\n",
        "    def __exit__(self, exc_type, exc, tb):\n",
        "        pass\n",
        "with Value('/tmp/d') as value:\n",
        "    value.replace('d', 'e')\n",
    ));
    assert!(!has_op(&local, "filesystem.move"));
    assert!(!has_op(&local, "filesystem.write"));
}

#[test]
fn ambiguous_path_assignment_widens_without_silence() {
    let plan = py(concat!(
        "from pathlib import Path\n",
        "p = Path('/a') if condition else Path('/b')\n",
        "p.unlink()\n",
    ));
    assert!(has(&plan, "filesystem.delete", "?filesystem"));
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        1
    );
}

#[test]
fn partially_bound_path_receivers_widen_without_silence() {
    let cases = [
        (
            concat!(
                "from pathlib import Path\n",
                "import os\n",
                "def go():\n",
                "    try:\n",
                "        p = Path(os.environ['X'])\n",
                "    except KeyError:\n",
                "        return\n",
                "    p.write_text('data')\n",
                "go()\n",
            ),
            "filesystem.write",
        ),
        (
            concat!(
                "from pathlib import Path\n",
                "def go(flag):\n",
                "    p = None\n",
                "    if flag:\n",
                "        p = Path('/tmp/scratch')\n",
                "    if p:\n",
                "        p.unlink()\n",
                "go(condition)\n",
            ),
            "filesystem.delete",
        ),
        (
            concat!(
                "from pathlib import Path\n",
                "import os\n",
                "if os.environ.get('C'):\n",
                "    p = Path('/cond')\n",
                "p.unlink()\n",
            ),
            "filesystem.delete",
        ),
        (
            concat!(
                "from pathlib import Path\n",
                "import os\n",
                "if os.environ.get('C'):\n",
                "    p = Path('/cond')\n",
                "p.open('w')\n",
            ),
            "filesystem.write",
        ),
    ];

    for (source, operation) in cases {
        let plan = py(source);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == operation
                && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                    if family.0 == "filesystem")
        }));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
    }

    let ambiguous = py(concat!(
        "from pathlib import Path\n",
        "if condition:\n",
        "    value = Path('/tmp/path')\n",
        "else:\n",
        "    value = 'plain-string'\n",
        "value.replace('a', 'b')\n",
        "alias = value\n",
        "alias.replace('a', 'b')\n",
    ));
    assert!(!has_op(&ambiguous, "filesystem.move"));
    assert!(!has_op(&ambiguous, "filesystem.write"));

    let converted = py(concat!(
        "from pathlib import Path\n",
        "if condition:\n",
        "    value = Path('/tmp/path')\n",
        "else:\n",
        "    value = 'plain-string'\n",
        "converted = Path(value)\n",
        "converted.open('w')\n",
    ));
    assert!(has(&converted, "filesystem.write", "?filesystem"));
    assert!(has_boundary(&converted, "unmodeled_dynamic"));

    let explicit = py(concat!(
        "from pathlib import Path\n",
        "if condition:\n",
        "    value = Path('/tmp/path')\n",
        "else:\n",
        "    value = 'plain-string'\n",
        "Path(value).open('w')\n",
        "(Path.home() / value).open('w')\n",
        "Path(value).replace('/tmp/other')\n",
    ));
    assert_eq!(
        explicit
            .effects
            .iter()
            .filter(|effect| {
                effect.operation.0 == "filesystem.write"
                    && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                        if family.0 == "filesystem")
            })
            .count(),
        2
    );
    assert!(has(&explicit, "filesystem.move", "?filesystem"));
    assert!(has(&explicit, "filesystem.write", "/tmp/other"));
    assert!(has_boundary(&explicit, "unmodeled_dynamic"));
}

#[test]
fn non_static_loop_rebinding_widens_a_tracked_path() {
    let plan = py(concat!(
        "from pathlib import Path\n",
        "p = Path('/a')\n",
        "for p in values:\n",
        "    p.unlink()\n",
    ));
    assert!(has(&plan, "filesystem.delete", "?filesystem"));
    assert!(!has(&plan, "filesystem.delete", "/a"));
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        1
    );
}

#[test]
fn non_static_rebinding_patterns_widen_tracked_path_receivers() {
    let cases = [
        (
            concat!(
                "from pathlib import Path\n",
                "p = Path('/var/data')\n",
                "for key, p in rows:\n",
                "    p.replace('a', 'b')\n",
            ),
            "filesystem.move",
        ),
        (
            concat!(
                "from pathlib import Path\n",
                "def replace(rows):\n",
                "    p = Path('/var/data')\n",
                "    for key, p in rows:\n",
                "        p.replace('a', 'b')\n",
                "replace(values)\n",
            ),
            "filesystem.move",
        ),
        (
            concat!(
                "from pathlib import Path\n",
                "p = Path('/var/data')\n",
                "out = [p.replace('a', 'b') for p in names]\n",
                "p.unlink()\n",
            ),
            "filesystem.move",
        ),
        (
            concat!(
                "from pathlib import Path\n",
                "p = Path('/var/data')\n",
                "try:\n",
                "    run()\n",
                "except Exception as p:\n",
                "    p.unlink()\n",
            ),
            "filesystem.delete",
        ),
        (
            concat!(
                "from pathlib import Path\n",
                "p = Path('/var/data')\n",
                "if (p := load()):\n",
                "    p.unlink()\n",
            ),
            "filesystem.delete",
        ),
        (
            concat!(
                "from pathlib import Path\n",
                "p = Path('/var/data')\n",
                "q = None\n",
                "with open('values') as (p, q):\n",
                "    p.unlink()\n",
            ),
            "filesystem.delete",
        ),
    ];

    for (source, operation) in cases {
        let plan = py(source);
        assert!(has(&plan, operation, "?filesystem"));
        assert!(!has(&plan, operation, "/var/data"));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
    }
}

#[test]
fn non_static_unpack_assignment_widens_tracked_path_receivers() {
    let cases = [
        "p, q = load()\np.unlink()\n",
        "[p, q] = load()\np.replace('a', 'b')\n",
        "*p, q = load()\np.unlink()\n",
        "(p, q), r = load()\np.unlink()\n",
    ];

    for assignment in cases {
        let plan = py(&format!(
            "from pathlib import Path\np = Path('/var/data')\n{assignment}"
        ));
        assert!(plan.effects.iter().any(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )));
        assert!(plan.effects.iter().all(|effect| {
            !matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/var/data")
        }));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
    }

    let local = py(concat!(
        "from pathlib import Path\n",
        "def replace(rows):\n",
        "    p = Path('/var/data')\n",
        "    p, q = rows\n",
        "    p.replace('a', 'b')\n",
        "replace(load())\n",
    ));
    assert!(has(&local, "filesystem.move", "?filesystem"));
    assert!(!has(&local, "filesystem.move", "/var/data"));
    assert!(has_boundary(&local, "unmodeled_dynamic"));
}

#[test]
fn match_patterns_widen_tracked_path_receivers() {
    let patterns = [
        "[p, q]",
        "{'key': p}",
        "[*p]",
        "{'key': q, **p}",
        "[q] as p",
        "Point(value=p)",
        "[p] | (p,)",
    ];

    for pattern in patterns {
        let plan = py(&format!(
            "from pathlib import Path\np = Path('/var/data')\nmatch open('/subject').read():\n    case {pattern}:\n        pass\np.unlink()\n"
        ));
        assert!(has(&plan, "filesystem.read", "/subject"));
        assert!(has(&plan, "filesystem.delete", "?filesystem"));
        assert!(!has(&plan, "filesystem.delete", "/var/data"));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
    }
}

#[test]
fn match_guards_and_bodies_widen_tracked_path_receivers() {
    let body = py(concat!(
        "from pathlib import Path\n",
        "p = Path('/var/data')\n",
        "match value:\n",
        "    case 1:\n",
        "        p = compute()\n",
        "        open('/inside-case').read()\n",
        "p.unlink()\n",
    ));
    assert!(has(&body, "filesystem.read", "/inside-case"));
    assert!(has(&body, "filesystem.delete", "?filesystem"));
    assert!(!has(&body, "filesystem.delete", "/var/data"));
    assert!(has_boundary(&body, "unmodeled_dynamic"));

    let guard = py(concat!(
        "from pathlib import Path\n",
        "p = Path('/var/data')\n",
        "match value:\n",
        "    case 1 if (p := compute()):\n",
        "        pass\n",
        "p.unlink()\n",
    ));
    assert!(has(&guard, "filesystem.delete", "?filesystem"));
    assert!(!has(&guard, "filesystem.delete", "/var/data"));
    assert!(has_boundary(&guard, "unmodeled_dynamic"));
}

#[test]
fn try_star_handlers_widen_tracked_path_receivers() {
    let alias = py(concat!(
        "from pathlib import Path\n",
        "p = Path('/var/data')\n",
        "try:\n",
        "    open('/inside-try').read()\n",
        "except* ValueError as p:\n",
        "    open('/inside-handler').read()\n",
        "    p.unlink()\n",
        "p.unlink()\n",
    ));
    assert!(has(&alias, "filesystem.read", "/inside-try"));
    assert!(has(&alias, "filesystem.read", "/inside-handler"));
    assert!(has(&alias, "filesystem.delete", "?filesystem"));
    assert!(!has(&alias, "filesystem.delete", "/var/data"));
    assert!(has_boundary(&alias, "unmodeled_dynamic"));

    let body = py(concat!(
        "from pathlib import Path\n",
        "p = Path('/var/data')\n",
        "try:\n",
        "    pass\n",
        "except* ValueError:\n",
        "    p = compute()\n",
        "p.unlink()\n",
    ));
    assert!(has(&body, "filesystem.delete", "?filesystem"));
    assert!(!has(&body, "filesystem.delete", "/var/data"));
    assert!(has_boundary(&body, "unmodeled_dynamic"));
}

#[test]
fn definitions_and_imports_widen_tracked_path_receivers() {
    let bindings = [
        "def p():\n    pass",
        "async def p():\n    pass",
        "class p:\n    pass",
        "import p",
        "import p.module",
        "import helper as p",
        "from helper import p",
        "from helper import value as p",
    ];

    for binding in bindings {
        let plan = py(&format!(
            "from pathlib import Path\np = Path('/var/data')\n{binding}\np.unlink()\n"
        ));
        assert!(has(&plan, "filesystem.delete", "?filesystem"));
        assert!(!has(&plan, "filesystem.delete", "/var/data"));
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
    }

    let class_scoped = py(concat!(
        "from pathlib import Path\n",
        "p = Path('/var/data')\n",
        "class Holder:\n",
        "    open('/class-body').read()\n",
        "    def p():\n",
        "        pass\n",
        "p.unlink()\n",
    ));
    assert!(has(&class_scoped, "filesystem.read", "/class-body"));
    assert!(has(&class_scoped, "filesystem.delete", "/var/data"));
    assert!(!has(&class_scoped, "filesystem.delete", "?filesystem"));
}

#[test]
fn static_bindings_refresh_path_receiver_evidence() {
    let strings = py(concat!(
        "from pathlib import Path\n",
        "p = Path('/var/data')\n",
        "p, q = ['x', 'y']\n",
        "p.replace('a', 'b')\n",
        "p = Path('/var/data')\n",
        "for p in ['x', 'y']:\n",
        "    p.replace('a', 'b')\n",
    ));
    assert!(!has_op(&strings, "filesystem.move"));
    assert!(!has_op(&strings, "filesystem.write"));

    let comprehension = py(concat!(
        "from pathlib import Path\n",
        "p = Path('/old')\n",
        "values = [p for p in ['x']]\n",
        "for p in values:\n",
        "    p.replace('a', 'b')\n",
    ));
    assert!(!has_op(&comprehension, "filesystem.move"));
    assert!(!has_op(&comprehension, "filesystem.write"));

    let paths = py(concat!(
        "from pathlib import Path\n",
        "p = Path('/old')\n",
        "p, q = [Path('/unpacked'), 'x']\n",
        "p.unlink()\n",
        "for p in [Path('/iterated')]:\n",
        "    p.unlink()\n",
        "p = Path('/swapped')\n",
        "q = 'plain'\n",
        "p, q = q, p\n",
        "q.unlink()\n",
        "p.replace('a', 'b')\n",
    ));
    assert!(has(&paths, "filesystem.delete", "/unpacked"));
    assert!(has(&paths, "filesystem.delete", "/iterated"));
    assert!(has(&paths, "filesystem.delete", "/swapped"));
    assert!(!has(&paths, "filesystem.delete", "/old"));
    assert!(!has_op(&paths, "filesystem.move"));
}

#[test]
fn widened_path_parts_do_not_specialize_from_call_arguments() {
    let plan = py(concat!(
        "from pathlib import Path\n",
        "def remove(path):\n",
        "    path = Path('/a') if condition else Path('/b')\n",
        "    (path / 'x').unlink()\n",
        "remove('/etc/passwd')\n",
    ));
    assert!(has(&plan, "filesystem.delete", "?filesystem"));
    assert!(!has(&plan, "filesystem.delete", "/etc/passwd/x"));
    assert!(has_boundary(&plan, "unmodeled_dynamic"));
}

/// Return tracking stays deterministic.
#[test]
fn return_tracking_is_deterministic() {
    let src =
        "import os\nROOT=\"/c\"\ndef cp(t): return os.path.join(ROOT, t)\np = cp(x)\nos.remove(p)";
    let a = effinterp_proto::canonical_json(&py(src));
    let b = effinterp_proto::canonical_json(&py(src));
    assert_eq!(a, b);
}

#[test]
fn effectless_builtins_do_not_flood() {
    // print and sys.exit are effectless terminals: no unresolved_call boundary.
    // A real os.remove in the same body still deletes.
    let plan = py("import sys\nimport os\nprint('x')\nos.remove('/a')\nsys.exit(1)");
    assert!(!has_boundary(&plan, "unresolved_call"));
    assert!(has(&plan, "filesystem.delete", "/a"));
}

#[test]
fn dynamic_builtins_remain_boundaries() {
    // eval over a runtime value stays a dynamic boundary even though
    // sys.exit no longer floods.
    let plan = py("import os\neval(os.environ['X'])");
    assert!(has_boundary(&plan, "unmodeled_dynamic"));
}

fn has_op(plan: &Plan, op: &str) -> bool {
    plan.effects.iter().any(|e| e.operation.0 == op)
}

#[test]
fn open_result_write_is_a_filesystem_write() {
    // The `open(...)` inside a chained `.write(...)` is still reached.
    let plan = py("open('/tmp/x','w').write('data')");
    assert!(has(&plan, "filesystem.write", "/tmp/x"));
}

#[test]
fn open_handle_method_does_not_dispatch_to_same_named_function() {
    let plan = py(concat!(
        "def write(path, a, b):\n",
        "    with open(path, 'w') as f:\n",
        "        f.write(a)\n",
        "        f.write(b)\n",
        "class Other:\n",
        "    def write(self, value): open('/tmp/phantom', 'w')\n",
        "write('/tmp/notes.txt', 'a', 'b')\n",
    ));
    assert!(
        !plan.boundaries.iter().any(|boundary| {
            boundary.reason == effinterp_proto::BoundaryReason::DYNAMIC_DISPATCH
        })
    );
    let writes: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.write")
        .collect();
    assert_eq!(writes.len(), 1, "{:?}", plan.effects);
    assert!(matches!(
        &writes[0].resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if path == "/tmp/notes.txt"
    ));
}

#[test]
fn io_open_is_modeled_like_builtin_open() {
    let plan = py("import io\nio.open('/a','w')");
    assert!(has(&plan, "filesystem.write", "/a"));
    let read = py("from io import open\nopen('/b')");
    assert!(has(&read, "filesystem.read", "/b"));
}

#[test]
fn os_listdir_scandir_stat_are_modeled() {
    let listdir = py("import os\nos.listdir('/etc')");
    assert!(has(&listdir, "filesystem.read", "/etc"));
    // A content listing is not a metadata probe.
    assert!(!listdir.effects[0].attributes.contains_key("metadata"));
    assert!(has(
        &py("import os\nos.scandir('/etc')"),
        "filesystem.read",
        "/etc"
    ));
    // Stat probes are metadata reads, matching the fsutils ls/stat models.
    let stat = py("import os\nos.stat('/etc/passwd')");
    assert!(has(&stat, "filesystem.read", "/etc/passwd"));
    assert_eq!(
        stat.effects[0].attributes.get("metadata"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
}

#[test]
fn pathlib_open_uses_its_mode() {
    let plan = py("from pathlib import Path\nPath('/tmp/z').open('w')");
    assert!(has(&plan, "filesystem.write", "/tmp/z"));
    let read = py("from pathlib import Path\nPath('/tmp/z').open()");
    assert!(has(&read, "filesystem.read", "/tmp/z"));
}

#[test]
fn typed_path_parameters_require_the_exact_annotation() {
    let plan = py(concat!(
        "from pathlib import Path\n",
        "def load(path: Path):\n",
        "    return path.read_text()\n",
        "load('/tmp/tox.ini')\n",
    ));
    assert!(has(&plan, "filesystem.read", "/tmp/tox.ini"));

    let wrong = py(concat!(
        "from other import Path\n",
        "def load(path: Path):\n",
        "    return path.read_text()\n",
        "load('/tmp/tox.ini')\n",
    ));
    assert!(!has(&wrong, "filesystem.read", "/tmp/tox.ini"));
}

#[test]
fn typed_path_attributes_and_class_string_keys_are_exact() {
    let plan = py(concat!(
        "import os\n",
        "from pathlib import Path\n",
        "class Config:\n",
        "    KEY = 'TOX_USER_CONFIG_FILE'\n",
        "    def __init__(self):\n",
        "        self.path = Path('/tmp/config.ini')\n",
        "        self.path = self.path.absolute()\n",
        "        self._load()\n",
        "    def _load(self):\n",
        "        os.environ.get(self.KEY)\n",
        "        self.path.open()\n",
        "Config()\n",
    ));
    assert!(has(&plan, "environment.read", "$TOX_USER_CONFIG_FILE"));
    assert!(has(&plan, "filesystem.read", "/tmp/config.ini"));

    let wrong = py(concat!(
        "from other import Path\n",
        "class Config:\n",
        "    def __init__(self):\n",
        "        self.path = Path('/tmp/config.ini')\n",
        "        self._load()\n",
        "    def _load(self):\n",
        "        self.path.open()\n",
        "Config()\n",
    ));
    assert!(!has_op(&wrong, "filesystem.read"));
}

#[test]
fn requests_request_verb_and_endpoint() {
    // The URL is the second argument; the verb classifies the operation.
    let plan = py("import requests\nrequests.request('POST', 'https://api.test/a', data=d)");
    assert!(has(&plan, "network.upload", "api.test"));
}

#[test]
fn requests_session_chained_is_network() {
    let plan = py("import requests\nrequests.Session().post('https://x.com/a', data=d)");
    assert!(has(&plan, "network.upload", "x.com"));
    let get = py("import requests\nrequests.Session().get('https://x.com/b')");
    assert!(has(&get, "network.request", "x.com"));
}

#[test]
fn modeled_network_constructors_are_not_external_unmodeled() {
    for source in [
        "import requests\nrequests.Session()",
        "import httpx\nhttpx.Client()",
        "import httpx\nhttpx.AsyncClient()",
        "import http.client\nhttp.client.HTTPConnection('example.com')",
        "import http.client\nhttp.client.HTTPSConnection('example.com')",
    ] {
        let plan = py(source);
        assert!(
            plan.boundaries
                .iter()
                .all(|boundary| boundary.reason.as_str() != "external_unmodeled"),
            "{source}: {:?}",
            plan.boundaries
        );
    }
}

#[test]
fn session_returned_from_a_helper_is_tracked() {
    // The constructor is hidden behind a helper's return value (httpie's
    // `requests_session = build_requests_session()`); the caller's `.send`
    // must still resolve to a network effect.
    let plan = py(concat!(
        "import requests\n",
        "def make_session():\n",
        "    s = requests.Session()\n",
        "    return s\n",
        "def run(req):\n",
        "    session = make_session()\n",
        "    return session.post('https://x.com/a', data=req)\n",
        "run('r')\n",
    ));
    assert!(has(&plan, "network.upload", "x.com"));
    // A helper that returns something else does not make its result a session.
    let non = py(concat!(
        "import requests\n",
        "def not_a_session():\n",
        "    return object()\n",
        "def run(req):\n",
        "    session = not_a_session()\n",
        "    session.post('https://x.com/a', data=req)\n",
        "run('r')\n",
    ));
    assert!(!has(&non, "network.upload", "x.com"));
}

#[test]
fn requests_session_variable_is_tracked() {
    let plan = py("import requests\ns = requests.Session()\ns.post('https://x.com/a', data=d)");
    assert!(has(&plan, "network.upload", "x.com"));
    // Rebinding the name drops the session tracking.
    let rebound =
        py("import requests\ns = requests.Session()\ns = object()\ns.post('https://x.com/a')");
    assert!(!has(&rebound, "network.upload", "x.com"));
}

#[test]
fn httpx_module_and_client_are_network() {
    assert!(has(
        &py("import httpx\nhttpx.get('https://api.test/v1')"),
        "network.request",
        "api.test"
    ));
    let client = py("import httpx\nhttpx.Client().post('https://api.test/up', data=d)");
    assert!(has(&client, "network.upload", "api.test"));
}

#[test]
fn urlretrieve_is_download_and_write() {
    let plan =
        py("import urllib.request\nurllib.request.urlretrieve('https://x.com/f', '/tmp/out')");
    assert!(has(&plan, "network.download", "x.com"));
    assert!(has(&plan, "filesystem.write", "/tmp/out"));
}

#[test]
fn socket_connect_is_network() {
    let plan = py("import socket\nsocket.socket().connect(('example.com', 80))");
    assert!(has(&plan, "network.request", "example.com"));
}

#[test]
fn http_client_connection_request_hits_host() {
    let plan =
        py("import http.client\nhttp.client.HTTPConnection('example.com').request('GET', '/')");
    assert!(has(&plan, "network.request", "example.com"));
}

#[test]
fn non_literal_session_url_stays_symbolic() {
    let plan = py("import requests\ns = requests.Session()\nurl = input()\ns.get(url)");
    assert!(has(&plan, "network.request", "<url>"));
    // A non-literal endpoint is still a network effect, never dropped.
    assert!(has_op(&plan, "network.request"));
}

#[test]
fn class_method_and_constructor_are_followed() {
    // `self.method` and `Class()` reach the method body.
    let plan = py(
        "class Loader:\n    def __init__(self, p):\n        self._read(p)\n    def _read(self, p):\n        open(p)\nLoader('/a.yml')\n",
    );
    assert!(has(&plan, "filesystem.read", "/a.yml"));
    let via_self = py(
        "class C:\n    def run(self):\n        open('/b')\n    def main(self):\n        self.run()\nC.main(C())\n",
    );
    assert!(has(&via_self, "filesystem.read", "/b"));
}

#[test]
fn finite_containers_and_comprehensions_preserve_exact_paths() {
    let plan = py(
        "import os\nroots = ['/srv/a', '/srv/b']\npaths = [os.path.join(root, 'cache') for root in roots]\nfor path in paths:\n    os.remove(path)\nselected = {'log': '/var/log/app.log'}\nos.remove(selected['log'])\nfor final in ['/final']:\n    pass\nos.remove(final)\nfor skipped in []:\n    os.remove('/never')",
    );
    assert!(has(&plan, "filesystem.delete", "/srv/a/cache"));
    assert!(has(&plan, "filesystem.delete", "/srv/b/cache"));
    assert!(has(&plan, "filesystem.delete", "/var/log/app.log"));
    assert!(has(&plan, "filesystem.delete", "/final"));
    assert!(!has(&plan, "filesystem.delete", "/never"));
}

#[test]
fn container_mutation_removes_exact_selection_evidence() {
    let plan =
        py("import os\npaths = ['/safe']\nalias = paths\nalias.clear()\nos.remove(paths[0])");
    assert!(!has(&plan, "filesystem.delete", "/safe"));
    assert!(has_boundary(&plan, "unmodeled_dynamic"));
}

#[test]
fn context_manager_binds_only_a_proven_session_receiver() {
    let plan = py(
        "import requests\nwith requests.Session() as session:\n    session.get('https://api.test/context')",
    );
    assert!(has(&plan, "network.request", "api.test"));

    let negative = py(
        "import requests\nwith unknown_factory() as session:\n    session.get('https://api.test/context')",
    );
    assert!(!has(&negative, "network.request", "api.test"));
}

#[test]
fn exception_branch_values_survive_only_when_every_path_agrees() {
    let exact = py(
        "import os\ntry:\n    path = '/same'\nexcept OSError:\n    path = '/same'\nos.remove(path)",
    );
    assert!(has(&exact, "filesystem.delete", "/same"));

    let ambiguous =
        py("import os\ntry:\n    path = '/a'\nexcept OSError:\n    path = '/b'\nos.remove(path)");
    assert!(!has(&ambiguous, "filesystem.delete", "/a"));
    assert!(!has(&ambiguous, "filesystem.delete", "/b"));
    assert!(has_boundary(&ambiguous, "unmodeled_dynamic"));
}

#[test]
fn async_function_effects_require_await_or_a_static_runner() {
    let plan = py(
        "import asyncio, os\nasync def wipe(path):\n    os.remove(path)\nasync def locate(path):\n    return path\nwipe('/cold')\nasyncio.run(wipe('/hot'))\ncold = locate('/cold-return')\nhot = asyncio.run(locate('/hot-return'))\nos.remove(hot)",
    );
    assert!(has(&plan, "filesystem.delete", "/hot"));
    assert!(!has(&plan, "filesystem.delete", "/cold"));
    assert!(has(&plan, "filesystem.delete", "/hot-return"));
    assert!(!has(&plan, "filesystem.delete", "/cold-return"));
}

#[test]
fn consumed_generators_preserve_yielded_paths_but_unused_ones_stay_deferred() {
    let plan = py(
        "import os\ndef targets(root):\n    os.remove('/generator-ran')\n    for name in ['a', 'b']:\n        yield os.path.join(root, name)\ndef extras():\n    yield from ['/extra']\ntargets('/unused')\nfor path in targets('/srv'):\n    os.remove(path)\npaths = list(targets('/list'))\nos.remove(paths[1])\nfor path in extras():\n    os.remove(path)",
    );
    assert!(has(&plan, "filesystem.delete", "/generator-ran"));
    assert!(
        has(&plan, "filesystem.delete", "/srv/a"),
        "{:?}",
        plan.effects
    );
    assert!(has(&plan, "filesystem.delete", "/srv/b"));
    assert!(has(&plan, "filesystem.delete", "/list/b"));
    assert!(has(&plan, "filesystem.delete", "/extra"));

    let unused =
        py("import os\ndef targets():\n    os.remove('/not-run')\n    yield '/x'\ntargets()");
    assert!(!has(&unused, "filesystem.delete", "/not-run"));
}

#[test]
fn contextmanager_protocol_executes_the_generator_body() {
    let plan = py(
        "import contextlib, os\n@contextlib.contextmanager\ndef cleanup(path):\n    yield path\n    os.remove('/tmp/finalizer')\nwith cleanup('/tmp/context') as path:\n    os.remove(path)",
    );
    assert!(has(&plan, "filesystem.delete", "/tmp/context"));
    assert!(has(&plan, "filesystem.delete", "/tmp/finalizer"));

    let unused = py(
        "import contextlib, os\n@contextlib.contextmanager\ndef cleanup(path):\n    yield path\n    os.remove(path)\ncleanup('/tmp/context')",
    );
    assert!(!has(&unused, "filesystem.delete", "/tmp/context"));
}

#[test]
fn closure_captures_are_specialized_through_the_enclosing_call() {
    let plan = py(
        "import os\ndef outer(root):\n    def wipe(name):\n        os.remove(os.path.join(root, name))\n    wipe('cache')\nouter('/srv')",
    );
    assert_eq!(delete_resource(&plan), "/srv/cache");

    let out_of_scope = py(
        "import os\ndef outer(root):\n    def wipe(name):\n        os.remove(os.path.join(root, name))\nwipe('cache')",
    );
    assert!(!has_op(&out_of_scope, "filesystem.delete"));
}

#[test]
fn decorators_require_static_identity_evidence() {
    let identity = py(
        "import os\ndef identity(fn):\n    return fn\n@identity\ndef wipe(path):\n    os.remove(path)\nwipe('/decorated')",
    );
    assert!(has(&identity, "filesystem.delete", "/decorated"));

    let replacement = py(
        "import os\ndef suppress(fn):\n    return lambda *args: None\n@suppress\ndef wipe(path):\n    os.remove(path)\nwipe('/decorated')",
    );
    assert!(has_op(&replacement, "filesystem.delete"));
    assert!(has_boundary(&replacement, "unresolved_decorator"));

    let named_replacement = py(
        "import os\ndef suppress(fn):\n    def wrapper(*args):\n        pass\n    return wrapper\n@suppress\ndef wipe(path):\n    os.remove(path)\nwipe('/decorated')",
    );
    assert!(has_op(&named_replacement, "filesystem.delete"));
    assert!(has_boundary(&named_replacement, "unresolved_decorator"));
}

#[test]
fn effectful_decorator_keeps_process_wrapper_opaque() {
    let plan = py(
        "import subprocess\ndef audit(func):\n    def wrapper():\n        func()\n        subprocess.Popen(['curl', 'https://example.test'])\n    return wrapper\n@audit\ndef run():\n    pass\nrun()",
    );
    assert!(has_op(&plan, "process.exec"));
    assert!(has_boundary(&plan, "unresolved_decorator"));
}

#[test]
fn effectful_decorator_keeps_filesystem_wrapper_opaque() {
    let plan = py(
        "import os\ndef audit(func):\n    def wrapper(dst, src):\n        func(dst, src)\n        os.remove(src)\n    return wrapper\n@audit\ndef work(src, dst):\n    pass\nwork('/source', '/destination')",
    );
    assert!(has_op(&plan, "filesystem.delete"));
    assert!(has_boundary(&plan, "unresolved_decorator"));
    assert!(!has(&plan, "filesystem.delete", "/source"));
}

#[test]
fn decorator_factory_expression_executes_at_definition_time() {
    let plan = py(
        "import os\ndef register(path):\n    os.remove(path)\n    return lambda fn: fn\n@register('/registration')\ndef task():\n    pass",
    );
    assert!(has(&plan, "filesystem.delete", "/registration"));
}

#[test]
fn external_instance_methods_require_an_exact_receiver_type() {
    let url = ResourceExpr::Concrete {
        identity: ResourceIdentity::NetworkEndpoint {
            scheme: Some("https".into()),
            host: "api.example.test".into(),
            port: None,
            path: Some("/items".into()),
        },
    };
    let effects = python_external_method_effects(
        "requests.Session",
        "get",
        None,
        &[ValueArgument::positional(0, url.clone())],
    )
    .expect("requests session is modeled");
    assert_eq!(effects[0].operation.0, "network.request");
    assert_eq!(effects[0].resource, url);

    let path = ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: "/not/a/url".into(),
        },
    };
    let effects = python_external_method_effects(
        "requests.Session",
        "get",
        None,
        &[ValueArgument::positional(0, path)],
    )
    .expect("requests session is modeled");
    assert!(matches!(
        &effects[0].resource,
        ResourceExpr::Unresolved { family } if family.0 == "network"
    ));

    let effects = python_external_method_effects(
        "requests.Session",
        "send",
        None,
        &[ValueArgument::positional(0, url)],
    )
    .expect("requests session is modeled");
    assert!(matches!(
        &effects[0].resource,
        ResourceExpr::Unresolved { family } if family.0 == "network"
    ));
    assert!(python_external_method_effects("LocalSession", "send", None, &[]).is_none());
}

#[test]
fn external_instance_methods_bind_keyword_arguments() {
    let url = ResourceExpr::Concrete {
        identity: ResourceIdentity::NetworkEndpoint {
            scheme: Some("https".into()),
            host: "api.example.test".into(),
            port: None,
            path: Some("/items".into()),
        },
    };
    let effects = python_external_method_effects(
        "requests.Session",
        "request",
        None,
        &[
            ValueArgument::keyword("url", 0, url.clone()),
            ValueArgument::keyword(
                "method",
                0,
                ResourceExpr::Literal {
                    value: "POST".into(),
                },
            ),
        ],
    )
    .expect("requests session is modeled");
    assert_eq!(effects[0].operation.0, "network.upload");
    assert_eq!(effects[0].resource, url);

    let path = ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: "/tmp/output".into(),
        },
    };
    let effects = python_external_method_effects(
        "pathlib.Path",
        "open",
        Some(path.clone()),
        &[ValueArgument::keyword(
            "mode",
            0,
            ResourceExpr::Literal { value: "w".into() },
        )],
    )
    .expect("path open is modeled");
    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].operation.0, "filesystem.write");
    assert_eq!(effects[0].resource, path);
}

#[test]
fn external_pathlib_methods_match_local_path_dispatch() {
    let source = ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: "/tmp/source".into(),
        },
    };
    let target = ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: "/tmp/target".into(),
        },
    };
    let rename = python_external_method_effects(
        "pathlib.Path",
        "rename",
        Some(source.clone()),
        &[ValueArgument::positional(0, target.clone())],
    )
    .expect("path rename is modeled");
    assert_eq!(rename.len(), 2);
    assert_eq!(rename[0].operation.0, "filesystem.move");
    assert_eq!(rename[0].resource, source.clone());
    assert_eq!(rename[1].operation.0, "filesystem.write");
    assert_eq!(rename[1].resource, target);

    let stat = python_external_method_effects("pathlib.Path", "stat", Some(source), &[])
        .expect("path stat is modeled");
    assert_eq!(
        stat[0].attributes.get("metadata"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );

    let mkdir = python_external_method_effects(
        "pathlib.Path",
        "mkdir",
        Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: "/tmp/tree".into(),
            },
        }),
        &[ValueArgument::keyword(
            "parents",
            0,
            ResourceExpr::Literal {
                value: "true".into(),
            },
        )],
    )
    .expect("path mkdir is modeled");
    assert_eq!(
        mkdir[0].attributes.get("parents"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
}

#[test]
fn in_function_git_push_composes_remote_sync() {
    let plan = py(
        "import subprocess\ndef push():\n    subprocess.run(['git', 'push', '--force', 'origin', 'main'])\npush()\n",
    );
    let sync = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.remote_sync")
        .expect("in-function git push composes");
    assert_eq!(sync.attributes.get("force"), Some(&AttrValue::Bool(true)));
    assert_eq!(sync.attributes.get("push"), Some(&AttrValue::Bool(true)));
    assert!(!has_boundary(&plan, "uncomposed_subprocess"));
}

#[test]
fn bound_list_argument_composes_subprocess() {
    let plan = py(
        "import subprocess\ndef sh(cmd):\n    subprocess.run(cmd)\nsh(['rm', '-rf', '/tmp/z'])\n",
    );
    assert!(has(&plan, "filesystem.delete", "/tmp/z"));
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert_eq!(
        delete.attributes.get("recursive"),
        Some(&AttrValue::Bool(true))
    );
}

#[test]
fn os_system_inside_function_nests_shell() {
    let plan = py("import os\ndef wipe():\n    os.system('rm -rf /var/www/current')\nwipe()\n");
    assert!(has(&plan, "filesystem.delete", "/var/www/current"));
}

#[test]
fn shlex_split_nests_exec() {
    let plan = py(
        "import subprocess, shlex\nsubprocess.run(shlex.split('git push --force origin main'))\n",
    );
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "git.remote_sync")
    );
}

#[test]
fn unbound_argv_stays_symbolic() {
    let plan =
        py("import subprocess\ndef run(cmd):\n    subprocess.run(['git', cmd])\nrun(unknown())\n");
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "process.exec")
    );
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "unmodeled_dynamic"
            || boundary.reason.as_str() == "unresolved_alias"
            || !boundary.domains.is_empty()
    }));
}

#[test]
fn pathlib_globs_include_hidden_names_in_local_and_external_dispatch() {
    for glob in ["a**b", "["] {
        let plan = py(&format!(
            "from pathlib import Path\nlist(Path('/tmp').glob({glob:?}))"
        ));
        assert!(
            plan.boundaries.iter().any(
                |boundary| boundary.reason == effinterp_proto::BoundaryReason::UNTYPED_RESOURCE
            ),
            "{glob}: {:?}",
            plan.boundaries
        );
    }

    for glob in ["../*", "a/../../*.rs", "../[ab]/*"] {
        let plan = py(&format!(
            "from pathlib import Path\nlist(Path('/tmp/root').glob({glob:?}))"
        ));
        let external = python_external_method_effects(
            "pathlib.Path",
            "glob",
            Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: "/tmp/root".into(),
                },
            }),
            &[ValueArgument::positional(
                0,
                ResourceExpr::Literal { value: glob.into() },
            )],
        )
        .unwrap();
        for effects in [&plan.effects, &external] {
            for target in ["/tmp/.hidden.rs", "/tmp/a/.hidden", "/tmp/visible.rs"] {
                assert!(effects.iter().any(|effect| matches!(&effect.resource,
                    ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern } } if effinterp_proto::glob_match(pattern, target) == Ok(true)
                )), "{glob}: {effects:?}");
            }
        }
        let recursive = py(&format!(
            "from pathlib import Path\nlist(Path('/tmp/root').rglob({glob:?}))"
        ));
        assert!(
            recursive.boundaries.iter().any(
                |boundary| boundary.reason == effinterp_proto::BoundaryReason::UNTYPED_RESOURCE
            )
        );
    }

    for root in ["/tmp/[ab]", r"/tmp/a\b", "/tmp/plain"] {
        for method in ["glob", "rglob"] {
            let plan = py(&format!(
                "from pathlib import Path\nlist(Path({root:?}).{method}('*'))"
            ));
            let external = python_external_method_effects(
                "pathlib.Path",
                method,
                Some(ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: root.into() },
                }),
                &[ValueArgument::positional(
                    0,
                    ResourceExpr::Literal { value: "*".into() },
                )],
            )
            .unwrap();
            for effects in [&plan.effects, &external] {
                for tail in [".hidden", "visible", ".hidden/nested"] {
                    assert!(effects.iter().any(|effect| {
                        effect.operation.0 == "filesystem.read"
                            && matches!(&effect.resource, ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern } }
                                if effinterp_proto::glob_match(pattern, &format!("{root}/{tail}")) == Ok(true))
                    }), "{method} at {root}: {effects:?}");
                }
            }
        }
    }
}

#[test]
fn quiet_python_calls_require_exact_binding_and_safe_operands() {
    for source in [
        "print('hello', 3); len([1, 2]); str(1); list((1, 2)); dict(); sorted([3, 1]); isinstance(1, int)",
        "import json\nvalues = list((1, 2)); len(values); json.dumps(values)",
        "import sys\nout = sys.stdout; print('x'); print('x', file=sys.stdout); print('x', file=sys.stderr)",
        "import os\npath = os.path.join(b'/srv', b'cache'); path.decode('utf-8').strip()",
        "import os, re\np = '/srv'; os.path.join(p, 'cache'); os.path.dirname(p); re.compile(p)",
        "import json, re, time, argparse, logging, sys\njson.dumps({'a': [1, 2]}); json.loads('{}'); re.search('x', 'text'); re.match('x', 'text'); re.fullmatch('x', 'text'); re.escape('x'); time.time(); time.monotonic(); time.perf_counter(); time.sleep(1); time.strftime('%Y'); argparse.ArgumentParser(description='app'); logging.getLogger('app'); sys.path.append('/src'); sys.path.insert(0, '/src')",
    ] {
        let plan = py(source);
        assert!(
            plan.boundaries.iter().all(|b| b.callee.is_none()),
            "{source}: {:?}",
            plan.boundaries
        );
        assert!(plan.effects.is_empty(), "{source}: {:?}", ops(&plan));
    }
    for source in [
        "values = [1]; alias = values; alias.append(unknown); str(values)",
        "values = [1]; mutate(values); str(values)",
        "import re\nre.compile('x', 0, flags=0)",
        "str(unknown)",
        "len(unknown)",
        "iter(unknown)",
        "hasattr(unknown, 'field')",
        "def f(x: str):\n    str(x)\nf(unknown)",
        "print('data', file=writer)",
        "import json\njson.dump({}, writer)",
        "import json\njson.load(reader)",
        "import logging\nlogging.basicConfig(filename='/tmp/log')",
        "import os\nos.path.join(unknown, 'x')",
        "import sys\nsys.path = unknown\nsys.path.append('/x')",
        "from pathlib import Path\ndef f(x: Path):\n    x.read_text().strip()\nf(unknown)",
        "import re\nre.compile(*unknown)",
        "import json\njson.dumps({}, default=unknown)",
        "with unknown():\n    pass",
        "import argparse\nwith argparse.ArgumentParser():\n    pass",
        "import re\nre.unknown('x')",
    ] {
        let plan = py(source);
        assert!(
            !plan.boundaries.iter().all(|b| b.callee.is_none()),
            "silenced {source}"
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.callee.is_some() && !b.provenance.is_empty()),
            "{source}"
        );
    }
    for source in [
        "import os\ndef len(x):\n    os.remove('/shadow')\nlen('a')",
        "import os\nos.path.join = lambda x, y: os.remove('/shadow')\nos.path.join('a', 'b')",
        "import os\nclass C:\n    def __str__(self):\n        os.remove('/shadow')\nstr(C())",
        "import os\nsorted([1], key=lambda x: os.remove('/shadow'))",
    ] {
        let plan = py(source);
        assert!(
            has(&plan, "filesystem.delete", "/shadow")
                || !plan.boundaries.iter().all(|b| b.callee.is_none()),
            "{source}"
        );
    }
    for source in [
        "values = [1]; alias = values; alias.append(unknown); str(values)",
        "values = [1]; mutate(values); str(values)",
        "values = [1]; values[0] = unknown; str(values)",
    ] {
        let plan = py(source);
        assert!(
            plan.boundaries.iter().any(|b| {
                b.callee
                    .as_ref()
                    .is_some_and(|callee| callee.symbol == "str")
            }),
            "stale container evidence: {source}"
        );
    }
    // Stale exact values would hide custom conversion/iteration hooks and path IO.
    for (source, callee) in [
        ("def run(format):\n    format('x')\nrun(unknown)", "format"),
        ("def run(str=unknown):\n    str('x')\nrun()", "str"),
        ("def run(*, len):\n    len('x')\nrun(len=unknown)", "len"),
        ("def run(*print):\n    print('x')\nrun(unknown)", "print"),
        ("def run(**str):\n    str('x')\nrun(x=unknown)", "str"),
        (
            "import builtins\ndef change():\n    builtins.print = unknown\n[change() for x in [1]]\nprint('x')",
            "print",
        ),
        (
            "import builtins\ndef change():\n    builtins.print = unknown\n[change() for x in items]\nprint('x')",
            "print",
        ),
        ("(len := unknown)\nlen('x')", "len"),
        (
            "import sys\nout, = [sys.stdout]\nalias = out\nalias.write = unknown\nprint('x')",
            "print",
        ),
        (
            "import sys\nout = sys.stdout\nfor out.write in items:\n    pass\nprint('x')",
            "print",
        ),
        ("import foo\nwith foo.cm() as len:\n    len([1])", "len"),
        (
            "import foo\nasync with foo.cm() as len:\n    len([1])",
            "len",
        ),
        (
            "import foo, sys\nwith foo.cm() as sys:\n    print('x', file=sys.stdout)",
            "print",
        ),
        (
            "import foo, json\nwith foo.cm() as json:\n    json.dumps('x')",
            "json.dumps",
        ),
        (
            "import foo, os\nwith foo.cm() as os:\n    os.path.join('a', 'b')",
            "os.path.join",
        ),
        (
            "import sys, foo\nout = sys.stdout\nout.write = foo.w\nprint('x')",
            "print",
        ),
        (
            "import sys, foo\nout = sys.stdout\nout.__class__ = foo.C\nprint('x')",
            "print",
        ),
        (
            "import sys, foo\nout = sys.stderr\nout.__class__ = foo.C\nprint('x', file=sys.stderr)",
            "print",
        ),
        (
            "import sys, foo\ndef h(o):\n    o.__class__ = foo.C\nh(sys.stdout)\nprint('x')",
            "print",
        ),
        (
            "import sys, foo\nout = sys.stdout\nout.flush = foo.w\nprint('x', flush=True)",
            "print",
        ),
        (
            "import sys, foo\ndef h(o):\n    o.flush = foo.w\nh(sys.stdout)\nprint('x', flush=True)",
            "print",
        ),
        (
            "from sys import stderr\nout, = [stderr]\nout.flush = unknown\nprint('x', file=stderr, flush=True)",
            "print",
        ),
        (
            "import sys, foo\nout = sys.stdout\nfor out.__class__ in [foo.C]:\n    pass\nprint('x')",
            "print",
        ),
        (
            "import sys, foo\nout = sys.stdout\nwith foo.cm() as out.flush:\n    print('x', flush=True)",
            "print",
        ),
        (
            "from sys import stdout\nout = stdout\nout.write = unknown\nprint('x')",
            "print",
        ),
        (
            "import sys, foo\nfor sys.stdout in [foo.w]:\n    pass\nprint('x')",
            "print",
        ),
        (
            "import builtins, foo\nfor builtins.len in [foo.f]:\n    pass\nlen([1])",
            "len",
        ),
        (
            "import builtins, foo\nasync for builtins.len in items:\n    pass\nlen([1])",
            "len",
        ),
        (
            "import builtins, foo\nwith foo.cm() as builtins.len:\n    pass\nlen([1])",
            "len",
        ),
        (
            "import builtins, foo\nasync with foo.cm() as builtins.len:\n    pass\nlen([1])",
            "len",
        ),
        (
            "import builtins, foo\nfor (x, builtins.len) in items:\n    pass\nlen([1])",
            "len",
        ),
        (
            "import builtins\n[0 for builtins.len in items]\nlen([1])",
            "len",
        ),
        (
            "def g():\n    pass\nd = g.__globals__\nd['len'] = unknown\nlen('x')",
            "len",
        ),
        (
            "d = (lambda: 0).__globals__\nd['len'] = unknown\nlen('x')",
            "len",
        ),
        (
            "def g():\n    pass\ng.__globals__['len'] = unknown\nlen('x')",
            "len",
        ),
        (
            "def run():\n    d = run.__globals__\n    d['len'] = unknown\n    len('x')\nrun()",
            "len",
        ),
        (
            "import os\ns = os.__dict__['sys']\ns.stdout = writer\nprint('x')",
            "print",
        ),
        (
            "import os\nd = os.__dict__\nd['sys'].stdout = writer\nprint('x')",
            "print",
        ),
        (
            "import os\nos.__dict__['sys'].stdout = writer\nprint('x')",
            "print",
        ),
        (
            "from os import __dict__ as d\nd['sys'].stdout = writer\nprint('x')",
            "print",
        ),
        ("d = frame.f_globals\nd['len'] = unknown\nlen('x')", "len"),
        ("d = frame.f_builtins\nd['len'] = unknown\nlen('x')", "len"),
        (
            "s = 'x'\nd = frame.f_locals\nd['s'] = unknown\nstr(s)",
            "str",
        ),
        (
            "def g():\n    pass\nd = {'ns': g.__globals__}\nd['ns']['len'] = unknown\nlen('x')",
            "len",
        ),
        ("b = print.__self__\nb.len = unknown\nlen('x')", "len"),
        (
            "p = print\nb = p.__self__\nb.len = unknown\nlen('x')",
            "len",
        ),
        ("print.__self__.len = unknown\nlen('x')", "len"),
        (
            "from builtins import print as p\nb = p.__self__\nb.len = unknown\nlen('x')",
            "len",
        ),
        (
            "from os import sys\nsys.stdout = writer\nprint('x')",
            "print",
        ),
        (
            "from os import sys as s\ns.stdout = writer\nprint('x')",
            "print",
        ),
        ("import os\nos.sys.stdout = writer\nprint('x')", "print"),
        (
            "import os\nm = os.sys\nm.stdout = writer\nprint('x')",
            "print",
        ),
        (
            "import logging\nlogging.sys.stdout = writer\nprint('x')",
            "print",
        ),
        ("m = unknown.builtins\nm.len = unknown\nlen('x')", "len"),
        (
            "from module import __main__ as m\nm.print = unknown\nprint('x')",
            "print",
        ),
        (
            "import os\ndef run():\n    os.sys.stdout = writer\n    print('x')\nrun()",
            "print",
        ),
        (
            "def run():\n    b = print.__self__\n    b.len = unknown\n    len('x')\nrun()",
            "len",
        ),
        (
            "import builtins\nbuiltins.print = unknown\nprint('x')",
            "print",
        ),
        ("import builtins as b\nb.str = unknown\nstr('x')", "str"),
        ("__builtins__.print = unknown\nprint('x')", "print"),
        (
            "d = __builtins__.__dict__\nd['print'] = unknown\nprint('x')",
            "print",
        ),
        (
            "import builtins\nx = builtins\nx.print = unknown\nprint('x')",
            "print",
        ),
        (
            "import builtins\ndef change(m):\n    m.print = unknown\nchange(builtins)\nprint('x')",
            "print",
        ),
        (
            "import builtins\nd = {'b': builtins}\nd['b'].print = unknown\nprint('x')",
            "print",
        ),
        (
            "import builtins\nfor m in [builtins]:\n    m.print = unknown\nprint('x')",
            "print",
        ),
        (
            "from builtins import __dict__ as d\nd['print'] = unknown\nprint('x')",
            "print",
        ),
        (
            "from builtins import __dict__\n__dict__['len'] = unknown\nlen('x')",
            "len",
        ),
        (
            "import sys\nm = sys\nm.stdout = writer\nprint('x')",
            "print",
        ),
        (
            "import sys\ndef change(m):\n    m.stdout = writer\nchange(sys)\nprint('x')",
            "print",
        ),
        (
            "import sys\nsys.stdout.write = unknown\nprint('x')",
            "print",
        ),
        (
            "import sys\ns = 'a'\nm = sys.modules[__name__]\nm.s = obj\nstr(s)",
            "str",
        ),
        ("import __main__\ns = 'a'\n__main__.s = obj\nstr(s)", "str"),
        (
            "import builtins\ndef namespace():\n    return builtins\nm = namespace()\nm.print = unknown\nprint('x')",
            "print",
        ),
        (
            "import builtins\nbuiltins.__dict__['len'] = unknown\nlen('x')",
            "len",
        ),
        ("globals()['print'] = unknown\nprint('x')", "print"),
        ("s = 'a'\nglobals()['s'] = obj\nstr(s)", "str"),
        (
            "import sys\ns = 'a'\nsys.modules[__name__].s = obj\nstr(s)",
            "str",
        ),
        (
            "import sys\nsys.__dict__['stdout'] = writer\nprint('x')",
            "print",
        ),
        (
            "import builtins\ndef change():\n    builtins.print = unknown\nchange()\nprint('x')",
            "print",
        ),
        ("str, other = unknown, 1\nstr('x')", "str"),
        ("s = unknown\nclass C:\n    s = str(1)\nstr(s)", "str"),
        ("for str in funcs:\n    str('x')", "str"),
        ("[str('x') for str in funcs]", "str"),
        ("s = 'a'\nx, s = 1, obj\nstr(s)", "str"),
        (
            "import os\np = '/a'\n_, p = 1, obj\nos.path.join(p, 'x')",
            "os.path.join",
        ),
        (
            "import os\np = '/a'\nfor p in objs:\n    os.path.join(p, 'x')",
            "os.path.join",
        ),
        ("s = 'a'\nwhile cond:\n    str(s)\n    s = obj", "str"),
        ("v = [1]\nwhile cond:\n    str(v)\n    v = obj", "str"),
        ("s = 'a'\nfor item in objs:\n    str(s)\n    s = obj", "str"),
        ("s = 'a'\n[str(s) for s in objs]", "str"),
        ("v = [1]\nwhile cond:\n    str(v)\n    v[0] = obj", "str"),
        ("v = [1]\nwhile cond:\n    str(v)\n    v.append(obj)", "str"),
        ("s = 'a'\nwhile cond:\n    str(s)\n    (s := obj)", "str"),
        (
            "import tempfile\np = tempfile.mkdtemp()\nwhile cond:\n    str(p)\n    p = obj",
            "str",
        ),
        ("v = [1]\n[str(v) for v in [obj]]", "str"),
        (
            "e = 'a'\ntry:\n    pass\nexcept E as e:\n    print(str(e))",
            "str",
        ),
        (
            "s = 'a'\ndef change():\n    global s\n    s = obj\nchange()\nstr(s)",
            "str",
        ),
        (
            "s = 'a'\ndef change():\n    global s\n    s = obj\ndef main():\n    change()\n    str(s)\nmain()",
            "str",
        ),
        (
            "s = 'a'\ndef change(*args):\n    global s\n    s = obj\nd = {'k': change}\nd['k']()\nstr(s)",
            "str",
        ),
        (
            "s = 'a'\ndef change(*args):\n    global s\n    s = obj\nx = [change]\nx[0]()\nstr(s)",
            "str",
        ),
        (
            "s = 'a'\ndef change(*args):\n    global s\n    s = obj\nlist(map(change, [1]))\nstr(s)",
            "str",
        ),
        (
            "s = 'a'\ndef change(*args):\n    global s\n    s = obj\nsorted([1], key=change)\nstr(s)",
            "str",
        ),
        (
            "s = 'a'\nclass K:\n    global s\n    s = obj\nstr(s)",
            "str",
        ),
        (
            "s = 'a'\ndef change():\n    global s\n    s = obj\nclass K:\n    unknown(change)\nstr(s)",
            "str",
        ),
        (
            "def outer():\n    s = 'a'\n    class K:\n        nonlocal s\n        s = obj\n    return str(s)\nouter()",
            "str",
        ),
        ("import sys\nsys.stdout = writer\nprint('x')", "print"),
        (
            "import sys\nsys.stdout = writer\nprint('x', file=sys.stdout)",
            "print",
        ),
        (
            "import os\nclass C:\n    def __str__(self):\n        os.remove('/victim')\nlabel = 'a'\nlabel, other = C(), 1\nprint(str(label))",
            "str",
        ),
        (
            "import os\nclass C:\n    def __len__(self):\n        os.remove('/victim')\nv = 'a'\nfor v in [C()]:\n    len(v)",
            "len",
        ),
    ] {
        let plan = py(source);
        assert!(
            plan.boundaries.iter().any(|b| {
                b.callee.as_ref().is_some_and(|c| {
                    c.symbol == callee || c.symbol == callee.rsplit('.').next().unwrap()
                }) && !b.provenance.is_empty()
            }),
            "stale evidence for {callee}: {source}\n{:?}",
            plan.boundaries
        );
    }
    for source in [
        "import os\ndef run(open):\n    open('/not-a-read')\nrun(unknown)",
        "import os\ndef run(os):\n    os.remove('/not-a-delete')\nrun(unknown)",
    ] {
        let plan = py(source);
        assert!(plan.effects.is_empty(), "{source}: {:?}", ops(&plan));
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.callee.is_some() && !b.provenance.is_empty())
        );
    }
    let target_call = py("import os\nd[os.remove('/target-index')] = 1");
    assert!(has(&target_call, "filesystem.delete", "/target-index"));
    let scope = py("def run(str):\n    str('x')\nrun(unknown)\nlen('x')");
    assert!(
        !scope
            .boundaries
            .iter()
            .any(|b| b.callee.as_ref().is_some_and(|c| c.symbol == "len"))
    );
    let rebound_path = py(
        "from pathlib import Path\np = Path('/stale')\nwhile cond:\n    p.read_text()\n    p = obj",
    );
    assert!(!has(&rebound_path, "filesystem.read", "/stale"));
    assert!(
        rebound_path
            .boundaries
            .iter()
            .any(|b| !b.provenance.is_empty())
    );
    let plan = py("import os\nmap(lambda x: os.remove('/deferred'), [1])");
    assert!(!has(&plan, "filesystem.delete", "/deferred"));
    assert!(!plan.boundaries.iter().all(|b| b.callee.is_none()));
    let consumed = py("import os\nlist(map(lambda x: os.remove('/deferred'), [1]))");
    assert!(
        has(&consumed, "filesystem.delete", "/deferred")
            || consumed
                .boundaries
                .iter()
                .any(|b| b.callee.as_ref().is_some_and(|c| c.symbol == "map"))
    );
    for source in [
        "import os, json\njson.dumps({}, default=lambda x: os.remove('/not-called'))",
        "import os\nsorted([], key=lambda x: os.remove('/not-called'))",
    ] {
        let plan = py(source);
        assert!(!has(&plan, "filesystem.delete", "/not-called"));
        assert!(plan.boundaries.iter().any(|b| b.callee.is_some()));
    }
}

#[test]
fn python_stdlib_resources_preserve_execution_and_return_shapes() {
    let context = py("with open('/input') as open:\n    pass");
    assert!(has(&context, "filesystem.read", "/input"));
    assert!(context.boundaries.iter().all(|b| b.callee.is_none()));
    let plan = py(
        "import os, shutil\nshutil.rmtree(os.path.expanduser('~/.hermes/cache'))\nos.path.exists('/metadata')\nos.kill(123, 15)",
    );
    let deleted = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .unwrap();
    let resource = serde_json::to_string(&deleted.resource).unwrap();
    assert!(
        resource.contains("HOME") && resource.contains(".hermes/cache"),
        "{resource}"
    );
    let nested = py(
        "import os, shutil\nshutil.rmtree(os.path.join(os.path.expanduser('~/.hermes'), 'cache'))",
    );
    let nested_resource = serde_json::to_string(
        &nested
            .effects
            .iter()
            .find(|e| e.operation.0 == "filesystem.delete")
            .unwrap()
            .resource,
    )
    .unwrap();
    assert!(
        nested_resource.contains("HOME") && nested_resource.contains("cache"),
        "{nested_resource}"
    );
    assert!(has(&plan, "filesystem.read", "/metadata"));
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "process.signal" && !e.provenance.is_empty())
    );
    let unknown_home = py("import os\nos.path.expanduser('~someone/file')");
    assert!(!unknown_home.boundaries.iter().all(|b| b.callee.is_none()));
    assert!(!has(&unknown_home, "environment.read", "$HOME"));
    for call in ["glob.iglob('/tmp/*')", "os.walk('/tmp')"] {
        let unused = py(&format!("import glob, os\n{call}"));
        assert!(unused.effects.is_empty(), "{call}");
        assert!(!unused.boundaries.iter().all(|b| b.callee.is_none()));
        let context = py(&format!("import glob, os\nwith {call}:\n    pass"));
        assert!(context.effects.is_empty(), "context entry consumed {call}");
        assert!(context.boundaries.iter().any(|b| b.callee.is_some()));
        let used = py(&format!("import glob, os\nfor entry in {call}:\n    pass"));
        assert!(
            used.effects
                .iter()
                .any(|e| e.operation.0 == "filesystem.read"),
            "{call}: {:?}",
            used.boundaries
        );
    }
    let temporary = py(
        "import tempfile, os\np = tempfile.mkdtemp(dir='/scratch', prefix='work-', suffix='.tmp')\nos.remove(p)\nfd, name = tempfile.mkstemp(dir='/scratch')\nos.remove(name)\nwith tempfile.TemporaryDirectory(dir='/scratch') as root:\n    os.listdir(root)\nwith tempfile.NamedTemporaryFile(dir='/scratch') as f:\n    os.remove(f.name)",
    );
    assert_eq!(
        temporary
            .effects
            .iter()
            .filter(|e| e.operation.0 == "filesystem.create")
            .count(),
        4
    );
    for effect in temporary
        .effects
        .iter()
        .filter(|e| e.operation.0 == "filesystem.delete")
    {
        assert!(
            serde_json::to_string(&effect.resource)
                .unwrap()
                .contains("/scratch"),
            "{:?}",
            effect.resource
        );
    }
    assert!(
        !temporary.boundaries.iter().all(|b| b.callee.is_none()),
        "cleanup must remain bounded"
    );
    let pair = py("import tempfile, os\npair = tempfile.mkstemp()\nos.remove(pair)");
    assert!(
        pair.effects
            .iter()
            .filter(|e| e.operation.0 == "filesystem.delete")
            .all(|e| matches!(e.resource, ResourceExpr::Unresolved { .. }))
    );
    for source in [
        "import tempfile\ntempfile.mkdtemp(delete=True)",
        "import tempfile\ntempfile.NamedTemporaryFile(mode='invalid')",
        "import glob\nglob.glob('*.py', root_dir=unknown)",
        "import glob\nglob.glob('*.py', include_hidden=True)",
        "import glob\nglob.glob('*.py', topdown=True)",
        "import os\nfor path in os.walk('/tmp', recursive=True):\n    pass",
    ] {
        let unsupported = py(source);
        assert!(
            unsupported.effects.is_empty(),
            "{source}: {:?}",
            ops(&unsupported)
        );
        assert!(unsupported.boundaries.iter().any(|b| b.callee.is_some()));
    }
    let selected = py("import tempfile\ntempfile.gettempdir()");
    assert!(selected.effects.is_empty());
    assert!(!selected.boundaries.iter().all(|b| b.callee.is_none()));
    let direct = py("import shutil\ncommand = '/bin/tool'\nshutil.which(command)");
    assert!(has(&direct, "filesystem.read", "/bin/tool"));
    assert!(!has(&direct, "environment.read", "$PATH"));
    let search = py("import shutil\nshutil.which('tool', path=':/bin')");
    assert!(has(&search, "filesystem.read", "/work/tool"));
    assert!(!has(&search, "filesystem.read", "/tool"));
    let archive = py("import zipfile\nzipfile.ZipFile('/archive', mode)");
    assert!(archive.effects.is_empty());
    assert!(!archive.boundaries.iter().all(|b| b.callee.is_none()));
}

#[test]
fn python_request_values_and_chained_reads_preserve_effects() {
    let constructed = py("from urllib.request import Request\nRequest('https://api.github.com/x')");
    assert!(constructed.effects.is_empty());
    assert!(
        constructed.boundaries.iter().all(|b| b.callee.is_none()),
        "{:?}",
        constructed.boundaries
    );
    for (data, operation) in [
        ("", "network.request"),
        (", data=b'payload'", "network.upload"),
        (", method='POST'", "network.upload"),
    ] {
        let plan = py(&format!(
            "from urllib.request import Request, urlopen\nreq = Request('https://api.github.com/x'{data})\nwith urlopen(req) as response:\n    pass"
        ));
        assert!(has(&plan, operation, "api.github.com"), "{:?}", ops(&plan));
        assert_eq!(plan.effects.len(), 1);
        assert!(
            plan.boundaries.iter().all(|b| b.callee.is_none()),
            "{:?}",
            plan.boundaries
        );
    }
    for expression in [
        "Path('/etc/passwd').read_text().strip().replace('x', 'y').splitlines()",
        "Path('/etc/passwd').read_bytes().decode('utf-8').strip()",
    ] {
        let plan = py(&format!("from pathlib import Path\n{expression}"));
        assert!(has(&plan, "filesystem.read", "/etc/passwd"));
        assert!(
            plan.boundaries.iter().all(|b| b.callee.is_none()),
            "{expression}: {:?}",
            plan.boundaries
        );
    }
    let mutated = py(
        "from urllib.request import Request, urlopen\nreq = Request('https://old.example/x')\nchange(req)\nurlopen(req)",
    );
    assert!(!has(&mutated, "network.request", "old.example"));
    assert!(mutated.boundaries.iter().any(|b| b.callee.is_some()));
    let unsafe_codec =
        py("from pathlib import Path\nPath('/etc/passwd').read_bytes().decode('user_codec')");
    assert!(has(&unsafe_codec, "filesystem.read", "/etc/passwd"));
    assert!(!unsafe_codec.boundaries.iter().all(|b| b.callee.is_none()));
}

#[test]
fn raise_walks_exception_and_cause_without_entering_uncalled_functions() {
    let plan = py(
        "import os\ndef main():\n    os.remove('/raised-main')\nif __name__ == '__main__':\n    raise SystemExit(main())\n",
    );
    assert!(has(&plan, "filesystem.delete", "/raised-main"));
    assert!(!has_boundary(&plan, "no_entry_point"));
    let negative =
        py("import os\ndef unused():\n    os.remove('/unused')\nraise ValueError('bad input')\n");
    assert!(!has(&negative, "filesystem.delete", "/unused"));
    let cause = py("import os\nraise ValueError('bad') from os.remove('/cause')\n");
    assert!(has(&cause, "filesystem.delete", "/cause"));
}

#[test]
fn fire_component_dispatch_respects_function_class_and_module_scope() {
    let definitions = "import fire\nimport os\ndef main(): os.remove('/main')\ndef other(): os.remove('/other')\nclass Commands:\n    def run(self): os.remove('/run')\n    def clean(self): os.remove('/clean')\n    def _private(self): os.remove('/private')\n";
    for (call, expected, absent) in [
        ("fire.Fire(main)", vec!["/main"], vec!["/other", "/run"]),
        (
            "fire.Fire(Commands)",
            vec!["/run", "/clean"],
            vec!["/main", "/private"],
        ),
        (
            "fire.Fire()",
            vec!["/main", "/other"],
            vec!["/run", "/private"],
        ),
    ] {
        let plan = py(&format!(
            "{definitions}\nif __name__ == '__main__':\n    {call}\n"
        ));
        for path in expected {
            assert!(
                has(&plan, "filesystem.delete", path),
                "{call}: {path}: {:?}",
                plan.boundaries
            );
        }
        for path in absent {
            assert!(!has(&plan, "filesystem.delete", path), "{call}: {path}");
        }
        assert!(!has_boundary(&plan, "no_entry_point"));
        assert!(!plan.boundaries.iter().any(|b| matches!(
            b.reason.as_str(),
            "unmodeled_import" | "unresolved_call"
        )
            && b.detail.as_ref().is_some_and(|d| d.contains("fire"))));
    }
    for call in ["fire.Fire(main)", "fire.Fire()"] {
        let rebound = py(&format!(
            "import fire\nimport os\ndef main(): os.remove('/stale-main')\nmain = 1\n{call}\n"
        ));
        assert!(!has(&rebound, "filesystem.delete", "/stale-main"), "{call}");
    }
    let imported = py(
        "import fire\nimport unknown\nimport os\ndef main(): os.remove('/wrong-main')\nfire.Fire(unknown.main)\n",
    );
    assert!(!has(&imported, "filesystem.delete", "/wrong-main"));
    let shadowed = py(
        "import fire\nimport os\ndef main(): os.remove('/unreached')\nclass Fake:\n    def Fire(self, component): pass\nfire = Fake()\nfire.Fire(main)\n",
    );
    assert!(!has(&shadowed, "filesystem.delete", "/unreached"));
}

#[test]
fn importlib_plugin_boundaries_name_paths_and_groups_without_guessing_effects() {
    let plan = py(
        "import importlib.util\nimport importlib.metadata\nfrom pathlib import Path\nfor path in Path('plugins').rglob('__init__.py'):\n    spec = importlib.util.spec_from_file_location('plugin', path)\n    module = importlib.util.module_from_spec(spec)\n    spec.loader.exec_module(module)\nimportlib.metadata.entry_points(group='tool.plugins')\neps = importlib.metadata.entry_points()\nGROUP = 'selected.plugins'\nif hasattr(eps, 'select'):\n    eps.select(group=GROUP)\nimportlib.import_module(plugin_name)\n",
    );
    for expected in [
        "plugins/**/__init__.py",
        "tool.plugins",
        "selected.plugins",
        "plugin_name",
    ] {
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.reason.as_str() == "cross_module"
                    && b.detail.as_ref().is_some_and(|d| d.contains(expected))),
            "{expected}: {:?}",
            plan.boundaries
        );
    }
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
}

#[test]
fn os_exec_replaces_the_process_with_exact_argv() {
    for source in [
        "import os\nos.execvp('rm', ['rm', '-rf', '/srv'])",
        "import os\nos.execl('/bin/rm', 'rm', '-rf', '/srv')",
        "import os\nos.execve('/bin/rm', ('rm', '-rf', '/srv'), {})",
        "from os import *\nexeclp('rm', 'rm', '-rf', '/srv')",
    ] {
        let plan = py(source);
        assert!(
            has(&plan, "filesystem.delete", "/srv"),
            "{source}: {:?}",
            ops(&plan)
        );
    }
    // CPython refuses an empty argv before replacing the process.
    assert!(py("import os\nos.execv('/bin/rm', [])").effects.is_empty());
}

#[test]
fn os_chdir_moves_later_children_and_relative_paths() {
    let plan = py("import os, subprocess\n\
         os.chdir('/srv')\n\
         subprocess.run(['rm', '-rf', 'data'])\n\
         os.system('rm -rf cache')\n\
         os.remove('log')");
    for path in ["/srv/data", "/srv/cache", "/srv/log"] {
        assert!(has(&plan, "filesystem.delete", path), "{:?}", ops(&plan));
    }
    assert!(!has(&plan, "filesystem.delete", "/work/data"));
    // A move on one arm only leaves later children in an unknown directory.
    let branched = py("import os, subprocess\n\
         if flag:\n    os.chdir('/srv')\n\
         subprocess.run(['rm', '-rf', 'data'])");
    assert!(!has(&branched, "filesystem.delete", "/srv/data"));
    assert!(!has(&branched, "filesystem.delete", "/work/data"));
    // After a call that moves, later children are not in the launch cwd.
    let called = py("import os, subprocess\n\
         def enter():\n    os.chdir('/srv')\n\
         enter()\n\
         subprocess.run(['rm', '-rf', 'data'])");
    assert!(!has(&called, "filesystem.delete", "/work/data"));
}

#[test]
fn os_lchown_is_a_chown_metadata_change() {
    let plan = py("import os\nos.lchown('/tmp/link', 0, 0)");
    let effect = one_effect(&plan, "filesystem.metadata");
    assert_eq!(render(&effect.resource), "/tmp/link");
    assert_eq!(
        effect.attributes.get("action"),
        Some(&AttrValue::String("chown".into()))
    );
}

#[test]
fn os_removedirs_deletes_the_leaf() {
    let plan = py("import os\nos.removedirs('/tmp/a/b')");
    assert!(has(&plan, "filesystem.delete", "/tmp/a/b"));
}

#[test]
fn os_open_flags_select_read_and_write() {
    let write = py("import os\nos.open('/tmp/a', os.O_WRONLY | os.O_CREAT)");
    assert_eq!(ops(&write), [("filesystem.write", "/tmp/a".to_string())]);
    let append = py("from os import O_APPEND, O_RDWR, open\nopen('/tmp/a', O_RDWR | O_APPEND)");
    assert!(has(&append, "filesystem.read", "/tmp/a"));
    let effect = one_effect(&append, "filesystem.write");
    assert_eq!(
        effect.attributes.get("append"),
        Some(&AttrValue::Bool(true))
    );
    let read = py("import os\nos.open('/tmp/a', os.O_RDONLY)");
    assert_eq!(ops(&read), [("filesystem.read", "/tmp/a".to_string())]);
    let unknown = py("import os\nos.open('/tmp/a', flags)");
    assert!(unknown.effects.is_empty());
    assert!(has_boundary(&unknown, "unmodeled_dynamic"));
}

#[test]
fn io_fileio_mode_selects_read_and_write() {
    let write = py("import io\nio.FileIO('/tmp/a', 'w')");
    assert_eq!(ops(&write), [("filesystem.write", "/tmp/a".to_string())]);
    let read = py("import io\nio.FileIO('/tmp/a')");
    assert_eq!(ops(&read), [("filesystem.read", "/tmp/a".to_string())]);
}

#[test]
fn path_symlink_to_and_hardlink_to_create_the_receiver() {
    let symlink = py("from pathlib import Path\nPath('/tmp/link').symlink_to('/etc/passwd')");
    let effect = one_effect(&symlink, "filesystem.create");
    assert_eq!(render(&effect.resource), "/tmp/link");
    assert_eq!(
        effect.attributes.get("symlink"),
        Some(&AttrValue::Bool(true))
    );
    let hardlink = py("from pathlib import Path\nPath('/tmp/link').hardlink_to('/etc/passwd')");
    assert!(has(&hardlink, "filesystem.create", "/tmp/link"));
    let read = one_effect(&hardlink, "filesystem.read");
    assert_eq!(render(&read.resource), "/etc/passwd");
    assert_eq!(
        read.attributes.get("metadata"),
        Some(&AttrValue::Bool(true))
    );
}

#[test]
fn constant_if_test_runs_only_its_selected_arm() {
    let plan = py("import shutil\n\
         if False:\n    shutil.rmtree('/never')\nelse:\n    shutil.rmtree('/else')\n\
         if 1:\n    shutil.rmtree('/always')");
    assert!(!has(&plan, "filesystem.delete", "/never"));
    assert!(has(&plan, "filesystem.delete", "/else"));
    assert!(has(&plan, "filesystem.delete", "/always"));
}

#[test]
fn urlretrieve_target_executed_later_carries_the_download() {
    let downloads_reach_code = |source: &str| {
        let plan = py_with_causality(source);
        let graph = plan.causality.graph.as_ref().unwrap();
        let operation_nodes = |wanted: &str| {
            graph
                .nodes
                .iter()
                .filter(|node| {
                    matches!(&node.occurrence,
                        effinterp_proto::OccurrenceKind::ResourceInteraction { operation, .. }
                            if operation.0 == wanted)
                })
                .map(|node| node.id.clone())
                .collect::<std::collections::BTreeSet<_>>()
        };
        let targets = operation_nodes("process.code_execution");
        let mut pending: Vec<_> = operation_nodes("network.download").into_iter().collect();
        let mut seen = std::collections::BTreeSet::new();
        while let Some(node) = pending.pop() {
            if targets.contains(&node) {
                return true;
            }
            if seen.insert(node.clone()) {
                pending.extend(
                    graph
                        .edges
                        .iter()
                        .filter(|edge| edge.from == node)
                        .map(|edge| edge.to.clone()),
                );
            }
        }
        false
    };
    assert!(downloads_reach_code(
        "import os, urllib.request\n\
         urllib.request.urlretrieve('https://x.com/f', '/tmp/out')\n\
         os.system('sh /tmp/out')"
    ));
    assert!(!downloads_reach_code(
        "import os, urllib.request\n\
         urllib.request.urlretrieve('https://x.com/f', '/tmp/out')\n\
         os.system('sh /tmp/other')"
    ));
}

#[test]
fn path_chmod_is_the_os_chmod_permission_change() {
    let facts = |plan: &Plan| {
        plan.effects
            .iter()
            .map(|effect| {
                (
                    effect.operation.0.clone(),
                    render(&effect.resource),
                    effect.attributes.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    let os_chmod = py("import os\nos.chmod('/tmp/a', 0o777)");
    let path_chmod = py("from pathlib import Path\nPath('/tmp/a').chmod(0o777)");
    assert_eq!(facts(&path_chmod), facts(&os_chmod));
    assert_eq!(os_chmod.effects[0].operation.0, "filesystem.metadata");
    // A literal mode states the grants it sets; a computed one states none.
    assert_eq!(
        os_chmod.effects[0].attributes.get("world_write"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    let computed_chmod = py("import os\nos.chmod('/tmp/a', mode)");
    // A typed `Path` parameter reaches the same fact through the external table.
    let receiver = ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: "/tmp/a".into(),
        },
    };
    let external = python_external_method_effects("pathlib.Path", "chmod", Some(receiver), &[])
        .expect("pathlib is modeled");
    assert_eq!(external.len(), 1);
    assert_eq!(external[0].operation.0, "filesystem.metadata");
    assert_eq!(external[0].attributes, computed_chmod.effects[0].attributes);
}

#[test]
fn pypy_launcher_names_run_inline_python() {
    for interpreter in ["pypy2", "pypy3.10"] {
        let plan = Engine::new()
            .analyze(&Subject::Exec {
                argv: vec![
                    interpreter.to_string(),
                    "-c".to_string(),
                    "import os; os.remove('/tmp/doomed')".to_string(),
                ],
                cwd: Some("/work".to_string()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            ops(&plan).contains(&("filesystem.delete", "/tmp/doomed".to_string())),
            "{interpreter}: {plan:?}"
        );
    }
    // A version suffix is digits after the major version's dot.
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: vec![
                "pypy3.x".to_string(),
                "-c".to_string(),
                "import os; os.remove('/tmp/doomed')".to_string(),
            ],
            cwd: Some("/work".to_string()),
            context: Default::default(),
        })
        .unwrap();
    assert!(!ops(&plan).iter().any(|(op, _)| *op == "filesystem.delete"));
}

#[test]
fn exec_of_compiled_literal_runs_its_source() {
    for source in [
        "exec(compile(\"import os; os.remove('/tmp/doomed')\", '<x>', 'exec'))",
        "eval(compile(\"__import__('os').remove('/tmp/doomed')\", 'x', 'eval'))",
    ] {
        let plan = pyexec(source);
        assert!(
            ops(&plan).contains(&("filesystem.delete", "/tmp/doomed".to_string())),
            "{source}: {plan:?}"
        );
        assert!(
            !has_boundary(&plan, "unmodeled_dynamic"),
            "{source}: {plan:?}"
        );
    }
    // Compiling runs nothing; a code object whose source is not a literal, or
    // one compiled with flags, stays dynamic.
    assert!(!has_boundary(
        &pyexec("c = compile('x = 1', 'x', 'exec')"),
        "unmodeled_dynamic"
    ));
    for source in [
        "exec(compile(payload, 'x', 'exec'))",
        "exec(compile('import os', 'x', 'exec', flags=0))",
        "c = compile('import os', 'x', 'exec'); exec(c)",
    ] {
        assert!(
            has_boundary(&pyexec(source), "unmodeled_dynamic"),
            "{source}"
        );
    }
}

#[test]
fn subprocess_args_keyword_names_the_command() {
    for source in [
        "import subprocess\nsubprocess.call(args=['rm', '-rf', '/data'])",
        "import subprocess\nsubprocess.run(args='rm -rf /data', shell=True)",
    ] {
        assert!(has(&py(source), "filesystem.delete", "/data"), "{source}");
    }
}
