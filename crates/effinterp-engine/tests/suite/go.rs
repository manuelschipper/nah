use effinterp_engine::{Engine, Lang, ObjectIdentity, ScopeKey, module_summaries};
use effinterp_proto::{
    BoundaryClass, CoverageLevel, Domain, ResourceExpr, ResourceIdentity, Subject, validate_plan,
};

fn go_module_summary(source: &str, lang: Lang) -> effinterp_engine::ModuleSummary {
    module_summaries(
        source,
        lang,
        "cmd/main.go",
        ScopeKey::GoPackage {
            key: "example.com/app/cmd".into(),
        },
        &effinterp_engine::SummaryBudget::for_lang(&effinterp_engine::default_limits(), lang),
    )
}

fn analyze(src: &str) -> effinterp_proto::Plan {
    let plan = Engine::new()
        .analyze(&Subject::Source {
            dialect: None,
            language: "go".to_string(),
            source: src.to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn ops(plan: &effinterp_proto::Plan) -> Vec<(&str, String)> {
    plan.effects
        .iter()
        .map(|e| (e.operation.0.as_str(), render(&e.resource)))
        .collect()
}

fn render(expr: &ResourceExpr) -> String {
    match expr {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => path.clone(),
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, .. },
        } => executable.clone(),
        ResourceExpr::Join { parts } => {
            format!(
                "join({})",
                parts.iter().map(render).collect::<Vec<_>>().join(",")
            )
        }
        ResourceExpr::Parameter { name } => format!("<{name}>"),
        ResourceExpr::Unresolved { family } => format!("?{}", family.0),
        other => format!("{other:?}"),
    }
}

fn has(plan: &effinterp_proto::Plan, op: &str, res: &str) -> bool {
    ops(plan).iter().any(|(o, r)| *o == op && r == res)
}

fn no_boundary_except_frontend_partial(plan: &effinterp_proto::Plan) -> bool {
    plan.boundaries
        .iter()
        .all(|boundary| boundary.reason.as_str() == "frontend_partial")
}

#[test]
fn no_entry_point_distinguishes_unreached_go_callables() {
    let declarations = "package util\nimport \"os\"\nfunc Purge(path string) error { return os.RemoveAll(path) }\n";
    let plan = analyze(declarations);
    let boundary = plan
        .boundaries
        .iter()
        .find(|boundary| boundary.reason.as_str() == "no_entry_point")
        .expect("declaration-only Go has no execution root");
    assert_eq!(boundary.class, BoundaryClass::Unresolved);
    assert_eq!(
        boundary.detail.as_deref(),
        Some("no execution root reached; declared callables not executed: Purge")
    );
    for domain in ["environment", "filesystem", "network", "process"] {
        assert_eq!(
            plan.coverage.0[&Domain::new(domain)].level,
            CoverageLevel::Partial
        );
    }

    let reached = analyze(
        "package main\nimport \"os\"\nfunc Purge(path string) error { return os.RemoveAll(path) }\nfunc main() { Purge(\"/tmp/reached\") }\n",
    );
    assert!(has(&reached, "filesystem.delete", "/tmp/reached"));
    assert!(
        reached
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );

    let executed = analyze(
        "package main\nimport \"os\"\nfunc stale() { os.RemoveAll(\"/stale\") }\nfunc main() { os.RemoveAll(\"/top\") }\n",
    );
    assert!(has(&executed, "filesystem.delete", "/top"));
    assert!(
        executed
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );
    assert!(
        analyze("package util\n")
            .boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "no_entry_point")
    );
}

// Regression: Cobra invokes Run-family fields from Execute without passing the
// callback as an argument at that call site.
#[test]
fn cobra_execute_fires_command_callbacks() {
    let plan = analyze(
        r#"package main
import (
    "os"
    "github.com/spf13/cobra"
)
func main() {
    cmd := &cobra.Command{RunE: func(cmd *cobra.Command, args []string) error {
        return os.RemoveAll("/cobra")
    }}
    cmd.Execute()
}"#,
    );
    assert!(has(&plan, "filesystem.delete", "/cobra"));

    let subcommand = analyze(
        r#"package main
import "github.com/spf13/cobra"
func prep(cmd *cobra.Command, args []string) {}
func main() {
    root := &cobra.Command{}
    child := &cobra.Command{Run: prep}
    root.AddCommand(child)
    root.Execute()
}"#,
    );
    assert!(
        subcommand
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "escaped_callable")
    );
}

/// An interpreted string literal names its bytes through escapes: an
/// undecoded `\057etc` would plan the delete on a cwd-relative path.
#[test]
fn interpreted_string_escapes_are_decoded() {
    let plan = analyze(
        r#"package main
import "os"
func main() {
	os.RemoveAll("\057etc\x2fnah")
	os.RemoveAll("\u002fvar\U0000002flog")
	os.RemoveAll("/a\\nb")
	os.RemoveAll("/\xc3\xa9")
}
"#,
    );
    for path in ["/etc/nah", "/var/log", "/a\\nb", "/é"] {
        assert!(
            has(&plan, "filesystem.delete", path),
            "{path}: {:?}",
            ops(&plan)
        );
    }
}

#[test]
fn os_removeall_in_main() {
    let plan = analyze("package main\nimport \"os\"\nfunc main() { os.RemoveAll(\"/data\") }\n");
    assert!(has(&plan, "filesystem.delete", "/data"), "{:?}", ops(&plan));
    let del = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.delete")
        .unwrap();
    assert_eq!(
        del.attributes.get("recursive"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
}

#[test]
fn one_line_import_groups_preserve_every_import() {
    let cases = [
        (
            "package main\nimport (\"os\")\nfunc main() { os.RemoveAll(\"/single\") }\n",
            "/single",
            false,
        ),
        (
            "package main\nimport (\"os\"; \"net/http\")\nfunc main() { os.RemoveAll(\"/multi\"); http.Get(\"https://example.com\") }\n",
            "/multi",
            true,
        ),
        (
            "package main\nimport (\"os\";)\nfunc main() { os.RemoveAll(\"/trailing\") }\n",
            "/trailing",
            false,
        ),
        (
            "package main\nimport (\n\"os\"\n)\nfunc main() { os.RemoveAll(\"/multiline\") }\n",
            "/multiline",
            false,
        ),
    ];
    for (source, path, has_network) in cases {
        let plan = analyze(source);
        assert!(has(&plan, "filesystem.delete", path), "{plan:?}");
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "network.request"),
            has_network,
            "{plan:?}"
        );
    }
}

#[test]
fn net_listen_models_unix_and_tcp_addresses() {
    let plan = analyze(
        "package main\nimport \"net\"\nimport \"strings\"\nfunc main() { net.Listen(\"unix\", \"/tmp/probe.sock\"); net.Listen(\"tcp\", \"127.0.0.1:8080\"); net.Listen(\"tcp\", \":5432\"); net.Dial(\"tcp\", \"db.example:5432\"); strings.Join(nil, \",\") }\n",
    );
    let listeners: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "network.listen")
        .collect();
    assert_eq!(listeners.len(), 3, "{:?}", ops(&plan));
    assert!(listeners.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::NetworkEndpoint {
                host,
                scheme: Some(scheme),
                path: None,
                port: None,
            }
        } if host == "/tmp/probe.sock" && scheme == "unix"
    )));
    assert!(has(&plan, "filesystem.create", "/tmp/probe.sock"));
    assert!(listeners.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::NetworkEndpoint {
                host,
                scheme: Some(scheme),
                port: Some(8080),
                ..
            }
        } if host == "127.0.0.1" && scheme == "tcp"
    )));
    assert!(listeners.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::NetworkEndpoint {
                host,
                scheme: Some(scheme),
                port: Some(5432),
                ..
            }
        } if host == "*" && scheme == "tcp"
    )));
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.connect")
            .count(),
        1
    );
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "external_unmodeled")
    );
}

#[test]
fn a_wrong_package_does_not_inherit_a_known_domain_set() {
    // A same-named method on a different stdlib package is classified from
    // that package: `os.Chtimes` touches files, not the network.
    let plan =
        analyze("package main\nimport \"os\"\nfunc main() { os.Chtimes(\"/x\", nil, nil) }\n");
    let boundary = plan
        .boundaries
        .iter()
        .find(|b| b.reason.as_str() == "external_unmodeled")
        .expect("os.Chtimes is unmodeled and effectful");
    let domains: Vec<&str> = boundary.domains.iter().map(|d| d.0.as_str()).collect();
    assert_eq!(domains, vec!["filesystem"]);
}

#[test]
fn starting_an_unknown_program_reaches_every_domain() {
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() { os.StartProcess(\"/usr/bin/curl\", []string{\"curl\", \"https://example.com\"}, nil) }\n",
    );
    let boundary = plan
        .boundaries
        .iter()
        .find(|boundary| boundary.reason.as_str() == "external_unmodeled")
        .expect("os.StartProcess is an unmodeled external call");
    let domains: std::collections::BTreeSet<&str> = boundary
        .domains
        .iter()
        .map(|domain| domain.0.as_str())
        .collect();
    assert_eq!(domains, effinterp_proto::DOMAINS.into_iter().collect());
}

#[test]
fn exec_command_nests_subprocess() {
    let plan = analyze(
        "package main\nimport \"os/exec\"\nfunc main() { exec.Command(\"rm\", \"-rf\", \"/tmp/x\").Run() }\n",
    );
    // The nested rm is analyzed: process.exec rm + the recursive delete.
    assert!(has(&plan, "process.exec", "rm"), "{:?}", ops(&plan));
    assert!(
        has(&plan, "filesystem.delete", "/tmp/x"),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn uncalled_function_is_not_executed() {
    let plan = analyze(
        "package main\nimport \"os\"\nfunc danger() { os.RemoveAll(\"/important\") }\nfunc main() {}\n",
    );
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.delete"),
        "uncalled danger() must not execute: {:?}",
        ops(&plan)
    );
}

#[test]
fn local_call_substitutes_arguments() {
    let plan = analyze(
        "package main\nimport \"os\"\nfunc wipe(p string) { os.RemoveAll(p) }\nfunc main() { wipe(\"/var/cache\") }\n",
    );
    assert!(
        has(&plan, "filesystem.delete", "/var/cache"),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn filepath_join_builds_a_join() {
    let plan = analyze(
        "package main\nimport (\n\"os\"\n\"path/filepath\"\n)\nfunc wipe(root string, t string) { os.RemoveAll(filepath.Join(root, t)) }\nfunc main() { wipe(\"/cache\", name) }\n",
    );
    // root specialized to /cache, t stays symbolic (name is not a param here).
    assert!(
        ops(&plan)
            .iter()
            .any(|(o, r)| *o == "filesystem.delete" && r.starts_with("join(/cache")),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn module_summaries_expose_parameterized_summary_and_imports() {
    let ms = go_module_summary(
        "package util\nimport \"os\"\nfunc wipe(root string, t string) { os.RemoveAll(root) }\n",
        Lang::Go,
    );
    let wipe = ms
        .functions
        .iter()
        .find(|f| f.name == "wipe")
        .expect("wipe summarized");
    assert_eq!(wipe.summary.params, vec!["root", "t"]);
    // Its delete targets the `root` parameter.
    assert!(wipe.summary.effects.iter().any(|e| {
        e.operation.0 == "filesystem.delete"
            && matches!(&e.resource, ResourceExpr::Parameter { name } if name == "root")
    }));
    assert!(ms.imports.iter().any(|i| i.module == "os"));
    let requirements =
        wipe.summary
            .control_flow
            .requirements(&mut |_| false, &mut |_| None, &mut |_, _| true);
    assert!(
        requirements
            .on_success
            .contains(&effinterp_engine::ControlFact::Effect(0))
    );

    // The second walk's call slots must bind to the first walk's syntax sites,
    // including a local callee whose effect slots were substituted.
    let ms = go_module_summary(
        "package app\nimport \"os\"\nfunc leaf(path string) { os.Remove(path) }\nfunc run(flag bool) { leaf(\"/before\"); if flag { os.Remove(\"/arm\") } else { os.Remove(\"/arm\") }; os.Remove(\"/tail\") }\nfunc recurse() { recurse(); os.Remove(\"/recursive\") }\n",
        Lang::Go,
    );
    let ms: effinterp_engine::ModuleSummary =
        serde_json::from_slice(&serde_json::to_vec(&ms).unwrap()).unwrap();
    let run = ms.functions.iter().find(|f| f.name == "run").unwrap();
    assert_eq!(run.summary.effects.len(), 4);
    let requirements =
        run.summary
            .control_flow
            .requirements(&mut |_| false, &mut |_| None, &mut |_, _| true);
    for (slot, required) in [true, false, false, true].into_iter().enumerate() {
        assert_eq!(
            requirements
                .on_success
                .contains(&effinterp_engine::ControlFact::Effect(slot as u32)),
            required,
            "effect {slot}"
        );
        assert_eq!(
            requirements
                .on_success
                .contains(&effinterp_engine::ControlFact::Call(slot as u32)),
            required,
            "call {slot}"
        );
    }
    let recursive = ms.functions.iter().find(|f| f.name == "recurse").unwrap();
    let requirements =
        recursive
            .summary
            .control_flow
            .requirements(&mut |_| false, &mut |_| None, &mut |_, _| true);
    assert!(
        !requirements
            .on_success
            .contains(&effinterp_engine::ControlFact::Effect(0))
    );
}

#[test]
fn module_calls_record_main_cross_package_call_edge() {
    // `main`'s call on an imported package becomes a cross-package call edge in
    // the selected entrypoint roots (not silently dropped).
    let ms = go_module_summary(
        "package main\nimport \"ex.com/app/ghcmd\"\nfunc main() { ghcmd.Main() }\n",
        Lang::Go,
    );
    assert!(
        ms.main_calls.iter().any(|e| e.callee == "ghcmd.Main"),
        "main_calls: {:?}",
        ms.main_calls
    );
}

#[test]
fn function_records_package_qualified_call_edge() {
    let ms = go_module_summary(
        "package main\nimport \"ex.com/app/util\"\nfunc run() { util.Wipe(\"/x\") }\n",
        Lang::Go,
    );
    let run = ms
        .functions
        .iter()
        .find(|f| f.name == "run")
        .expect("run summarized");
    assert!(
        run.calls.iter().any(|e| e.callee == "util.Wipe"),
        "run.calls: {:?}",
        run.calls
    );
}

#[test]
fn http_get_is_a_network_request() {
    let plan = analyze(
        "package main\nimport \"net/http\"\nfunc main() { http.Get(\"https://evil.example/x\") }\n",
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "network.request")
    );
}

#[test]
fn os_readfile_is_a_filesystem_read() {
    let plan =
        analyze("package main\nimport \"os\"\nfunc main() { os.ReadFile(\"/etc/hosts\") }\n");
    assert!(
        has(&plan, "filesystem.read", "/etc/hosts"),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn ioutil_readfile_is_a_filesystem_read() {
    let plan = analyze(
        "package main\nimport \"io/ioutil\"\nfunc main() { ioutil.ReadFile(\"/etc/hosts\") }\n",
    );
    assert!(
        has(&plan, "filesystem.read", "/etc/hosts"),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn os_getenv_is_an_environment_read() {
    let plan = analyze("package main\nimport \"os\"\nfunc main() { os.Getenv(\"HOME\") }\n");
    let effect = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "environment.read")
        .expect("environment.read effect");
    assert!(
        matches!(&effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name }
        } if name == "HOME"),
        "{:?}",
        effect.resource
    );
}

#[test]
fn nonliteral_environment_and_filesystem_targets_keep_the_operation_family() {
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() { var target string; os.Getenv(target); os.RemoveAll(target) }\n",
    );
    let environment = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "environment.read")
        .unwrap();
    assert!(matches!(
        &environment.resource,
        ResourceExpr::Unresolved { family } if family.0 == "environment"
    ));
    let filesystem = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert!(!matches!(
        &filesystem.resource,
        ResourceExpr::Unresolved { family } if family.0 == "other" || family.0 == "value"
    ));

    let empty = analyze("package main\nimport \"os\"\nfunc main() { os.Getenv(\"\") }\n");
    assert!(empty.effects.iter().any(|effect| {
        effect.operation.0 == "environment.read"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family }
                if family.0 == "environment")
    }));
}

#[test]
fn os_lookupenv_is_an_environment_read() {
    let plan = analyze("package main\nimport \"os\"\nfunc main() { os.LookupEnv(\"HOME\") }\n");
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "environment.read"),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn environment_concatenation_is_typed_by_filesystem_sink() {
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tos.Remove(os.Getenv(\"HOME\") + \"/.cache/x\")\n\troot, _ := os.LookupEnv(\"CACHE\")\n\tos.RemoveAll(root + \"/stale\")\n\tpath := os.Getenv(\"STORED\") + \"/value\"\n\tos.RemoveAll(path)\n\tvar key string\n\tos.Remove(os.Getenv(key) + \"/tail\")\n}\n",
    );
    let deletes: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 4);
    for (effect, expected_name, expected_path) in [
        (deletes[0], "HOME", "/.cache/x"),
        (deletes[1], "CACHE", "/stale"),
        (deletes[2], "STORED", "/value"),
    ] {
        assert!(matches!(
            &effect.resource,
            ResourceExpr::Join { parts }
                if matches!(
                    parts.as_slice(),
                    [
                        ResourceExpr::Environment { name },
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path }
                        }
                    ] if name == expected_name && path == expected_path
                )
        ));
    }
    assert!(matches!(
        &deletes[3].resource,
        ResourceExpr::Join { parts }
            if matches!(
                parts.as_slice(),
                [
                    ResourceExpr::Unresolved { family },
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    }
                ] if family.0 == "filesystem" && path == "/tail"
            )
    ));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "environment.read"
            && matches!(
                &effect.resource,
                ResourceExpr::Unresolved { family } if family.0 == "environment"
            )
    }));
}

#[test]
fn os_setenv_is_an_environment_write() {
    let plan =
        analyze("package main\nimport \"os\"\nfunc main() { os.Setenv(\"TOKEN\", \"x\") }\n");
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "environment.write"),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn os_openfile_readonly_is_a_filesystem_read() {
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() { os.OpenFile(\"/a\", os.O_RDONLY, 0) }\n",
    );
    assert!(has(&plan, "filesystem.read", "/a"), "{:?}", ops(&plan));
}

#[test]
fn os_openfile_create_is_a_filesystem_write() {
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() { os.OpenFile(\"/a\", os.O_WRONLY|os.O_CREATE, 0644) }\n",
    );
    assert!(has(&plan, "filesystem.write", "/a"), "{:?}", ops(&plan));
}

#[test]
fn os_openfile_append_marks_attribute() {
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() { os.OpenFile(\"/a\", os.O_WRONLY|os.O_APPEND, 0644) }\n",
    );
    let write = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.write")
        .expect("filesystem.write effect");
    assert_eq!(
        write.attributes.get("append"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
}

#[test]
fn http_post_is_a_network_upload() {
    let plan = analyze(
        "package main\nimport \"net/http\"\nfunc main() { http.Post(\"https://x.com\", \"application/json\", nil) }\n",
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "network.upload"),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn environment_concatenation_is_typed_by_network_sinks() {
    let plan = analyze(
        "package main\nimport (\n\t\"net\"\n\t\"net/http\"\n\t\"os\"\n)\nfunc main() {\n\thttp.Post(os.Getenv(\"API\") + \"/meta/auth\", \"application/json\", nil)\n\tnet.Dial(\"tcp\", os.Getenv(\"SOCKET\") + \":443\")\n\turl := os.Getenv(\"ASSIGNED\") + \"/stored\"\n\thttp.Post(url, \"application/json\", nil)\n\tvar key string\n\thttp.Post(os.Getenv(key) + \"/tail\", \"application/json\", nil)\n\tnet.Dial(\"tcp\", os.Getenv(key) + \":8443\")\n\tlookup, _ := os.LookupEnv(key)\n\thttp.Post(lookup + \"/lookup\", \"application/json\", nil)\n\thttp.Post(key + \"/unbounded\", \"application/json\", nil)\n}\n",
    );
    let uploads: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "network.upload")
        .collect();
    assert_eq!(uploads.len(), 5);
    assert!(matches!(
        &uploads[0].resource,
        ResourceExpr::Join { parts }
            if matches!(
                parts.as_slice(),
                [
                    ResourceExpr::Environment { name },
                    ResourceExpr::Literal { value }
                ] if name == "API" && value == "/meta/auth"
            )
    ));
    assert!(matches!(
        &uploads[1].resource,
        ResourceExpr::Join { parts }
            if matches!(
                parts.as_slice(),
                [
                    ResourceExpr::Environment { name },
                    ResourceExpr::Literal { value }
                ] if name == "ASSIGNED" && value == "/stored"
            )
    ));
    assert!(matches!(
        &uploads[2].resource,
        ResourceExpr::Join { parts }
            if matches!(
                parts.as_slice(),
                [
                    ResourceExpr::Unresolved { family },
                    ResourceExpr::Literal { value }
                ] if family.0 == "network" && value == "/tail"
            )
    ));
    assert!(matches!(
        &uploads[3].resource,
        ResourceExpr::Join { parts }
            if matches!(
                parts.as_slice(),
                [
                    ResourceExpr::Unresolved { family },
                    ResourceExpr::Literal { value }
                ] if family.0 == "network" && value == "/lookup"
            )
    ));
    assert!(matches!(
        &uploads[4].resource,
        ResourceExpr::Unresolved { family } if family.0 == "network"
    ));
    let connects: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "network.connect")
        .collect();
    assert_eq!(connects.len(), 2);
    assert!(matches!(
        &connects[0].resource,
        ResourceExpr::Join { parts }
            if matches!(
                parts.as_slice(),
                [
                    ResourceExpr::Environment { name },
                    ResourceExpr::Literal { value }
                ] if name == "SOCKET" && value == ":443"
            )
    ));
    assert!(matches!(
        &connects[1].resource,
        ResourceExpr::Join { parts }
            if matches!(
                parts.as_slice(),
                [
                    ResourceExpr::Unresolved { family },
                    ResourceExpr::Literal { value }
                ] if family.0 == "network" && value == ":8443"
            )
    ));
}

#[test]
fn http_newrequest_post_is_a_network_upload_with_endpoint() {
    let plan = analyze(
        "package main\nimport \"net/http\"\nfunc main() { http.NewRequest(\"POST\", \"https://x.com/api\", nil) }\n",
    );
    let effect = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "network.upload")
        .expect("network.upload effect");
    assert!(
        matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host, .. } } if host == "x.com"),
        "{:?}",
        effect.resource
    );
}

#[test]
fn http_get_endpoint_is_concrete() {
    let plan =
        analyze("package main\nimport \"net/http\"\nfunc main() { http.Get(\"https://x.com\") }\n");
    let effect = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "network.request")
        .expect("network.request effect");
    assert!(
        matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host, .. } } if host == "x.com"),
        "{:?}",
        effect.resource
    );
}

#[test]
fn malformed_source_is_a_boundary_no_panic() {
    let plan = analyze("package main\nfunc main( { this is not go");
    // Never a silent empty plan; a parse boundary or degraded coverage.
    assert!(
        !plan.boundaries.is_empty()
            || plan
                .coverage
                .0
                .values()
                .all(|l| l.level != effinterp_proto::CoverageLevel::Full)
    );
}

#[test]
fn deterministic() {
    let src =
        "package main\nimport \"os\"\nfunc main() { os.RemoveAll(\"/a\"); os.Remove(\"/b\") }\n";
    let a = effinterp_proto::canonical_json(&analyze(src));
    let b = effinterp_proto::canonical_json(&analyze(src));
    assert_eq!(a, b);
}

#[test]
fn closure_bound_to_local_is_callable() {
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tdial := func() { os.RemoveAll(\"/conn\") }\n\tdial()\n}\n",
    );
    assert!(has(&plan, "filesystem.delete", "/conn"), "{:?}", ops(&plan));
}

#[test]
fn deferred_function_literal_executes() {
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tdefer func() {\n\t\tos.RemoveAll(\"/deferred\")\n\t}()\n}\n",
    );
    assert!(
        has(&plan, "filesystem.delete", "/deferred"),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn function_passed_to_an_unknown_target_stays_explicit() {
    let plan = analyze(
        "package main\nimport \"os\"\nfunc work() { os.RemoveAll(\"/cb\") }\nfunc main() { runner.Register(work) }\n",
    );
    assert!(has(&plan, "filesystem.delete", "/cb"), "{:?}", ops(&plan));
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "escaped_callable")
    );
}

#[test]
fn callback_passed_to_a_package_call_is_may_executed() {
    // An imported package is entered by nobody: `sort.Search` runs the literal,
    // and no later stage can account for what it does.
    let plan = analyze(
        "package main\nimport (\n\t\"os\"\n\t\"sort\"\n)\nfunc main() {\n\tsort.Search(10, func(i int) bool { os.Remove(\"/search\"); return true })\n}\n",
    );
    assert!(
        has(&plan, "filesystem.delete", "/search"),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn named_callback_passed_to_a_package_call_is_may_executed() {
    let plan = analyze(
        "package main\nimport (\n\t\"os\"\n\t\"sort\"\n)\nvar items []int\nfunc less(i, j int) bool {\n\tos.WriteFile(\"/cmp\", nil, 0)\n\treturn i < j\n}\nfunc main() { sort.Slice(items, less) }\n",
    );
    assert!(has(&plan, "filesystem.write", "/cmp"), "{:?}", ops(&plan));
}

#[test]
fn callback_passed_to_a_package_typed_receiver_is_may_executed() {
    // `once` is declared with an imported package's type, so `once.Do` is that
    // package's method — the callable reaches a target nothing else follows.
    let plan = analyze(
        "package main\nimport (\n\t\"os\"\n\t\"sync\"\n)\nvar once sync.Once\nfunc main() {\n\tonce.Do(func() { os.Remove(\"/once\") })\n}\n",
    );
    assert!(has(&plan, "filesystem.delete", "/once"), "{:?}", ops(&plan));
}

#[test]
fn callable_a_package_call_receives_indirectly_stays_explicit() {
    // The callable reaches `sort.Slice` out of a collection, so this file
    // cannot name what runs: no guessed effect, but no silence either.
    let plan = analyze(
        "package main\nimport (\n\t\"os\"\n\t\"sort\"\n)\nvar items []int\nfunc wipe(i, j int) bool {\n\tos.RemoveAll(\"/indirect\")\n\treturn true\n}\nfunc main() {\n\tfns := []func(int, int) bool{wipe}\n\tsort.Slice(items, fns[0])\n}\n",
    );
    assert!(
        !has(&plan, "filesystem.delete", "/indirect"),
        "{:?}",
        ops(&plan)
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "escaped_callable"),
        "{:?}",
        plan.boundaries
    );
}

#[test]
fn callable_bound_to_a_local_name_reaches_a_package_call_exactly() {
    let plan = analyze(
        "package main\nimport (\n\t\"os\"\n\t\"sort\"\n)\nvar items []int\nfunc wipe(i, j int) bool {\n\tos.RemoveAll(\"/aliased\")\n\treturn true\n}\nfunc main() {\n\tless := wipe\n\tsort.Slice(items, less)\n}\n",
    );
    assert!(
        has(&plan, "filesystem.delete", "/aliased"),
        "{:?}",
        ops(&plan)
    );
    assert!(
        no_boundary_except_frontend_partial(&plan),
        "{:?}",
        plan.boundaries
    );
}

#[test]
fn package_constant_argument_is_not_a_call() {
    // `os.O_RDONLY` is a constant in a position `os.OpenFile` never invokes;
    // treating it as a call raised an all-domain unmodeled-external boundary.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tos.OpenFile(\"/tmp/x\", os.O_RDONLY, 0644)\n}\n",
    );
    assert!(has(&plan, "filesystem.read", "/tmp/x"), "{:?}", ops(&plan));
    assert!(
        no_boundary_except_frontend_partial(&plan),
        "{:?}",
        plan.boundaries
    );
}

#[test]
fn constant_beside_a_callback_argument_is_not_a_call() {
    // `time.AfterFunc` runs its second argument; the first is a duration
    // constant that must not be modeled as a call of its own.
    let plan = analyze(
        "package main\nimport (\n\t\"os\"\n\t\"time\"\n)\nfunc main() {\n\ttime.AfterFunc(time.Second, func() { os.Remove(\"/timer\") })\n}\n",
    );
    assert!(
        has(&plan, "filesystem.delete", "/timer"),
        "{:?}",
        ops(&plan)
    );
    assert!(
        no_boundary_except_frontend_partial(&plan),
        "{:?}",
        plan.boundaries
    );
}

#[test]
fn function_value_passed_as_data_is_not_executed() {
    // Printing or storing a function value is not a call: `fmt.Println` never
    // invokes what it is handed, so `cleanup` must contribute no effect.
    let plan = analyze(
        "package main\nimport (\n\t\"fmt\"\n\t\"os\"\n)\nfunc cleanup() { os.RemoveAll(\"/data\") }\nfunc main() { fmt.Println(cleanup) }\n",
    );
    assert!(
        !has(&plan, "filesystem.delete", "/data"),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn net_dial_is_a_network_connect() {
    let plan = analyze(
        "package main\nimport \"net\"\nfunc main() { net.Dial(\"tcp\", \"db.example:5432\") }\n",
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "network.connect"),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn net_dialer_composite_receiver_dialcontext_is_a_network_connect() {
    let plan = analyze(
        "package main\nimport (\n\t\"context\"\n\t\"net\"\n)\nfunc main() { (&net.Dialer{}).DialContext(context.Background(), \"tcp\", \"db.example:5432\") }\n",
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "network.connect"),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn bare_call_to_undefined_name_is_a_sibling_edge_not_a_builtin() {
    let ms = go_module_summary(
        "package cmd\nfunc run() {\n\thelperInSibling(\"/x\")\n\tprintln(\"noise\")\n\t_ = make([]int, 0)\n}\n",
        Lang::Go,
    );
    let run = ms.functions.iter().find(|f| f.name == "run").unwrap();
    assert!(
        run.calls.iter().any(|e| e.callee == "helperInSibling"),
        "sibling candidate recorded: {:?}",
        run.calls
    );
    assert!(
        !run.calls
            .iter()
            .any(|e| e.callee == "println" || e.callee == "make"),
        "builtins are not sibling candidates: {:?}",
        run.calls
    );
}

#[test]
fn constructor_returns_and_ambiguity() {
    let ms = go_module_summary(
        "package lib\ntype H struct{}\ntype A struct{}\ntype B struct{}\nfunc NewH() *H { return &H{} }\nfunc Pick(f bool) any {\n\tif f {\n\t\treturn &A{}\n\t}\n\treturn &B{}\n}\n",
        Lang::Go,
    );
    let newh = ms.functions.iter().find(|f| f.name == "NewH").unwrap();
    assert_eq!(newh.returns_instances, vec![Some("H".to_string())]);
    let pick = ms.functions.iter().find(|f| f.name == "Pick").unwrap();
    assert!(
        pick.returns_instances.is_empty(),
        "branch-dependent construction is ambiguous: {:?}",
        pick.returns_instances
    );
    assert!(ms.classes.iter().any(|c| c.name == "H"));
}

#[test]
fn returned_local_binding_is_recorded() {
    let ms = go_module_summary(
        "package lib\ntype H struct{}\nfunc NewH() *H { h := &H{}; return h }\n",
        Lang::Go,
    );
    let newh = ms.functions.iter().find(|f| f.name == "NewH").unwrap();
    assert_eq!(newh.return_bindings, vec![Some("h".to_string())]);
}

#[test]
fn semantic_import_versions_recover_only_the_imported_qualifier() {
    let summary = go_module_summary(
        r#"package main
import "github.com/urfave/cli/v3"
func action() {}
func main() { app := &cli.Command{Action: action}; app.Run() }
"#,
        Lang::Go,
    );
    let main = summary.functions.iter().find(|f| f.name == "main").unwrap();
    let command = main
        .calls
        .iter()
        .find(|call| call.callee == "cli.Command")
        .expect("semantic import qualifier");
    assert!(matches!(
        command.result_type(),
        Some(effinterp_engine::TypeRef::External { path })
            if path == "github.com/urfave/cli/v3.Command"
    ));
    assert!(command.callback_arguments().any(|(argument, function)| {
        argument.name.as_deref() == Some("Action") && function == "action"
    }));

    let negative = go_module_summary(
        r#"package main
import urfave "github.com/urfave/cli/v3"
func action() {}
func main() { app := &cli.Command{Action: action}; app.Run() }
"#,
        Lang::Go,
    );
    let main = negative
        .functions
        .iter()
        .find(|f| f.name == "main")
        .unwrap();
    assert!(main.calls.iter().all(|call| call.result_type().is_none()));
}

#[test]
fn asdf_process_and_config_calls_require_exact_import_ownership() {
    let plan = analyze(
        r#"package main
import (
    "os/exec"
    "syscall"
    "gopkg.in/ini.v1"
)
func main() {
    ini.Load(".asdfrc")
    syscall.Exec("/usr/bin/asdf", nil, nil)
    exec.Command("bash", "-c", "echo ok").Run()
}
"#,
    );
    assert!(
        has(&plan, "filesystem.read", "join(<cwd>,.asdfrc)"),
        "{:?}",
        ops(&plan)
    );
    assert!(has(&plan, "process.exec", "asdf"), "{:?}", ops(&plan));
    assert!(has(&plan, "process.exec", "bash"), "{:?}", ops(&plan));

    let negative = analyze(
        r#"package main
type api struct{}
func (api) Load(string) {}
func (api) Exec(string, any, any) {}
func (api) Command(string, ...string) api { return api{} }
func (api) Run() {}
func main() {
    var ini, syscall, exec api
    ini.Load(".asdfrc")
    syscall.Exec("/usr/bin/asdf", nil, nil)
    exec.Command("bash", "-c", "echo ok").Run()
}
"#,
    );
    assert!(
        negative.effects.is_empty(),
        "name-only calls fired: {:?}",
        ops(&negative)
    );
}

#[test]
fn declared_param_type_dispatches_same_file_method() {
    // `opts.AddFlags()` on a parameter declared `*Options` is assignment
    // provenance, not a guess: the method body runs.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Options struct{}\nfunc (o *Options) AddFlags() { os.Getenv(\"RESTIC_REPOSITORY\") }\nfunc apply(opts *Options) { opts.AddFlags() }\nfunc main() { apply(&Options{}) }\n",
    );
    let effect = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "environment.read")
        .expect("typed receiver dispatches AddFlags");
    assert!(
        matches!(&effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name }
        } if name == "RESTIC_REPOSITORY"),
        "{:?}",
        effect.resource
    );
}

#[test]
fn composite_literal_assignment_types_receiver() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype Store struct{}\nfunc (s *Store) Purge() { os.RemoveAll(\"/cache\") }\nfunc main() {\n\ts := &Store{}\n\ts.Purge()\n}\n",
    );
    assert!(
        has(&plan, "filesystem.delete", "/cache"),
        "composite-literal typed local dispatches: {:?}",
        ops(&plan)
    );
}

#[test]
fn typed_method_edge_records_class_receiver() {
    let ms = go_module_summary(
        "package cli\ntype Options struct{}\nfunc (o *Options) AddFlags() {}\nfunc New(opts *Options) { opts.AddFlags() }\n",
        Lang::Go,
    );
    let new = ms.functions.iter().find(|f| f.name == "New").unwrap();
    let edge = new
        .calls
        .iter()
        .find(|e| e.callee == "opts.AddFlags")
        .expect("method edge recorded");
    assert!(
        matches!(
            edge.receiver_identity(),
            Some(ObjectIdentity::Parameter { name, fallback })
                if name == "opts" && fallback.as_deref() == Some("Options")
        ),
        "declared param type becomes Param recv: {:?}",
        edge.receiver
    );
}

#[test]
fn struct_fields_retain_concrete_types_and_tag_keys() {
    let summary = go_module_summary(
        r#"package main
import cmd "example.com/app/command"
type CLI struct {
    Nested cmd.Group `cmd:"" help:"commands"`
    Helper cmd.Helper `help:"not a command"`
}
type Runner interface { Run() error }
"#,
        Lang::Go,
    );
    let cli = summary
        .classes
        .iter()
        .find(|class| class.name == "CLI")
        .unwrap();
    assert!(cli.is_struct);
    let nested = cli
        .struct_fields
        .iter()
        .find(|field| field.name == "Nested")
        .unwrap();
    assert_eq!(nested.typ, "cmd.Group");
    assert_eq!(nested.tags, ["cmd", "help"]);
    let helper = cli
        .struct_fields
        .iter()
        .find(|field| field.name == "Helper")
        .unwrap();
    assert_eq!(helper.tags, ["help"]);
    assert!(
        !summary
            .classes
            .iter()
            .find(|class| class.name == "Runner")
            .unwrap()
            .is_struct
    );
}

#[test]
fn interface_dispatch_is_deferred_with_its_contract() {
    let summary = go_module_summary(
        "package main\nimport \"os\"\ntype Doer interface { Do() }\ntype A struct{}\nfunc (a *A) Do() { os.RemoveAll(\"/from-a\") }\nfunc use(d Doer) { d.Do() }\nfunc main() { use(&A{}) }\n",
        Lang::Go,
    );
    assert_eq!(summary.dispatch_contracts.len(), 1);
    assert_eq!(summary.dispatch_contracts[0].name, "Doer");
    assert_eq!(summary.dispatch_contracts[0].methods, ["Do"]);
    assert_eq!(summary.dispatch_contracts[0].method_signatures.len(), 1);
    assert_eq!(summary.dispatch_contracts[0].method_signatures[0].0, "Do");
    assert!(
        summary.dispatch_contracts[0].method_signatures[0]
            .1
            .params
            .is_empty()
    );
    assert!(
        summary.dispatch_contracts[0].method_signatures[0]
            .1
            .results
            .is_empty()
    );

    let use_fn = summary.functions.iter().find(|f| f.name == "use").unwrap();
    let call = use_fn
        .calls
        .iter()
        .find(|call| call.callee == "d.Do")
        .unwrap();
    assert!(matches!(
        call.receiver_identity(),
        Some(ObjectIdentity::Parameter { name, fallback })
            if name == "d" && fallback.as_deref() == Some("Doer")
    ));
}

#[test]
fn interface_candidate_cardinality_is_not_guessed_by_the_frontend() {
    let summary = go_module_summary(
        "package main\nimport \"os\"\ntype Doer interface { Do() }\ntype A struct{}\nfunc (a *A) Do() { os.RemoveAll(\"/from-a\") }\ntype B struct{}\nfunc (b *B) Do() { os.RemoveAll(\"/from-b\") }\nfunc use(d Doer) { d.Do() }\nfunc main() { use(&A{}) }\n",
        Lang::Go,
    );
    assert_eq!(summary.dispatch_contracts.len(), 1);
    assert_eq!(summary.dispatch_contracts[0].methods, ["Do"]);
    let use_fn = summary.functions.iter().find(|f| f.name == "use").unwrap();
    assert!(matches!(
        use_fn.calls[0].receiver_identity(),
        Some(ObjectIdentity::Parameter { name, fallback })
            if name == "d" && fallback.as_deref() == Some("Doer")
    ));
}

#[test]
fn interface_dispatch_is_loud_in_single_file_analysis() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype Doer interface { Do() }\ntype A struct{}\nfunc (a *A) Do() { os.RemoveAll(\"/from-a\") }\nfunc use(d Doer) { d.Do() }\nfunc main() { use(&A{}) }\n",
    );
    assert!(plan.effects.is_empty());
    let unresolved: Vec<_> = plan
        .boundaries
        .iter()
        .filter(|boundary| boundary.reason.as_str() == "unresolved_interface")
        .collect();
    assert_eq!(unresolved.len(), 1, "{:?}", plan.boundaries);
    assert!(
        unresolved[0]
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("interface Doer"))
    );
}

#[test]
fn generic_instantiation_follows_the_declared_function() {
    let plan = analyze(
        "package main\nimport \"os\"\nfunc wipe[T ~string](path T) { os.RemoveAll(path) }\nfunc main() { wipe[string](\"/generic\") }\n",
    );
    assert!(
        has(&plan, "filesystem.delete", "/generic"),
        "generic call must reach wipe: {:?}",
        ops(&plan)
    );
}

#[test]
fn goroutine_channel_value_reaches_the_receiver() {
    for source in [
        "package main\nimport \"os\"\nfunc main() {\n\tpaths := make(chan string, 1)\n\tgo func() { paths <- \"/from-channel\" }()\n\tpath := <-paths\n\tos.RemoveAll(path)\n}\n",
        "package main\nimport \"os\"\nfunc main() {\n\tpaths := make(chan string, 1)\n\tpaths <- \"/from-channel\"\n\tos.RemoveAll(<-paths)\n}\n",
    ] {
        let plan = analyze(source);
        assert!(
            has(&plan, "filesystem.delete", "/from-channel"),
            "channel send must carry the concrete path: {:?}",
            ops(&plan)
        );
    }
}

#[test]
fn channel_passed_to_another_sender_widens_the_receiver() {
    let source = "package main\nimport \"os\"\nfunc send(paths chan string) { paths <- \"/other\" }\nfunc main() {\n\tpaths := make(chan string, 2)\n\tgo send(paths)\n\tpaths <- \"/local\"\n\tpath := <-paths\n\tos.Remove(path)\n}\n";
    let plan = analyze(source);
    assert!(
        plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                )
        }),
        "an escaped multi-writer channel must not retain one concrete send: {:?}",
        ops(&plan)
    );
    let summary = go_module_summary(source, Lang::Go);
    let main = summary
        .functions
        .iter()
        .find(|function| function.name == "main")
        .expect("main summary");
    assert!(main.summary.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Unresolved { family } if family.0 == "filesystem"
            )
    }));
}

#[test]
fn parameter_channel_receiver_stays_unresolved() {
    let source = "package main\nimport \"os\"\nfunc consume(paths chan string) {\n\tpaths <- \"/local\"\n\tpath := <-paths\n\tos.Remove(path)\n}\nfunc main() {\n\tpaths := make(chan string, 2)\n\tpaths <- \"/from-main\"\n\tconsume(paths)\n}\n";
    let plan = analyze(source);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Unresolved { family } if family.0 == "filesystem"
            )
    }));
    let summary = go_module_summary(source, Lang::Go);
    let consume = summary
        .functions
        .iter()
        .find(|function| function.name == "consume")
        .expect("consume summary");
    assert!(consume.summary.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Unresolved { family } if family.0 == "filesystem"
            )
    }));
}

#[test]
fn aliased_embedded_and_select_channels_widen_the_receiver() {
    for source in [
        "package main\nimport \"os\"\nfunc main() {\n\tpaths := make(chan string, 2)\n\talias := paths\n\talias <- \"/other\"\n\tpaths <- \"/local\"\n\tpath := <-paths\n\tos.Remove(path)\n}\n",
        "package main\nimport \"os\"\ntype box struct { paths chan string }\nfunc (b box) send() { b.paths <- \"/other\" }\nfunc main() {\n\tpaths := make(chan string, 2)\n\tb := box{paths: paths}\n\tgo b.send()\n\tpaths <- \"/local\"\n\tpath := <-paths\n\tos.Remove(path)\n}\n",
        "package main\nimport \"os\"\nfunc main() {\n\tpaths := make(chan string, 2)\n\tselect { case paths <- \"/other\": default: }\n\tpaths <- \"/local\"\n\tpath := <-paths\n\tos.Remove(path)\n}\n",
    ] {
        let plan = analyze(source);
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                    )
            }),
            "a multiply reachable channel must not retain one concrete send: {:?}",
            ops(&plan)
        );
    }
}

#[test]
fn captured_and_package_channels_widen_the_receiver() {
    for source in [
        "package main\nimport \"os\"\nfunc main() {\n\tpaths := make(chan string, 2)\n\tpaths <- \"/local\"\n\tsend := func() { paths <- \"/other\" }\n\tgo send()\n\tpath := <-paths\n\tos.Remove(path)\n}\n",
        "package main\nimport \"os\"\nfunc main() {\n\tpaths := make(chan string, 2)\n\tsend := func() { paths <- \"/other\" }\n\tgo send()\n\tpaths <- \"/local\"\n\tpath := <-paths\n\tos.Remove(path)\n}\n",
        "package main\nimport \"os\"\nvar paths = make(chan string, 2)\nfunc send() { paths <- \"/other\" }\nfunc main() {\n\tpaths <- \"/local\"\n\tgo send()\n\tpath := <-paths\n\tos.Remove(path)\n}\n",
    ] {
        let plan = analyze(source);
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                    )
            }),
            "a shared channel must not retain one concrete send: {:?}",
            ops(&plan)
        );
    }
}

#[test]
fn stored_channel_closure_does_not_widen_until_called() {
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tpaths := make(chan string, 2)\n\tunused := func() { paths <- \"/other\" }\n\t_ = unused\n\tpaths <- \"/local\"\n\tpath := <-paths\n\tos.Remove(path)\n}\n",
    );
    assert!(
        has(&plan, "filesystem.delete", "/local"),
        "an uncalled closure must not widen its captured channel: {:?}",
        ops(&plan)
    );
}

#[test]
fn transmitted_and_stored_closure_channels_widen_the_receiver() {
    for source in [
        "package main\nimport \"os\"\nfunc main() {\n\tpaths := make(chan string, 2)\n\tchannels := make(chan chan string, 1)\n\tchannels <- paths\n\tpaths <- \"/local\"\n\tpath := <-paths\n\tos.Remove(path)\n}\n",
        "package main\nimport \"os\"\ntype handler struct { send func() }\nfunc register(h handler) { h.send() }\nfunc main() {\n\tpaths := make(chan string, 2)\n\th := handler{send: func() { paths <- \"/other\" }}\n\tregister(h)\n\tpaths <- \"/local\"\n\tpath := <-paths\n\tos.Remove(path)\n}\n",
    ] {
        let plan = analyze(source);
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                    )
            }),
            "an escaped channel must not retain one concrete send: {:?}",
            ops(&plan)
        );
        let summary = go_module_summary(source, Lang::Go);
        let main = summary
            .functions
            .iter()
            .find(|function| function.name == "main")
            .expect("main summary");
        assert!(main.summary.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                )
        }));
    }
}

#[test]
fn computed_channel_bindings_widen_the_receiver() {
    for source in [
        "package main\nimport \"os\"\nfunc makePaths() chan string { paths := make(chan string, 2); paths <- \"/first\"; return paths }\nfunc main() {\n\tpaths := makePaths()\n\tpaths <- \"/local\"\n\tpath := <-paths\n\tos.Remove(path)\n}\n",
        "package main\nimport \"os\"\ntype box struct { paths chan string }\nfunc (b box) send() { b.paths <- \"/first\" }\nfunc main() {\n\tb := box{paths: make(chan string, 2)}\n\tgo b.send()\n\tpaths := b.paths\n\tpaths <- \"/local\"\n\tpath := <-paths\n\tos.Remove(path)\n}\n",
    ] {
        let plan = analyze(source);
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                    )
            }),
            "a channel from a computed expression must not appear fresh: {:?}",
            ops(&plan)
        );
        let summary = go_module_summary(source, Lang::Go);
        let main = summary
            .functions
            .iter()
            .find(|function| function.name == "main")
            .expect("main summary");
        assert!(main.summary.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                )
        }));
    }
}

#[test]
fn pointer_stored_and_labeled_channels_widen_the_receiver() {
    for source in [
        "package main\nimport \"os\"\ntype box struct { paths chan string }\nfunc (b *box) send() { b.paths <- \"/other\" }\nfunc main() {\n\tpaths := make(chan string, 2)\n\tpaths <- \"/local\"\n\tb := &box{paths: paths}\n\tb.send()\n\tpath := <-paths\n\tos.Remove(path)\n}\n",
        "package main\nimport \"os\"\nfunc main() {\n\tpaths := make(chan string, 2)\n\tpaths <- \"/local\"\nloop:\n\tfor {\n\t\tpaths <- \"/other\"\n\t\tbreak loop\n\t}\n\tpath := <-paths\n\tos.Remove(path)\n}\n",
    ] {
        let plan = analyze(source);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                )
        }));
        let summary = go_module_summary(source, Lang::Go);
        let main = summary
            .functions
            .iter()
            .find(|function| function.name == "main")
            .expect("main summary");
        assert!(main.summary.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                )
        }));
    }
}

#[test]
fn type_switch_and_for_post_channels_widen_the_receiver() {
    for source in [
        "package main\nimport \"os\"\nfunc main() {\n\tpaths := make(chan string, 2)\n\tpaths <- \"/local\"\n\tvar value interface{} = 1\n\tswitch value.(type) { case int: paths <- \"/other\" }\n\tpath := <-paths\n\tos.Remove(path)\n}\n",
        "package main\nimport \"os\"\nfunc main() {\n\tpaths := make(chan string, 2)\n\tpaths <- \"/local\"\n\tfor i := 0; i < 1; paths <- \"/other\" { i++ }\n\tpath := <-paths\n\tos.Remove(path)\n}\n",
    ] {
        let plan = analyze(source);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                )
        }));
        let summary = go_module_summary(source, Lang::Go);
        let main = summary
            .functions
            .iter()
            .find(|function| function.name == "main")
            .expect("main summary");
        assert!(main.summary.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                )
        }));
    }
}

#[test]
fn range_and_multi_value_rebindings_drop_stale_channel_evidence() {
    for source in [
        "package main\nimport \"os\"\nfunc main() {\n\tpaths := make(chan string, 1)\n\tpaths <- \"/stale\"\n\tpath := <-paths\n\tfor path = range os.Args { os.Remove(path) }\n}\n",
        "package main\nimport \"os\"\nfunc lookup() (bool, string) { return true, os.Getenv(\"PATH\") }\nfunc main() {\n\tpaths := make(chan string, 1)\n\tpaths <- \"/stale\"\n\tpath := <-paths\n\tvar ok bool\n\tok, path = lookup()\n\t_ = ok\n\tos.Remove(path)\n}\n",
        "package main\nimport \"os\"\nfunc main() {\n\tpath := make(chan string, 1)\n\tpath <- \"/stale\"\n\tnext := make(chan string, 1)\n\tnext <- \"/actual\"\n\tpaths := make(chan chan string, 1)\n\tpaths <- next\n\tfor path = range paths { os.Remove(<-path) }\n}\n",
        "package main\nimport \"os\"\nfunc lookup() (bool, chan string) { path := make(chan string, 1); path <- \"/actual\"; return true, path }\nfunc main() {\n\tpath := make(chan string, 1)\n\tpath <- \"/stale\"\n\tvar ok bool\n\tok, path = lookup()\n\t_ = ok\n\tos.Remove(<-path)\n}\n",
    ] {
        let plan = analyze(source);
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert!(
            !deletes.is_empty()
                && deletes.iter().all(|effect| matches!(
                    &effect.resource,
                    ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                )),
            "a rebound value must not retain its earlier channel resource: {:?}",
            ops(&plan)
        );
        let summary = go_module_summary(source, Lang::Go);
        let main = summary
            .functions
            .iter()
            .find(|function| function.name == "main")
            .expect("main summary");
        let deletes: Vec<_> = main
            .summary
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect();
        assert!(
            !deletes.is_empty()
                && deletes.iter().all(|effect| matches!(
                    &effect.resource,
                    ResourceExpr::Unresolved { family } if family.0 == "filesystem"
                ))
        );
    }
}

#[test]
fn same_name_channel_alias_widens_the_outer_receiver() {
    let source = "package main\nimport \"os\"\nfunc main() {\n\tpaths := make(chan string, 2)\n\tpaths <- \"/local\"\n\tfor i := 0; i < 1; i++ {\n\t\tpaths := paths\n\t\tgo func() { paths <- \"/other\" }()\n\t}\n\tpath := <-paths\n\tos.Remove(path)\n}\n";
    let plan = analyze(source);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Unresolved { family } if family.0 == "filesystem"
            )
    }));
    let summary = go_module_summary(source, Lang::Go);
    let main = summary
        .functions
        .iter()
        .find(|function| function.name == "main")
        .expect("main summary");
    assert!(main.summary.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Unresolved { family } if family.0 == "filesystem"
            )
    }));
}

#[test]
fn unused_goroutine_and_defer_closure_does_not_execute() {
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tunused := func() {\n\t\tgo os.RemoveAll(\"/unused-go\")\n\t\tdefer os.RemoveAll(\"/unused-defer\")\n\t}\n\t_ = unused\n}\n",
    );
    assert!(
        plan.effects.is_empty(),
        "unused work fired: {:?}",
        ops(&plan)
    );
}

#[test]
fn conditionally_rebound_values_keep_the_pre_branch_value() {
    for body in [
        "if len(targets()) == 2 { q = \"/rebound\" }",
        "for _, a := range targets() { _ = a; q = \"/rebound\" }",
        "switch len(targets()) { case 2: q = \"/rebound\" }",
        "select { case <-ready: q = \"/rebound\"\ncase <-other: }",
    ] {
        let plan = analyze(&format!(
            "package main\nimport \"os\"\nfunc targets() []string {{ return nil }}\nfunc main() {{\n\tready := make(chan int)\n\tother := make(chan int)\n\tq := \"/default\"\n\t{body}\n\tos.Remove(q)\n}}\n"
        ));
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && match &effect.resource {
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        } => path == "/default",
                        ResourceExpr::Union { alternatives } => {
                            alternatives.iter().any(|alternative| {
                                matches!(
                                    alternative,
                                    ResourceExpr::Concrete {
                                        identity: ResourceIdentity::FsPath { path }
                                    } if path == "/default"
                                )
                            })
                        }
                        _ => false,
                    }
            }),
            "{body}: {:?}",
            ops(&plan)
        );
        assert!(
            !has(&plan, "filesystem.delete", "/rebound")
                || has(&plan, "filesystem.delete", "/default"),
            "{body}: {:?}",
            ops(&plan)
        );
    }
}

#[test]
fn slices_equal_func_runs_its_third_argument() {
    // `slices.EqualFunc(s1, s2, eq)` carries its callback third; reading it out
    // of the second position both missed the callback and modeled a slice as a
    // call.
    let plan = analyze(
        "package main\nimport (\n\t\"os\"\n\t\"slices\"\n)\nfunc compare(a, b int) bool {\n\tos.RemoveAll(\"/equal-func\")\n\treturn a == b\n}\nfunc main() { slices.EqualFunc([]int{1}, []int{1}, compare) }\n",
    );
    assert!(
        has(&plan, "filesystem.delete", "/equal-func"),
        "{:?}",
        ops(&plan)
    );
    assert!(
        no_boundary_except_frontend_partial(&plan),
        "{:?}",
        plan.boundaries
    );
}

#[test]
fn stdlib_callback_table_covers_every_invoker_of_its_families() {
    // Each of these standard-library entry points invokes the function value it
    // is handed; leaving one out of the position table turned its callback's
    // effects into a precise negative with no boundary to say so.
    for (marker, source) in [
        (
            "/comparefunc",
            "package main\nimport (\n\t\"os\"\n\t\"slices\"\n)\nfunc cmp(a, b int) int {\n\tos.RemoveAll(\"/comparefunc\")\n\treturn a - b\n}\nfunc main() { slices.CompareFunc([]int{1}, []int{2}, cmp) }\n",
        ),
        (
            "/sortedfunc",
            "package main\nimport (\n\t\"os\"\n\t\"slices\"\n)\nfunc cmp(a, b int) int {\n\tos.RemoveAll(\"/sortedfunc\")\n\treturn a - b\n}\nfunc main() { slices.SortedFunc(slices.Values([]int{2, 1}), cmp) }\n",
        ),
        (
            "/sortedstablefunc",
            "package main\nimport (\n\t\"os\"\n\t\"slices\"\n)\nfunc cmp(a, b int) int {\n\tos.RemoveAll(\"/sortedstablefunc\")\n\treturn a - b\n}\nfunc main() { slices.SortedStableFunc(slices.Values([]int{2, 1}), cmp) }\n",
        ),
        (
            "/addcleanup",
            "package main\nimport (\n\t\"os\"\n\t\"runtime\"\n)\nfunc main() {\n\tt := 1\n\truntime.AddCleanup(&t, func(x int) { os.RemoveAll(\"/addcleanup\") }, 1)\n}\n",
        ),
        (
            "/fieldsfuncseq",
            "package main\nimport (\n\t\"os\"\n\t\"strings\"\n)\nfunc pred(r rune) bool {\n\tos.RemoveAll(\"/fieldsfuncseq\")\n\treturn r == ' '\n}\nfunc main() {\n\tfor range strings.FieldsFuncSeq(\"a b\", pred) {\n\t}\n}\n",
        ),
        (
            "/shutdown",
            "package main\nimport (\n\t\"net/http\"\n\t\"os\"\n)\nfunc main() {\n\tvar srv http.Server\n\tsrv.RegisterOnShutdown(func() { os.RemoveAll(\"/shutdown\") })\n}\n",
        ),
    ] {
        let plan = analyze(source);
        assert!(has(&plan, "filesystem.delete", marker), "{:?}", ops(&plan));
        assert!(
            no_boundary_except_frontend_partial(&plan),
            "{marker}: {:?}",
            plan.boundaries
        );
    }
}

#[test]
fn once_func_runs_its_argument_only_when_the_result_is_called() {
    // `sync.OnceFunc` wraps the callable; nothing runs until the returned
    // function is called.
    let wrapped = analyze(
        "package main\nimport (\n\t\"os\"\n\t\"sync\"\n)\nfunc cleanup() { os.RemoveAll(\"/once-func\") }\nfunc main() { sync.OnceFunc(cleanup) }\n",
    );
    assert!(
        !has(&wrapped, "filesystem.delete", "/once-func"),
        "{:?}",
        ops(&wrapped)
    );
    let called = analyze(
        "package main\nimport (\n\t\"os\"\n\t\"sync\"\n)\nfunc cleanup() { os.RemoveAll(\"/once-func\") }\nfunc main() {\n\trun := sync.OnceFunc(cleanup)\n\trun()\n}\n",
    );
    assert!(
        has(&called, "filesystem.delete", "/once-func"),
        "{:?}",
        ops(&called)
    );
}

#[test]
fn range_rebinding_drops_the_pre_loop_callable() {
    // Every iteration rebinds `callback`, and a zero-iteration range calls
    // nothing: the value it held before the loop must not be executed.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc stale() { os.RemoveAll(\"/stale-guess\") }\nfunc safe() { os.RemoveAll(\"/ranged\") }\nfunc main() {\n\tcallback := stale\n\tfor _, callback = range []func(){safe} {\n\t\tcallback()\n\t}\n}\n",
    );
    assert!(
        !has(&plan, "filesystem.delete", "/stale-guess"),
        "{:?}",
        ops(&plan)
    );
    assert!(
        has(&plan, "filesystem.delete", "/ranged"),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn range_rebinding_drops_the_pre_loop_path() {
    // The same rebinding over a collection this walk cannot name leaves the
    // value unknown rather than the pre-loop literal.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc targets() []string { return nil }\nfunc main() {\n\tq := \"/qdefault\"\n\tfor _, a := range targets() {\n\t\tq = a\n\t}\n\tos.Remove(q)\n}\n",
    );
    assert!(
        !has(&plan, "filesystem.delete", "/qdefault"),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn exact_struct_field_callable_reaches_a_package_call() {
    // A callable stored in a struct field is an exact value: passing it on
    // must reach the function it names.
    let plan = analyze(
        "package main\nimport (\n\t\"os\"\n\t\"sort\"\n)\ntype hooks struct{ less func(i, j int) bool }\nfunc compare(i, j int) bool {\n\tos.RemoveAll(\"/field-callback\")\n\treturn i < j\n}\nfunc main() {\n\th := hooks{less: compare}\n\tsort.Slice([]int{2, 1}, h.less)\n}\n",
    );
    assert!(
        has(&plan, "filesystem.delete", "/field-callback"),
        "{:?}",
        ops(&plan)
    );
    assert!(
        no_boundary_except_frontend_partial(&plan),
        "{:?}",
        plan.boundaries
    );
}

#[test]
fn ambiguous_struct_field_callable_reaches_every_alternative() {
    // A branch that reassigns the field leaves a finite set of callables in it.
    // Both may run, so both are reported rather than the read collapsing to an
    // opaque property whose callables the walk can no longer see.
    let plan = analyze(
        "package main\nimport (\n\t\"os\"\n\t\"sort\"\n)\ntype hooks struct{ less func(i, j int) bool }\nfunc compare(i, j int) bool {\n\tos.RemoveAll(\"/field-callback\")\n\treturn i < j\n}\nfunc other(i, j int) bool {\n\tos.RemoveAll(\"/other-callback\")\n\treturn i > j\n}\nfunc main() {\n\th := hooks{less: compare}\n\tif len(os.Args) > 1 {\n\t\th.less = other\n\t}\n\tsort.Slice([]int{2, 1}, h.less)\n}\n",
    );
    assert!(
        has(&plan, "filesystem.delete", "/field-callback"),
        "{:?}",
        ops(&plan)
    );
    assert!(
        has(&plan, "filesystem.delete", "/other-callback"),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn implicit_package_constant_repeats_the_previous_expression() {
    // `const ( first = "/implicit-const"; target )` gives `target` the same
    // expression as `first`.
    let plan = analyze(
        "package main\nimport \"os\"\nconst (\n\tfirst = \"/implicit-const\"\n\ttarget\n)\nfunc main() { os.RemoveAll(target) }\n",
    );
    assert!(
        has(&plan, "filesystem.delete", "/implicit-const"),
        "{:?}",
        ops(&plan)
    );
    let plan = analyze(
        "package main\nimport \"os\"\nconst target = \"/package-constant\"\nfunc purge() { os.RemoveAll(target) }\nfunc main() { target := \"/caller-local\"; purge(); _ = target }\n",
    );
    assert!(has(&plan, "filesystem.delete", "/package-constant"));
    assert!(!has(&plan, "filesystem.delete", "/caller-local"));
}

#[test]
fn implicit_iota_constant_is_not_repeated_as_a_value() {
    // `const ( a = iota; b )` counts up: `b` repeats the expression but not the
    // value, so no package value may claim `a`'s.
    let summary = go_module_summary(
        "package main\nconst (\n\tfirst = \"/iota-guard\"\n\tsecond = iota\n\tthird\n)\n",
        Lang::Go,
    );
    assert_eq!(
        summary.module_values.get("first").map(|value| &value.kind),
        Some(&effinterp_engine::SemanticValueKind::Literal(
            "/iota-guard".to_string()
        ))
    );
    assert!(
        !matches!(
            summary.module_values.get("third").map(|value| &value.kind),
            Some(effinterp_engine::SemanticValueKind::Literal(_))
        ),
        "{:?}",
        summary.module_values.get("third")
    );
}

#[test]
fn call_through_a_local_binding_is_a_dynamic_edge() {
    // A local variable and a function-typed parameter shadow every package
    // symbol spelled the same way, so their call edges may only be followed
    // through the value bound to the name — never by resolving the name
    // against the package. A literal bound to a local still names its target.
    let summary = go_module_summary(
        "package main\nfunc apply(less func(int, int) bool) { _ = less(1, 2) }\nfunc makeHandler() func() { return func() {} }\nfunc main() {\n\thandler := makeHandler()\n\thandler()\n\tdial := func() {}\n\tdial()\n}\n",
        Lang::Go,
    );
    let edge = |function: &str, callee: &str| {
        summary
            .functions
            .iter()
            .find(|entry| entry.name == function)
            .unwrap_or_else(|| panic!("no function {function}"))
            .calls
            .iter()
            .find(|edge| edge.callee == callee)
            .cloned()
    };
    assert!(edge("apply", "less").unwrap().dynamic_target);
    assert!(edge("main", "handler").unwrap().dynamic_target);
    // `dial` holds a literal this file declares, so its target is named.
    assert!(!edge("main", "dial").unwrap().dynamic_target);
}

#[test]
fn shadowed_package_function_is_never_called_by_name() {
    // `handler` names a local holding a closure this file cannot follow; the
    // package function of the same name is shadowed and must not run.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc handler() { os.RemoveAll(\"/danger\") }\nfunc makeHandler() func() {\n\treturn func() { os.Remove(\"/safe\") }\n}\nfunc main() {\n\thandler := makeHandler()\n\thandler()\n}\n",
    );
    assert!(
        !has(&plan, "filesystem.delete", "/danger"),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn sequence_consumers_run_the_iterator_they_are_handed() {
    // A `range`-over-func iterator is invoked by the consumer it is passed to,
    // so its effects belong to the consuming call site.
    for (marker, source) in [
        (
            "/sorted",
            "package main\nimport (\n\t\"os\"\n\t\"slices\"\n)\nfunc paths(yield func(string) bool) {\n\tos.RemoveAll(\"/sorted\")\n\tyield(\"a\")\n}\nfunc main() { slices.Sorted(paths) }\n",
        ),
        (
            "/collect",
            "package main\nimport (\n\t\"os\"\n\t\"slices\"\n)\nfunc paths(yield func(string) bool) {\n\tos.RemoveAll(\"/collect\")\n\tyield(\"a\")\n}\nfunc main() { slices.Collect(paths) }\n",
        ),
        (
            "/appendseq",
            "package main\nimport (\n\t\"os\"\n\t\"slices\"\n)\nfunc paths(yield func(string) bool) {\n\tos.RemoveAll(\"/appendseq\")\n\tyield(\"a\")\n}\nfunc main() { slices.AppendSeq([]string{}, paths) }\n",
        ),
        (
            "/sortedfunc-seq",
            "package main\nimport (\n\t\"os\"\n\t\"slices\"\n\t\"strings\"\n)\nfunc paths(yield func(string) bool) {\n\tos.RemoveAll(\"/sortedfunc-seq\")\n\tyield(\"a\")\n}\nfunc main() { slices.SortedFunc(paths, strings.Compare) }\n",
        ),
        (
            "/maps-collect",
            "package main\nimport (\n\t\"maps\"\n\t\"os\"\n)\nfunc pairs(yield func(string, int) bool) {\n\tos.RemoveAll(\"/maps-collect\")\n\tyield(\"a\", 1)\n}\nfunc main() { maps.Collect(pairs) }\n",
        ),
        (
            "/maps-insert",
            "package main\nimport (\n\t\"maps\"\n\t\"os\"\n)\nfunc pairs(yield func(string, int) bool) {\n\tos.RemoveAll(\"/maps-insert\")\n\tyield(\"a\", 1)\n}\nfunc main() { maps.Insert(map[string]int{}, pairs) }\n",
        ),
    ] {
        let plan = analyze(source);
        assert!(has(&plan, "filesystem.delete", marker), "{:?}", ops(&plan));
        assert!(
            no_boundary_except_frontend_partial(&plan),
            "{marker}: {:?}",
            plan.boundaries
        );
    }
}

#[test]
fn unix_listener_keeps_its_filesystem_consequence_when_the_path_is_unknown() {
    // Binding a unix socket creates a file. A bind whose address or network is
    // unknown must stay uncertain in the filesystem domain instead of
    // answering a filesystem query with a precise negative.
    let plan = analyze(
        "package main\nimport (\n\t\"net\"\n\t\"os\"\n)\nfunc main() {\n\tnet.Listen(\"unix\", os.Getenv(\"S\"))\n\tnet.Listen(os.Getenv(\"NET\"), \"/tmp/s.sock\")\n\tnet.Listen(\"tcp\", os.Getenv(\"T\"))\n}\n",
    );
    let creates: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.create")
        .collect();
    assert_eq!(creates.len(), 2, "{:?}", ops(&plan));
    assert!(
        creates.iter().all(|effect| matches!(
            &effect.resource,
            ResourceExpr::Unresolved { family } if family.0 == "filesystem"
        )),
        "{:?}",
        ops(&plan)
    );
}

#[test]
fn package_variables_assigned_elsewhere_are_recorded_as_rebound() {
    let summary = go_module_summary(
        "package main\nimport \"os\"\nvar target = \"/initial\"\nvar other = \"/other\"\nfunc init() { target = \"/changed\" }\nfunc shadow() { other := os.Getenv(\"O\"); other = \"/local\"; os.RemoveAll(other) }\n",
        Lang::Go,
    );
    assert!(summary.module_values.contains_key("target"));
    assert!(summary.module_values.contains_key("other"));
    assert_eq!(
        summary.module_value_rebindings,
        ["target".to_string()].into_iter().collect(),
        "a name the function declares itself shadows the package variable"
    );
}

#[test]
fn package_variables_assigned_in_a_closure_are_recorded_as_rebound() {
    let summary = go_module_summary(
        "package main\nvar hook = \"/initial\"\nfunc register() func() { return func() { hook = \"/changed\" } }\n",
        Lang::Go,
    );
    assert!(
        summary.module_value_rebindings.contains("hook"),
        "{:?}",
        summary.module_value_rebindings
    );
}

#[test]
fn a_returned_function_literal_is_a_callable_the_package_can_enter() {
    let summary = go_module_summary(
        "package main\nimport \"os\"\nfunc makeHandler() func() { return func() { os.Remove(\"/returned\") } }\n",
        Lang::Go,
    );
    let returned = summary
        .functions
        .iter()
        .find(|function| function.name == "makeHandler")
        .and_then(|function| function.summary.returns.clone())
        .expect("makeHandler returns a value");
    let effinterp_engine::SemanticValueKind::Callable(effinterp_engine::CallableValue::Function {
        name,
    }) = &returned.kind
    else {
        panic!("expected a callable return, got {returned:?}");
    };
    let literal = summary
        .functions
        .iter()
        .find(|function| &function.name == name)
        .expect("the returned literal is a callable of the file");
    assert!(
        literal
            .summary
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete"),
        "{:?}",
        literal.summary.effects
    );
}

#[test]
fn a_write_through_a_qualifier_is_recorded_as_a_rebinding() {
    // `lib.Target = ...` is how a write from another package is spelled, and
    // `cfg.Field = ...` is an in-place write of the package's own value: both
    // leave the declaration's initializer describing something the program no
    // longer holds.
    let summary = go_module_summary(
        "package main\nimport \"ex.com/app/lib\"\ntype Config struct{ Path string }\nvar cfg = Config{Path: \"/declared\"}\nfunc main() { lib.Target = \"/danger\"; cfg.Path = \"/changed\" }\n",
        Lang::Go,
    );
    assert!(
        summary.module_value_rebindings.contains("lib.Target"),
        "the qualified write names the package it assigns: {:?}",
        summary.module_value_rebindings
    );
    assert!(
        summary.module_value_rebindings.contains("cfg"),
        "an in-place field write invalidates the value it is reached through: {:?}",
        summary.module_value_rebindings
    );
}

#[test]
fn a_closure_call_drops_the_bindings_it_assigns() {
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/safe\"\n\tf := func() { p = \"/danger\" }\n\tf()\n\tos.RemoveAll(p)\n}\n",
    );
    let deletes: Vec<_> = ops(&plan)
        .into_iter()
        .filter(|(operation, _)| *operation == "filesystem.delete")
        .collect();
    assert_eq!(deletes.len(), 1, "{:?}", ops(&plan));
    assert_ne!(
        deletes[0].1, "/safe",
        "the closure rebound the name before the read: {:?}",
        deletes[0]
    );
}

#[test]
fn a_callee_writing_through_a_pointer_parameter_drops_the_caller_value() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype H struct{ path string }\nfunc mutate(h *H) { h.path = \"/danger\" }\nfunc main() {\n\th := &H{path: \"/safe\"}\n\tmutate(h)\n\tos.RemoveAll(h.path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/safe"),
        "the callee wrote the caller's struct through the pointer: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_callee_that_forwards_the_pointer_drops_the_caller_value() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype H struct{ path string }\nfunc forward(h *H) { h.path = \"/danger\" }\nfunc mutate(h *H) { forward(h) }\nfunc main() {\n\th := &H{path: \"/safe\"}\n\tmutate(h)\n\tos.RemoveAll(h.path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/safe"),
        "the write a forwarded pointer reaches belongs to the caller too: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_method_writing_through_its_receiver_drops_the_caller_value() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype H struct{ path string }\nfunc (h *H) Set(p string) { h.path = p }\nfunc main() {\n\th := &H{path: \"/safe\"}\n\th.Set(\"/danger\")\n\tos.RemoveAll(h.path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/safe"),
        "a pointer receiver is the caller's own storage: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_method_that_only_reads_its_receiver_keeps_the_caller_exact() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype H struct{ path string }\nfunc (h *H) Show() string { return h.path }\nfunc main() {\n\th := &H{path: \"/kept\"}\n\t_ = h.Show()\n\tos.RemoveAll(h.path)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/kept"),
        "a method that assigns nothing leaves the receiver exact: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_write_through_a_pointer_alias_drops_the_variable_it_addresses() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype H struct{ path string }\nfunc mutate(h *H) { h.path = \"/danger\" }\nfunc main() {\n\tc := H{path: \"/safe\"}\n\tp := &c\n\tmutate(p)\n\tos.RemoveAll(c.path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/safe"),
        "the pointer and the variable it addresses are one storage: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_call_through_a_callable_field_leaves_the_object_exact() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype Hooks struct{ Run func(); Path string }\nfunc wipe() { os.RemoveAll(\"/hook\") }\nfunc main() {\n\th := Hooks{Run: wipe, Path: \"/kept\"}\n\th.Run()\n\tos.RemoveAll(h.Path)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/kept"),
        "a callable field hands the object to nobody: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_value_a_callee_only_reads_keeps_its_exact_field() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc show(c Config) { _ = c.Path }\nfunc main() {\n\tc := Config{Path: \"/kept\"}\n\tshow(c)\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/kept"),
        "a callee that writes through no parameter leaves the caller exact: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_method_of_a_type_this_file_does_not_declare_may_write_its_receiver() {
    // `Config` and its methods live in a sibling file of the same package, so
    // the walk cannot read the body it calls: the receiver may be rewritten.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tc.Retarget()\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a sibling file's method is as unreadable as any other: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_method_on_a_repository_package_type_may_write_its_receiver() {
    // `lib.Config`'s methods live in another package of this repository, which
    // this walk reads no more than a sibling file: the receiver may be
    // rewritten, so the declared path is not the one deleted.
    let plan = analyze(
        "package main\nimport (\n\t\"os\"\n\n\t\"ex.com/app/lib\"\n)\nfunc main() {\n\tc := lib.Config{Path: \"/declared\"}\n\tc.Retarget()\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a method of an imported repository package is unreadable too: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_method_on_a_standard_library_type_leaves_its_receiver_exact() {
    // The engine models standard-library receiver identities itself, so a
    // method call on one keeps the caller's exact view of it.
    let plan = analyze(
        "package main\nimport (\n\t\"os\"\n\t\"os/exec\"\n)\nfunc main() {\n\tcmd := exec.Cmd{Path: \"/kept\"}\n\t_ = cmd.String()\n\tos.RemoveAll(cmd.Path)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/kept"),
        "a modeled standard-library receiver keeps its fields: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_body_local_closure_shadowing_a_package_function_is_not_read_for_its_writes() {
    // `run` binds a closure to `apply`, shadowing the package function of that
    // name, so that function's empty write set says nothing about the call.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc apply(c *Config) {}\nfunc run(c *Config) {\n\tapply := func(x *Config) { x.Path = \"/actual\" }\n\tapply(c)\n}\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\trun(&c)\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "the shadowed package function is not the callee: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_body_local_closure_that_writes_nothing_keeps_the_caller_exact() {
    // No package function is shadowed here, so the closure bound to the name
    // is read for its writes: it assigns nothing and the caller stays exact.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc run(c *Config) {\n\tinspect := func(x *Config) { _ = x.Path }\n\tinspect(c)\n}\nfunc main() {\n\tc := Config{Path: \"/kept\"}\n\trun(&c)\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/kept"),
        "a closure that assigns nothing leaves the caller exact: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_method_assigning_through_a_dereferenced_receiver_drops_the_caller_value() {
    // `*c = ...` and `(*c).Path = ...` assign the receiver's storage exactly as
    // `c.Path = ...` does, so the caller loses its exact view either way.
    for body in ["*c = Config{Path: \"/actual\"}", "(*c).Path = \"/actual\""] {
        let plan = analyze(&format!(
            "package main\nimport \"os\"\ntype Config struct{{ Path string }}\nfunc (c *Config) Retarget() {{ {body} }}\nfunc main() {{\n\tc := Config{{Path: \"/declared\"}}\n\tc.Retarget()\n\tos.RemoveAll(c.Path)\n}}\n"
        ));
        assert!(
            !ops(&plan)
                .iter()
                .any(|(operation, resource)| *operation == "filesystem.delete"
                    && resource == "/declared"),
            "a dereferenced receiver is still the caller's storage ({body}): {:?}",
            ops(&plan)
        );
    }
}

#[test]
fn a_callee_assigning_through_a_dereferenced_parameter_drops_the_caller_value() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc reset(c *Config) { *c = Config{Path: \"/actual\"} }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\treset(&c)\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a callee replacing the whole pointee writes through the parameter: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_direct_write_through_a_pointer_alias_drops_the_variable_it_addresses() {
    // `p := &c` makes `p` and `c` one storage, so `p.Path = ...` in the same
    // body leaves `c` as stale as a callee's write through the pointer would.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tp := &c\n\tp.Path = \"/actual\"\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a write through an alias reaches the variable it addresses: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_write_through_a_copied_pointer_drops_the_variable_it_addresses() {
    // `q := p` copies a pointer, so `q`, `p` and `c` are one storage: a write
    // through the copy leaves `c` as stale as a write through `p` does.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tp := &c\n\tq := p\n\tq.Path = \"/actual\"\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a copied pointer addresses the same storage: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_callee_writing_through_a_copied_pointer_parameter_costs_the_caller_its_value() {
    // The callee copies the pointer it was handed and writes through the copy,
    // which is the caller's storage all the same.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc retarget(p *Config) {\n\tq := p\n\tq.Path = \"/actual\"\n}\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tretarget(&c)\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a write through a copy of a pointer parameter reaches the caller: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_callee_writing_a_copy_of_a_by_value_parameter_leaves_the_caller_exact() {
    // The precision guard for the rule above: Go copies a struct parameter, so
    // the callee's copy of it is storage of its own.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc show(c Config) {\n\td := c\n\td.Path = \"/other\"\n}\nfunc main() {\n\tc := Config{Path: \"/kept\"}\n\tshow(c)\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/kept"),
        "a by-value parameter's copy is not the caller's storage: {:?}",
        ops(&plan)
    );
}

#[test]
fn copying_a_struct_value_leaves_the_original_exact() {
    // The precision guard for the rule above: `d := c` on a struct copies the
    // value, so writing `d` says nothing about `c`.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/kept\"}\n\td := c\n\td.Path = \"/other\"\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/kept"),
        "a struct copy is not an alias: {:?}",
        ops(&plan)
    );
}

#[test]
fn an_address_a_callee_returns_costs_the_caller_its_value() {
    // `ptr` hands the address back, so the caller holds a second name for `c`
    // that the walk cannot follow: a write through it leaves `c` stale.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc ptr(c *Config) *Config { return c }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tp := ptr(&c)\n\tp.Path = \"/actual\"\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a returned address escapes the call: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_callee_returning_a_field_of_its_argument_leaves_the_caller_exact() {
    // The precision guard for the rule above: `c.Path` hands back the field's
    // value, not the storage, so the caller keeps its exact view.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc name(c *Config) string { return c.Path }\nfunc main() {\n\tc := Config{Path: \"/kept\"}\n\t_ = name(&c)\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/kept"),
        "a returned field value is not the caller's storage: {:?}",
        ops(&plan)
    );
}

#[test]
fn an_address_stored_in_a_composite_literal_costs_the_variable_its_value() {
    // `Holder{C: &c}` puts the address in storage the walk does not follow, so
    // the later write through the field reaches `c` unseen.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\ntype Holder struct{ C *Config }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\th := Holder{C: &c}\n\th.C.Path = \"/actual\"\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "an address stored in a literal escapes: {:?}",
        ops(&plan)
    );
}

#[test]
fn an_address_stored_in_a_collection_element_costs_the_variable_its_value() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tps := []*Config{&c}\n\tps[0].Path = \"/actual\"\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "an address stored in an element escapes: {:?}",
        ops(&plan)
    );
}

#[test]
fn an_address_assigned_into_a_container_costs_the_variable_its_value() {
    // `m["a"] = &c` stores the address in a map entry; only `p = &c` on a plain
    // name is a tracked alias, so the variable loses its exact contents.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tm := map[string]*Config{}\n\tm[\"a\"] = &c\n\tm[\"a\"].Path = \"/actual\"\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "an address assigned into a container escapes: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_callable_field_reached_through_an_escaped_address_is_not_claimed_exactly() {
    // The element write swaps the callable, so neither the declared nor the
    // assigned function may be reported as the one that runs.
    let plan = analyze(
        "package main\nimport \"os\"\ntype H struct{ Fn func() }\nfunc safe() { os.RemoveAll(\"/safe\") }\nfunc wipe() { os.RemoveAll(\"/danger\") }\nfunc main() {\n\th := H{Fn: safe}\n\ths := []*H{&h}\n\ths[0].Fn = wipe\n\th.Fn()\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/safe"),
        "a swapped callable must not be claimed by its declaration: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_closure_handed_to_a_call_costs_the_names_it_assigns() {
    // `run(f)` hands over a closure that rebinds `c`, and nothing here follows
    // it into `run`: the field it assigns is stale once the call returns.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc run(f func()) { f() }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tf := func() { c.Path = \"/actual\" }\n\trun(f)\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a closure handed to a call escapes: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_literal_handed_to_a_call_costs_the_names_it_assigns() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc run(f func()) { f() }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\trun(func() { c.Path = \"/actual\" })\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a literal handed to a call escapes: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_closure_stored_in_a_collection_costs_the_names_it_assigns() {
    // The element call `fs[0]()` reaches a body no name of this walk holds, so
    // the closure's writes are already unaccounted for where it was stored.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tfs := []func(){func() { c.Path = \"/actual\" }}\n\tfs[0]()\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a closure stored in a collection escapes: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_closure_stored_in_a_struct_field_costs_the_names_it_assigns() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\ntype Holder struct{ Fn func() }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\th := Holder{Fn: func() { c.Path = \"/actual\" }}\n\th.Fn()\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a closure stored in a field escapes: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_method_value_costs_its_receiver_its_value() {
    // `m := c.Retarget` captures `&c`, and the call through `m` reaches the
    // method body unseen, so the receiver is stale from where it was taken.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc (c *Config) Retarget() { c.Path = \"/actual\" }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tm := c.Retarget\n\tm()\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a method value escapes its receiver: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_closure_bound_to_a_shared_name_costs_the_names_it_assigns() {
    // Two closures under one name resolve to neither body, so `f()` applies
    // no writes: the literal is not a tracked binding and escapes where it is
    // bound.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tf := func() { c.Path = \"/first\" }\n\tf = func() { c.Path = \"/second\" }\n\tf()\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a closure no name resolves to escapes: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_callable_that_assigns_nothing_of_the_caller_leaves_it_exact() {
    // The precision guard for the rules above: a closure that writes none of
    // the caller's bindings costs it nothing, and a field read is not a method
    // value.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc run(f func()) { f() }\nfunc main() {\n\tc := Config{Path: \"/kept\"}\n\trun(func() { os.RemoveAll(\"/other\") })\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/kept"),
        "an inert callable keeps the caller exact: {:?}",
        ops(&plan)
    );
}

#[test]
fn an_effect_before_a_closure_escapes_keeps_its_exact_path() {
    // The escape costs the binding its value from where it happens, not before.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc run(f func()) { f() }\nfunc main() {\n\tc := Config{Path: \"/kept\"}\n\tos.RemoveAll(c.Path)\n\tf := func() { c.Path = \"/actual\" }\n\trun(f)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/kept"),
        "an effect before the escape stays exact: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_callback_the_walk_enters_applies_its_write_exactly() {
    // `once.Do` is a callback position this walk runs itself, so the write it
    // performs is seen and the caller keeps an exact - updated - view.
    let plan = analyze(
        "package main\nimport (\n\t\"os\"\n\t\"sync\"\n)\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tvar once sync.Once\n\tonce.Do(func() { c.Path = \"/actual\" })\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/actual"),
        "an entered callback applies its write: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_method_called_on_a_constructor_result_is_dispatched() {
    // `newRemover().Wipe()` runs a method on a value no name holds; the
    // receiver is the constructor's result, and the call is not silent.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Remover struct{ path string }\nfunc newRemover() *Remover { return &Remover{path: \"/target\"} }\nfunc (r *Remover) Wipe() { os.RemoveAll(\"/target\") }\nfunc main() { newRemover().Wipe() }\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/target"),
        "a chained constructor call dispatches its method: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_chained_standard_library_call_is_still_modeled_by_its_inner_call() {
    // The precision guard for the rule above: `exec.Command(...).Run()` is the
    // modeled inner call, not a method on a package-declared constructor.
    let plan = analyze(
        "package main\nimport \"os/exec\"\nfunc main() { _ = exec.Command(\"ls\").Run() }\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "process.exec" && resource == "ls"),
        "a modeled stdlib chain keeps its executable: {:?}",
        ops(&plan)
    );
}

#[test]
fn two_closures_sharing_a_name_resolve_to_neither_body() {
    // Closures are registered by the name they are bound to, so a name two
    // functions each bind says nothing about which body a call site reaches —
    // whichever order they are declared in.
    let noop = "func noop() {\n\tw := func(x *Config) {}\n\tw(nil)\n}\n";
    let run = "func run(c *Config) {\n\tw := func(x *Config) { x.Path = \"/actual\" }\n\tw(c)\n}\n";
    for (first, second) in [(noop, run), (run, noop)] {
        let plan = analyze(&format!(
            "package main\nimport \"os\"\ntype Config struct{{ Path string }}\n{first}{second}func main() {{\n\tc := Config{{Path: \"/declared\"}}\n\trun(&c)\n\tnoop()\n\tos.RemoveAll(c.Path)\n}}\n"
        ));
        assert!(
            !ops(&plan)
                .iter()
                .any(|(operation, resource)| *operation == "filesystem.delete"
                    && resource == "/declared"),
            "a shared closure name must not decide the write set by declaration order: {:?}",
            ops(&plan)
        );
    }
}

#[test]
fn a_closure_name_bound_only_once_keeps_the_caller_exact() {
    // The precision guard for the rule above: one binding of the name, so the
    // closure that assigns nothing is still read for its writes.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc noop() {\n\tinspect := func(x *Config) {}\n\tinspect(nil)\n}\nfunc run(c *Config) {\n\tw := func(x *Config) { _ = x.Path }\n\tw(c)\n}\nfunc main() {\n\tc := Config{Path: \"/kept\"}\n\trun(&c)\n\tnoop()\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/kept"),
        "distinct closure names stay resolvable: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_method_on_a_dot_free_module_package_type_may_write_its_receiver() {
    // `go mod init app` is legal, so an import path without a dotted domain is
    // not evidence of the standard library: `lib.Config`'s methods are as
    // unreadable here as under `ex.com/app/lib`.
    let plan = analyze(
        "package main\nimport (\n\t\"os\"\n\n\t\"app/lib\"\n)\nfunc main() {\n\tc := lib.Config{Path: \"/declared\"}\n\tc.Retarget()\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a dot-free module path is not the standard library: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_method_on_an_imported_type_leaves_the_receiver_exact() {
    let plan = analyze(
        "package main\nimport (\n\t\"os\"\n\t\"sync\"\n)\ntype H struct{ path string }\nfunc main() {\n\tvar once sync.Once\n\th := &H{path: \"/kept\"}\n\tonce.Do(func() {})\n\tos.RemoveAll(h.path)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/kept"),
        "a modeled standard-library receiver stays exact: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_parameter_shadowing_a_package_function_is_not_read_for_its_writes() {
    // `run`'s parameter `apply` shadows the package function of that name, so
    // the package function's (empty) write set says nothing about the callable
    // `main` actually hands over.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc apply(c *Config) {}\nfunc run(c *Config, apply func(*Config)) { apply(c) }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\trun(&c, func(x *Config) { x.Path = \"/actual\" })\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "the shadowed package function is not the callee: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_the_value_the_function_ends_with() {
    // The deferred body runs after `c` is reassigned, so the path it names is
    // whatever `c` holds at the return, not what it held at the defer.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tc := \"/tmp/declared.txt\"\n\tdefer func() { os.Remove(c) }()\n\tc = \"/tmp/actual.txt\"\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "a deferred body must not claim a superseded value: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_does_not_write_the_statements_before_the_return() {
    // The deferred write lands after `os.Remove`, which still sees `/declared`.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tc := \"/declared\"\n\tdefer func() { c = \"/actual\" }()\n\tos.Remove(c)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a deferred write must not reach the statements it follows: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_keeps_a_name_the_function_never_reassigns() {
    // The precision guard: nothing reassigns `c`, so the deferred body reads
    // the one value it was given.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tc := \"/tmp/kept.txt\"\n\tdefer func() { os.Remove(c) }()\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/kept.txt"),
        "a deferred body keeps an unassigned name exact: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_call_evaluates_its_arguments_where_it_stands() {
    // `defer os.Remove(c)` captures `c` at the defer statement, so the later
    // assignment does not reach it.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tc := \"/tmp/declared.txt\"\n\tdefer os.Remove(c)\n\tc = \"/tmp/actual.txt\"\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "a deferred argument is evaluated at the defer: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_goroutine_costs_the_caller_the_names_it_assigns() {
    // The goroutine runs at a moment nothing orders against `os.Remove`, so
    // neither the value it writes nor the one it replaces can be claimed.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tgo func() { p = \"/tmp/actual.txt\" }()\n\tos.Remove(p)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && (resource == "/tmp/actual.txt" || resource == "/tmp/declared.txt")),
        "a goroutine write must not be applied in program order: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_goroutine_that_assigns_nothing_leaves_the_caller_exact() {
    // The precision guard for the rule above.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/tmp/kept.txt\"\n\tgo func() { os.Remove(\"/other\") }()\n\tos.Remove(p)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/kept.txt"),
        "an inert goroutine keeps the caller exact: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_field_the_function_writes_later() {
    // The write reaches `c.Path` through `c`, and the deferred body runs after
    // it, so the declared path is not the one removed.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/tmp/declared.txt\"}\n\tdefer func() { os.Remove(c.Path) }()\n\tc.Path = \"/tmp/actual.txt\"\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "a later field write must reach a deferred read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_pointer_field_the_function_writes_later() {
    // The same write through a pointer receiver.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := &Config{Path: \"/tmp/declared.txt\"}\n\tdefer func() { os.Remove(c.Path) }()\n\tc.Path = \"/tmp/actual.txt\"\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "a later field write through a pointer must reach a deferred read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_goroutine_reads_a_field_the_caller_writes_after_it() {
    // The goroutine may observe either value, so neither can be claimed.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/tmp/declared.txt\"}\n\tgo func() { os.Remove(c.Path) }()\n\tc.Path = \"/tmp/actual.txt\"\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "a concurrent read must not claim the superseded field: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_the_function_writes_through_a_pointer() {
    // `*q = v` names `q`, but writes the storage `p` names, which the deferred
    // body reads.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tq := &p\n\tdefer func() { os.Remove(p) }()\n\t*q = \"/tmp/actual.txt\"\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "a write through an alias must reach a deferred read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_keeps_a_field_the_function_never_writes() {
    // The precision guard: nothing writes `c`, so the field stays exact.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/tmp/kept.txt\"}\n\tdefer func() { os.Remove(c.Path) }()\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/kept.txt"),
        "an unwritten field stays exact in a deferred body: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_a_pointer_bound_after_it_writes() {
    // `q := &p` stands below the defer, so the walk has not bound the alias
    // when it reaches the body; the write through it is no more ordered
    // against the body than the alias statement is.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tdefer func() { os.Remove(p) }()\n\tq := &p\n\t*q = \"/tmp/actual.txt\"\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "a pointer bound below the defer must still reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_goroutine_reads_a_name_a_pointer_bound_after_it_writes() {
    // The concurrent form of the same shape.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tgo func() { os.Remove(p) }()\n\tq := &p\n\t*q = \"/tmp/actual.txt\"\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "a pointer bound below the goroutine must still reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_a_copied_pointer_writes() {
    // `r := q` addresses what `q` addresses, wherever the block states either.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tdefer func() { os.Remove(p) }()\n\tq := &p\n\tr := q\n\t*r = \"/tmp/actual.txt\"\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "a copy of a pointer must reach the read too: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_keeps_a_name_only_a_pointer_reads() {
    // The precision guard for the pointers a block states: nothing writes
    // through `q`, so `p` keeps its value.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/tmp/kept.txt\"\n\tdefer func() { os.Remove(p) }()\n\tq := &p\n\t_ = q\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/kept.txt"),
        "an unwritten name stays exact beside a pointer to it: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_a_sibling_literal_writes() {
    // The immediately invoked literal runs between the defer statement and the
    // deferred body, which the walk cannot place either.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tdefer func() { os.Remove(p) }()\n\tfunc() { p = \"/tmp/actual.txt\" }()\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "a sibling literal's write must reach a deferred read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_a_literal_handed_to_a_callee_writes() {
    // The same write, made where the callee decides to call it.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc run(f func()) { f() }\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tdefer func() { os.Remove(p) }()\n\trun(func() { p = \"/tmp/actual.txt\" })\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "a handed-over literal's write must reach a deferred read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_a_callee_writes_through_an_address() {
    // `mutate(&p)` writes `p` exactly as `*q = v` does; the callee holds the
    // address, so the block's own text never states the write.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc mutate(s *string) { *s = \"/tmp/actual.txt\" }\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tdefer func() { os.Remove(p) }()\n\tmutate(&p)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "a write through an address handed to a callee must reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_goroutine_reads_a_name_a_callee_writes_through_an_address() {
    // The concurrent form of the same shape.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc mutate(s *string) { *s = \"/tmp/actual.txt\" }\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tgo func() { os.Remove(p) }()\n\tmutate(&p)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "a write through an address handed to a callee must reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_keeps_a_name_a_callee_only_reads() {
    // The precision guard for it: `report` assigns nothing through its
    // parameter, so the address it is handed costs `p` nothing, exactly as it
    // costs nothing when the read stands in program order.
    let plan = analyze(
        "package main\nimport \"fmt\"\nimport \"os\"\nfunc report(s *string) { fmt.Println(*s) }\nfunc main() {\n\tp := \"/tmp/kept.txt\"\n\tdefer func() { os.Remove(p) }()\n\treport(&p)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/kept.txt"),
        "a callee that only reads through the address leaves the name exact: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_field_a_pointer_receiver_writes() {
    // A method on a pointer receiver assigns the caller's own storage, so the
    // field the body reads is no more ordered against `Update` than against a
    // bare assignment.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc (c *Config) Update(p string) { c.Path = p }\nfunc main() {\n\tc := &Config{Path: \"/tmp/declared.txt\"}\n\tdefer func() { os.Remove(c.Path) }()\n\tc.Update(\"/tmp/actual.txt\")\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "a pointer-receiver write must reach a deferred read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_a_container_pointer_writes() {
    // `&p` stored in a map is a second name for `p` that this walk does not
    // follow, so every write through the container costs `p` its value.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tdefer func() { os.Remove(p) }()\n\tm := map[string]*string{\"k\": &p}\n\t*m[\"k\"] = \"/tmp/actual.txt\"\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "an address stored in a container must reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_a_map_element_pointer_writes() {
    // `m["k"] = &p` hands the address to storage this walk does not follow,
    // exactly as the composite literal form does; the assignment target is not
    // a plain name, so nothing here tracks the pointer it stores.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tdefer func() { os.Remove(p) }()\n\tm := map[string]*string{}\n\tm[\"k\"] = &p\n\t*m[\"k\"] = \"/tmp/actual.txt\"\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "an address assigned into a container must reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_a_struct_field_pointer_writes() {
    // The same for a field: `h.C = &p` names no binding of this walk either.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Holder struct{ C *string }\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tdefer func() { os.Remove(p) }()\n\tvar h Holder\n\th.C = &p\n\t*h.C = \"/tmp/actual.txt\"\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "an address assigned into a field must reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_a_channelled_pointer_writes() {
    // A channel carries the address to a receiver neither walk follows, so the
    // send costs `p` its value here as it does in program order.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tdefer func() { os.Remove(p) }()\n\tch := make(chan *string, 1)\n\tch <- &p\n\tq := <-ch\n\t*q = \"/tmp/actual.txt\"\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "an address sent over a channel must reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_a_sibling_literal_hands_a_callee() {
    // The block states the call inside the sibling literal's body, so the
    // callee's write through the address it is handed counts as the block's,
    // just as it does when the call stands directly in the block.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc mutate(s *string) { *s = \"/tmp/actual.txt\" }\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tdefer func() { os.Remove(p) }()\n\tfunc() { mutate(&p) }()\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "a write a sibling literal's callee makes must reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_a_sibling_literal_stores_in_a_container() {
    // The sibling literal hands `&p` to a map element, which this walk does not
    // follow, so the write through that element costs `p` its value exactly as
    // the same statements standing in the block itself do.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tdefer func() { os.Remove(p) }()\n\tfunc() {\n\t\tm := map[string]*string{}\n\t\tm[\"k\"] = &p\n\t\t*m[\"k\"] = \"/tmp/actual.txt\"\n\t}()\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "an address a sibling literal stores in a container must reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_a_sibling_literal_puts_in_a_composite_literal() {
    // The same when the sibling literal builds the container around the address
    // instead of assigning into it.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tdefer func() { os.Remove(p) }()\n\tfunc() {\n\t\tm := map[string]*string{\"k\": &p}\n\t\t*m[\"k\"] = \"/tmp/actual.txt\"\n\t}()\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "an address a sibling literal puts in a composite literal must reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_a_sibling_literal_writes_through_a_pointer() {
    // The pointer is a name of the sibling literal, not of the block, so the
    // block learns of the write only through the alias the literal binds.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tdefer func() { os.Remove(p) }()\n\tfunc() {\n\t\tq := &p\n\t\t*q = \"/tmp/actual.txt\"\n\t}()\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "a write through a pointer a sibling literal binds must reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_a_sibling_literal_stores_in_a_field() {
    // And the field form: `h.C = &p` inside the literal names no binding of the
    // block either.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tdefer func() { os.Remove(p) }()\n\tfunc() {\n\t\tvar h struct{ C *string }\n\t\th.C = &p\n\t\t*h.C = \"/tmp/actual.txt\"\n\t}()\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/declared.txt"),
        "an address a sibling literal stores in a field must reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_keeps_a_name_a_sibling_literal_only_reads() {
    // The precision guard for that descent: the callee the literal calls
    // assigns nothing through its parameter, so `p` stays exact.
    let plan = analyze(
        "package main\nimport \"fmt\"\nimport \"os\"\nfunc report(s *string) { fmt.Println(*s) }\nfunc main() {\n\tp := \"/tmp/kept.txt\"\n\tdefer func() { os.Remove(p) }()\n\tfunc() { report(&p) }()\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/tmp/kept.txt"),
        "a callee that only reads through the address leaves the name exact: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_receiver_an_escaping_method_value_writes() {
    // `run = b.Set` hands the method value `b`'s storage, and nothing here can
    // order the call through `run` against the deferred read, so `b` holds no
    // known value inside the body — exactly as the in-order walk already reads
    // it.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Box struct{ V string }\nfunc (b *Box) Set() { b.V = \"/actual\" }\nvar run func()\nfunc main() {\n\tb := Box{V: \"/declared\"}\n\tdefer func() { os.Remove(b.V) }()\n\trun = b.Set\n\trun()\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a method value that writes its receiver must reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_receiver_a_sibling_literal_hands_over() {
    // The same when the sibling literal, not the block's own text, states the
    // escape.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Box struct{ V string }\nfunc (b *Box) Set() { b.V = \"/actual\" }\nvar run func()\nfunc main() {\n\tb := Box{V: \"/declared\"}\n\tdefer func() { os.Remove(b.V) }()\n\th := func() { run = b.Set }\n\th()\n\trun()\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a method value a sibling literal hands over must reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_receiver_a_composite_literal_holds() {
    // And when the method value goes into a container instead of a name.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Box struct{ V string }\nfunc (b *Box) Set() { b.V = \"/actual\" }\nvar reg []func()\nfunc main() {\n\tb := Box{V: \"/declared\"}\n\tdefer func() { os.Remove(b.V) }()\n\treg = []func(){b.Set}\n\treg[0]()\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a method value held by a composite literal must reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_keeps_a_receiver_a_read_only_method_value_escapes() {
    // The precision guard: the escaping method assigns nothing through its
    // receiver, so the widening stays gated on what the method writes rather
    // than on the method value itself.
    let plan = analyze(
        "package main\nimport \"fmt\"\nimport \"os\"\ntype Box struct{ V string }\nfunc (b *Box) Show() { fmt.Println(b.V) }\nvar run func()\nfunc main() {\n\tb := Box{V: \"/kept\"}\n\tdefer func() { os.Remove(b.V) }()\n\trun = b.Show\n\trun()\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/kept"),
        "a method value that only reads leaves the receiver exact: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_a_type_switch_init_hands_over() {
    // A type switch states its init where it stands, exactly as a value switch
    // does, so the address it hands a map element costs `p` its value.
    let plan = analyze(
        "package main\nimport \"os\"\nvar sink map[string]*string\nvar probe interface{}\nfunc mutate() { *sink[\"k\"] = \"/actual\" }\nfunc main() {\n\tp := \"/declared\"\n\tdefer func() { os.Remove(p) }()\n\tsink = map[string]*string{}\n\tswitch sink[\"k\"] = &p; v := probe.(type) {\n\tcase int:\n\t\t_ = v\n\t}\n\tmutate()\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "an address a type switch's init hands over must reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_literal_reads_a_name_a_type_switch_tag_hands_over() {
    // And its tag: the literal the tag calls states the same escape.
    let plan = analyze(
        "package main\nimport \"os\"\nvar sink map[string]*string\nfunc mutate() { *sink[\"k\"] = \"/actual\" }\nfunc main() {\n\tp := \"/declared\"\n\tdefer func() { os.Remove(p) }()\n\tsink = map[string]*string{}\n\tswitch v := func() interface{} {\n\t\tsink[\"k\"] = &p\n\t\treturn 1\n\t}().(type) {\n\tcase int:\n\t\t_ = v\n\t}\n\tmutate()\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "an address a type switch's tag hands over must reach the read: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_named_closure_stored_in_a_field_costs_the_names_it_assigns() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\ntype Holder struct{ Fn func() }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tcb := func() { c.Path = \"/actual\" }\n\th := Holder{Fn: cb}\n\th.Fn()\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a named closure stored in a field escapes: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_named_closure_stored_in_a_map_costs_the_names_it_assigns() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tcb := func() { c.Path = \"/actual\" }\n\tm := map[string]func(){}\n\tm[\"k\"] = cb\n\tm[\"k\"]()\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a named closure stored in a map escapes: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_named_closure_stored_in_a_slice_costs_the_names_it_assigns() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\nfunc main() {\n\tc := Config{Path: \"/declared\"}\n\tcb := func() { c.Path = \"/actual\" }\n\tfns := []func(){cb}\n\tfns[0]()\n\tos.RemoveAll(c.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a named closure stored in a slice escapes: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_stored_named_closure_costs_only_what_it_assigns() {
    // The precision guard: the escape reaches the bindings the closure writes,
    // not every binding beside them.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Config struct{ Path string }\ntype Holder struct{ Fn func() }\nfunc main() {\n\ta := Config{Path: \"/a\"}\n\tb := Config{Path: \"/kept\"}\n\tcb := func() { a.Path = \"/actual\" }\n\th := Holder{Fn: cb}\n\th.Fn()\n\tos.RemoveAll(b.Path)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete" && resource == "/kept"),
        "an unrelated binding survives the escape: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_spawn_through_a_constructed_receiver_is_reported() {
    // `e := NewExecutor()` types `e` by what the constructor returns, so the
    // method call reaches `exec.Command` and the file is not reported as a
    // program that spawns nothing.
    let plan = analyze(
        "package main\nimport (\n\t\"os\"\n\t\"os/exec\"\n)\ntype Executor struct{ shell string }\nfunc NewExecutor() *Executor {\n\ts := os.Getenv(\"SHELL\")\n\tif s == \"\" {\n\t\ts = \"sh\"\n\t}\n\treturn &Executor{shell: s}\n}\nfunc (e *Executor) ExecCommand(c string) *exec.Cmd { return exec.Command(e.shell, \"-c\", c) }\nfunc main() {\n\te := NewExecutor()\n\te.ExecCommand(\"rm -rf /data\").Run()\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, _)| *operation == "process.exec"),
        "a spawn through a constructed receiver is reported: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_goroutine_calling_a_named_closure_costs_what_it_assigns() {
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/tmp/declared.txt\"\n\tcb := func() { p = \"/tmp/actual.txt\" }\n\tgo cb()\n\tos.Remove(p)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && (resource == "/tmp/actual.txt" || resource == "/tmp/declared.txt")),
        "a goroutine calling a closure by name costs its writes: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_named_closure_writes_after_the_statements_it_follows() {
    // `defer cb()` runs at the return, so `os.Remove` still sees `/declared`.
    let plan = analyze(
        "package main\nimport \"os\"\nfunc main() {\n\tp := \"/declared\"\n\tcb := func() { p = \"/actual\" }\n\tdefer cb()\n\tos.Remove(p)\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a deferred closure writes after the call it follows: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_method_writing_through_a_pointer_alias_drops_the_variable_it_addresses() {
    // `s := &b` types `s` as `Box`, so `s.Set()` dispatches to the pointer
    // receiver method and its write reaches `b`'s storage.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Box struct{ Path string }\nfunc (b *Box) Set() { b.Path = \"/actual\" }\nfunc main() {\n\tb := Box{Path: \"/declared\"}\n\ts := &b\n\ts.Set()\n\tos.Remove(b.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "a method call through a pointer alias writes the variable it addresses: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_method_call_through_a_pointer_alias_reports_its_own_effects() {
    // The receiver's type comes from the variable `&b` addresses, so the
    // method body's effects are read instead of silently dropped.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Box struct{ Path string }\nfunc (b *Box) Wipe() { os.RemoveAll(b.Path) }\nfunc main() {\n\tb := Box{Path: \"/declared\"}\n\ts := &b\n\ts.Wipe()\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, _)| *operation == "filesystem.delete"),
        "a method reached through a pointer alias still reports its effects: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_method_call_on_a_new_allocation_reports_its_own_effects() {
    // `new(Box)` names the type it allocates just as a composite literal does.
    let plan = analyze(
        "package main\nimport \"os\"\ntype Box struct{ Path string }\nfunc (b *Box) Wipe() { os.RemoveAll(b.Path) }\nfunc main() {\n\ts := new(Box)\n\ts.Path = \"/declared\"\n\ts.Wipe()\n}\n",
    );
    assert!(
        ops(&plan)
            .iter()
            .any(|(operation, _)| *operation == "filesystem.delete"),
        "a method reached through new(T) still reports its effects: {:?}",
        ops(&plan)
    );
}

#[test]
fn a_deferred_method_call_through_a_pointer_alias_drops_the_variable() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype Box struct{ Path string }\nfunc (b *Box) Set() { b.Path = \"/actual\" }\nfunc main() {\n\tb := Box{Path: \"/declared\"}\n\tdefer func() { os.Remove(b.Path) }()\n\ts := &b\n\ts.Set()\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "an out-of-order body sees the alias method's write: {:?}",
        ops(&plan)
    );
}

#[test]
fn an_interface_binding_of_an_address_drops_the_variable_it_addresses() {
    let plan = analyze(
        "package main\nimport \"os\"\ntype Setter interface{ Set() }\ntype Box struct{ Path string }\nfunc (b *Box) Set() { b.Path = \"/actual\" }\nfunc main() {\n\tb := Box{Path: \"/declared\"}\n\tvar s Setter = &b\n\ts.Set()\n\tos.Remove(b.Path)\n}\n",
    );
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, resource)| *operation == "filesystem.delete"
                && resource == "/declared"),
        "an interface variable bound to an address is the same storage: {:?}",
        ops(&plan)
    );
}

fn one_effect<'a>(plan: &'a effinterp_proto::Plan, operation: &str) -> &'a effinterp_proto::Effect {
    let effects: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == operation)
        .collect();
    assert_eq!(effects.len(), 1, "{operation}: {:?}", plan.effects);
    effects[0]
}

fn assert_no_untyped_resource(plan: &effinterp_proto::Plan) {
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "untyped_resource")
    );
}

#[test]
fn relative_http_url_is_an_unresolved_network_resource() {
    let plan = analyze("package main\nimport \"net/http\"\nfunc main(){ http.Get(\"/relative\") }");
    assert!(matches!(
        &one_effect(&plan, "network.request").resource,
        ResourceExpr::Unresolved { family } if family.0 == "network"
    ));
    assert_no_untyped_resource(&plan);
}

#[test]
fn filepath_join_preserves_an_environment_value() {
    let plan = analyze(
        "package main\nimport (\n\"os\"\n\"path/filepath\"\n)\nfunc main(){ os.RemoveAll(filepath.Join(os.Getenv(\"APP_ROOT\"), \"cache\")) }",
    );
    assert!(matches!(
        &one_effect(&plan, "filesystem.delete").resource,
        ResourceExpr::Join { parts }
            if parts.len() == 2
                && matches!(&parts[0], ResourceExpr::Environment { name } if name == "APP_ROOT")
                && matches!(
                    &parts[1],
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } if path == "cache"
                )
    ));
    assert_no_untyped_resource(&plan);
}

fn spawn_is_not_silent(plan: &effinterp_proto::Plan) {
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "process.exec"),
        "spawn must emit process.exec; ops={:?}",
        ops(plan)
    );
    let nested = plan.effects.iter().any(|effect| {
        effect.operation.0.starts_with("filesystem.")
            || effect.operation.0.starts_with("git.")
            || effect.operation.0.starts_with("network.")
    });
    if !nested {
        assert!(
            plan.boundaries.iter().any(|boundary| {
                boundary.reason.as_str() == "uncomposed_subprocess"
                    || boundary.domains.iter().any(|domain| domain.0 == "process")
            }),
            "uncomposed spawn must be loud; boundaries={:?}",
            plan.boundaries
        );
    }
}

#[test]
fn go_spawn_shapes_are_never_silent() {
    spawn_is_not_silent(&analyze(
        "package main\nimport \"os/exec\"\nfunc main() { exec.Command(\"rm\", \"-rf\", \"/tmp/x\").Run() }\n",
    ));
    spawn_is_not_silent(&analyze(
        "package main\nimport \"os/exec\"\nfunc main() {\n\targs := []string{\"rm\"}\n\targs = append(args, \"-rf\", \"/tmp/x\")\n\texec.Command(args[0], args[1:]...).Run()\n}\n",
    ));
    spawn_is_not_silent(&analyze(
        "package main\nimport \"os/exec\"\nfunc run(name string, args ...string) { exec.Command(name, args...).Run() }\nfunc main() { run(\"rm\", \"-rf\", \"/tmp/x\") }\n",
    ));
}

#[test]
fn database_sql_receivers_nest_sql() {
    for (body, operation, table) in [
        (
            r#"func purge(db *sql.DB) { db.Exec("DELETE FROM accounts") }; func main() { purge(nil) }"#,
            "database.write",
            "accounts",
        ),
        (
            r#"var db *sql.DB; func main() { db.Exec("DELETE FROM users") }"#,
            "database.write",
            "users",
        ),
        (
            r#"type Repo struct { db *sql.DB }; func (r *Repo) Purge() { r.db.Exec("DELETE FROM users") }; func main() { r := &Repo{}; r.Purge() }"#,
            "database.write",
            "users",
        ),
        (
            r#"func main() { db, _ := sql.Open("postgres", "x"); tx, _ := db.Begin(); tx.Exec("DROP TABLE legacy") }"#,
            "database.schema_drop",
            "legacy",
        ),
        (
            r#"func main() { db := sql.OpenDB(nil); conn, _ := db.Conn(nil); conn.ExecContext(nil, "TRUNCATE audit_logs") }"#,
            "database.truncate",
            "audit_logs",
        ),
        (
            r#"func purge(db *sql.DB) { db.ExecContext(nil, "DELETE FROM t") }; func main() { purge(nil) }"#,
            "database.write",
            "t",
        ),
        (
            r#"func purge(db *sql.Tx) { db.QueryContext(nil, "SELECT * FROM accounts") }; func main() { purge(nil) }"#,
            "database.read",
            "accounts",
        ),
        (
            r#"func purge(db *sql.Conn) { db.QueryRowContext(nil, "SELECT * FROM users") }; func main() { purge(nil) }"#,
            "database.read",
            "users",
        ),
    ] {
        let plan = analyze(&format!("package main\nimport \"database/sql\"\n{body}"));
        assert!(plan.effects.iter().any(|effect| effect.operation.as_str() == operation && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::DatabaseTable { table: name, .. } } if name == table)), "{body}: {plan:#?}");
        assert_eq!(
            plan.coverage.0[&Domain::new("database")].level,
            CoverageLevel::Full,
            "{body}"
        );
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|b| b.reason.as_str() == "external_unmodeled"),
            "{body}: {:?}",
            plan.boundaries
        );
    }
    let plan = analyze(
        "package main\nimport \"database/sql\"\nfunc purge(db *sql.DB, query string) { db.Exec(query) }; func main() { purge(nil, \"dynamic\") }",
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "uncomposed_sql")
    );
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.as_str().starts_with("database."))
    );
}

#[test]
fn cobra_literal_callbacks_run_without_execute() {
    for body in [
        r#"var addCmd = &cobra.Command{PreRun: func(cmd *cobra.Command, args []string) { os.RemoveAll("/cobra-pkg") }}"#,
        r#"var addCmd = any(&cobra.Command{RunE: func(cmd *cobra.Command, args []string) error { return os.RemoveAll("/cobra-pkg") }}).(*cobra.Command)"#,
        r#"var commands = map[*cobra.Command]bool{&cobra.Command{RunE: func(cmd *cobra.Command, args []string) error { return os.RemoveAll("/cobra-pkg") }}: true}"#,
        r#"var addCmd = &cobra.Command{RunE: func(cmd *cobra.Command, args []string) error { return os.RemoveAll("/cobra-pkg") }}"#,
        r#"func newCmd() *cobra.Command { cmd := &cobra.Command{RunE: func(cmd *cobra.Command, args []string) error { return os.RemoveAll("/cobra-pkg") }}; return cmd }; func main() { newCmd().Execute() }"#,
        r#"func run(cmd *cobra.Command, args []string) error { return os.RemoveAll("/cobra-pkg") }; var addCmd = &cobra.Command{RunE: run}"#,
    ] {
        let plan = analyze(&format!(
            "package cmd\nimport (\"os\"; \"github.com/spf13/cobra\")\n{body}"
        ));
        assert!(has(&plan, "filesystem.delete", "/cobra-pkg"), "{plan:#?}");
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|b| b.reason.as_str() == "no_entry_point")
        );
    }
    let plan = analyze(
        "package cmd\nimport \"github.com/spf13/cobra\"\nvar cmd = &cobra.Command{Run: func(cmd *cobra.Command, args []string) {}}",
    );
    assert!(plan.effects.is_empty());
    assert!(
        plan.boundaries
            .iter()
            .all(|b| matches!(b.reason.as_str(), "frontend_partial" | "unmodeled_import")),
        "{:?}",
        plan.boundaries
    );
}

#[test]
fn init_field_registration_runs_the_callback() {
    for (registration, expected) in [
        ("CmdClean.Run = runClean", true),
        ("", false),
        (
            "CmdClean.Run = func(args []string) { os.Remove(\"/clean\") }",
            true,
        ),
    ] {
        let plan = analyze(&format!(
            r#"package clean
import "os"
type Command struct {{ Run func([]string) }}
var CmdClean = &Command{{}}
func init() {{ {registration} }}
func runClean(args []string) {{ os.Remove("/clean") }}"#
        ));
        assert_eq!(
            has(&plan, "filesystem.delete", "/clean"),
            expected,
            "{plan:#?}"
        );
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|b| b.reason.as_str() == "no_entry_point")
        );
    }
}

#[test]
fn callable_values_dispatch_or_stay_loud() {
    for body in [
        "f := a; if len(os.Args) > 1 { f = b }; f()",
        "var f func(); if len(os.Args) > 1 { f = a } else { f = b }; f()",
    ] {
        let plan = analyze(&format!(
            r#"package main
import "os"
func a() {{ os.Remove("/a") }}
func b() {{ os.RemoveAll("/b") }}
func main() {{ {body} }}"#
        ));
        assert!(has(&plan, "filesystem.delete", "/a"), "{plan:#?}");
        assert!(has(&plan, "filesystem.delete", "/b"), "{plan:#?}");
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unresolved_call"),
            "{plan:#?}"
        );
    }
    for (body, path) in [
        (
            r#"func main() { ops := map[string]func(string) error{"rm": os.Remove, "rmr": os.RemoveAll}; ops["rmr"]("/data/purge") }"#,
            "/data/purge",
        ),
        (
            r#"func cleaner(root string) func() error { return func() error { return os.RemoveAll(root) } }; func main() { fn := cleaner("/srv/tmp"); fn() }"#,
            "/srv/tmp",
        ),
        (
            r#"type Repo struct { Dir string }; func (r Repo) Wipe() error { return os.RemoveAll(r.Dir) }; func main() { wipe := Repo.Wipe; wipe(Repo{Dir: "/repo/tmp"}) }"#,
            "/repo/tmp",
        ),
        (
            r#"type Repo struct { Dir string }; func (r Repo) Wipe(path string) error { return os.RemoveAll(path) }; func main() { r := Repo{Dir: "/method/arg"}; wipe := Repo.Wipe; wipe(Repo{}, r.Dir) }"#,
            "/method/arg",
        ),
        (
            r#"func main() { ops := map[string]func(string) error{"rm": func(path string) error { return os.RemoveAll(path) }}; ops["rm"]("/map/closure") }"#,
            "/map/closure",
        ),
    ] {
        let plan = analyze(&format!("package main\nimport \"os\"\n{body}"));
        assert!(has(&plan, "filesystem.delete", path), "{body}: {plan:#?}");
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "filesystem.delete"
                    && effect.attributes.get("recursive")
                        == Some(&effinterp_proto::AttrValue::Bool(true)))
        );
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unresolved_call"),
            "{plan:#?}"
        );
    }
    for body in [
        r#"func main() { var dyn func(string) error; dyn("/x") }"#,
        r#"func main() { ops := map[string]func(string) error{"rm": os.RemoveAll}; key := "rm"; ops[key]("/x") }"#,
        r#"func invoke(dyn func(string) error) { dyn("/x") }; func main() { invoke(nil) }"#,
    ] {
        let plan = analyze(&format!("package main\nimport \"os\"\n{body}"));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|b| b.reason.as_str() == "unresolved_call")
                .count(),
            1,
            "{plan:#?}"
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.as_str() == "filesystem.delete")
        );
    }
}
