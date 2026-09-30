//! Execution realms: an effect produced inside a container/pod is stamped
//! with that realm so its resource is never confused with the host's.
//! A compose service label has the same container-realm shape as a container
//! name; both identify the container selected by the operator.

use std::collections::BTreeSet;

use effinterp_engine::Engine;
use effinterp_proto::{
    AttrValue, CoverageLevel, Domain, Effect, ExecutionRealm, Plan, ResourceExpr, ResourceFamily,
    ResourceIdentity, Subject, validate_plan,
};

fn exec(argv: &[&str]) -> Subject {
    Subject::Exec {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        cwd: Some("/w".to_string()),
        context: Default::default(),
    }
}

fn delete_of(plan: &effinterp_proto::Plan, path: &str) -> ExecutionRealm {
    plan.effects
        .iter()
        .find(|e| {
            e.operation.0 == "filesystem.delete"
                && matches!(
                    &e.resource,
                    ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: p } } if p == path
                )
        })
        .unwrap_or_else(|| panic!("no filesystem.delete on {path}"))
        .realm
        .clone()
}

fn kubectl_plan(argv: &[&str]) -> Plan {
    let plan = Engine::new().analyze(&exec(argv)).unwrap();
    validate_plan(&plan).unwrap();
    let repeated = Engine::new().analyze(&exec(argv)).unwrap();
    validate_plan(&repeated).unwrap();
    assert_eq!(
        effinterp_proto::canonical_json(&plan),
        effinterp_proto::canonical_json(&repeated)
    );
    plan
}

fn compose_plan(argv: &[&str]) -> Plan {
    let plan = Engine::new().analyze(&exec(argv)).unwrap();
    validate_plan(&plan).unwrap();
    let repeated = Engine::new().analyze(&exec(argv)).unwrap();
    validate_plan(&repeated).unwrap();
    assert_eq!(
        effinterp_proto::canonical_json(&plan),
        effinterp_proto::canonical_json(&repeated)
    );
    plan
}

fn assert_kubectl_delete(argv: &[&str], expected_realm: ExecutionRealm) {
    let plan = kubectl_plan(argv);
    assert_eq!(delete_of(&plan, "/data"), expected_realm);
    assert!(plan.boundaries.is_empty());
    let effect_domains = plan
        .effects
        .iter()
        .map(|effect| Domain::new(effect.operation.domain()))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        plan.coverage.0.keys().cloned().collect::<BTreeSet<_>>(),
        effect_domains
    );
    for domain in effect_domains {
        assert_eq!(
            plan.coverage.0.get(&domain).map(|claim| &claim.level),
            Some(&CoverageLevel::Full)
        );
    }
}

fn effect<'a>(plan: &'a Plan, operation: &str) -> &'a Effect {
    plan.effects
        .iter()
        .find(|effect| effect.operation.0 == operation)
        .unwrap_or_else(|| panic!("no {operation} effect"))
}

fn has_unrecognized_arguments(plan: &Plan) -> bool {
    plan.boundaries
        .iter()
        .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments")
}

fn assert_compose_exec_effect(plan: &Plan, runtime: &str, service: &str) {
    let effects = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "container.exec")
        .collect::<Vec<_>>();
    assert_eq!(effects.len(), 1);
    assert!(matches!(
        &effects[0].resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Container {
                runtime: actual_runtime,
                name: Some(name),
                image: None,
                ..
            }
        } if actual_runtime == runtime && name == service
    ));
}

#[test]
fn docker_exec_scopes_effects_to_the_container() {
    let plan = Engine::new()
        .analyze(&exec(&[
            "docker",
            "exec",
            "postgres",
            "rm",
            "-rf",
            "/etc/passwd",
        ]))
        .unwrap();
    validate_plan(&plan).unwrap();

    // The delete happens inside the container, not on the host.
    assert_eq!(
        delete_of(&plan, "/etc/passwd"),
        ExecutionRealm::Container {
            runtime: "docker".to_string(),
            name: "postgres".to_string(),
        }
    );
    // The docker process itself and the container.exec are host effects.
    let docker = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "process.exec")
        .unwrap();
    assert!(docker.realm.is_host());
}

#[test]
fn docker_exec_value_options_preserve_the_container_operand() {
    for (option, value) in [
        ("--detach-keys", "ctrl-c"),
        ("-e", "FOO=1"),
        ("--env", "FOO=1"),
        ("--env-file", ".env"),
        ("-u", "root"),
        ("--user", "root"),
        ("-w", "/tmp"),
        ("--workdir", "/tmp"),
    ] {
        let plan = Engine::new()
            .analyze(&exec(&[
                "docker", "exec", option, value, "web", "rm", "-rf", "/data",
            ]))
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(!has_unrecognized_arguments(&plan), "{option}");
        assert_eq!(
            delete_of(&plan, "/data"),
            ExecutionRealm::Container {
                runtime: "docker".to_string(),
                name: "web".to_string(),
            }
        );
    }
}

#[test]
fn docker_exec_boolean_options_preserve_the_container_operand() {
    for option in [
        "-d",
        "--detach",
        "-i",
        "--interactive",
        "--privileged",
        "-t",
        "--tty",
        "--preserve-fd",
        "--preserve-fds",
    ] {
        let plan = Engine::new()
            .analyze(&exec(&[
                "docker", "exec", option, "web", "rm", "-rf", "/data",
            ]))
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(!has_unrecognized_arguments(&plan), "{option}");
        assert_eq!(
            delete_of(&plan, "/data"),
            ExecutionRealm::Container {
                runtime: "docker".to_string(),
                name: "web".to_string(),
            }
        );
    }
}

#[test]
fn docker_exec_short_value_clusters_preserve_the_container_operand() {
    for (option, value) in [("-ite", "FOO=1"), ("-itu", "root"), ("-itw", "/tmp")] {
        let plan = Engine::new()
            .analyze(&exec(&[
                "docker", "exec", option, value, "web", "rm", "-rf", "/data",
            ]))
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(!has_unrecognized_arguments(&plan), "{option}");
        assert_eq!(
            delete_of(&plan, "/data"),
            ExecutionRealm::Container {
                runtime: "docker".to_string(),
                name: "web".to_string(),
            }
        );
    }
}

#[test]
fn podman_exec_latest_uses_an_unresolved_container() {
    for option in ["-l", "--latest"] {
        let plan = Engine::new()
            .analyze(&exec(&["podman", "exec", option, "rm", "-rf", "/data"]))
            .unwrap();
        validate_plan(&plan).unwrap();
        let container = effect(&plan, "container.exec");
        assert!(matches!(
            &container.resource,
            ResourceExpr::Unresolved { family } if family == &ResourceFamily::new("container")
        ));
        assert!(matches!(
            delete_of(&plan, "/data"),
            ExecutionRealm::Container { runtime, .. } if runtime == "podman"
        ));
        assert!(!has_unrecognized_arguments(&plan));
    }
}

#[test]
fn docker_exec_unknown_flags_keep_or_symbolize_the_container_effect_by_arity() {
    let plan = Engine::new()
        .analyze(&exec(&[
            "docker",
            "exec",
            "--future=1",
            "web",
            "rm",
            "-rf",
            "/data",
        ]))
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(has_unrecognized_arguments(&plan));
    assert_eq!(
        delete_of(&plan, "/data"),
        ExecutionRealm::Container {
            runtime: "docker".to_string(),
            name: "web".to_string(),
        }
    );
    assert_eq!(
        plan.coverage
            .0
            .get(&Domain::new("container"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Partial)
    );

    let plan = Engine::new()
        .analyze(&exec(&[
            "docker",
            "exec",
            "--privileged",
            "--future",
            "web",
            "rm",
            "-rf",
            "/data",
        ]))
        .unwrap();
    validate_plan(&plan).unwrap();
    let container = effect(&plan, "container.exec");
    assert!(matches!(
        &container.resource,
        ResourceExpr::Unresolved { family } if family == &ResourceFamily::new("container")
    ));
    assert_eq!(
        container.attributes.get("privileged"),
        Some(&AttrValue::Bool(true))
    );
    assert!(!plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/data")
    }));
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .all(|node| node.realm.is_host())
    );
}

#[test]
fn host_command_stays_on_the_host() {
    let plan = Engine::new()
        .analyze(&exec(&["rm", "-rf", "/etc/passwd"]))
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(delete_of(&plan, "/etc/passwd").is_host());
}

#[test]
fn ssh_relative_paths_use_the_remote_runtime_cwd() {
    let plan = Engine::new()
        .analyze(&exec(&["ssh", "host", "rm", "-rf", "data"]))
        .unwrap();
    validate_plan(&plan).unwrap();
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert_eq!(
        delete.realm,
        ExecutionRealm::Remote {
            endpoint: "host".to_string()
        }
    );
    assert!(matches!(&delete.resource, ResourceExpr::Join { parts }
        if matches!(parts.first(), Some(ResourceExpr::Parameter { name }) if name == "cwd")));
    assert!(!format!("{:?}", delete.resource).contains("/w"));
}

#[test]
fn vm_remote_shells_do_not_reuse_the_host_cwd() {
    let plan = Engine::new()
        .analyze(&exec(&["vagrant", "ssh", "-c", "rm -rf data"]))
        .unwrap();
    validate_plan(&plan).unwrap();
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert_eq!(
        delete.realm,
        ExecutionRealm::Remote {
            endpoint: "vagrant:default".to_string()
        }
    );
    assert!(matches!(&delete.resource, ResourceExpr::Join { parts }
        if matches!(parts.first(), Some(ResourceExpr::Parameter { name }) if name == "cwd")));
    assert!(!format!("{:?}", delete.resource).contains("/w"));
}

#[test]
fn chroot_resolves_host_roots_without_relabeling_container_commands() {
    let relative = Engine::new()
        .analyze(&exec(&["chroot", "jail", "rm", "-rf", "data"]))
        .unwrap();
    validate_plan(&relative).unwrap();
    assert_eq!(
        delete_of(&relative, "/data"),
        ExecutionRealm::Chroot {
            host_root: Some("/w/jail".to_string())
        }
    );

    let symbolic = Engine::new()
        .analyze(&Subject::Shell {
            source: "chroot $ROOT rm -rf /etc".to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&symbolic).unwrap();
    assert_eq!(
        delete_of(&symbolic, "/etc"),
        ExecutionRealm::Chroot { host_root: None }
    );

    let container = Engine::new()
        .analyze(&exec(&[
            "docker", "run", "-v", "/:/host", "alpine", "chroot", "/host", "rm", "-rf", "/etc",
        ]))
        .unwrap();
    validate_plan(&container).unwrap();
    assert_eq!(
        delete_of(&container, "/etc"),
        ExecutionRealm::Container {
            runtime: "docker".to_string(),
            name: "alpine".to_string()
        }
    );
    assert!(
        container
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "chroot_reroots_filesystem")
    );
}

#[test]
fn nested_container_effects_pop_back_to_host() {
    // A host rm after a docker exec must not inherit the container realm.
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "docker exec pg rm /in/container; rm /on/host".to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(matches!(
        delete_of(&plan, "/in/container").clone(),
        ExecutionRealm::Container { .. }
    ));
    assert!(delete_of(&plan, "/on/host").is_host());
}

#[test]
fn kubectl_exec_scopes_to_the_pod() {
    let plan = kubectl_plan(&["kubectl", "exec", "web-0", "--", "rm", "/data"]);
    assert!(matches!(
        delete_of(&plan, "/data"),
        ExecutionRealm::Kubernetes { pod, .. } if pod == "web-0"
    ));
}

#[test]
fn kubectl_exec_preserves_namespace_and_container_identity() {
    let plan = kubectl_plan(&[
        "kubectl", "exec", "-n", "prod", "-c", "app", "web-0", "--", "rm", "/data",
    ]);

    assert_eq!(
        delete_of(&plan, "/data"),
        ExecutionRealm::Kubernetes {
            namespace: Some("prod".to_string()),
            pod: "web-0".to_string(),
            container: Some("app".to_string()),
        }
    );
}

#[test]
fn kubectl_exec_accepts_boolean_option_forms() {
    let cases: &[&[&str]] = &[
        &["kubectl", "exec", "-it", "pod", "--", "rm", "-rf", "/data"],
        &["kubectl", "exec", "-ti", "pod", "--", "rm", "-rf", "/data"],
        &[
            "kubectl", "exec", "-i", "-t", "pod", "--", "rm", "-rf", "/data",
        ],
        &[
            "kubectl", "exec", "--stdin", "--tty", "pod", "--", "rm", "-rf", "/data",
        ],
        &["kubectl", "exec", "-itq", "pod", "--", "rm", "-rf", "/data"],
    ];
    for argv in cases {
        assert_kubectl_delete(
            argv,
            ExecutionRealm::Kubernetes {
                namespace: None,
                pod: "pod".to_string(),
                container: None,
            },
        );
    }
}

#[test]
fn kubectl_exec_accepts_global_options_before_the_verb() {
    let cases: &[(&[&str], Option<&str>, Option<&str>)] = &[
        (
            &[
                "kubectl", "-n", "ns", "exec", "pod", "--", "rm", "-rf", "/data",
            ],
            Some("ns"),
            None,
        ),
        (
            &[
                "kubectl",
                "--namespace=ns",
                "exec",
                "pod",
                "--",
                "rm",
                "-rf",
                "/data",
            ],
            Some("ns"),
            None,
        ),
        (
            &[
                "kubectl",
                "--context",
                "prod",
                "-n",
                "ns",
                "exec",
                "-c",
                "app",
                "pod",
                "--",
                "rm",
                "-rf",
                "/data",
            ],
            Some("ns"),
            Some("app"),
        ),
        (
            &["kubectl", "-v=6", "exec", "pod", "--", "rm", "-rf", "/data"],
            None,
            None,
        ),
    ];
    for (argv, namespace, container) in cases {
        assert_kubectl_delete(
            argv,
            ExecutionRealm::Kubernetes {
                namespace: namespace.map(str::to_string),
                pod: "pod".to_string(),
                container: container.map(str::to_string),
            },
        );
    }
}

#[test]
fn kubectl_exec_accepts_container_clusters_and_workload_targets() {
    assert_kubectl_delete(
        &[
            "kubectl", "exec", "-itc", "app", "pod", "--", "rm", "-rf", "/data",
        ],
        ExecutionRealm::Kubernetes {
            namespace: None,
            pod: "pod".to_string(),
            container: Some("app".to_string()),
        },
    );
    assert_kubectl_delete(
        &[
            "kubectl",
            "exec",
            "-it",
            "deploy/api",
            "--",
            "sh",
            "-c",
            "rm -rf /data",
        ],
        ExecutionRealm::Kubernetes {
            namespace: None,
            pod: "deploy/api".to_string(),
            container: None,
        },
    );
}

#[test]
fn kubectl_exec_unknown_options_fail_closed() {
    let plan = kubectl_plan(&[
        "kubectl",
        "exec",
        "--unknown-option",
        "value",
        "web-0",
        "--",
        "rm",
        "/data",
    ]);

    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments")
    );
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
}

#[test]
fn compose_exec_nests_the_command_in_the_service_realm() {
    for (argv, runtime) in [
        (
            &["docker", "compose", "exec", "web", "rm", "-rf", "/data"][..],
            "docker",
        ),
        (
            &["docker-compose", "exec", "web", "rm", "-rf", "/data"][..],
            "docker",
        ),
        (
            &["podman-compose", "exec", "web", "rm", "-rf", "/data"][..],
            "podman",
        ),
        (
            &["podman", "compose", "exec", "web", "rm", "-rf", "/data"][..],
            "podman",
        ),
    ] {
        let plan = compose_plan(argv);
        assert_compose_exec_effect(&plan, runtime, "web");
        assert_eq!(
            delete_of(&plan, "/data"),
            ExecutionRealm::Container {
                runtime: runtime.to_string(),
                name: "web".to_string(),
            }
        );
        assert_eq!(plan.boundaries.len(), 1, "{argv:?}");
        assert_eq!(plan.boundaries[0].domains, vec![Domain::new("network")]);
        for domain in ["container", "filesystem", "process"] {
            assert_eq!(
                plan.coverage
                    .0
                    .get(&Domain::new(domain))
                    .map(|claim| &claim.level),
                Some(&CoverageLevel::Full),
                "{argv:?}"
            );
        }
    }

    let plan = compose_plan(&[
        "docker", "compose", "-f", "a.yml", "-p", "proj", "exec", "-T", "--index", "1", "-u",
        "root", "-e", "FOO=1", "-w", "/app", "web", "rm", "-rf", "data",
    ]);
    assert_compose_exec_effect(&plan, "docker", "web");
    let realm = ExecutionRealm::Container {
        runtime: "docker".to_string(),
        name: "web".to_string(),
    };
    assert_eq!(delete_of(&plan, "/app/data"), realm);
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .any(|node| node.realm == realm && node.environment.contains_key("FOO"))
    );
    assert_eq!(plan.boundaries.len(), 1);
    assert_eq!(plan.boundaries[0].domains, vec![Domain::new("network")]);
}

#[test]
fn compose_exec_without_a_command_only_records_the_exec() {
    let plan = compose_plan(&["docker", "compose", "exec", "web"]);
    assert_compose_exec_effect(&plan, "docker", "web");
    assert_eq!(plan.execution_graph.nodes.len(), 1);
    assert_eq!(plan.boundaries.len(), 1);
    assert_eq!(plan.boundaries[0].domains, vec![Domain::new("network")]);
}

#[test]
fn compose_exec_unknown_flags_follow_the_arity_policy() {
    let plan = compose_plan(&[
        "docker",
        "compose",
        "exec",
        "--future=1",
        "web",
        "rm",
        "-rf",
        "/data",
    ]);
    assert!(has_unrecognized_arguments(&plan));
    assert_compose_exec_effect(&plan, "docker", "web");
    assert_eq!(
        delete_of(&plan, "/data"),
        ExecutionRealm::Container {
            runtime: "docker".to_string(),
            name: "web".to_string(),
        }
    );
    assert_eq!(
        plan.coverage
            .0
            .get(&Domain::new("container"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Partial)
    );

    let plan = compose_plan(&[
        "docker", "compose", "exec", "--future", "v", "web", "rm", "-rf", "/data",
    ]);
    assert!(has_unrecognized_arguments(&plan));
    assert!(matches!(
        &effect(&plan, "container.exec").resource,
        ResourceExpr::Unresolved { family } if family == &ResourceFamily::new("container")
    ));
    assert_eq!(plan.execution_graph.nodes.len(), 1);
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "process.exec")
            .count(),
        1
    );
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
}

#[test]
fn wrapper_models_assign_only_filesystem_changing_realms() {
    let nsenter_mount = Engine::new()
        .analyze(&exec(&[
            "nsenter", "-t", "1", "-m", "--", "rm", "-rf", "/x",
        ]))
        .unwrap();
    validate_plan(&nsenter_mount).unwrap();
    assert_eq!(
        delete_of(&nsenter_mount, "/x"),
        ExecutionRealm::Chroot { host_root: None }
    );

    let nsenter_root = Engine::new()
        .analyze(&exec(&[
            "nsenter",
            "--root=/mnt",
            "-w=/srv",
            "--",
            "rm",
            "-rf",
            "data",
        ]))
        .unwrap();
    validate_plan(&nsenter_root).unwrap();
    assert_eq!(
        delete_of(&nsenter_root, "/srv/data"),
        ExecutionRealm::Chroot {
            host_root: Some("/mnt".to_string())
        }
    );

    let unshare = Engine::new()
        .analyze(&exec(&["unshare", "-R", "/mnt", "rm", "-rf", "/etc"]))
        .unwrap();
    validate_plan(&unshare).unwrap();
    assert_eq!(
        delete_of(&unshare, "/etc"),
        ExecutionRealm::Chroot {
            host_root: Some("/mnt".to_string())
        }
    );

    let machine = Engine::new()
        .analyze(&exec(&["systemd-run", "-M", "box", "rm", "-rf", "/x"]))
        .unwrap();
    validate_plan(&machine).unwrap();
    assert_eq!(
        delete_of(&machine, "/x"),
        ExecutionRealm::Container {
            runtime: "systemd-nspawn".to_string(),
            name: "box".to_string(),
        }
    );

    let remote = Engine::new()
        .analyze(&exec(&[
            "systemd-run",
            "-H",
            "user@host",
            "rm",
            "-rf",
            "/x",
        ]))
        .unwrap();
    validate_plan(&remote).unwrap();
    assert_eq!(
        delete_of(&remote, "/x"),
        ExecutionRealm::Remote {
            endpoint: "host".to_string(),
        }
    );
}

#[test]
fn nsenter_keeps_an_existing_container_realm() {
    let plan = Engine::new()
        .analyze(&exec(&[
            "docker",
            "run",
            "--privileged",
            "--pid=host",
            "alpine",
            "nsenter",
            "-t",
            "1",
            "-m",
            "sh",
        ]))
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(plan.execution_graph.nodes.iter().any(|node| {
        node.realm
            == ExecutionRealm::Container {
                runtime: "docker".to_string(),
                name: "alpine".to_string(),
            }
            && matches!(&node.subject, Subject::Exec { argv, .. }
                if argv.first().map(String::as_str) == Some("sh"))
    }));
}
