//! `docker run <cmd>` scopes the nested command to the container's realm, and
//! a `-v` bind mount stays a valid plan rather than an uncovered-domain error.
//! Compose service names use the same realm label as container names because
//! both are the operator's label for the selected container.

use effinterp_engine::Engine;
use effinterp_proto::{
    AttrValue, CoverageLevel, Domain, Effect, ExecutionRealm, Plan, ResourceExpr, ResourceFamily,
    ResourceIdentity, Subject, validate_plan,
};

fn analyze(argv: &[&str]) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    let repeated = Engine::new()
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&repeated).unwrap();
    assert_eq!(
        effinterp_proto::canonical_json(&plan),
        effinterp_proto::canonical_json(&repeated)
    );
    plan
}

fn delete_of(plan: &Plan, path: &str) -> ExecutionRealm {
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

fn assert_compose_service_effect(plan: &Plan, operation: &str, runtime: &str, service: &str) {
    let effects = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == operation)
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

fn assert_alpine_run(plan: &Plan) {
    let runs = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "container.run")
        .collect::<Vec<_>>();
    assert_eq!(runs.len(), 1);
    assert!(matches!(
        &runs[0].resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Container {
                image: Some(image),
                ..
            }
        } if image == "alpine"
    ));
    assert_eq!(
        delete_of(plan, "/x"),
        ExecutionRealm::Container {
            runtime: "docker".to_string(),
            name: "alpine".to_string(),
        }
    );
}

#[test]
fn docker_run_scopes_the_command_to_the_container() {
    let plan = analyze(&["docker", "run", "--rm", "alpine", "rm", "-rf", "/"]);
    // The nested command runs inside the container, not on the host.
    assert_eq!(
        delete_of(&plan, "/"),
        ExecutionRealm::Container {
            runtime: "docker".to_string(),
            name: "alpine".to_string(),
        }
    );
}

#[test]
fn docker_run_with_volume_mount_is_a_valid_plan() {
    // `-v /:/host` emits a host-FS write; the plan must stay valid (analyze
    // asserts validate() succeeds).
    let plan = analyze(&["docker", "run", "-v", "/:/host", "alpine"]);
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.write")
    );
}

#[test]
fn docker_run_entrypoint_override_is_the_launched_subject() {
    for argv in [
        &[
            "docker",
            "run",
            "--entrypoint",
            "/bin/true",
            "alpine",
            "sh",
            "-c",
            "rm -rf /ignored",
        ][..],
        &[
            "podman",
            "run",
            "--entrypoint=/bin/true",
            "alpine",
            "sh",
            "-c",
            "rm -rf /ignored",
        ][..],
    ] {
        let plan = analyze(argv);
        assert!(!plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/ignored")
        }));
    }

    let plan = analyze(&["docker", "run", "--entrypoint", "/bin/true"]);
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .all(|node| !matches!(node.realm, ExecutionRealm::Container { .. }))
    );

    let plan = analyze(&[
        "docker",
        "run",
        "--entrypoint",
        "/bin/sh",
        "alpine",
        "-c",
        "rm -rf /launched",
    ]);
    assert_eq!(
        delete_of(&plan, "/launched"),
        ExecutionRealm::Container {
            runtime: "docker".to_string(),
            name: "alpine".to_string(),
        }
    );
}

#[test]
fn docker_run_options_cannot_shift_the_image_operand() {
    for option in ["--cpus", "--memory", "--pull"] {
        let value = if option == "--cpus" {
            "2"
        } else if option == "--memory" {
            "1g"
        } else {
            "always"
        };
        let plan = analyze(&[
            "docker",
            "run",
            option,
            value,
            "alpine",
            "rm",
            "-rf",
            "/right-image",
        ]);
        assert_eq!(
            delete_of(&plan, "/right-image"),
            ExecutionRealm::Container {
                runtime: "docker".to_string(),
                name: "alpine".to_string(),
            }
        );
    }

    let plan = analyze(&[
        "docker",
        "run",
        "--future-option",
        "operand",
        "alpine",
        "rm",
        "-rf",
        "/shifted",
    ]);
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments")
    );
    let run = effect(&plan, "container.run");
    assert!(matches!(
        &run.resource,
        ResourceExpr::Unresolved { family } if family == &ResourceFamily::new("container")
    ));
    assert!(!plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/shifted")
    }));
}

#[test]
fn docker_run_value_options_preserve_the_image_operand() {
    let options = [
        "--add-host",
        "-a",
        "--attach",
        "--annotation",
        "--blkio-weight",
        "--blkio-weight-device",
        "--cap-add",
        "--cap-drop",
        "--cgroup-parent",
        "--cgroupns",
        "--cidfile",
        "--cpu-period",
        "--cpu-quota",
        "--cpu-rt-period",
        "--cpu-rt-runtime",
        "-c",
        "--cpu-shares",
        "--cpus",
        "--cpuset-cpus",
        "--cpuset-mems",
        "--detach-keys",
        "--device",
        "--device-cgroup-rule",
        "--device-read-bps",
        "--device-read-iops",
        "--device-write-bps",
        "--device-write-iops",
        "--dns",
        "--dns-option",
        "--dns-search",
        "--domainname",
        "--entrypoint",
        "-e",
        "--env",
        "--env-file",
        "--expose",
        "--gpus",
        "--group-add",
        "--health-cmd",
        "--health-interval",
        "--health-retries",
        "--health-start-period",
        "--health-start-interval",
        "--health-timeout",
        "-h",
        "--hostname",
        "--ip",
        "--ip6",
        "--ipc",
        "--isolation",
        "--kernel-memory",
        "-l",
        "--label",
        "--label-file",
        "--link",
        "--link-local-ip",
        "--log-driver",
        "--log-opt",
        "--mac-address",
        "-m",
        "--memory",
        "--memory-reservation",
        "--memory-swap",
        "--memory-swappiness",
        "--mount",
        "--name",
        "--network",
        "--net",
        "--network-alias",
        "--net-alias",
        "--oom-score-adj",
        "--pid",
        "--pids-limit",
        "--platform",
        "-p",
        "--publish",
        "--pull",
        "--restart",
        "--runtime",
        "--security-opt",
        "--shm-size",
        "--stop-signal",
        "--stop-timeout",
        "--storage-opt",
        "--sysctl",
        "--tmpfs",
        "--ulimit",
        "-u",
        "--user",
        "--userns",
        "--uts",
        "-v",
        "--volume",
        "--volume-driver",
        "--volumes-from",
        "-w",
        "--workdir",
        "--arch",
        "--authfile",
        "--cgroup-conf",
        "--cgroups",
        "--chrootdirs",
        "--conmon-pidfile",
        "--env-merge",
        "--gidmap",
        "--group-entry",
        "--hostuser",
        "--image-volume",
        "--init-path",
        "--init-ctr",
        "--os",
        "--passwd-entry",
        "--personality",
        "--pidfile",
        "--pod",
        "--pod-id-file",
        "--preserve-fds",
        "--requires",
        "--sdnotify",
        "--seccomp-policy",
        "--secret",
        "--shm-size-systemd",
        "--subgidname",
        "--subuidname",
        "--timeout",
        "--tls-verify",
        "--tz",
        "--uidmap",
        "--umask",
        "--unsetenv",
        "--variant",
    ];

    for option in options {
        let value = match option {
            "--entrypoint" => "rm",
            "-e" | "--env" | "--env-merge" => "FOO=1",
            "--mount" => "type=volume,source=data,target=/data",
            "-v" | "--volume" => "data:/data",
            "--name" => "worker",
            "--network" | "--net" | "--pid" | "--ipc" | "--userns" | "--uts" => "host",
            "--cap-add" => "SYS_ADMIN",
            "--device" => "/dev/sda",
            "--gpus" => "all",
            "--health-cmd" => "curl -f localhost",
            "--restart" => "always",
            "--security-opt" => "seccomp=unconfined",
            "--sysctl" => "x=1",
            "-w" | "--workdir" => "/tmp",
            _ => "value",
        };
        let plan = analyze(&["docker", "run", option, value, "alpine", "rm", "-rf", "/x"]);
        assert!(!has_unrecognized_arguments(&plan), "{option}");
        assert_alpine_run(&plan);
    }
}

#[test]
fn docker_run_boolean_options_preserve_the_image_operand() {
    let options = [
        "-d",
        "--detach",
        "--disable-content-trust",
        "--help",
        "--init",
        "-i",
        "--interactive",
        "--no-healthcheck",
        "--oom-kill-disable",
        "--privileged",
        "-P",
        "--publish-all",
        "-q",
        "--quiet",
        "--read-only",
        "--rm",
        "--sig-proxy",
        "-t",
        "--tty",
        "--use-api-socket",
        "--env-host",
        "--http-proxy",
        "--no-hosts",
        "--passwd",
        "--read-only-tmpfs",
        "--replace",
        "--rmi",
        "--rootfs",
        "--systemd",
        "--unsetenv-all",
    ];

    for option in options {
        let plan = analyze(&["docker", "run", option, "alpine", "rm", "-rf", "/x"]);
        assert!(!has_unrecognized_arguments(&plan), "{option}");
        assert_alpine_run(&plan);
    }
}

#[test]
fn docker_run_short_value_clusters_preserve_the_image_operand() {
    for (option, value) in [
        ("-ita", "stdout"),
        ("-itc", "1024"),
        ("-ite", "FOO=1"),
        ("-ith", "worker"),
        ("-itl", "role=test"),
        ("-itm", "1g"),
        ("-itp", "8080:80"),
        ("-itu", "root"),
        ("-itv", "data:/data"),
        ("-itw", "/tmp"),
    ] {
        let plan = analyze(&["docker", "run", option, value, "alpine", "rm", "-rf", "/x"]);
        assert!(!has_unrecognized_arguments(&plan), "{option}");
        assert_alpine_run(&plan);
    }
}

#[test]
fn docker_run_inline_value_options_preserve_the_image_operand() {
    for option in [
        "--pid=host",
        "--sysctl=x=1",
        "--restart=always",
        "--security-opt=seccomp=unconfined",
        "--device=/dev/sda",
    ] {
        let plan = analyze(&["docker", "run", option, "alpine", "rm", "-rf", "/x"]);
        assert!(!has_unrecognized_arguments(&plan), "{option}");
        assert_alpine_run(&plan);
    }
}

#[test]
fn docker_create_uses_the_run_option_tables_and_attributes() {
    let plan = analyze(&[
        "docker",
        "create",
        "--privileged",
        "--pid=host",
        "--sysctl",
        "x=1",
        "alpine",
    ]);
    assert!(!has_unrecognized_arguments(&plan));
    let create = effect(&plan, "container.create");
    assert!(matches!(
        &create.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Container {
                image: Some(image),
                ..
            }
        } if image == "alpine"
    ));
    assert_eq!(
        create.attributes.get("privileged"),
        Some(&AttrValue::Bool(true))
    );
    assert_eq!(
        create.attributes.get("pid"),
        Some(&AttrValue::String("host".to_string()))
    );
}

#[test]
fn podman_run_additions_preserve_the_image_operand() {
    let plan = analyze(&[
        "podman",
        "run",
        "--replace",
        "--tz",
        "local",
        "--userns",
        "keep-id",
        "alpine",
        "rm",
        "-rf",
        "/x",
    ]);
    assert!(!has_unrecognized_arguments(&plan));
    assert!(matches!(
        delete_of(&plan, "/x"),
        ExecutionRealm::Container { runtime, name } if runtime == "podman" && name == "alpine"
    ));
}

#[test]
fn docker_build_options_preserve_the_context_operand() {
    let value_options = [
        "--add-host",
        "--annotation",
        "--attest",
        "--build-arg",
        "--build-context",
        "--cache-from",
        "--cache-to",
        "--cgroup-parent",
        "-f",
        "--file",
        "--iidfile",
        "--isolation",
        "--label",
        "--network",
        "-o",
        "--output",
        "--platform",
        "--progress",
        "--provenance",
        "--sbom",
        "--secret",
        "--shm-size",
        "--ssh",
        "-t",
        "--tag",
        "--target",
        "--ulimit",
    ];
    for option in value_options {
        let plan = analyze(&["docker", "build", option, "value", "."]);
        assert!(!has_unrecognized_arguments(&plan), "{option}");
        assert_eq!(effect(&plan, "filesystem.read").realm, ExecutionRealm::Host);
        assert_eq!(
            plan.coverage
                .0
                .get(&Domain::new("filesystem"))
                .map(|claim| &claim.level),
            Some(&CoverageLevel::Full)
        );
    }

    for option in [
        "--check",
        "--compress",
        "--force-rm",
        "--load",
        "--no-cache",
        "--pull",
        "--push",
        "-q",
        "--quiet",
        "--rm",
        "--squash",
    ] {
        let plan = analyze(&["docker", "build", option, "."]);
        assert!(!has_unrecognized_arguments(&plan), "{option}");
        effect(&plan, "filesystem.read");
        assert_eq!(
            plan.coverage
                .0
                .get(&Domain::new("filesystem"))
                .map(|claim| &claim.level),
            Some(&CoverageLevel::Full)
        );
    }

    let plan = analyze(&[
        "docker",
        "build",
        "--secret",
        "id=x,src=y",
        "--sbom=true",
        "--check",
        "-t",
        "app",
        ".",
    ]);
    assert!(!has_unrecognized_arguments(&plan));
    effect(&plan, "filesystem.read");
}

#[test]
fn docker_unknown_run_flags_keep_or_symbolize_the_container_effect_by_arity() {
    for argv in [
        &["docker", "run", "--future=1", "alpine", "rm", "-rf", "/x"][..],
        &[
            "docker",
            "run",
            "--privileged=false",
            "alpine",
            "rm",
            "-rf",
            "/x",
        ][..],
        &["docker", "run", "-eNAME=value", "alpine", "rm", "-rf", "/x"][..],
        &[
            "docker", "run", "--future", "--rm", "alpine", "rm", "-rf", "/x",
        ][..],
    ] {
        let plan = analyze(argv);
        assert!(has_unrecognized_arguments(&plan));
        assert_alpine_run(&plan);
        assert_eq!(
            plan.coverage
                .0
                .get(&Domain::new("container"))
                .map(|claim| &claim.level),
            Some(&CoverageLevel::Partial)
        );
    }

    assert!(has_unrecognized_arguments(&analyze(&[
        "docker", "run", "-itv"
    ])));

    let plan = analyze(&["docker", "run", "--privileged=false", "alpine"]);
    assert!(
        !effect(&plan, "container.run")
            .attributes
            .contains_key("privileged")
    );
    let plan = analyze(&["docker", "run", "-w/tmp", "alpine", "rm", "-rf", "/x"]);
    assert!(has_unrecognized_arguments(&plan));
    assert!(matches!(
        &effect(&plan, "container.run").resource,
        ResourceExpr::Unresolved { .. }
    ));

    let plan = analyze(&[
        "docker",
        "run",
        "--privileged",
        "--future-flag",
        "value",
        "alpine",
        "rm",
        "-rf",
        "/x",
    ]);
    assert!(has_unrecognized_arguments(&plan));
    let run = effect(&plan, "container.run");
    assert!(matches!(
        &run.resource,
        ResourceExpr::Unresolved { family } if family == &ResourceFamily::new("container")
    ));
    assert_eq!(
        run.attributes.get("privileged"),
        Some(&AttrValue::Bool(true))
    );
    assert!(!plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/x")
    }));
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .all(|node| node.realm.is_host())
    );
}

#[test]
fn docker_unknown_build_flags_keep_or_drop_the_context_by_arity() {
    let plan = analyze(&["docker", "build", "--future=1", "-t", "app", "."]);
    assert!(has_unrecognized_arguments(&plan));
    effect(&plan, "filesystem.read");
    assert_eq!(
        plan.coverage
            .0
            .get(&Domain::new("filesystem"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Partial)
    );

    let plan = analyze(&["docker", "build", "--future", "value", "."]);
    assert!(has_unrecognized_arguments(&plan));
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.read")
    );
    assert_eq!(
        plan.coverage
            .0
            .get(&Domain::new("filesystem"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Partial)
    );
}

#[test]
fn docker_run_records_literal_host_sharing_attributes() {
    let plan = analyze(&[
        "docker",
        "run",
        "--privileged",
        "--pid=host",
        "--network",
        "host",
        "--ipc=host",
        "--userns",
        "host",
        "--uts=host",
        "--cap-add",
        "SYS_ADMIN",
        "--cap-add=NET_ADMIN",
        "--device",
        "/dev/sdb",
        "--device=/dev/sda",
        "--security-opt",
        "label=disable",
        "--security-opt=seccomp=unconfined",
        "alpine",
        "true",
    ]);
    let attributes = &effect(&plan, "container.run").attributes;
    assert_eq!(attributes.get("privileged"), Some(&AttrValue::Bool(true)));
    assert_eq!(
        attributes.get("pid"),
        Some(&AttrValue::String("host".to_string()))
    );
    assert_eq!(
        attributes.get("network"),
        Some(&AttrValue::String("host".to_string()))
    );
    assert_eq!(
        attributes.get("ipc"),
        Some(&AttrValue::String("host".to_string()))
    );
    assert_eq!(
        attributes.get("userns"),
        Some(&AttrValue::String("host".to_string()))
    );
    assert_eq!(
        attributes.get("uts"),
        Some(&AttrValue::String("host".to_string()))
    );
    assert_eq!(
        attributes.get("cap_add"),
        Some(&AttrValue::String("NET_ADMIN,SYS_ADMIN".to_string()))
    );
    assert_eq!(
        attributes.get("device"),
        Some(&AttrValue::String("/dev/sda,/dev/sdb".to_string()))
    );
    assert_eq!(
        attributes.get("security_opt"),
        Some(&AttrValue::String(
            "label=disable,seccomp=unconfined".to_string()
        ))
    );
}

#[test]
fn docker_run_omits_symbolic_host_sharing_attributes() {
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "docker run --pid=$NS alpine true".to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        !effect(&plan, "container.run")
            .attributes
            .contains_key("pid")
    );
}

#[test]
fn docker_run_preserves_inline_name_with_clustered_flags() {
    let plan = analyze(&[
        "docker",
        "run",
        "--name=worker",
        "-it",
        "alpine",
        "rm",
        "-rf",
        "/named",
    ]);
    assert_eq!(
        delete_of(&plan, "/named"),
        ExecutionRealm::Container {
            runtime: "docker".to_string(),
            name: "alpine".to_string(),
        }
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "container.run"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Container {
                        name: Some(name),
                        image: Some(image),
                        ..
                    }
                } if name == "worker" && image == "alpine"
            )
    }));
}

#[test]
fn compose_run_nests_the_command_and_mounts_like_docker_run() {
    let plan = analyze(&[
        "docker", "compose", "run", "--rm", "web", "rm", "-rf", "/data",
    ]);
    assert_compose_service_effect(&plan, "container.run", "docker", "web");
    assert_eq!(
        delete_of(&plan, "/data"),
        ExecutionRealm::Container {
            runtime: "docker".to_string(),
            name: "web".to_string(),
        }
    );

    let plan = analyze(&[
        "docker",
        "compose",
        "run",
        "--rm",
        "-v",
        "./data:/data",
        "--entrypoint",
        "sh",
        "web",
        "-c",
        "rm -rf /data",
    ]);
    assert_compose_service_effect(&plan, "container.run", "docker", "web");
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.write"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/w/data"
            )
            && effect.realm.is_host()
    }));
    assert!(plan.execution_graph.nodes.iter().any(|node| {
        matches!(
            &node.subject,
            Subject::Exec { argv, .. }
                if argv.first().map(String::as_str) == Some("sh")
                    && argv.get(1).map(String::as_str) == Some("-c")
        )
    }));
    assert_eq!(
        delete_of(&plan, "/data"),
        ExecutionRealm::Container {
            runtime: "docker".to_string(),
            name: "web".to_string(),
        }
    );

    let plan = analyze(&[
        "docker",
        "compose",
        "run",
        "--build",
        "--no-deps",
        "--env-from-file",
        ".env",
        "--quiet-pull",
        "web",
    ]);
    assert_compose_service_effect(&plan, "container.run", "docker", "web");
    assert_unknown_daemon_transport(&plan);
    assert_eq!(plan.execution_graph.nodes.len(), 1);
    assert_eq!(
        plan.coverage
            .0
            .get(&Domain::new("container"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Full)
    );

    let plan = analyze(&[
        "docker", "compose", "run", "--future", "v", "web", "rm", "-rf", "/data",
    ]);
    assert!(has_unrecognized_arguments(&plan));
    assert!(matches!(
        &effect(&plan, "container.run").resource,
        ResourceExpr::Unresolved { family } if family == &ResourceFamily::new("container")
    ));
    assert_eq!(plan.execution_graph.nodes.len(), 1);
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
}

#[test]
fn compose_down_records_container_remove_with_volumes() {
    for argv in [
        &["docker-compose", "down", "-v"][..],
        &["docker", "compose", "down", "--volumes", "--remove-orphans"][..],
        &["podman-compose", "down", "-v", "-t", "30"][..],
        &["/usr/bin/docker-compose", "down", "-v"][..],
    ] {
        let plan = analyze(argv);
        let controls = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "container.remove")
            .collect::<Vec<_>>();
        assert_eq!(controls.len(), 1, "{argv:?}");
        assert!(matches!(
            &controls[0].resource,
            ResourceExpr::Unresolved { family } if family == &ResourceFamily::new("container")
        ));
        assert_eq!(
            controls[0].attributes.get("volumes"),
            Some(&AttrValue::Bool(true))
        );
        effect(&plan, "container.stop");
        assert_unknown_daemon_transport(&plan);
        assert_eq!(
            plan.coverage
                .0
                .get(&Domain::new("container"))
                .map(|claim| &claim.level),
            Some(&CoverageLevel::Full)
        );
    }

    let plan = analyze(&["docker-compose", "down"]);
    assert!(
        !effect(&plan, "container.remove")
            .attributes
            .contains_key("volumes")
    );

    // A wrapper at an arbitrary path is not established as Compose.
    let plan = analyze(&["/usr/local/bin/docker-compose", "down", "-v"]);
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "container.remove")
    );

    let plan = analyze(&["docker", "compose", "down", "--future"]);
    assert!(has_unrecognized_arguments(&plan));
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "container.remove")
    );
    assert_eq!(
        plan.coverage
            .0
            .get(&Domain::new("container"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Partial)
    );
}

#[test]
fn compose_other_verbs_stay_bounded() {
    for argv in [&["docker", "compose", "ps"][..], &["docker", "compose"][..]] {
        let plan = analyze(argv);
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unmodeled_subcommand")
        );
        assert!(plan.effects.iter().all(|effect| !matches!(
            effect.operation.0.as_str(),
            "container.remove" | "container.run" | "container.exec"
        )));
    }
}

#[test]
fn lifecycle_operations_distinguish_signals_suspension_and_removal() {
    for (verb, operation) in [
        ("rm", "container.remove"),
        ("stop", "container.stop"),
        ("kill", "container.kill"),
        ("pause", "container.pause"),
        ("start", "container.start"),
        ("restart", "container.restart"),
        ("unpause", "container.unpause"),
    ] {
        let plan = analyze(&["docker", verb, "app"]);
        effect(&plan, operation);
        assert_unknown_daemon_transport(&plan);
        // A kill also stops the container; see `terminating_kill_also_stops`.
        assert_eq!(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.domain() == "container")
                .count(),
            if verb == "kill" { 2 } else { 1 },
            "{verb}",
        );
    }
    for args in [
        vec!["--all"],
        vec!["-a"],
        vec!["--all=true"],
        vec!["--all=false", "-a"],
        vec!["-t", "5", "--all"],
        vec!["--all", "--time=5"],
    ] {
        let mut argv = vec!["podman", "stop"];
        argv.extend(args);
        let plan = analyze(&argv);
        let stop = effect(&plan, "container.stop");
        assert_eq!(stop.attributes.get("all"), Some(&AttrValue::Bool(true)));
        assert_eq!(
            stop.resource,
            ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::Container {
                    runtime: effinterp_proto::Field::Exact {
                        value: "podman".into()
                    },
                    name_glob: Some("*".into()),
                    image_glob: None,
                }
            },
            "{argv:?}",
        );
        assert_eq!(
            plan.coverage.level(&Domain::new("container")),
            Some(CoverageLevel::Full)
        );
        assert_eq!(
            plan.effects
                .iter()
                .filter(|e| e.operation.0 == "container.stop")
                .count(),
            1
        );
    }
    for args in [
        vec!["--all=false"],
        vec!["--all", "--all=false"],
        vec!["--all=invalid"],
        vec!["--all", "--time"],
        vec!["--all", "app"],
        vec!["--filter", "label=selected", "app"],
        vec!["--filter", "invalid"],
        vec!["--time", "invalid", "app"],
    ] {
        let mut argv = vec!["podman", "stop"];
        argv.extend(args);
        let plan = analyze(&argv);
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "container.stop"),
            "{argv:?}"
        );
        if argv
            .iter()
            .any(|arg| matches!(*arg, "--all=invalid" | "--filter" | "--time"))
        {
            assert!(has_unrecognized_arguments(&plan), "{argv:?}");
        }
    }
    for args in [
        vec!["--", "--all"],
        vec!["--all=false", "app"],
        vec!["-t", "5", "app"],
    ] {
        let mut argv = vec!["podman", "stop"];
        argv.extend(&args);
        let plan = analyze(&argv);
        let stops: Vec<_> = plan
            .effects
            .iter()
            .filter(|e| e.operation.0 == "container.stop")
            .collect();
        assert_eq!(stops.len(), 1, "{argv:?}");
        assert!(
            matches!(&stops[0].resource, ResourceExpr::Concrete { identity: ResourceIdentity::Container { name: Some(name), .. } } if name == args.last().unwrap())
        );
        assert_eq!(
            stops[0].attributes.get("all"),
            Some(&AttrValue::Bool(false))
        );
        assert_eq!(
            stops[0].attributes.get("active"),
            Some(&AttrValue::Bool(true))
        );
        assert_eq!(
            stops[0].attributes.get("dry_run"),
            Some(&AttrValue::Bool(false))
        );
    }
    assert!(
        !analyze(&["docker", "stop", "--all"])
            .effects
            .iter()
            .any(|e| e.operation.0 == "container.stop")
    );
    for manager in ["docker", "podman", "nerdctl"] {
        for (verb, operation) in [
            ("stop", "container.stop"),
            ("kill", "container.kill"),
            ("restart", "container.restart"),
            ("pause", "container.pause"),
        ] {
            for args in [
                vec!["app", "--help"],
                vec!["--help"],
                vec!["--help=false", "app"],
            ] {
                let mut argv = vec![manager, verb];
                argv.extend(&args);
                let plan = analyze(&argv);
                let mutation = effect(&plan, operation);
                assert_eq!(
                    mutation.attributes.get("active"),
                    Some(&AttrValue::Bool(args[0] == "--help=false")),
                    "{argv:?}"
                );
                assert_eq!(
                    mutation.attributes.get("dry_run"),
                    Some(&AttrValue::Bool(false))
                );
            }
            let options = match verb {
                "stop" | "restart" => vec![vec!["--time", "5"], vec!["-t5"], vec!["--time=-1"]],
                "kill" => vec![vec!["--signal", "HUP"], vec!["-sKILL"]],
                _ => vec![vec![]],
            };
            for args in options {
                let mut argv = vec![manager, verb];
                argv.extend(args);
                argv.push("app");
                let plan = analyze(&argv);
                let mutations: Vec<_> = plan
                    .effects
                    .iter()
                    .filter(|e| e.operation.0 == operation)
                    .collect();
                assert_eq!(mutations.len(), 1, "{argv:?}");
                assert!(
                    matches!(&mutations[0].resource, ResourceExpr::Concrete { identity: ResourceIdentity::Container { name: Some(name), runtime, .. }} if name == "app" && runtime == manager),
                    "{argv:?}"
                );
            }
            if manager == "podman" {
                let plan = analyze(&[manager, verb, "--all"]);
                let mutation = effect(&plan, operation);
                assert_eq!(mutation.attributes.get("all"), Some(&AttrValue::Bool(true)));
                assert_eq!(
                    mutation.attributes.get("active"),
                    Some(&AttrValue::Bool(true))
                );
                assert_eq!(
                    mutation.attributes.get("dry_run"),
                    Some(&AttrValue::Bool(false))
                );
                for selector in ["--latest", "--cidfile=/tmp/container-id"] {
                    let plan = analyze(&[manager, verb, selector]);
                    let mutation = effect(&plan, operation);
                    assert!(
                        matches!(&mutation.resource, ResourceExpr::Unresolved { family } if family.0 == "container")
                    );
                    assert_eq!(
                        mutation.attributes.get("all"),
                        Some(&AttrValue::Bool(false))
                    );
                    assert!(plan
                        .boundaries
                        .iter()
                        .any(|b| b.reason == effinterp_proto::BoundaryReason::UNRESOLVED_SOURCE));
                    if selector.starts_with("--cidfile") {
                        effect(&plan, "filesystem.read");
                    }
                }
                if verb != "kill" {
                    let plan = analyze(&[manager, verb, "--all", "--filter", "label=selected"]);
                    let mutation = effect(&plan, operation);
                    assert_eq!(
                        mutation.attributes.get("all"),
                        Some(&AttrValue::Bool(false))
                    );
                    assert!(matches!(
                        &mutation.resource,
                        ResourceExpr::Unresolved { .. }
                    ));
                }
            } else {
                let plan = analyze(&[manager, verb, "--all"]);
                assert!(has_unrecognized_arguments(&plan));
                assert!(!plan.effects.iter().any(|e| e.operation.0 == operation));
            }
            for args in [
                vec!["--dry-run", "app"],
                vec!["--time"],
                vec!["--unknown", "value", "app"],
            ] {
                let mut argv = vec![manager, verb];
                argv.extend(args);
                let plan = analyze(&argv);
                assert!(has_unrecognized_arguments(&plan), "{argv:?}");
                assert!(
                    !plan.effects.iter().any(|e| e.operation.0 == operation),
                    "{argv:?}"
                );
            }
        }
    }
    // A lone unquoted `docker ps -q` substitution, or the pipe xargs reads
    // it from, feeds its exact running-set selection into the stop it names,
    // whether appended or replacing a whole argument; a variable operand, a
    // name derived from the item, an input delimiter that keeps the newlines
    // inside one item, or an inner pipe or redirection that replaces the
    // stdin xargs would inherit stays unresolved. A compound command or
    // process substitution reads the same selection through a channel,
    // unless another writer shares that channel.
    for (source, fed) in [
        ("docker stop $(docker ps -q)", true),
        ("docker stop $(docker ps -q --filter status=running)", true),
        ("docker rm -f $(docker ps -q)", true),
        ("docker ps -q | xargs docker stop", true),
        ("docker ps -q | xargs -I{} docker stop {}", true),
        ("docker ps -q | xargs -I{} docker stop prefix-{}", false),
        ("docker ps -q | xargs -0 docker stop", false),
        ("docker ps -q | sh -c 'xargs docker stop'", true),
        ("docker ps -q | sh -c 'cat ids | xargs docker stop'", false),
        ("docker ps -q | sh -c 'xargs docker stop < ids'", false),
        ("docker ps -q; docker stop $TARGET", false),
        ("docker ps -q; cat ids | xargs docker stop", false),
        ("docker ps -q | { xargs docker stop; }", true),
        ("docker ps -q | (xargs docker stop)", true),
        ("xargs docker stop < <(docker ps -q)", true),
        ("docker ps -q | sort | { xargs docker stop; }", false),
        ("xargs docker stop < <(docker ps -q; echo extra)", false),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        let stop = effect(&plan, "container.stop");
        if fed {
            assert!(
                matches!(&stop.resource, ResourceExpr::Pattern { .. }),
                "{source}"
            );
            assert_eq!(stop.attributes.get("all"), Some(&AttrValue::Bool(true)));
            assert_eq!(
                stop.attributes.get("selection"),
                Some(&AttrValue::String("running".into()))
            );
        } else {
            assert!(
                matches!(&stop.resource, ResourceExpr::Unresolved { .. }),
                "{source}"
            );
            assert!(!stop.attributes.contains_key("all"));
        }
        let selection = effect(&plan, "container.resource.read");
        assert!(matches!(&selection.resource, ResourceExpr::Pattern { .. }));
        assert_eq!(
            selection.attributes.get("all"),
            Some(&AttrValue::Bool(true))
        );
        assert_eq!(stop.attributes.get("active"), Some(&AttrValue::Bool(true)));
        assert_eq!(
            stop.attributes.get("dry_run"),
            Some(&AttrValue::Bool(false))
        );
    }
    // A removal stops what it removes only while force's last value is true;
    // help or an option rm rejects removes nothing, so it stops nothing.
    for (source, stops) in [
        ("docker rm -f web", true),
        ("docker rm -vf web", true),
        ("docker rm --force=false -f web", true),
        ("docker rm -f -v=false web", true),
        ("docker rm -f --force=false web", false),
        ("docker rm -f=false web", false),
        ("docker rm -fv=false web", true),
        ("docker rm -vf=0 web", false),
        ("docker rm -f --help web", false),
        ("docker rm --force -h web", false),
        ("docker rm -foo web", false),
        ("docker rm -f=maybe web", false),
    ] {
        let plan = analyze(&source.split(' ').collect::<Vec<_>>());
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "container.stop"),
            stops,
            "{source}"
        );
        effect(&plan, "container.remove");
    }
}

#[test]
fn remote_daemon_transport_stays_in_the_callers_realm() {
    let plan = analyze(&[
        "docker",
        "--host",
        "tcp://daemon.example:2376",
        "exec",
        "worker",
        "mosquitto_pub",
        "-h",
        "broker.example",
        "-t",
        "jobs",
        "-m",
        "x",
    ]);
    let connections: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "network.connect")
        .collect();
    assert_eq!(connections.len(), 2);
    for (host, realm) in [
        ("daemon.example", ExecutionRealm::Host),
        (
            "broker.example",
            ExecutionRealm::Container {
                runtime: "docker".into(),
                name: "worker".into(),
            },
        ),
    ] {
        let connection = connections.iter().find(|effect| matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host: actual, .. } } if actual == host)).unwrap();
        assert_eq!(connection.realm, realm);
        assert!(!connection.provenance.is_empty());
    }
    for argv in [
        vec!["docker", "stop", "worker"],
        vec![
            "docker",
            "--host",
            "unix:///run/docker.sock",
            "stop",
            "worker",
        ],
        vec!["docker", "--help"],
    ] {
        let plan = analyze(&argv);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.domain() == "network")
        );
    }
}

fn assert_unknown_daemon_transport(plan: &Plan) {
    assert_eq!(plan.boundaries.len(), 1);
    assert_eq!(plan.boundaries[0].domains, vec![Domain::new("network")]);
    assert_eq!(
        plan.coverage.level(&Domain::new("network")),
        Some(CoverageLevel::Partial)
    );
}

#[test]
fn compose_up_and_build_keep_services_unresolved_and_read_configuration() {
    for argv in [
        &["docker", "compose", "up", "-d", "hermes-gateway"][..],
        &["docker-compose", "up", "--build"][..],
        &[
            "docker",
            "compose",
            "-f",
            "deploy.yml",
            "up",
            "-d",
            "gateway",
        ][..],
        &["docker", "compose", "--file=deploy.yml", "up", "gateway"][..],
        &["docker", "compose", "-fdeploy.yml", "up", "gateway"][..],
    ] {
        let plan = analyze(argv);
        assert!(!has_unrecognized_arguments(&plan), "{argv:?}");
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unmodeled_subcommand")
        );
        let start = effect(&plan, "container.start");
        assert!(
            matches!(&start.resource, ResourceExpr::Unresolved { family } if family.0 == "container")
        );
        assert_eq!(start.realm, ExecutionRealm::Host);
        effect(&plan, "network.download");
        let read = effect(&plan, "filesystem.read");
        if argv.iter().any(|arg| arg.contains("deploy.yml")) {
            assert!(
                matches!(&read.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/w/deploy.yml")
            );
        } else {
            assert!(
                matches!(&read.resource, ResourceExpr::Union { alternatives } if alternatives.len() == 2)
            );
        }
    }
    let plan = analyze(&["docker", "compose", "up", "--pull", "never", "gateway"]);
    effect(&plan, "container.start");
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0 == "network.download")
    );
    let plan = analyze(&["docker", "compose", "--dry-run", "up", "gateway"]);
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0 == "container.start")
    );
    for argv in [
        &["docker", "compose", "build"][..],
        &["docker", "compose", "build", "--no-cache", "gateway"][..],
    ] {
        let plan = analyze(argv);
        assert!(plan.effects.iter().any(|e| e.operation.0 == "filesystem.read"
            && matches!(&e.resource, ResourceExpr::Unresolved { family } if family.0 == "filesystem")));
        assert!(!plan.effects.iter().any(|e| matches!(&e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/w/gateway")));
    }
}

#[test]
fn compose_configuration_selectors_control_reads() {
    let path = |name: &str| ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path: name.into() },
    };
    for verb in ["up", "build"] {
        for (options, expected) in [
            (
                "--project-directory sub",
                vec![ResourceExpr::Union {
                    alternatives: vec![
                        path("/w/sub/compose.yaml"),
                        path("/w/sub/docker-compose.yml"),
                    ],
                }],
            ),
            (
                "--project-directory=/deploy",
                vec![ResourceExpr::Union {
                    alternatives: vec![
                        path("/deploy/compose.yaml"),
                        path("/deploy/docker-compose.yml"),
                    ],
                }],
            ),
            (
                "--env-file prod.env -f deploy.yml",
                vec![path("/w/prod.env"), path("/w/deploy.yml")],
            ),
            (
                "--env-file=a.env --env-file b.env -f deploy.yml",
                vec![path("/w/a.env"), path("/w/b.env"), path("/w/deploy.yml")],
            ),
            ("-f explicit.yml", vec![path("/w/explicit.yml")]),
            ("", vec![path("/w/deploy.yml"), path("/w/override.yml")]),
        ] {
            let command =
                format!("COMPOSE_FILE=deploy.yml:override.yml docker compose {options} {verb}");
            // Project-directory lookup applies only without an explicit file selector.
            let command = if options.starts_with("--project-directory") {
                format!("docker compose {options} {verb}")
            } else {
                command
            };
            let plan = analyze(&["sh", "-c", &command]);
            let reads: Vec<_> = plan
                .effects
                .iter()
                .filter(|e| {
                    e.operation.0 == "filesystem.read"
                        && !matches!(e.resource, ResourceExpr::Unresolved { .. })
                })
                .map(|e| e.resource.clone())
                .collect();
            assert_eq!(reads, expected, "{command}");
            assert_eq!(
                plan.coverage.level(&Domain::new("filesystem")),
                Some(CoverageLevel::Full),
                "{command}"
            );
        }
    }
    for command in [
        "COMPOSE_FILE=$UNKNOWN docker compose up",
        "docker compose --project-directory \"$UNKNOWN\" up",
        "docker compose -f \"$UNKNOWN\" up",
        "docker compose --env-file prod.env up",
        "COMPOSE_FILE=deploy.yml COMPOSE_PATH_SEPARATOR=$UNKNOWN docker compose up",
        "docker compose -f - up",
    ] {
        let plan = analyze(&["sh", "-c", command]);
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unresolved_source"
                    && b.domains.contains(&Domain::new("filesystem"))),
            "{command}"
        );
        assert_eq!(
            plan.coverage.level(&Domain::new("filesystem")),
            Some(CoverageLevel::Partial),
            "{command}"
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "filesystem.read"
                    && matches!(e.resource, ResourceExpr::Union { .. })),
            "{command}"
        );
    }
    let plan = analyze(&[
        "sh",
        "-c",
        "COMPOSE_PATH_SEPARATOR=, COMPOSE_FILE=deploy.yml,override.yml docker compose up",
    ]);
    let reads: Vec<_> = plan
        .effects
        .iter()
        .filter(|e| e.operation.0 == "filesystem.read")
        .map(|e| e.resource.clone())
        .collect();
    assert_eq!(reads, vec![path("/w/deploy.yml"), path("/w/override.yml")]);
}

#[test]
fn docker_image_and_buildx_verbs_have_effects_without_subcommand_boundaries() {
    for (argv, operation, target) in [
        (
            &["docker", "pull", "--platform=linux/amd64", "ghcr.io/x/y:1"][..],
            "network.download",
            "ghcr.io/x/y:1",
        ),
        (
            &[
                "docker",
                "buildx",
                "imagetools",
                "inspect",
                "--raw",
                "ghcr.io/x/y:1",
            ][..],
            "network.request",
            "ghcr.io/x/y:1",
        ),
        (
            &[
                "docker",
                "buildx",
                "imagetools",
                "create",
                "-tghcr.io/x/y:2",
                "ghcr.io/x/y:1",
            ][..],
            "network.upload",
            "ghcr.io/x/y:2",
        ),
    ] {
        let plan = analyze(argv);
        assert!(!has_unrecognized_arguments(&plan), "{argv:?}");
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unmodeled_subcommand")
        );
        let effect = effect(&plan, operation);
        assert_eq!(effect.realm, ExecutionRealm::Host);
        assert!(matches!(&effect.resource, ResourceExpr::Literal { value } if value == target));
    }
    let plan = analyze(&[
        "docker",
        "buildx",
        "build",
        "--platform",
        "linux/amd64",
        ".",
    ]);
    assert!(matches!(&effect(&plan, "filesystem.read").resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/w"));
    for verb in ["inspect", "ls"] {
        let plan = analyze(&["docker", "image", verb]);
        assert!(plan.boundaries.is_empty());
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0.starts_with("network.")
                    || e.operation.0.starts_with("container."))
        );
    }
    for argv in [
        &[
            "docker",
            "pull",
            "--future",
            "not-an-image",
            "ghcr.io/x/y:1",
        ][..],
        &["docker", "pull", "--platform"][..],
    ] {
        let plan = analyze(argv);
        assert!(has_unrecognized_arguments(&plan));
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "network.download")
        );
    }
}

#[test]
fn terminating_kill_also_stops() {
    for argv in [
        &["docker", "kill", "app"][..],
        &["podman", "kill", "--all"][..],
        &["podman", "kill", "--all", "--signal", "TERM"][..],
        &["docker", "kill", "-s", "sigint", "app"][..],
        &["docker", "kill", "--signal=9", "app"][..],
    ] {
        let plan = analyze(argv);
        let kill = effect(&plan, "container.kill");
        let stop = effect(&plan, "container.stop");
        assert_eq!(stop.resource, kill.resource, "{argv:?}");
        assert_eq!(stop.attributes, kill.attributes, "{argv:?}");
    }
    // A signal the main process may handle, or one the invocation does not
    // name, does not establish that the container ends.
    for argv in [
        &["docker", "kill", "--signal", "HUP", "app"][..],
        &["podman", "kill", "--all", "-s", "USR1"][..],
    ] {
        let plan = analyze(argv);
        effect(&plan, "container.kill");
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "container.stop"),
            "{argv:?}"
        );
    }
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "docker kill --signal \"$SIGNAL\" app".into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    effect(&plan, "container.kill");
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0 == "container.stop")
    );
}

#[test]
fn compose_root_version_runs_the_named_command_except_in_podman_compose() {
    for argv in [
        &["docker", "compose", "-v", "down", "--volumes"][..],
        &["docker", "compose", "--version", "rm", "--volumes"][..],
        &["docker-compose", "--version", "down", "--volumes"][..],
        &["podman", "compose", "-v", "down", "--volumes"][..],
        &["docker", "compose", "--all-resources", "down", "-v"][..],
    ] {
        let plan = analyze(argv);
        assert_eq!(
            effect(&plan, "container.remove").attributes.get("volumes"),
            Some(&AttrValue::Bool(true)),
            "{argv:?}"
        );
    }
    for argv in [
        &["podman-compose", "-v", "rm", "--volumes", "app"][..],
        &["podman-compose", "--version", "down", "--volumes"][..],
    ] {
        let plan = analyze(argv);
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.domain() == "container"),
            "{argv:?}"
        );
    }
}

#[test]
fn docker_cleanup_option_spellings_reach_the_prune() {
    for (argv, all) in [
        (&["docker", "volume", "prune", "-af=false"][..], true),
        (&["docker", "volume", "prune", "-fa=false"][..], false),
        (&["docker", "volume", "prune", "-fa=true"][..], true),
        (
            &["docker", "volume", "--help=false", "prune", "--all"][..],
            true,
        ),
        (
            &[
                "docker",
                "-DH=tcp://daemon.example:2376",
                "volume",
                "prune",
                "-a",
            ][..],
            true,
        ),
    ] {
        let plan = analyze(argv);
        let removal = effect(&plan, "container.remove");
        assert_eq!(
            removal.attributes.get("all"),
            Some(&AttrValue::Bool(all)),
            "{argv:?}"
        );
        assert_eq!(
            removal.attributes.get("volumes"),
            Some(&AttrValue::Bool(true))
        );
    }
    for argv in [
        &["docker", "volume", "--help", "prune", "--all"][..],
        &["docker", "volume", "prune", "-af=maybe"][..],
    ] {
        let plan = analyze(argv);
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "container.remove"),
            "{argv:?}"
        );
    }
}

#[test]
fn podman_url_selects_a_remote_service() {
    let plan = analyze(&[
        "podman",
        "--url=ssh://operator@host/run/podman.sock",
        "system",
        "prune",
        "--volumes",
    ]);
    assert_eq!(
        effect(&plan, "container.remove").attributes.get("volumes"),
        Some(&AttrValue::Bool(true))
    );
    assert!(matches!(
        &effect(&plan, "network.connect").resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host, .. } } if host == "host"
    ));
    // The remote client refuses the local-only reset.
    for argv in [
        &[
            "podman",
            "--url",
            "ssh://operator@host/run/podman.sock",
            "system",
            "reset",
        ][..],
        &["podman", "--connection", "production", "system", "reset"][..],
    ] {
        let plan = analyze(argv);
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.domain() == "container"),
            "{argv:?}"
        );
    }
    let plan = analyze(&["docker", "--url", "tcp://daemon.example", "volume", "prune"]);
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0 == "container.remove")
    );
}
