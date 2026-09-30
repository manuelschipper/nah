use effinterp_engine::Engine;
use effinterp_proto::{
    BoundaryClass, CoverageLevel, Domain, ExecutionEdgeKind, ExecutionRealm, Plan,
    RequestAssurance, ResourceExpr, ResourceIdentity, Subject, validate_plan,
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
    plan
}

fn ops(plan: &Plan) -> Vec<&str> {
    plan.effects
        .iter()
        .map(|e| e.operation.0.as_str())
        .collect()
}

fn has_op_on(plan: &Plan, op: &str, needle: &str) -> bool {
    plan.effects
        .iter()
        .any(|e| e.operation.0 == op && render(&e.resource).contains(needle))
}

fn render(expr: &ResourceExpr) -> String {
    match expr {
        ResourceExpr::Concrete { identity } => match identity {
            ResourceIdentity::FsPath { path } => path.clone(),
            ResourceIdentity::Process { executable, .. } => executable.clone(),
            ResourceIdentity::NetworkEndpoint { host, scheme, .. } => {
                format!("{}{host}", scheme.as_deref().unwrap_or(""))
            }
            ResourceIdentity::Container { name, image, .. } => format!(
                "container:{}",
                name.as_deref().or(image.as_deref()).unwrap_or("?")
            ),
            _ => "db".to_string(),
        },
        ResourceExpr::Unresolved { family } => format!("?{}", family.0),
        other => format!("{other:?}"),
    }
}

fn boundary(plan: &Plan, reason: &str) -> bool {
    plan.boundaries.iter().any(|b| b.reason.as_str() == reason)
}

fn code_effect(plan: &Plan) -> Option<&effinterp_proto::Effect> {
    plan.effects
        .iter()
        .find(|effect| effect.operation.0 == "process.code_execution")
}

fn code_attribute<'a>(plan: &'a Plan, name: &str) -> Option<&'a str> {
    code_effect(plan)
        .and_then(|effect| effect.attributes.get(name))
        .and_then(|value| match value {
            effinterp_proto::AttrValue::String(value) => Some(value.as_str()),
            _ => None,
        })
}

#[test]
fn terminal_carriers_enter_literal_commands() {
    for argv in [
        &["herdr", "pane", "run", "example-pane", "nah nap"][..],
        &[
            "tmux",
            "send-keys",
            "-t",
            "example-pane",
            "nah nap",
            "Enter",
        ][..],
        &[
            "herdr",
            "--session",
            "example",
            "pane",
            "send-keys",
            "example-pane",
            "nah nap",
            "Enter",
        ][..],
        &["tmux", "send-keys", "-t", "example-pane", "nah nap", "C-m"][..],
        &["tmux", "send-keys", "nah", " nap", "Return"][..],
        &["tmux", "neww", "nah", "nap"][..],
        &["tmux", "split-window", "-h", "nah nap"][..],
        &["tmux", "splitw", "-t", "example-pane", "nah", "nap"][..],
    ] {
        let plan = analyze(argv);
        let delivered = plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "process.exec" && render(&effect.resource) == "nah"
            })
            .unwrap_or_else(|| panic!("{argv:?}: {:?}", plan.effects));
        assert_eq!(
            delivered.attributes.get("delivery"),
            Some(&effinterp_proto::AttrValue::String("terminal".to_string()))
        );
        assert!(
            plan.execution_graph
                .edges
                .iter()
                .any(|edge| edge.kind == ExecutionEdgeKind::ToolModel)
        );
        assert!(boundary(&plan, "unmodeled_command"), "{argv:?}");
    }

    for argv in [
        &["herdr", "agent", "prompt", "example-agent", "nah nap"][..],
        &["tmux", "send-keys", "-t", "example-pane", "nah nap"][..],
        &["tmux", "send-keys", "-l", "nah nap", "Enter"][..],
        &["tmux", "send-keys", "nah nap", "Escape", "Enter"][..],
        &["tmux", "paste-buffer", "-t", "example-pane"][..],
    ] {
        let plan = analyze(argv);
        assert!(
            !plan.effects.iter().any(|effect| {
                effect.operation.0 == "process.exec" && render(&effect.resource) == "nah"
            }),
            "{argv:?}"
        );
    }
}

#[test]
fn terminal_input_states_typed_text_and_its_candidate_programs() {
    for (argv, candidates) in [
        (
            &[
                "herdr",
                "pane",
                "send-text",
                "p",
                "if true; then nah nap; fi",
            ][..],
            &["nah"][..],
        ),
        (
            &["herdr", "pane", "send-keys", "p", "nah nap"][..],
            &["nah"][..],
        ),
        (
            &["tmux", "send", "-l", "-t", "p", "sh -c 'nah nap'"][..],
            &["sh", "nah"][..],
        ),
        // Text that names no program still records the input.
        (&["tmux", "send-keys", "x=1"][..], &["?process"][..]),
    ] {
        let plan = analyze(argv);
        let typed = plan
            .effects
            .iter()
            .filter(|effect| {
                effect.operation.0 == "process.code_execution"
                    && effect.attributes.get("source")
                        == Some(&effinterp_proto::AttrValue::String(
                            "terminal_input".to_string(),
                        ))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            typed
                .iter()
                .map(|effect| render(&effect.resource))
                .collect::<Vec<_>>(),
            candidates,
            "{argv:?}"
        );
        let text = argv.last().unwrap();
        assert!(typed.iter().all(|effect| effect.attributes.get("text")
            == Some(&effinterp_proto::AttrValue::String(text.to_string()))));
        // Typed text runs nothing until the receiver submits it: the analysis
        // that found the candidates is not part of the plan.
        assert_eq!(ops(&plan), {
            let mut expected = vec!["process.exec"];
            expected.extend(candidates.iter().map(|_| "process.code_execution"));
            expected
        });
        assert!(boundary(&plan, "unmodeled_command"), "{argv:?}");
    }
}

#[test]
fn sudo_strips_user_flag_and_runs_command() {
    let plan = analyze(&["sudo", "-u", "root", "rm", "-rf", "/var/log"]);
    assert_eq!(
        ops(&plan),
        vec!["process.exec", "process.exec", "filesystem.delete"]
    );
    assert!(has_op_on(&plan, "filesystem.delete", "/var/log"));
}

#[test]
fn sudo_accepts_env_assignment_prefix() {
    let plan = analyze(&["sudo", "FOO=bar", "rm", "/tmp/x"]);
    assert!(has_op_on(&plan, "filesystem.delete", "/tmp/x"));
}

#[test]
fn timeout_skips_duration_operand() {
    let plan = analyze(&["timeout", "5", "rm", "/tmp/x"]);
    assert!(has_op_on(&plan, "filesystem.delete", "/tmp/x"));
    // The duration `5` must not become the command.
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| render(&e.resource).contains('5')
                && e.operation.0 == "process.exec"
                && !render(&e.resource).contains("timeout"))
    );
}

#[test]
fn nohup_and_nice_are_transparent() {
    assert!(has_op_on(
        &analyze(&["nohup", "rm", "/a"]),
        "filesystem.delete",
        "/a"
    ));
    assert!(has_op_on(
        &analyze(&["nice", "-n", "5", "rm", "/a"]),
        "filesystem.delete",
        "/a"
    ));
}

#[test]
fn chroot_enters_a_rerooted_filesystem_realm() {
    let plan = analyze(&["chroot", "/jail", "rm", "/etc/x"]);
    let read = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.read")
        .unwrap();
    assert!(read.realm.is_host());
    assert!(has_op_on(&plan, "filesystem.read", "/jail"));
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert_eq!(
        delete.realm,
        ExecutionRealm::Chroot {
            host_root: Some("/jail".to_string())
        }
    );
    assert!(matches!(
        &delete.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if path == "/etc/x"
    ));
    assert!(!boundary(&plan, "chroot_reroots_filesystem"));
    assert_eq!(
        plan.coverage
            .0
            .get(&Domain::new("filesystem"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Full)
    );
    assert!(plan.execution_graph.nodes.iter().any(|node| {
        node.realm == delete.realm
            && matches!(&node.subject, Subject::Exec { argv, cwd, .. }
                if argv.first().map(String::as_str) == Some("rm")
                    && cwd.as_deref() == Some("/"))
    }));
}

#[test]
fn chroot_skip_chdir_and_empty_command_preserve_their_distinct_shapes() {
    let skipped = analyze(&["chroot", "--skip-chdir", "/jail", "rm", "data"]);
    let rm = skipped
        .execution_graph
        .nodes
        .iter()
        .find(|node| {
            matches!(&node.subject, Subject::Exec { argv, .. }
                if argv.first().map(String::as_str) == Some("rm"))
        })
        .unwrap();
    assert_eq!(rm.cwd, None);
    assert!(!boundary(&skipped, "unrecognized_arguments"));

    let empty = analyze(&["chroot", "/jail"]);
    assert!(has_op_on(&empty, "filesystem.read", "/jail"));
    assert!(
        !empty
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
    assert!(!boundary(&empty, "chroot_reroots_filesystem"));
}

#[test]
fn xargs_nests_command_with_input_determined_args() {
    let plan = analyze(&["xargs", "-n1", "rm"]);
    assert!(boundary(&plan, "input_determined_arguments"));
    // rm runs; its target is the unknown stdin-provided argument.
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.delete")
    );
    assert!(has_op_on(&plan, "filesystem.delete", "?filesystem"));

    for command in [
        "xargs -I{} rm {}",
        "xargs -I {} rm {}",
        "xargs -i rm {}",
        "xargs -i{} rm {}",
        "xargs -I ITEM rm prefix-ITEM-ITEM",
        "xargs -I{} rm \"$DIR/{}\"",
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: format!("find . -name '*.log' | {command}"),
                cwd: Some("/w".to_string()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(boundary(&plan, "input_determined_arguments"));
        let deletes: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .map(|effect| render(&effect.resource))
            .collect();
        assert_eq!(deletes, vec!["?filesystem"], "{command}");
        assert!(plan.execution_graph.nodes.iter().any(|node| {
            matches!(&node.subject, Subject::Exec { argv, .. }
                if argv.first().map(String::as_str) == Some("xargs"))
                && node.streams.stdin.is_some()
        }));
    }

    for (source, deletes) in [
        ("printf '' | xargs -r rm -rf /", false),
        ("printf '' | cat | xargs --no-run-if-empty rm -rf /", false),
        ("xargs -r rm -rf / <<'EOF'\nEOF", false),
        ("printf '' | xargs rm -rf /", true),
        ("printf 'file' | xargs -r rm -rf /", true),
        ("printf '%s' \"$INPUT\" | xargs -r rm -rf /", true),
        ("printf '' | xargs -r -a list.txt rm -rf /", true),
        ("printf '' | xargs -r --arg-file=list.txt rm -rf /", true),
        ("printf '' | xargs -r -alist.txt rm -rf /", true),
        ("printf '' | xargs -r rm -rf / < list.txt", true),
        (
            "printf() { echo file; }; printf '' | xargs -r rm -rf /",
            true,
        ),
        ("printf '' > output | xargs -r rm -rf /", true),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert_eq!(
            ops(&plan).contains(&"filesystem.delete"),
            deletes,
            "{source}"
        );
    }

    let fixed = analyze(&["xargs", "-I{}", "rm", "fixed.log"]);
    assert!(has_op_on(&fixed, "filesystem.delete", "/w/fixed.log"));
    assert!(!has_op_on(&fixed, "filesystem.delete", "?filesystem"));

    // Literal stdin supplies the appended arguments outright, including
    // NUL-separated items under -0; a delimiter this model does not interpret
    // keeps them input-determined.
    for (source, recovered) in [
        ("printf '%s\\n' /w/one /w/two | xargs rm", true),
        ("printf '%s\\n' \"/w/it's\" | xargs rm", false),
        ("printf '%s\\0' /w/one | xargs -0 rm", true),
        ("printf \"/w/it's\\0\" | xargs -0 rm", true),
        ("printf '%s\\n' /w/one | xargs -d '\\n' rm", false),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert_eq!(
            !boundary(&plan, "input_determined_arguments"),
            recovered,
            "{source}"
        );
        assert_eq!(
            !has_op_on(&plan, "filesystem.delete", "?filesystem"),
            recovered,
            "{source}"
        );
    }
    let items = Engine::new()
        .analyze(&Subject::Shell {
            source: "printf '%s\\n' /w/one /w/two | xargs rm".into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(has_op_on(&items, "filesystem.delete", "/w/one"));
    assert!(has_op_on(&items, "filesystem.delete", "/w/two"));
    let null_items = Engine::new()
        .analyze(&Subject::Shell {
            source: "printf '/w/a b\\0/w/c' | xargs -0 rm".into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(has_op_on(&null_items, "filesystem.delete", "/w/a b"));
    assert!(has_op_on(&null_items, "filesystem.delete", "/w/c"));
}

#[test]
fn xargs_arg_file_is_read() {
    let plan = analyze(&["xargs", "-a", "list.txt", "rm"]);
    assert!(has_op_on(&plan, "filesystem.read", "list.txt"));
}

#[test]
fn docker_exec_records_container_and_nests_command() {
    let plan = analyze(&["docker", "exec", "-u", "postgres", "pg", "psql", "-c", "x"]);
    assert!(has_op_on(&plan, "container.exec", "container:pg"));
    // The in-container command is analyzed (psql has no model yet → boundary).
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "process.exec" && render(&e.resource) == "psql")
    );
}

#[test]
fn docker_exec_consumes_value_options_before_the_container() {
    for options in [
        &["--env-file", "prod.env"][..],
        &["--detach-keys", "ctrl-p"][..],
    ] {
        let argv = ["docker", "exec"]
            .into_iter()
            .chain(options.iter().copied())
            .chain(["pgbox", "psql", "-c", "drop table users"])
            .collect::<Vec<_>>();
        let plan = analyze(&argv);

        assert!(has_op_on(&plan, "container.exec", "container:pgbox"));
        assert!(ops(&plan).contains(&"database.schema_drop"));
        assert!(!boundary(&plan, "unrecognized_arguments"));
    }
}

#[test]
fn docker_exec_unknown_options_fail_closed_on_the_container_operand() {
    let plan = analyze(&[
        "docker",
        "exec",
        "--unknown-option",
        "value",
        "pgbox",
        "psql",
        "-c",
        "drop table users",
    ]);

    assert!(boundary(&plan, "unrecognized_arguments"));
    assert!(has_op_on(&plan, "container.exec", "?container"));
    assert!(!ops(&plan).contains(&"database.schema_drop"));
}

#[test]
fn docker_run_records_image_and_command() {
    let plan = analyze(&[
        "docker",
        "run",
        "--rm",
        "-v",
        "/host:/data",
        "alpine",
        "rm",
        "/data/x",
    ]);
    assert!(has_op_on(&plan, "container.run", "container:alpine"));
    // Host mount source is exposed.
    assert!(has_op_on(&plan, "filesystem.write", "/host"));
    // The container command composes.
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.delete")
    );
}

#[test]
fn docker_build_consumes_value_options_before_the_context() {
    let plan = analyze(&["docker", "build", "--platform", "linux/amd64", "."]);

    assert!(has_op_on(&plan, "filesystem.read", "/w"));
    assert!(!has_op_on(&plan, "filesystem.read", "linux/amd64"));
    assert!(!boundary(&plan, "unrecognized_arguments"));
}

#[test]
fn docker_build_unknown_options_fail_closed() {
    let plan = analyze(&["docker", "build", "--unknown-option", "value", "."]);

    assert!(boundary(&plan, "unrecognized_arguments"));
    assert!(!ops(&plan).contains(&"filesystem.read"));
}

#[test]
fn docker_cp_distinguishes_container_and_host_sides() {
    let plan = analyze(&["docker", "cp", "pg:/etc/passwd", "./out"]);
    assert!(has_op_on(&plan, "container.copy", "container:pg"));
    assert!(has_op_on(&plan, "filesystem.write", "/w/out"));
}

#[test]
fn docker_rm_is_a_container_removal() {
    let plan = analyze(&["docker", "rm", "-f", "pg"]);
    assert!(has_op_on(&plan, "container.remove", "container:pg"));
}

#[test]
fn container_cleanup_retains_volume_selection_and_safe_controls() {
    for action in ["rm", "remove"] {
        let plan = analyze(&["docker", "volume", action, "one", "two", "--force"]);
        let removals: Vec<_> = plan
            .effects
            .iter()
            .filter(|e| e.operation.0 == "container.remove")
            .collect();
        assert_eq!(removals.len(), 2);
        for (removal, name) in removals.iter().zip(["one", "two"]) {
            assert_eq!(
                removal.attributes.get("volume"),
                Some(&effinterp_proto::AttrValue::String(name.into()))
            );
            assert_eq!(
                removal.attributes.get("all"),
                Some(&effinterp_proto::AttrValue::Bool(false))
            );
            assert!(!matches!(
                &removal.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Container { name: Some(_), .. }
                }
            ));
        }
    }
    let machine = analyze(&["podman", "machine", "reset", "--force"]);
    assert!(machine.effects.iter().any(|e| {
        e.operation.0 == "container.remove"
            && e.attributes.get("scope")
                == Some(&effinterp_proto::AttrValue::String("system".into()))
            && e.attributes.get("volumes") == Some(&effinterp_proto::AttrValue::Bool(true))
            && matches!(e.resource, ResourceExpr::Pattern { .. })
    }));
    for (argv, volumes, all) in [
        (vec!["docker", "volume", "prune", "--all"], true, true),
        (
            vec!["docker", "volume", "prune", "--all=false", "--force"],
            true,
            false,
        ),
        (vec!["docker", "system", "prune", "--all"], false, true),
        (
            vec!["docker", "system", "prune", "--volumes", "--force"],
            true,
            false,
        ),
        (
            vec!["docker", "system", "prune", "--volumes", "--volumes=false"],
            false,
            false,
        ),
        (
            vec!["podman", "system", "prune", "--all", "--volumes"],
            true,
            true,
        ),
        (vec!["podman", "volume", "prune", "--force"], true, true),
        (vec!["podman", "volume", "prune", "-fa"], true, true),
        (vec!["podman", "system", "reset", "--force"], true, true),
        (
            vec![
                "docker",
                "--host",
                "ssh://operator@daemon.example",
                "volume",
                "prune",
                "--all",
            ],
            true,
            true,
        ),
    ] {
        let plan = analyze(&argv);
        let removal = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "container.remove")
            .unwrap_or_else(|| panic!("{argv:?}"));
        assert_eq!(
            removal.attributes.get("volumes"),
            Some(&effinterp_proto::AttrValue::Bool(volumes))
        );
        assert_eq!(
            removal.attributes.get("all"),
            Some(&effinterp_proto::AttrValue::Bool(all))
        );
        assert_eq!(removal.modality, effinterp_proto::Modality::May);
    }
    // A `--filter` hands the selection to the runtime, so the sweep reaches a
    // subset the invocation does not name rather than the scope's volumes.
    let filtered = analyze(&[
        "docker",
        "system",
        "prune",
        "--volumes",
        "--filter",
        "label=temporary",
    ]);
    let removal = filtered
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "container.remove")
        .expect("filtered prune still removes");
    assert_eq!(removal.attributes.get("volumes"), None);
    assert_eq!(
        removal.attributes.get("selection"),
        Some(&effinterp_proto::AttrValue::String("filtered".into()))
    );
    assert_eq!(
        removal.attributes.get("all"),
        Some(&effinterp_proto::AttrValue::Bool(false))
    );
    for argv in [
        vec!["docker", "system", "reset"],
        vec!["docker", "machine", "reset"],
        vec!["podman", "machine", "reset", "--help"],
        vec!["podman", "machine", "reset", "extra"],
        vec!["docker", "volume", "rm", "one", "--help"],
        vec!["docker", "volume", "rm", "one", "--force=invalid"],
        vec!["docker", "volume", "rm", "one", "--unknown"],
        vec!["docker", "volume", "rm"],
        vec!["podman", "system", "reset", "--help"],
        vec!["podman", "system", "reset", "--version=false"],
        vec![
            "podman",
            "--connection",
            "production",
            "system",
            "reset",
            "-f=false",
        ],
        vec!["docker", "volume", "prune", "extra"],
        vec!["docker", "volume", "prune", "-v=false"],
        vec!["docker", "system", "prune", "--volumes=bogus"],
        vec!["podman", "volume", "prune", "--all", "--dry-run"],
        vec!["docker", "--help", "system", "prune"],
    ] {
        let plan = analyze(&argv);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "container.remove"),
            "{argv:?}"
        );
    }
}

#[test]
fn compose_removal_preserves_volume_and_dry_run_controls() {
    for argv in [
        vec!["docker", "compose", "down", "-v"],
        vec![
            "podman",
            "--connection",
            "production",
            "compose",
            "-f",
            "compose.yaml",
            "down",
            "--volumes",
        ],
        vec!["docker-compose", "--env-file", ".env", "rm", "-v", "api"],
        vec![
            "podman-compose",
            "--project-name=demo",
            "rm",
            "worker",
            "--volumes",
        ],
        vec!["docker", "compose", "--dry-run=false", "rm", "-fv", "app"],
    ] {
        let plan = analyze(&argv);
        let effect = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "container.remove")
            .unwrap_or_else(|| panic!("{argv:?}: {:?}", plan.boundaries));
        assert_eq!(
            effect.attributes.get("volumes"),
            Some(&effinterp_proto::AttrValue::Bool(true)),
            "{argv:?}"
        );
        assert!(matches!(effect.resource, ResourceExpr::Unresolved { .. }));
    }
    for argv in [
        vec!["docker", "compose", "--dry-run", "down", "-v"],
        vec!["docker", "compose", "rm", "--dry-run", "-v"],
        vec!["docker", "compose", "rm", "--help", "-v"],
        vec!["podman-compose", "--version", "rm", "-v", "app"],
        vec!["docker", "compose", "rm", "--unknown", "-v"],
        vec!["docker", "compose", "down", "--volumes=invalid"],
        vec![
            "podman",
            "--connection",
            "production",
            "system",
            "reset",
            "-f=invalid",
        ],
    ] {
        let plan = analyze(&argv);
        assert!(
            !plan.effects.iter().any(|effect| matches!(
                effect.operation.0.as_str(),
                "container.remove" | "container.stop"
            )),
            "{argv:?}"
        );
    }
    let plan = analyze(&["docker", "compose", "rm", "-v", "--volumes=false", "app"]);
    let removal = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "container.remove")
        .unwrap();
    assert_eq!(
        removal.attributes.get("volumes"),
        Some(&effinterp_proto::AttrValue::Bool(false))
    );
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "container.stop")
    );
}

#[test]
fn docker_unknown_subcommand_is_opaque() {
    let plan = analyze(&["docker", "frobnicate", "x"]);
    assert!(boundary(&plan, "unmodeled_subcommand"));
}

#[test]
fn ssh_connects_and_analyzes_the_command_in_a_remote_realm() {
    let plan = analyze(&["ssh", "user@host.example.com", "rm", "-rf", "/data"]);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "network.connect"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint { host, scheme, port, .. }
            } if host == "host.example.com" && scheme.as_deref() == Some("ssh") && port.is_none())
    }));
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert_eq!(
        delete.realm,
        ExecutionRealm::Remote {
            endpoint: "host.example.com".to_string()
        }
    );
    assert!(!boundary(&plan, "remote_command"));
    for domain in ["filesystem", "network", "process"] {
        assert_eq!(
            plan.coverage
                .0
                .get(&Domain::new(domain))
                .map(|claim| &claim.level),
            Some(&CoverageLevel::Full)
        );
    }
    let shell = plan
        .execution_graph
        .nodes
        .iter()
        .position(|node| {
            node.realm == delete.realm && matches!(node.subject, Subject::Shell { .. })
        })
        .unwrap();
    assert!(
        plan.execution_graph
            .edges
            .iter()
            .any(|edge| { edge.to.0 as usize == shell && edge.kind == ExecutionEdgeKind::Launch })
    );
}

#[test]
fn ssh_with_option_flags_still_finds_host() {
    let plan = analyze(&[
        "ssh",
        "-i",
        "key.pem",
        "-p",
        "2222",
        "host.example.com",
        "whoami",
    ]);
    assert!(has_op_on(&plan, "network.connect", "host.example.com"));
}

#[test]
fn ssh_option_forms_preserve_the_destination_and_remote_command() {
    for argv in [
        &["ssh", "-tt", "host", "rm", "-rf", "/data"][..],
        &[
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "host",
            "rm",
            "-rf",
            "/data",
        ],
        &["ssh", "user@host", "--", "rm", "-rf", "/data"],
        &["ssh", "-4", "-q", "-T", "host", "rm", "-rf", "/data"],
    ] {
        let plan = analyze(argv);
        assert!(!boundary(&plan, "unrecognized_arguments"), "{argv:?}");
        assert!(!boundary(&plan, "remote_command"), "{argv:?}");
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(&effect.realm, ExecutionRealm::Remote { endpoint } if endpoint == "host")
        }));
    }

    let plan = analyze(&[
        "ssh",
        "-p2222",
        "-i",
        "key",
        "user@host",
        "rm",
        "-rf",
        "/data",
    ]);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "network.connect"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint { host, port: Some(2222), .. }
            } if host == "host")
    }));
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.realm, ExecutionRealm::Remote { endpoint } if endpoint == "host:2222")
    }));

    let no_command = analyze(&["ssh", "-fN", "host", "rm", "-rf", "/data"]);
    assert!(!boundary(&no_command, "unrecognized_arguments"));
    assert!(
        !no_command
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
}

#[test]
fn ssh_records_jump_and_stdio_forward_connections() {
    let plan = analyze(&[
        "ssh",
        "-J",
        "user@bastion:2200",
        "host",
        "rm",
        "-rf",
        "/data",
    ]);
    let endpoints = plan
        .effects
        .iter()
        .filter_map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::NetworkEndpoint {
                        host, port, scheme, ..
                    },
            } if effect.operation.0 == "network.connect" => {
                Some((host.as_str(), *port, scheme.as_deref()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(endpoints.contains(&("host", None, Some("ssh"))));
    assert!(endpoints.contains(&("bastion", Some(2200), Some("ssh"))));

    let plan = analyze(&["ssh", "-W", "db:5432", "bastion"]);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "network.connect"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint { host, port: Some(5432), scheme, .. }
            } if host == "db" && scheme.is_none())
    }));
    assert!(
        !plan
            .execution_graph
            .nodes
            .iter()
            .any(|node| matches!(node.subject, Subject::Shell { .. }))
    );
}

#[test]
fn ssh_destination_forms_choose_the_effective_host_and_port() {
    for argv in [
        &["ssh", "ssh://user@host:2222", "rm", "-rf", "/data"][..],
        &[
            "ssh", "-l", "user", "-p", "2222", "host", "rm", "-rf", "/data",
        ],
        &["ssh", "-p", "2200", "ssh://host:2222", "rm", "-rf", "/data"],
    ] {
        let plan = analyze(argv);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "network.connect"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, port: Some(2222), .. }
                } if host == "host")
        }));
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(&effect.realm, ExecutionRealm::Remote { endpoint } if endpoint == "host:2222")
        }));
    }

    let plan = analyze(&["ssh", "ssh://host", "rm", "-rf", "/data"]);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "network.connect"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint { host, port: None, .. }
            } if host == "host")
    }));
}

#[test]
fn ssh_raw_ipv6_destination_does_not_treat_the_final_hextet_as_a_port() {
    let plan = analyze(&["ssh", "user@2001:db8::1234", "-s", "sftp"]);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "network.connect"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint { host, port, .. }
            } if host == "2001:db8::1234" && port.is_none())
    }));
    assert!(boundary(&plan, "remote_command"));
    assert!(plan.execution_graph.nodes.iter().any(|node| {
        matches!(&node.realm, ExecutionRealm::Remote { endpoint }
            if endpoint.ends_with("2001:db8::1234"))
    }));
}

#[test]
fn ssh_bracketed_ipv6_destination_preserves_explicit_port() {
    for destination in ["user@[2001:db8::1]:2222", "ssh://user@[2001:db8::1]:2222"] {
        let plan = analyze(&["ssh", destination, "ls"]);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "network.connect"
                && matches!(&effect.resource, ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, port, .. }
                } if host == "[2001:db8::1]" && *port == Some(2222))
        }));
        assert!(plan.execution_graph.nodes.iter().any(|node| {
            matches!(&node.realm, ExecutionRealm::Remote { endpoint }
                if endpoint == "[2001:db8::1]:2222")
        }));
    }
}

#[test]
fn ssh_remote_source_preserves_argument_joining() {
    let split = analyze(&["ssh", "host", "sh", "-c", "rm -rf /x"]);
    assert!(
        !split
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );

    let quoted = analyze(&["ssh", "host", "sh -c 'rm -rf /x'"]);
    assert!(quoted.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.realm, ExecutionRealm::Remote { endpoint } if endpoint == "host")
    }));

    let subsystem = analyze(&["ssh", "host", "-s", "sftp"]);
    assert!(boundary(&subsystem, "remote_command"));
    assert!(
        !subsystem
            .execution_graph
            .nodes
            .iter()
            .any(|node| matches!(node.subject, Subject::Shell { .. }))
    );
}

#[test]
fn ssh_proxycommand_runs_locally_alongside_the_remote_command() {
    let plan = analyze(&[
        "ssh",
        "-voProxyCommand=rm -rf /",
        "host",
        "rm",
        "-rf",
        "/data",
    ]);
    let deletes = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .collect::<Vec<_>>();
    assert_eq!(deletes.len(), 2);
    assert!(deletes.iter().any(|effect| effect.realm.is_host()));
    assert!(deletes.iter().any(
        |effect| matches!(&effect.realm, ExecutionRealm::Remote { endpoint } if endpoint == "host")
    ));

    let substituted = analyze(&[
        "ssh",
        "-o",
        "ProxyCommand=ssh -W %h:%p bastion",
        "host",
        "rm",
        "-rf",
        "/data",
    ]);
    assert!(substituted.execution_graph.nodes.iter().any(|node| {
        matches!(&node.subject, Subject::Exec { argv, .. }
            if argv.first().map(String::as_str) == Some("ssh")
                && argv.iter().any(|argument| argument == "host:22"))
            && node.realm.is_host()
    }));

    let none = analyze(&["ssh", "-oProxyCommand=none", "host"]);
    assert!(
        !none
            .execution_graph
            .nodes
            .iter()
            .any(|node| matches!(node.subject, Subject::Shell { .. }))
    );
}

#[test]
fn kubectl_exec_nests_pod_command() {
    let plan = analyze(&["kubectl", "exec", "mypod", "--", "rm", "/tmp/x"]);
    let connections: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "network.connect")
        .collect();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].realm, ExecutionRealm::Host);
    assert!(
        matches!(&connections[0].resource, ResourceExpr::Unresolved { family } if family.0 == "network")
    );
    for server_flag in ["--server", "-s"] {
        let explicit = analyze(&[
            "kubectl",
            server_flag,
            "https://api.example:6443",
            "exec",
            "mypod",
            "--",
            "rm",
            "/tmp/x",
        ]);
        let connections: Vec<_> = explicit
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.connect")
            .collect();
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].realm, ExecutionRealm::Host);
        assert!(
            matches!(&connections[0].resource, ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host, port: Some(6443), .. } } if host == "api.example")
        );
    }

    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.delete")
    );
}

#[test]
fn kubectl_exec_legacy_form_nests_pod_commands() {
    for argv in [
        &["kubectl", "exec", "pod", "ls"][..],
        &["kubectl", "exec", "-it", "pod", "bash"][..],
    ] {
        let plan = analyze(argv);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "process.exec"
                && matches!(
                    &effect.realm,
                    ExecutionRealm::Kubernetes { pod, .. } if pod == "pod"
                )
        }));
    }

    let plan = analyze(&["kubectl", "exec", "pod", "ls"]);
    assert!(!boundary(&plan, "unrecoverable_source"));

    let plan = analyze(&["kubectl", "exec", "pod", "rm", "-rf", "/data"]);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.realm,
                ExecutionRealm::Kubernetes { pod, .. } if pod == "pod"
            )
    }));
    assert!(!boundary(&plan, "unrecoverable_source"));
}

#[test]
fn kubectl_exec_legacy_form_rejects_ambiguous_commands() {
    for argv in [
        &["kubectl", "exec", "pod", "ls", "-la"][..],
        &["kubectl", "exec", "pod"][..],
    ] {
        let plan = analyze(argv);
        assert!(boundary(&plan, "unrecoverable_source"));
        assert!(
            !plan
                .execution_graph
                .nodes
                .iter()
                .any(|node| matches!(node.realm, ExecutionRealm::Kubernetes { .. }))
        );
    }
}

#[test]
fn kubectl_unknown_global_option_fails_closed() {
    let plan = analyze(&[
        "kubectl",
        "--unknown-global",
        "exec",
        "pod",
        "--",
        "rm",
        "/data",
    ]);
    assert!(boundary(&plan, "unrecognized_arguments"));
    assert!(!boundary(&plan, "cluster_api"));
    assert!(
        !plan
            .execution_graph
            .nodes
            .iter()
            .any(|node| matches!(node.realm, ExecutionRealm::Kubernetes { .. }))
    );
    assert!(!has_op_on(&plan, "filesystem.delete", "/data"));
}

#[test]
fn kubectl_non_exec_is_cluster_api() {
    let help = analyze(&["kubectl", "--help"]);
    assert!(
        !help
            .effects
            .iter()
            .any(|effect| effect.operation.domain() == "network")
    );
    let explicit = analyze(&[
        "kubectl",
        "--server",
        "https://api.example:6443",
        "get",
        "pods",
    ]);
    assert!(has_op_on(&explicit, "network.request", "api.example"));
    assert!(!ops(&explicit).contains(&"network.connect"));

    let plan = analyze(&["kubectl", "get", "pods"]);
    assert!(boundary(&plan, "cluster_api"));

    let plan = analyze(&["kubectl", "-n", "ns", "delete", "ns", "prod"]);
    assert!(boundary(&plan, "cluster_api"));
    assert!(!boundary(&plan, "unrecognized_arguments"));
}

#[test]
fn deterministic() {
    let a = effinterp_proto::canonical_json(&analyze(&["sudo", "docker", "exec", "c", "rm", "/x"]));
    let b = effinterp_proto::canonical_json(&analyze(&["sudo", "docker", "exec", "c", "rm", "/x"]));
    assert_eq!(a, b);

    let subject = Subject::Shell {
        source: "ssh -J bastion -o ProxyCommand='nc %h %p' user@host \"cd /srv && rm -rf data\""
            .to_string(),
        cwd: Some("/w".to_string()),
        context: Default::default(),
    };
    let engine = Engine::new();
    let a_plan = engine.analyze(&subject).unwrap();
    let b_plan = engine.analyze(&subject).unwrap();
    validate_plan(&a_plan).unwrap();
    validate_plan(&b_plan).unwrap();
    let a = effinterp_proto::canonical_json(&a_plan);
    let b = effinterp_proto::canonical_json(&b_plan);
    assert_eq!(a, b);
}

#[test]
fn wrapped_symbolic_command_stays_honest() {
    // The symbolic script reaches the sink but is not re-parsed as recovered source.
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "sudo sh -c \"rm -rf $DIR\"".to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert_eq!(code_attribute(&plan, "source"), Some("argument"));
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.delete")
    );
    assert!(boundary(&plan, "unrecoverable_source"));
}

#[test]
fn shell_model_emits_code_execution_for_argument_file_and_stdin() {
    for (argv, source) in [
        (&["bash", "-c", "echo ok"][..], "argument"),
        (&["bash", "-co", "pipefail", "echo ok"][..], "argument"),
        (&["bash", "script.sh"][..], "file"),
        (&["bash", "-", "script.sh"][..], "file"),
        (&["bash", "-s", "+s", "script.sh"][..], "file"),
        (&["bash", "-s", "--", "argument"][..], "stdin"),
        (&["bash", "-euo", "pipefail"][..], "stdin"),
        (&["bash", "-n", "+n"][..], "stdin"),
    ] {
        let plan = analyze(argv);
        assert_eq!(code_attribute(&plan, "source"), Some(source), "{argv:?}");
    }
    assert!(code_effect(&analyze(&["bash", "-n"])).is_none());
    assert!(code_effect(&analyze(&["bash", "-euo", "noexec"])).is_none());
    assert!(code_effect(&analyze(&["bash", "-n", "-c", "echo skipped"])).is_none());
    assert!(code_effect(&analyze(&["bash", "--dump-strings"])).is_none());
    assert!(code_effect(&analyze(&["bash", "--dump-po-strings"])).is_none());
    assert!(code_effect(&analyze(&["bash", "--pretty-print"])).is_none());
}

#[test]
fn plain_shell_and_node_file_selectors_have_exact_request_assurance() {
    for argv in [
        &["bash", "script.sh"][..],
        &["sh", "--", "script.sh", "arg"][..],
        &["bash", "script.sh", "-n", "--init-file", "ignored"][..],
        &["node", "app.js"][..],
        &["node", "--", "app.js", "arg"][..],
        &["node", "app.js", "--check", "--require", "ignored.js"][..],
        &["node", "--", "--check", "--env-file", ".env"][..],
    ] {
        let plan = analyze(argv);
        let effect = code_effect(&plan).unwrap();
        assert_eq!(code_attribute(&plan, "source"), Some("file"), "{argv:?}");
        assert_eq!(
            effect.request_assurance,
            RequestAssurance::Exact,
            "{argv:?}"
        );
    }
}

#[test]
fn unaudited_shell_and_node_file_selectors_stay_conservative() {
    for argv in [
        &["dash", "script.sh"][..],
        &["zsh", "script.sh"][..],
        &["bash", "", "arg"][..],
        &["bash", "-", "script.sh"][..],
        &["bash", "--init-file", "startup.sh", "script.sh"][..],
        &["bash", "--rcfile", "startup.sh", "script.sh"][..],
        &["bash", "--future-option", "script.sh"][..],
        &["nodejs", "app.js"][..],
        &["node", "", "arg"][..],
        &["node", "--env-file", ".env", "app.js"][..],
        &["node", "--require", "preload.js", "app.js"][..],
        &["node", "--test", "app.js"][..],
    ] {
        let plan = analyze(argv);
        let effects = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "process.code_execution")
            .collect::<Vec<_>>();
        assert!(
            effects.iter().any(|effect| {
                effect.attributes.get("source")
                    == Some(&effinterp_proto::AttrValue::String("file".into()))
            }),
            "{argv:?}"
        );
        assert!(
            effects
                .iter()
                .all(|effect| effect.request_assurance == RequestAssurance::Conservative),
            "{argv:?}"
        );
    }

    for source in [
        "bash \"$SCRIPT\"",
        "node \"$SCRIPT\"",
        "if c; then SCRIPT=one.js; else SCRIPT=two.js; fi; node \"$SCRIPT\"",
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.to_string(),
                cwd: Some("/w".to_string()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        let effects = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "process.code_execution")
            .collect::<Vec<_>>();
        assert!(!effects.is_empty(), "{source}");
        assert!(
            effects
                .iter()
                .all(|effect| effect.request_assurance == RequestAssurance::Conservative),
            "{source}"
        );
    }
}

#[test]
fn inline_source_flags_require_an_argument() {
    for argv in [
        &["bash", "-c"][..],
        &["python3", "-c"][..],
        &["node", "-e"][..],
        &["node", "--eval="][..],
        &["node", "--print="][..],
        &["ruby", "-e"][..],
        &["php", "-r"][..],
    ] {
        assert!(code_effect(&analyze(argv)).is_none(), "{argv:?}");
    }
}

#[test]
fn node_print_without_an_argument_reads_stdin_code() {
    for option in ["-p", "--print"] {
        let plan = analyze(&["node", option]);
        assert_eq!(code_attribute(&plan, "source"), Some("stdin"), "{option}");
    }
}

#[test]
fn interpreter_value_options_require_an_argument() {
    for argv in [
        &["node", "--allow-fs-read"][..],
        &["node", "--allow-fs-write"][..],
        &["node", "--input-type"][..],
        &["node", "--icu-data-dir"][..],
        &["node", "--inspect-port"][..],
        &["node", "--debug-port"][..],
        &["node", "--max-http-header-size"][..],
        &["node", "--cpu-prof-dir"][..],
        &["node", "--cpu-prof-interval"][..],
        &["node", "--cpu-prof-name"][..],
        &["node", "--diagnostic-dir"][..],
        &["node", "--disable-proto"][..],
        &["node", "--disable-warning"][..],
        &["node", "--dns-result-order"][..],
        &["node", "--env-file"][..],
        &["node", "--env-file-if-exists"][..],
        &["node", "--experimental-test-isolation"][..],
        &["node", "--experimental-test-tag-filter"][..],
        &["node", "--openssl-config"][..],
        &["node", "--inspect-publish-uid"][..],
        &["node", "--localstorage-file"][..],
        &["node", "--max-old-space-size-percentage"][..],
        &["node", "--network-family-autoselection-attempt-timeout"][..],
        &["node", "--redirect-warnings"][..],
        &["node", "--report-dir"][..],
        &["node", "--report-directory"][..],
        &["node", "--report-filename"][..],
        &["node", "--report-signal"][..],
        &["node", "--secure-heap"][..],
        &["node", "--secure-heap-min"][..],
        &["node", "--snapshot-blob"][..],
        &["node", "--test-concurrency"][..],
        &["node", "--test-coverage-branches"][..],
        &["node", "--test-coverage-exclude"][..],
        &["node", "--test-coverage-functions"][..],
        &["node", "--test-coverage-include"][..],
        &["node", "--test-coverage-lines"][..],
        &["node", "--test-global-setup"][..],
        &["node", "--test-isolation"][..],
        &["node", "--test-name-pattern"][..],
        &["node", "--test-random-seed"][..],
        &["node", "--test-reporter"][..],
        &["node", "--test-reporter-destination"][..],
        &["node", "--test-rerun-failures"][..],
        &["node", "--test-shard"][..],
        &["node", "--test-skip-pattern"][..],
        &["node", "--test-timeout"][..],
        &["node", "--tls-cipher-list"][..],
        &["node", "--tls-keylog"][..],
        &["node", "--title"][..],
        &["node", "--trace-event-categories"][..],
        &["node", "--trace-event-file-pattern"][..],
        &["node", "--trace-require-module"][..],
        &["node", "--unhandled-rejections"][..],
        &["node", "--use-largepages"][..],
        &["node", "--v8-pool-size"][..],
        &["node", "--heap-prof-dir"][..],
        &["node", "--heap-prof-interval"][..],
        &["node", "--heap-prof-name"][..],
        &["node", "--heapsnapshot-near-heap-limit"][..],
        &["node", "--heapsnapshot-signal"][..],
        &["node", "--watch-kill-signal"][..],
        &["node", "--watch-path"][..],
        &["perl", "-e"][..],
        &["perl", "-E"][..],
        &["bash", "--init-file"][..],
        &["ruby", "-C"][..],
        &["python3", "-m"][..],
        &["python2", "-Q"][..],
        &["php", "-f"][..],
        &["php", "-R"][..],
        &["php", "-F"][..],
        &["php", "--php-ini"][..],
        &["php", "--define"][..],
        &["php", "--docroot"][..],
        &["php", "--zend-extension"][..],
        &["pwsh", "-ExecutionPolicy"][..],
        &["pwsh", "-ConfigurationFile"][..],
        &["pwsh", "-ConfigurationName"][..],
        &["pwsh", "-CustomPipeName"][..],
        &["powershell", "-OutputFormat"][..],
        &["pwsh", "-OutputFormat"][..],
        &["pwsh", "-SettingsFile"][..],
        &["pwsh", "-WindowStyle"][..],
        &["pwsh", "-WorkingDirectory"][..],
    ] {
        assert!(code_effect(&analyze(argv)).is_none(), "{argv:?}");
    }
}

#[test]
fn interpreter_end_of_options_allows_dashed_script_paths() {
    for (argv, script) in [
        (&["python3", "--", "-c"][..], "/w/-c"),
        (&["node", "--", "--check"][..], "/w/--check"),
        (&["ruby", "--", "-c"][..], "/w/-c"),
        (&["php", "--", "-l"][..], "/w/-l"),
    ] {
        let plan = analyze(argv);
        assert_eq!(code_attribute(&plan, "source"), Some("file"), "{argv:?}");
        assert!(has_op_on(&plan, "filesystem.read", script), "{argv:?}");
    }
    // `-c` takes the command string after the delimiter, not the delimiter.
    for argv in [
        &["sh", "-c", "--", "rm -rf /x"][..],
        &["bash", "-ec", "--", "rm -rf /x"][..],
    ] {
        let plan = analyze(argv);
        assert!(has_op_on(&plan, "filesystem.delete", "/x"), "{argv:?}");
        assert!(!has_op_on(&plan, "process.exec", "--"), "{argv:?}");
    }
}

#[test]
fn interpreter_end_of_options_preserves_explicit_stdin() {
    for argv in [&["python3", "--", "-"][..], &["node", "--", "-"][..]] {
        let plan = analyze(argv);
        assert_eq!(code_attribute(&plan, "source"), Some("stdin"), "{argv:?}");
        assert!(!ops(&plan).contains(&"filesystem.read"), "{argv:?}");
    }
}

#[test]
fn node_test_mode_treats_dash_as_a_file() {
    for argv in [
        &["node", "--test", "-"][..],
        &["node", "--test", "--", "-"][..],
    ] {
        let plan = analyze(argv);
        assert_eq!(code_attribute(&plan, "source"), Some("file"), "{argv:?}");
        assert!(has_op_on(&plan, "filesystem.read", "/w/-"), "{argv:?}");
    }
}

#[test]
fn node_inspect_port_consumes_its_value_before_inline_source() {
    let plan = analyze(&[
        "node",
        "--inspect-port",
        "9999",
        "-e",
        "require('fs').readFileSync('/tmp/payload')",
    ]);
    assert_eq!(code_attribute(&plan, "source"), Some("argument"));
    assert!(has_op_on(&plan, "filesystem.read", "/tmp/payload"));
    assert!(!has_op_on(&plan, "filesystem.read", "/w/9999"));
}

#[test]
fn unknown_node_option_stops_script_recovery() {
    let plan = analyze(&["node", "--future-option", "payload.js"]);
    assert!(boundary(&plan, "unrecognized_arguments"));
    assert!(code_effect(&plan).is_none());
    assert!(!has_op_on(&plan, "filesystem.read", "/w/payload.js"));
}

#[test]
fn shell_noexec_script_is_a_valid_filesystem_read() {
    let plan = analyze(&["bash", "-n", "script.sh"]);
    assert!(has_op_on(&plan, "filesystem.read", "/w/script.sh"));
    assert!(code_effect(&plan).is_none());
}

#[test]
fn declarative_interpreters_emit_typed_code_sinks() {
    for interpreter in ["perl", "powershell", "pwsh"] {
        let plan = analyze(&[interpreter]);
        assert_eq!(code_attribute(&plan, "source"), Some("stdin"));
        let effect = code_effect(&plan).unwrap();
        assert!(matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::Process {
                    executable,
                    path: None,
                    argv,
                    cwd: Some(cwd),
                },
            } if executable == interpreter
                && argv.is_empty()
                && matches!(
                    cwd.as_ref(),
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } if path == "/w"
                )
        ));
        let dynamic = plan
            .boundaries
            .iter()
            .find(|boundary| boundary.reason.as_str() == "dynamic_source")
            .unwrap();
        assert_eq!(dynamic.class, BoundaryClass::Unresolved);
        assert_eq!(
            dynamic
                .domains
                .iter()
                .map(|domain| domain.0.as_str())
                .collect::<Vec<_>>(),
            vec!["environment", "filesystem", "network", "process"]
        );
        assert!(
            dynamic
                .detail
                .as_ref()
                .is_some_and(|detail| !detail.is_empty())
        );
    }

    let perl = analyze(&["perl", "-e", "print 1"]);
    assert_eq!(code_attribute(&perl, "source"), Some("argument"));
    let perl = analyze(&["perl", "-E", "say 1"]);
    assert_eq!(code_attribute(&perl, "source"), Some("argument"));
    let perl = analyze(&["perl", "-pe", "s/x/y/"]);
    assert_eq!(code_attribute(&perl, "source"), Some("argument"));
    let perl = analyze(&["perl", "-ne", "print"]);
    assert_eq!(code_attribute(&perl, "source"), Some("argument"));
    let perl = analyze(&["perl", "-Mstrict"]);
    assert_eq!(code_attribute(&perl, "source"), Some("stdin"));
    let perl = analyze(&["perl", "-f"]);
    assert_eq!(code_attribute(&perl, "source"), Some("stdin"));
    let perl = analyze(&["perl", "-l"]);
    assert_eq!(code_attribute(&perl, "source"), Some("stdin"));
    let perl = analyze(&["perl", "-0"]);
    assert_eq!(code_attribute(&perl, "source"), Some("stdin"));
    let perl = analyze(&["perl", "-0777"]);
    assert_eq!(code_attribute(&perl, "source"), Some("stdin"));
    let perl = analyze(&["perl", "-C"]);
    assert_eq!(code_attribute(&perl, "source"), Some("stdin"));
    let perl = analyze(&["perl", "-s"]);
    assert_eq!(code_attribute(&perl, "source"), Some("stdin"));
    let perl = analyze(&["perl", "-W"]);
    assert_eq!(code_attribute(&perl, "source"), Some("stdin"));
    let perl = analyze(&["perl", "-U"]);
    assert_eq!(code_attribute(&perl, "source"), Some("stdin"));
    let perl = analyze(&["perl", "-a"]);
    assert_eq!(code_attribute(&perl, "source"), Some("stdin"));
    for option in ["-n", "-p"] {
        let perl = analyze(&["perl", option]);
        assert_eq!(code_attribute(&perl, "source"), Some("stdin"), "{option}");
    }

    for (interpreter, script) in [
        ("perl", "script.pl"),
        ("powershell", "script.ps1"),
        ("pwsh", "script.ps1"),
    ] {
        let plan = analyze(&[interpreter, script]);
        assert_eq!(code_attribute(&plan, "source"), Some("file"));
        assert!(ops(&plan).contains(&"filesystem.read"));
        assert!(boundary(&plan, "dynamic_source"));
    }

    let powershell = analyze(&["powershell", "-File", "script.ps1"]);
    assert_eq!(code_attribute(&powershell, "source"), Some("file"));

    for interpreter in ["powershell", "pwsh"] {
        let stdin = analyze(&[interpreter, "-File", "-"]);
        assert_eq!(code_attribute(&stdin, "source"), Some("stdin"));
        assert!(!ops(&stdin).contains(&"filesystem.read"));

        let stdin = analyze(&[interpreter, "-ExecutionPolicy", "Bypass", "-Command", "-"]);
        assert_eq!(code_attribute(&stdin, "source"), Some("stdin"));
        assert!(!ops(&stdin).contains(&"filesystem.read"));

        let stdin = analyze(&[interpreter, "-OutputFormat", "Text", "-Command", "-"]);
        assert_eq!(code_attribute(&stdin, "source"), Some("stdin"));
        assert!(!ops(&stdin).contains(&"filesystem.read"));

        let stdin = analyze(&[interpreter, "-NoProfile", "-Command", "-"]);
        assert_eq!(code_attribute(&stdin, "source"), Some("stdin"));
        assert!(!ops(&stdin).contains(&"filesystem.read"));

        let stdin = analyze(&[interpreter, "-WorkingDirectory", "/tmp", "-Command", "-"]);
        assert_eq!(code_attribute(&stdin, "source"), Some("stdin"));
        assert!(!ops(&stdin).contains(&"filesystem.read"));

        let stdin = analyze(&[interpreter, "-WindowStyle", "Hidden", "-Command", "-"]);
        assert_eq!(code_attribute(&stdin, "source"), Some("stdin"));
        assert!(!ops(&stdin).contains(&"filesystem.read"));
    }

    let encoded = analyze(&["pwsh", "-EncodedCommand", "cABy"]);
    assert_eq!(code_attribute(&encoded, "source"), Some("argument"));
    assert_eq!(code_attribute(&encoded, "encoding"), Some("base64"));

    let encoded = analyze(&["pwsh", "-encodedcommand", "cABy"]);
    assert_eq!(code_attribute(&encoded, "source"), Some("argument"));
    assert_eq!(code_attribute(&encoded, "encoding"), Some("base64"));

    // Any prefix of -EncodedCommand and the -ec alias select it, and the
    // interpreter name resolves in any case (`.exe` is platform-gated by
    // `program_name`, so a POSIX cwd here exercises the case fold only).
    for (interpreter, flag) in [
        ("powershell", "-e"),
        ("powershell", "-EC"),
        ("pwsh", "-enc"),
        ("POWERSHELL", "-EncodedCommand"),
        ("PoWeRsHeLl", "-encodedcomman"),
        ("PWSH", "-Enc"),
    ] {
        let encoded = analyze(&[interpreter, flag, "cABy"]);
        assert_eq!(
            code_attribute(&encoded, "encoding"),
            Some("base64"),
            "{interpreter} {flag}"
        );
        assert!(
            !boundary(&encoded, "unrecognized_arguments"),
            "{interpreter} {flag}"
        );
    }
    assert!(
        analyze(&["powershell.com", "-enc", "cABy"])
            .effects
            .iter()
            .all(|effect| effect.operation.0 != "process.code_execution")
    );

    // Other interpreter families fold the same way by case; a `.exe` spelling
    // is platform-gated by `program_name`, so a POSIX cwd here exercises the
    // case fold only. Any other program keeps its exact name.
    for argv in [
        &["NODE", "-e", "require('fs').rmSync('/tmp/doomed')"][..],
        &["DENO", "eval", "Deno.removeSync('/tmp/doomed')"],
        &["PYTHON3.11", "-c", "import os; os.remove('/tmp/doomed')"],
        &["R", "-e", "unlink('/tmp/doomed')"],
        &["BASH", "-c", "rm /tmp/doomed"],
    ] {
        assert!(
            has_op_on(&analyze(argv), "filesystem.delete", "/tmp/doomed"),
            "{argv:?}"
        );
    }
    assert!(has_op_on(
        &analyze(&["mkfs.ext4", "/dev/sdz"]),
        "filesystem.write",
        "/dev/sdz"
    ));
    for argv in [
        &["RM", "/tmp/doomed"][..],
        &["rm.exe", "/tmp/doomed"],
        &["MKFS.EXT4", "/dev/sdz"],
    ] {
        assert!(boundary(&analyze(argv), "unmodeled_command"), "{argv:?}");
    }

    let file = analyze(&["pwsh", "-file", "script.ps1"]);
    assert_eq!(code_attribute(&file, "source"), Some("file"));
}

#[test]
fn node_attached_value_and_boolean_flags_keep_inline_source() {
    let source = "require('fs').rmSync('/tmp/x', {recursive: true})";
    for flag in [
        "--input-type=module",
        "--input-type=commonjs",
        "--import=./x.mjs",
        "--env-file=.env",
        "--experimental-default-type=module",
        "--experimental-vm-modules",
        "--experimental-strip-types",
        "--no-warnings",
        "--enable-source-maps",
        "--trace-warnings",
    ] {
        let plan = analyze(&["node", flag, "-e", source]);
        assert_eq!(code_attribute(&plan, "source"), Some("argument"), "{flag}");
        assert!(plan.effects.iter().any(|effect| effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/tmp/x")), "{flag}");
        assert!(!boundary(&plan, "unrecognized_arguments"), "{flag}");
    }
    let unknown = analyze(&["node", "--bogus-flag", "-e", source]);
    assert!(boundary(&unknown, "unrecognized_arguments"));
    assert!(!ops(&unknown).contains(&"filesystem.delete"));
}

#[test]
fn bash_startup_unknown_and_explicit_absence_are_distinct() {
    for (source, expected) in [
        ("bash -c true", true),
        ("bash -s <<EOF\ntrue\nEOF", true),
        ("BASH_ENV='' bash -c true", false),
        ("env -u BASH_ENV bash -c true", false),
        ("env -u BASH_ENV bash -lc true", true),
        ("env -i bash -c true", false),
        ("bash -p -c true", false),
        ("bash -o \"$OPTION\" -c true", true),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        effinterp_proto::validate_plan(&plan).unwrap();
        let startup = plan.execution_graph.nodes.iter().any(|node| {
            node.input.as_ref().is_some_and(|input| {
                input.phase == effinterp_proto::ExecutionPhase::Startup && node.boundary.is_some()
            })
        });
        assert_eq!(startup, expected, "{source}");
        if source == "env -u BASH_ENV bash -lc true" {
            let inputs: Vec<_> = plan
                .execution_graph
                .nodes
                .iter()
                .filter_map(|node| node.input.as_ref())
                .filter(|input| input.phase == effinterp_proto::ExecutionPhase::Startup)
                .collect();
            assert!(!inputs.is_empty());
            assert!(inputs.iter().all(|input| matches!(
                &input.selector,
                effinterp_proto::ExecutionSelector::Convention { .. }
            )));
        }
    }
}

#[test]
fn bash_shellopts_preserves_known_startup_selection() {
    for shellopts in ["", "xtrace", "errexit:xtrace", "posix"] {
        let plan = Engine::new()
            .analyze(&Subject::Exec {
                argv: vec!["bash".into(), "-c".into(), "true".into()],
                cwd: None,
                context: effinterp_proto::HostContext {
                    env: [
                        ("BASH_ENV".into(), "/rc.sh".into()),
                        ("SHELLOPTS".into(), shellopts.into()),
                    ]
                    .into(),
                    ..Default::default()
                },
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(plan.execution_graph.nodes.iter().any(|node| {
            node.input.as_ref().is_some_and(|input| {
                matches!(&input.selector, effinterp_proto::ExecutionSelector::Environment { variable } if variable == "BASH_ENV")
                    && matches!(&input.selection, effinterp_proto::ExecutionSelection::Direct { request } if request == "/rc.sh")
            })
        }), "{shellopts}");
        let mode_gap = plan.execution_graph.nodes.iter().any(|node| {
            node.input.as_ref().is_some_and(|input| {
                matches!(
                    &input.selector,
                    effinterp_proto::ExecutionSelector::Convention { .. }
                ) && input.phase == effinterp_proto::ExecutionPhase::Startup
            })
        });
        assert_eq!(mode_gap, shellopts == "posix", "{shellopts}");
    }
}

#[test]
fn go_import_paths_do_not_invent_local_package_reads() {
    for verb in ["build", "install", "test", "vet", "fmt", "generate"] {
        for package in [
            "golang.org/x/tools/cmd/goimports",
            "github.com/foo/bar",
            "fmt",
        ] {
            let plan = analyze(&["go", verb, package]);
            assert!(
                !plan.effects.iter().any(|effect| {
                    effect.operation.0.starts_with("filesystem.")
                        && render(&effect.resource) == format!("/w/{package}")
                        && (effect.operation.0 == "filesystem.read" || verb == "fmt")
                }),
                "{verb} {package}: {:?}",
                plan.effects
            );
            assert!(plan.boundaries.iter().any(|boundary| {
                boundary.reason.as_str() == "dynamic_source"
                    && boundary.class == BoundaryClass::Unresolved
                    && boundary.domains == vec![Domain::new("filesystem"), Domain::new("network")]
            }));
            for domain in ["filesystem", "network"] {
                assert_eq!(
                    plan.coverage.0[&Domain::new(domain)].level,
                    CoverageLevel::Partial
                );
            }
        }
        for (package, path) in [
            (".", "/w"),
            ("./cmd/bd", "/w/cmd/bd"),
            ("../bd", "/bd"),
            ("/src/bd", "/src/bd"),
            ("main.go", "/w/main.go"),
        ] {
            let plan = analyze(&["go", verb, package]);
            assert!(
                has_op_on(&plan, "filesystem.read", path),
                "{verb} {package}"
            );
            assert_eq!(
                plan.coverage.0[&Domain::new("filesystem")].level,
                CoverageLevel::Full
            );
        }
    }
    let plan = analyze(&["go", "version", "bd"]);
    assert!(has_op_on(&plan, "filesystem.read", "/w/bd"));
    assert!(plan.boundaries.is_empty());
}

#[test]
fn go_verbs_report_effects_without_inventing_build_hooks() {
    for (argv, expected) in [
        (
            vec!["go", "build", "-o=bd", "./cmd/bd"],
            vec![("filesystem.write", "/w/bd")],
        ),
        (
            vec![
                "go",
                "build",
                "-o",
                "bd",
                "-tags=netgo",
                "-ldflags",
                "-s -w",
                "./cmd/bd",
            ],
            vec![("filesystem.read", "cmd/bd"), ("filesystem.write", "/w/bd")],
        ),
        (
            vec!["go", "install", "./cmd/bd"],
            vec![("filesystem.write", "bin"), ("filesystem.write", "pkg")],
        ),
        (
            vec![
                "go",
                "test",
                "./...",
                "-short",
                "-coverprofile=coverage.out",
                "-o",
                "tests",
            ],
            vec![
                ("process.code_execution", "go"),
                ("filesystem.write", "/w/coverage.out"),
                ("filesystem.write", "/w/tests"),
            ],
        ),
        (
            vec!["go", "env", "-w", "GOFLAGS=-tags=netgo"],
            vec![("filesystem.write", "go/env")],
        ),
        (
            vec!["go", "mod", "tidy"],
            vec![
                ("network.download", "network"),
                ("filesystem.write", "pkg/mod"),
                ("filesystem.write", "/w/go.mod"),
                ("filesystem.write", "/w/go.sum"),
            ],
        ),
        (
            vec!["go", "mod", "vendor"],
            vec![("filesystem.write", "/w/vendor")],
        ),
        (
            vec!["go", "build", "-mod=mod", "."],
            vec![("network.download", "network")],
        ),
        (
            vec!["go", "generate", "./..."],
            vec![("process.exec", "?process")],
        ),
        (
            vec!["go", "tool", "compile", "main.go"],
            vec![("process.exec", "?process")],
        ),
    ] {
        let plan = analyze(&argv);
        for (operation, resource) in expected {
            assert!(
                has_op_on(&plan, operation, resource),
                "{argv:?}: {operation} {resource}: {:?}",
                plan.effects
            );
        }
        assert!(!boundary(&plan, "unmodeled_command"), "{argv:?}");
        assert!(
            !plan.execution_graph.nodes.iter().any(|node| node
                .input
                .as_ref()
                .is_some_and(|input| input.phase == effinterp_proto::ExecutionPhase::BuildHook)),
            "{argv:?}"
        );
        if argv[1] == "generate" {
            assert_eq!(plan.boundaries.len(), 1);
            assert_eq!(plan.boundaries[0].reason.as_str(), "dynamic_source");
            assert_eq!(plan.boundaries[0].domains, vec![Domain::new("process")]);
        } else {
            assert!(
                plan.boundaries.is_empty(),
                "{argv:?}: {:?}",
                plan.boundaries
            );
            for domain in ["filesystem", "network", "process"] {
                assert_eq!(
                    plan.coverage.0[&Domain::new(domain)].level,
                    CoverageLevel::Full
                );
            }
        }
    }
    for verb in ["vet", "version", "fmt"] {
        let plan = analyze(&["go", verb]);
        assert!(ops(&plan).contains(&"filesystem.read"));
        assert_eq!(ops(&plan).contains(&"filesystem.write"), verb == "fmt");
        assert!(plan.boundaries.is_empty());
    }
    let plan = analyze(&["go", "version", "./bd"]);
    assert!(has_op_on(&plan, "filesystem.read", "/w/bd"));
    let plan = analyze(&["go", "fmt", "./..."]);
    assert!(has_op_on(&plan, "filesystem.write", "/w/..."));
    for package in ["./cmd/bd", "golang.org/x/tools/cmd/goimports@latest"] {
        let plan = analyze(&["go", "install", package]);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.write"
                    && render(&effect.resource).starts_with("/w/"))
        );
        assert_eq!(
            ops(&plan).contains(&"network.download"),
            package.contains('@')
        );
        if package.contains('@') {
            assert!(!has_op_on(&plan, "filesystem.read", package));
            assert!(!has_op_on(&plan, "filesystem.write", "@latest"));
        }
    }
    let plan = analyze(&["go", "install", "-o", "bd", "./cmd/bd"]);
    assert!(!has_op_on(&plan, "filesystem.write", "/w/bd"));
    assert!(!plan.boundaries.is_empty());
}

#[test]
fn environment_listing_native_context_is_open_or_proven_finite() {
    use effinterp_proto::{HostContext, ResourcePattern};
    for argv in [vec!["env"], vec!["printenv", "-0"]] {
        for context in [
            HostContext::default(),
            HostContext {
                env: std::collections::BTreeMap::from([("TOKEN".into(), "private-value".into())]),
                ..Default::default()
            },
        ] {
            let plan = Engine::new()
                .with_causality_detail(true)
                .analyze(&Subject::Exec {
                    argv: argv.iter().map(|s| s.to_string()).collect(),
                    cwd: None,
                    context,
                })
                .unwrap();
            validate_plan(&plan).unwrap();
            assert!(
                plan.effects
                    .iter()
                    .any(|effect| effect.operation.0 == "environment.read"
                        && effect.resource
                            == ResourceExpr::Pattern {
                                pattern: ResourcePattern::EnvironmentVariable {
                                    name_glob: "*".into()
                                }
                            })
            );
            let graph = plan.causality.graph.as_ref().unwrap();
            assert!(graph.edges.iter().any(|edge| {
                graph.nodes.iter().any(|node| node.id == edge.from && matches!(&node.occurrence, effinterp_proto::OccurrenceKind::ResourceInteraction { operation, .. } if operation.0 == "environment.read"))
                    && graph.nodes.iter().any(|node| node.id == edge.to && matches!(&node.occurrence, effinterp_proto::OccurrenceKind::Port { port: effinterp_proto::Port::Stdout }))
            }));
            assert!(plan.effects.iter().all(|effect| {
                !format!("{:?}{:?}", effect.attributes, effect.resource).contains("private-value")
            }));
        }
    }
    for argv in [
        vec!["env", "-i"],
        vec!["env", "-i", "printenv"],
        vec!["env", "-i", "printenv", "MISSING"],
    ] {
        assert!(!ops(&analyze(&argv)).contains(&"environment.read"));
    }
    let cleared = Engine::new()
        .analyze(&Subject::Exec {
            argv: ["env", "-i", "A=safe", "printenv", "TOKEN", "A"]
                .map(str::to_string)
                .to_vec(),
            cwd: None,
            context: HostContext {
                env: [("TOKEN".into(), "private-value".into())].into(),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&cleared).unwrap();
    assert_eq!(
        cleared
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "environment.read")
            .map(|effect| &effect.resource)
            .collect::<Vec<_>>(),
        vec![&ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name: "A".into() }
        }]
    );
    let names = analyze(&["printenv", "--", "A", "B", "-p"]);
    assert_eq!(
        names
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "environment.read")
            .count(),
        3
    );
    for argv in [
        vec!["env", "--unsupported"],
        vec!["printenv", "--unsupported"],
    ] {
        let plan = analyze(&argv);
        assert!(!plan.boundaries.is_empty());
        assert!(!ops(&plan).contains(&"environment.read"));
    }
    for options in [vec!["-v"], vec!["--debug"], vec!["-i", "-v"]] {
        let mut argv = vec!["env"];
        argv.extend(options);
        argv.extend(["-C", "/tmp", "curl", "-T", "payload", "https://x.example"]);
        let plan = analyze(&argv);
        assert!(boundary(&plan, "unrecognized_arguments"));
        assert!(has_op_on(&plan, "process.exec", "curl"));
        assert!(has_op_on(&plan, "filesystem.read", "/tmp/payload"));
        assert!(has_op_on(&plan, "network.upload", "x.example"));
        assert!(!ops(&plan).contains(&"environment.read"));
    }
    let plan = analyze(&["env", "-i", "-v", "A=safe", "-u", "A", "printenv"]);
    assert!(boundary(&plan, "unrecognized_arguments"));
    assert!(has_op_on(&plan, "process.exec", "printenv"));
    assert!(!ops(&plan).contains(&"environment.read"));
}

#[test]
fn developer_wrappers_forward_flags_and_environment_without_extra_processes() {
    let plan = analyze(&[
        "cross-env",
        "NODE_ENV=production",
        "OTHER=two",
        "tsc",
        "--noEmit",
        "-p",
        ".",
    ]);
    assert!(has_op_on(&plan, "filesystem.read", "/w"));
    assert!(!ops(&plan).contains(&"filesystem.write"));
    assert_eq!(
        plan.effects
            .iter()
            .filter(|e| e.operation.0 == "environment.write")
            .count(),
        2
    );
    assert!(!plan.effects.iter().any(|e| e.operation.0 == "process.exec" && matches!(&e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::Process { executable, .. }} if executable == "env")));
    assert!(!boundary(&plan, "unmodeled_command"));
    let plan = analyze(&["s6-setuidgid", "nobody", "gofmt", "-w", "main.go"]);
    assert!(has_op_on(&plan, "filesystem.write", "/w/main.go"));
    assert!(!boundary(&plan, "unrecognized_arguments"));
}
