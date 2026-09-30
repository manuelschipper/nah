use effinterp_engine::{Catalog, Engine};
use effinterp_proto::{
    AttrValue, CoverageLevel, Domain, ExecutionAssurance, ExecutionEdgeKind, ExecutionRealm,
    OsDialect, Plan, RequestAssurance, ResourceExpr, ResourceIdentity, Subject, validate_plan,
};

fn analyze(argv: &[&str]) -> Plan {
    analyze_subject(Subject::Exec {
        argv: argv.iter().map(|value| value.to_string()).collect(),
        cwd: Some("/w".to_string()),
        context: Default::default(),
    })
}

fn analyze_shell(source: &str) -> Plan {
    analyze_subject(Subject::Shell {
        source: source.to_string(),
        cwd: Some("/w".to_string()),
        context: Default::default(),
    })
}

fn analyze_subject(subject: Subject) -> Plan {
    let plan = Engine::new().analyze(&subject).unwrap();
    validate_plan(&plan).unwrap();
    let repeated = Engine::new().analyze(&subject).unwrap();
    validate_plan(&repeated).unwrap();
    assert_eq!(
        effinterp_proto::canonical_json(&plan),
        effinterp_proto::canonical_json(&repeated)
    );
    plan
}

fn has_op_on(plan: &Plan, operation: &str, needle: &str) -> bool {
    plan.effects
        .iter()
        .any(|effect| effect.operation.0 == operation && render(&effect.resource).contains(needle))
}

fn render(resource: &ResourceExpr) -> String {
    match resource {
        ResourceExpr::Concrete { identity } => match identity {
            ResourceIdentity::FsPath { path } => path.clone(),
            ResourceIdentity::Process { executable, .. } => executable.clone(),
            ResourceIdentity::NetworkEndpoint { host, .. } => host.clone(),
            _ => format!("{identity:?}"),
        },
        resource => format!("{resource:?}"),
    }
}

fn boundary(plan: &Plan, reason: &str) -> bool {
    plan.boundaries
        .iter()
        .any(|boundary| boundary.reason.as_str() == reason)
}

fn assert_wrapped_delete(plan: &Plan) {
    let deletes = plan
        .effects
        .iter()
        .filter(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    } if path == "/x"
                )
        })
        .collect::<Vec<_>>();
    assert_eq!(deletes.len(), 1);
    assert_eq!(
        deletes[0].attributes.get("force"),
        Some(&AttrValue::Bool(true))
    );
    assert_eq!(
        deletes[0].attributes.get("recursive"),
        Some(&AttrValue::Bool(true))
    );
    assert!(has_op_on(plan, "process.exec", "rm"));
    assert!(!boundary(plan, "unmodeled_command"));
    for domain in ["filesystem", "process"] {
        assert_eq!(
            plan.coverage
                .0
                .get(&Domain::new(domain))
                .map(|claim| &claim.level),
            Some(&CoverageLevel::Full)
        );
    }
}

#[test]
fn wrappers_expose_the_commands_they_run() {
    for argv in [
        &["su", "-c", "rm -rf /x", "root"][..],
        &["su", "root", "-c", "rm -rf /x"][..],
        &["su", "-", "root", "-c", "rm -rf /x"][..],
        &["su", "--session-command=rm -rf /x"][..],
        &["runuser", "-u", "www", "--", "rm", "-rf", "/x"][..],
        &["runuser", "www", "-c", "rm -rf /x"][..],
        &["runuser", "www", "sudo", "-u", "root", "rm", "-rf", "/x"][..],
        &["sshpass", "-p", "x", "ssh", "host", "rm", "-rf", "/x"][..],
        &["watch", "-n1", "rm", "-rf", "/x"][..],
        &["watch", "-x", "rm", "-rf", "/x"][..],
        &["watch", "-xn1", "rm", "-rf", "/x"][..],
        &["watch", "rm -rf /x; ls"][..],
        &["script", "-c", "rm -rf /x", "/dev/null"][..],
        &["script", "-qec", "rm -rf /x", "/dev/null"][..],
        &["flock", "/tmp/lock", "rm", "-rf", "/x"][..],
        &["flock", "-n", "/tmp/lock", "-c", "rm -rf /x"][..],
        &["systemd-run", "--scope", "rm", "-rf", "/x"][..],
        &[
            "systemd-run",
            "--unit=probe",
            "-p",
            "MemoryMax=1G",
            "rm",
            "-rf",
            "/x",
        ][..],
        &["nsenter", "-t", "1", "-n", "--", "rm", "-rf", "/x"][..],
        &["unshare", "-m", "rm", "-rf", "/x"][..],
        &["unshare", "--mount-proc", "rm", "-rf", "/x"][..],
        &["setsid", "--fork", "rm", "-rf", "/x"][..],
        &["ltrace", "rm", "-rf", "/x"][..],
        &["ltrace", "-f", "--", "rm", "-rf", "/x"][..],
        &["chrt", "--fifo", "1", "rm", "-rf", "/x"][..],
        &["ionice", "--class", "3", "rm", "-rf", "/x"][..],
        &["taskset", "--cpu-list", "0", "rm", "-rf", "/x"][..],
        &["strace", "-q", "rm", "-rf", "/x"][..],
        &["prlimit", "--nofile=1024:2048", "--", "rm", "-rf", "/x"][..],
        &["dbus-run-session", "--", "rm", "-rf", "/x"][..],
        &["eatmydata", "rm", "-rf", "/x"][..],
        &["pkexec", "rm", "-rf", "/x"][..],
        &["firejail", "rm", "-rf", "/x"][..],
        &["proot", "rm", "-rf", "/x"][..],
        &["sg", "users", "-c", "rm -rf /x"][..],
        &["sg", "-", "users", "rm -rf /x"][..],
        &["screen", "-dm", "rm", "-rf", "/x"][..],
        &["screen", "-dmS", "probe", "rm", "-rf", "/x"][..],
        &[
            "parallel",
            "--halt",
            "soon,fail=1",
            "rm -rf {}",
            ":::",
            "/x",
        ][..],
        &[
            "parallel",
            "-j4",
            "-k",
            "--will-cite",
            "rm",
            "-rf",
            ":::",
            "/x",
        ][..],
        &["parallel", "rm -rf {//}", ":::", "/x/y.tar"][..],
        &["parallel", "rm -rf /{/.}", ":::", "dir/x.tar"][..],
        &["parallel", ":::", "rm -rf /x"][..],
        &[
            "env", "-u", "X", "exec", "nice", "-n", "5", "rm", "-rf", "/x",
        ][..],
    ] {
        assert_wrapped_delete(&analyze(argv));
    }
    assert_wrapped_delete(&analyze_shell("printf '/x\\n' | parallel rm -rf"));

    // Each input is shell-quoted into the template, so it stays one operand.
    let quoted = analyze(&["parallel", "rm -rf {}", ":::", "/x y", "/it's"]);
    let deletes = quoted
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .map(|effect| render(&effect.resource))
        .collect::<Vec<_>>();
    assert_eq!(deletes, ["/x y", "/it's"]);

    let password_file = analyze(&["sshpass", "-f", "/run/pw", "ssh", "host", "true"]);
    assert!(has_op_on(&password_file, "filesystem.read", "/run/pw"));

    for plan in [
        analyze(&["sshpass", "-p", "x", "ssh", "host", "rm", "-rf", "/x"]),
        password_file,
    ] {
        assert!(has_op_on(&plan, "network.connect", "host"));
    }
}

#[test]
fn transparent_wrappers_preserve_argv_and_nested_execution_context() {
    let plan = analyze_shell("FOO=bar setsid --fork ltrace -f rm -rf 'relative path'");
    let rm = plan
        .execution_graph
        .nodes
        .iter()
        .find(|node| {
            matches!(&node.subject, Subject::Exec { argv, .. }
                if argv.first().map(String::as_str) == Some("rm"))
        })
        .unwrap();
    assert!(matches!(&rm.subject, Subject::Exec { argv, cwd, .. }
        if argv == &["rm", "-rf", "relative path"] && cwd.as_deref() == Some("/w")));
    assert!(rm.environment.contains_key("FOO"));
    assert_eq!(rm.realm, ExecutionRealm::Host);
    assert_eq!(rm.assurance, ExecutionAssurance::Exact);
    assert!(!rm.evidence.is_empty());
    assert!(plan.execution_graph.edges.iter().any(|edge| {
        edge.kind == ExecutionEdgeKind::ToolModel
            && !edge.evidence.is_empty()
            && plan.execution_graph.nodes[edge.to.0 as usize] == *rm
    }));
    let delete = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    assert_eq!(render(&delete.resource), "/w/relative path");
    assert_eq!(delete.realm, ExecutionRealm::Host);
    assert_eq!(delete.request_assurance, RequestAssurance::Exact);
    assert!(!delete.provenance.is_empty());
}

#[test]
fn transparent_wrappers_do_not_guess_past_rejected_or_nonexecuting_options() {
    for argv in [
        &["ltrace", "--unknown", "rm", "-rf", "/x"][..],
        &["ltrace", "-u", "root", "rm", "-rf", "/x"][..],
    ] {
        let plan = analyze(argv);
        assert!(boundary(&plan, "unrecognized_arguments"), "{argv:?}");
        assert!(!has_op_on(&plan, "filesystem.delete", "/x"), "{argv:?}");
        assert_eq!(plan.execution_graph.nodes.len(), 1, "{argv:?}");
    }

    for argv in [
        &["ltrace", "--help", "rm", "-rf", "/x"][..],
        &["ltrace", "--version", "rm", "-rf", "/x"][..],
    ] {
        let plan = analyze(argv);
        assert!(!boundary(&plan, "unrecognized_arguments"), "{argv:?}");
        assert!(!has_op_on(&plan, "filesystem.delete", "/x"), "{argv:?}");
        assert_eq!(plan.execution_graph.nodes.len(), 1, "{argv:?}");
    }

    for argv in [
        &["stdbuf", "-o", "rm", "-rf", "/x"][..],
        &["timeout", "--signal", "5", "rm", "-rf", "/x"][..],
    ] {
        let plan = analyze(argv);
        assert!(!has_op_on(&plan, "filesystem.delete", "/x"), "{argv:?}");
        assert!(
            plan.execution_graph.nodes.iter().all(|node| {
                !matches!(&node.subject, Subject::Exec { argv, .. }
                if argv.first().map(String::as_str) == Some("rm"))
            }),
            "{argv:?}"
        );
    }

    // Sandbox options remap what the command sees, and these screen and
    // prlimit options act on a running session or process instead.
    for argv in [
        &["firejail", "--private", "rm", "-rf", "/x"][..],
        &["proot", "-r", "/srv/root", "rm", "-rf", "/x"][..],
        &["screen", "-d", "rm", "-rf", "/x"][..],
        &["screen", "-X", "stuff", "rm -rf /x"][..],
        &["prlimit", "--pid", "1", "rm", "-rf", "/x"][..],
        &["sg", "users", "rm", "-rf /x"][..],
    ] {
        let plan = analyze(argv);
        assert!(boundary(&plan, "unrecognized_arguments"), "{argv:?}");
        assert!(!has_op_on(&plan, "filesystem.delete", "/x"), "{argv:?}");
        assert_eq!(plan.execution_graph.nodes.len(), 1, "{argv:?}");
    }

    // A busybox applet is that command, so its argv reaches the applet's
    // model: the option that model rejects stops it before any deletion.
    let applet = analyze(&["busybox", "rm", "--one-file-system", "-rf", "relative"]);
    assert!(!has_op_on(&applet, "filesystem.delete", "/w/relative"));
    assert!(boundary(&applet, "unrecognized_arguments"));
    assert_eq!(applet.execution_graph.nodes.len(), 2);

    for source in [
        "parallel --help rm -rf /x",
        "parallel --version",
        "parallel --citation",
        "parallel -S host 'rm -rf {}' ::: /x",
        "parallel --pipe rm -rf /x",
        "parallel \"$CMD\" ::: /x",
        "parallel 'rm -rf {%}' ::: /x",
        "parallel 'rm -rf {}' ::: \"$DIR\"",
        "parallel 'rm -rf {}' :::: list",
        "parallel rm -rf",
        "env exec -c rm -rf /x",
    ] {
        let plan = analyze_shell(source);
        assert!(!has_op_on(&plan, "filesystem.delete", "/x"), "{source}");
        assert!(
            plan.execution_graph.nodes.iter().all(|node| {
                !matches!(&node.subject, Subject::Exec { argv, .. }
                if argv.first().map(String::as_str) == Some("rm"))
            }),
            "{source}"
        );
        // Only the options that exit before any job runs leave nothing open.
        assert_eq!(
            plan.boundaries.is_empty(),
            source.contains("--help")
                || source.contains("--version")
                || source.contains("--citation"),
            "{source}"
        );
    }

    let missing_value = analyze(&["timeout", "--signal"]);
    assert!(!has_op_on(&missing_value, "filesystem.delete", "/x"));
    assert_eq!(missing_value.execution_graph.nodes.len(), 1);
}

#[test]
fn wrapper_environment_and_cwd_reach_the_inner_command() {
    let systemd = analyze(&[
        "systemd-run",
        "-E",
        "FOO=1",
        "--working-directory=/srv",
        "rm",
        "-rf",
        "data",
    ]);
    assert!(has_op_on(&systemd, "filesystem.delete", "/srv/data"));
    assert!(systemd.execution_graph.nodes.iter().any(|node| {
        node.environment.contains_key("FOO")
            && matches!(&node.subject, Subject::Exec { argv, cwd, .. }
                if argv.first().map(String::as_str) == Some("rm")
                    && cwd.as_deref() == Some("/srv"))
    }));

    let unshare = analyze(&["unshare", "--wd=/srv", "rm", "-rf", "data"]);
    assert!(has_op_on(&unshare, "filesystem.delete", "/srv/data"));

    // pkexec runs in the target user's home unless told to keep the cwd.
    let pkexec = analyze(&["pkexec", "rm", "-rf", "data"]);
    assert!(has_op_on(&pkexec, "filesystem.delete", "/root/data"));
    assert!(!has_op_on(&pkexec, "filesystem.delete", "/w/data"));
    let kept = analyze(&["pkexec", "--keep-cwd", "rm", "-rf", "data"]);
    assert!(has_op_on(&kept, "filesystem.delete", "/w/data"));
    let other_user = analyze(&["pkexec", "--user", "www", "rm", "-rf", "data"]);
    assert!(!has_op_on(&other_user, "filesystem.delete", "/w/data"));
    assert!(!has_op_on(&other_user, "filesystem.delete", "/root/data"));
}

#[test]
fn script_runs_operands_after_the_file_only_where_the_host_does() {
    let on = |os_dialect, argv: &[&str]| {
        analyze_subject(Subject::Exec {
            argv: argv.iter().map(|value| value.to_string()).collect(),
            cwd: Some("/w".to_string()),
            context: effinterp_proto::HostContext {
                os_dialect,
                ..Default::default()
            },
        })
    };
    let process_full = |plan: &Plan| {
        plan.coverage
            .0
            .get(&Domain::new("process"))
            .is_some_and(|claim| claim.level == CoverageLevel::Full)
    };
    // BSD script launches the words after the file; `-t` takes a value.
    for argv in [
        &["script", "-q", "/dev/null", "rm", "-rf", "/x"][..],
        &["script", "-t", "0", "/dev/null", "rm", "-rf", "/x"][..],
        &["script", "-qt0", "out.log", "rm", "-rf", "/x"][..],
    ] {
        let plan = on(OsDialect::Macos, argv);
        assert!(has_op_on(&plan, "filesystem.delete", "/x"), "{argv:?}");
        assert!(!boundary(&plan, "unrecognized_arguments"), "{argv:?}");
    }
    // Playback reads the file and runs nothing.
    let playback = on(
        OsDialect::Macos,
        &["script", "-p", "rec", "rm", "-rf", "/x"],
    );
    assert!(has_op_on(&playback, "filesystem.read", "/w/rec"));
    assert!(!has_op_on(&playback, "filesystem.delete", "/x"));
    assert!(!process_full(&playback));
    // util-linux rejects a second operand; an unknown host takes both readings.
    let linux = on(
        OsDialect::Linux,
        &["script", "-q", "/dev/null", "rm", "-rf", "/x"],
    );
    assert!(boundary(&linux, "unrecognized_arguments"));
    assert!(!has_op_on(&linux, "filesystem.delete", "/x"));
    assert!(!process_full(&linux));
    let unknown = analyze(&["script", "-q", "/dev/null", "rm", "-rf", "/x"]);
    assert!(boundary(&unknown, "unrecognized_arguments"));
    assert!(has_op_on(&unknown, "filesystem.delete", "/x"));
    // util-linux runs the words after `--` as a shell command.
    for plan in [
        on(
            OsDialect::Linux,
            &["script", "-q", "/dev/null", "--", "rm", "-rf", "/x"],
        ),
        analyze(&["script", "--", "rm", "-rf", "/x"]),
        // `-I` takes the first `--` as its log file.
        on(
            OsDialect::Linux,
            &["script", "-I", "--", "--", "rm", "-rf", "/x"],
        ),
    ] {
        assert!(has_op_on(&plan, "filesystem.delete", "/x"));
        assert!(!has_op_on(&plan, "filesystem.write", "/w/rm"));
        assert!(!boundary(&plan, "unrecognized_arguments"));
    }
    let both = on(
        OsDialect::Linux,
        &["script", "-c", "true", "/dev/null", "--", "rm", "-rf", "/x"],
    );
    assert!(boundary(&both, "unrecognized_arguments"));
}

#[test]
fn wrappers_report_their_own_files() {
    let script = analyze(&["script", "-c", "rm -rf /x", "out.log"]);
    assert!(has_op_on(&script, "filesystem.write", "/w/out.log"));

    let script = analyze(&["script"]);
    assert!(has_op_on(&script, "filesystem.write", "/w/typescript"));
    assert_eq!(script.execution_graph.nodes.len(), 1);

    let flock = analyze(&["flock", "/tmp/lock", "cmd"]);
    assert!(has_op_on(&flock, "filesystem.write", "/tmp/lock"));

    let fd = analyze(&["flock", "9"]);
    assert!(
        !fd.effects
            .iter()
            .any(|effect| effect.operation.0.starts_with("filesystem."))
    );
}

#[test]
fn shell_source_wrappers_distinguish_recoverable_and_opaque_source() {
    for source in [r#"su -c "$(cat cmd)" root"#, r#"watch "$(cat cmd)""#] {
        let plan = analyze_shell(source);
        assert!(boundary(&plan, "unrecoverable_source"));
        assert!(!has_op_on(&plan, "filesystem.delete", "/x"));
    }

    for argv in [
        &["su", "root"][..],
        &["script"][..],
        &["systemd-run", "--shell"][..],
    ] {
        let plan = analyze(argv);
        assert_eq!(plan.execution_graph.nodes.len(), 1);
        assert!(!boundary(&plan, "unrecoverable_source"));
    }

    let symbolic = analyze_shell("su root -c 'rm -rf $DIR'");
    assert!(has_op_on(&symbolic, "filesystem.delete", "DIR"));
}

#[test]
fn wrapper_unknown_flags_degrade_without_hiding_the_command() {
    let plan = analyze(&["su", "--future", "-c", "rm -rf /x", "root"]);
    assert!(boundary(&plan, "unrecognized_arguments"));
    assert!(has_op_on(&plan, "filesystem.delete", "/x"));
}

#[test]
fn shell_source_wrappers_emit_code_execution() {
    for argv in [
        &["su", "-c", "rm -rf /x", "root"][..],
        &["watch", "rm -rf /x"][..],
    ] {
        assert!(
            analyze(argv)
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "process.code_execution")
        );
    }
}

#[test]
fn wrapper_command_names_have_the_expected_model_owners() {
    let catalog = Catalog::builtin();
    for (name, model) in [
        ("su", "util-linux/su@v0"),
        ("runuser", "util-linux/runuser@v0"),
        ("sshpass", "sshpass/sshpass@v0"),
        ("watch", "procps/watch@v0"),
        ("script", "util-linux/script@v0"),
        ("flock", "util-linux/flock@v0"),
        ("systemd-run", "systemd/systemd-run@v0"),
        ("nsenter", "util-linux/nsenter@v0"),
        ("unshare", "util-linux/unshare@v0"),
        ("setsid", "util-linux/setsid@v0"),
        ("ltrace", "ltrace/ltrace@v0"),
        ("prlimit", "util-linux/prlimit@v0"),
        ("dbus-run-session", "dbus/dbus-run-session@v0"),
        ("eatmydata", "libeatmydata/eatmydata@v0"),
        ("pkexec", "polkit/pkexec@v0"),
        ("firejail", "firejail/firejail@v0"),
        ("proot", "proot/proot@v0"),
        ("sg", "shadow/sg@v0"),
        ("screen", "gnu/screen@v0"),
    ] {
        assert_eq!(catalog.find(name).map(|owner| owner.id()), Some(model));
    }
}
