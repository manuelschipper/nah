use effinterp_engine::{Engine, default_limits};
use effinterp_proto::{Plan, ResourceExpr, ResourceIdentity, Subject, validate_plan};

fn subject(argv: &[&str]) -> Subject {
    Subject::Exec {
        argv: argv.iter().map(|word| (*word).into()).collect(),
        cwd: Some("/work".into()),
        context: effinterp_proto::HostContext {
            env: [("HOME".into(), "/home/test".into())].into(),
            ..Default::default()
        },
    }
}

fn perl(argv: &[&str]) -> Plan {
    let plan = Engine::new().analyze(&subject(argv)).unwrap();
    validate_plan(&plan).unwrap();
    plan
}

fn paths(plan: &Plan) -> Vec<(&str, &str)> {
    plan.effects
        .iter()
        .filter_map(|effect| {
            if !effect.operation.0.starts_with("filesystem.") {
                return None;
            }
            match &effect.resource {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } => Some((effect.operation.0.as_str(), path.as_str())),
                _ => None,
            }
        })
        .collect()
}

#[test]
fn literal_launchers_reach_filesystem_effects() {
    for (argv, expected) in [
        (
            vec![
                "perl",
                "-pi",
                "-e",
                "s/off/on/",
                "/home/test/.nah/trust.json",
            ],
            vec![
                ("filesystem.read", "/home/test/.nah/trust.json"),
                ("filesystem.write", "/home/test/.nah/trust.json"),
            ],
        ),
        (
            vec!["perl", "-e", r#"unlink "$ENV{HOME}/.local/bin/nah""#],
            vec![("filesystem.delete", "/home/test/.local/bin/nah")],
        ),
        (
            vec![
                "perl",
                "-MFile::Copy",
                "-e",
                r#"copy("/tmp/replacement", "$ENV{HOME}/.nah/trust.json")"#,
            ],
            vec![
                ("filesystem.read", "/tmp/replacement"),
                ("filesystem.write", "/home/test/.nah/trust.json"),
            ],
        ),
        (
            vec![
                "perl",
                "-MFcntl=:DEFAULT",
                "-e",
                r#"sysopen(my $fh, "$ENV{HOME}/.nah/trust.json", O_WRONLY|O_CREAT)"#,
            ],
            vec![("filesystem.write", "/home/test/.nah/trust.json")],
        ),
        (
            vec!["perl5.38.2", r#"-weunlink "/home/test/.nah/trust.json""#],
            vec![("filesystem.delete", "/home/test/.nah/trust.json")],
        ),
        (
            vec![
                "perl",
                "-e",
                r#"unlink "\x{2f}home\x{2f}test\x{2f}.nah\x{2f}trust.json""#,
            ],
            vec![("filesystem.delete", "/home/test/.nah/trust.json")],
        ),
        (
            vec![
                "/usr/bin/perl5.38.2",
                "-w",
                "-Eunlink '\\x2ftmp'",
                "--",
                "-ignored",
            ],
            vec![("filesystem.delete", "/work/\\x2ftmp")],
        ),
        (
            vec!["perl5.36", "-e", "unlink '/tmp/a'"],
            vec![("filesystem.delete", "/tmp/a")],
        ),
        (
            vec!["perl", "-e", "my $p = '/tmp/a';", "-eunlink $p"],
            vec![("filesystem.delete", "/tmp/a")],
        ),
        (
            vec!["perl", "-mFile::Copy", "-e", "File::Copy::move('/a', '/b')"],
            vec![
                ("filesystem.read", "/a"),
                ("filesystem.move", "/a"),
                ("filesystem.delete", "/a"),
                ("filesystem.write", "/b"),
            ],
        ),
    ] {
        let plan = perl(&argv);
        assert_eq!(paths(&plan), expected, "{argv:?}: {:?}", plan.boundaries);
    }
}

#[test]
fn filesystem_modes_bindings_and_operand_selection() {
    let copy = Engine::new()
        .with_causality_detail(true)
        .analyze(&subject(&[
            "perl",
            "-MFile::Copy",
            "-e",
            "copy('/tmp/replacement', '/tmp/destination')",
        ]))
        .unwrap();
    validate_plan(&copy).unwrap();
    let read = copy
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.read")
        .unwrap();
    let write = copy
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.write")
        .unwrap();
    assert_eq!(
        read.attributes.get("access_purpose"),
        Some(&effinterp_proto::AttrValue::String("program_input".into()))
    );
    assert_eq!(
        write.attributes.get("disclosure"),
        Some(&effinterp_proto::AttrValue::String("contents".into()))
    );
    assert!(
        copy.causality
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

    let plan = perl(&[
        "perl",
        "-MFcntl",
        "-e",
        r#"
        my $path = 'data'; open(my $fh, '<', $path);
        open(my $out, '>>', '/out'); open(my $two, '>/two'); sysopen(my $rw, '/rw', O_RDWR|O_CREAT, 0600);
        rename('/old', '/new'); mkdir('/dir', 0700); rmdir('/empty'); chmod(0600, '/mode');
        unlink "\x2ftmp/\$literal", 'can\'t', 'a\\b', "\xc3\xa9"; # unlink '/comment'
    "#,
    ]);
    assert!(plan.boundaries.is_empty(), "{:?}", plan.boundaries);
    for expected in [
        ("filesystem.read", "/work/data"),
        ("filesystem.write", "/out"),
        ("filesystem.write", "/two"),
        ("filesystem.read", "/rw"),
        ("filesystem.write", "/rw"),
        ("filesystem.delete", "/old"),
        ("filesystem.write", "/new"),
        ("filesystem.create", "/dir"),
        ("filesystem.delete", "/empty"),
        ("filesystem.metadata", "/mode"),
        ("filesystem.delete", "/tmp/$literal"),
        ("filesystem.delete", "/work/can't"),
        ("filesystem.delete", "/work/a\\b"),
        ("filesystem.delete", "/work/é"),
    ] {
        assert!(
            paths(&plan).contains(&expected),
            "{expected:?}: {:?}",
            paths(&plan)
        );
    }
    for flags in ["-ni.bak", "-pi.bak"] {
        let plan = perl(&["perl", flags, "-e", "s/a/b/", "--", "-dash", "/second"]);
        for path in ["/work/-dash", "/second"] {
            assert!(paths(&plan).contains(&("filesystem.read", path)));
            assert!(paths(&plan).contains(&("filesystem.write", path)));
        }
        assert!(paths(&plan).contains(&("filesystem.write", "/second.bak")));
    }
    let plan = perl(&["perl", "-n", "-e", "unlink '/literal'", "/input"]);
    assert!(paths(&plan).contains(&("filesystem.read", "/input")));
    assert!(!paths(&plan).contains(&("filesystem.write", "/input")));
}

#[test]
fn unsupported_source_never_invents_filesystem_calls() {
    for source in [
        "#!/usr/bin/perl -c\nunlink '/never';",
        "unlink $runtime",
        "unlink '/never'; sub unlink {}",
        "print q(unlink '/never')",
        "unlink('/a' . $runtime)",
        "__DATA__\nunlink '/never'",
        "copy('/a', '/b')",
        "sysopen(my $fh, '/never', O_WRONLY)",
        "open(my $fh, '|-', '/never')",
        "open(my $fh, '<&STDIN')",
        "open(my $fh, '>cmd|')",
        "open(my $fh, '>', '-')",
        r#"unlink "$ENV{MISSING}/never""#,
        r#"unlink "$path/never""#,
        r#"unlink "@paths""#,
        "my unlink '/never'",
        "chmod(099, '/never')",
        "unlink '\\'",
        "unlink \"\\x{110000}\"",
        "unlink \"\\N{SLASH}never\"",
        "unlink ('/a', '/b'",
        "unlink '/never'; use subs 'unlink'",
        "sub system { } system('rm -rf /never')",
        "use File::Path; remove_tree('/never')",
        "remove_tree('/never')",
        "sub f { f() } f()",
        // Nothing after a refused statement is compiled: it may end the
        // program or change the environment, the cwd or a sub.
        "exit 0; unlink '/never'",
        "die 'stop'; unlink '/never'",
        "$ENV{HOME} = '/tmp'; unlink \"$ENV{HOME}/never\"",
        "chdir '/etc'; unlink 'never'",
        "sub cleanup { unlink '/never' } *cleanup = sub {}; cleanup()",
        "my $d = '/never'; eval '$d = q!/tmp/out!'; unlink $d",
        // Word lists are data, and unlexed source may hold compile-time code.
        "print qw(a; unlink '/never'; b)",
        "unlink '/never'; print q(x); BEGIN { exit 0 }",
        "unlink '/never'; print qw(\\(); BEGIN { exit 0 } # )",
        "unlink '/never'; print \"@{[ do { BEGIN { exit 0 } 1 } ]}\"",
        // A later argument that cannot be established may prevent the call.
        "unlink('/never', die 'stop')",
        "unlink '/never', exit 0",
        "chmod 0644, '/never', $runtime",
        "use File::Path; rmtree('/never', $runtime)",
        // Output continues only with plain arguments: these rebind or call.
        "my $d = '/never'; print $d++; unlink $d",
        "my $d = '/never'; print \"@{[ $d = '/tmp/out' ]}\"; unlink $d",
        "my $d = '/never'; printf '%n', $d; unlink $d",
        "sub stop { exit 0 } my $f = 'stop'; print $f->(); unlink '/never'",
    ] {
        let plan = perl(&["perl", "-e", source]);
        assert!(paths(&plan).is_empty(), "{source}: {:?}", paths(&plan));
        assert_eq!(plan.boundaries.len(), 1, "{source}: {:?}", plan.boundaries);
        assert!(
            plan.boundaries[0]
                .detail
                .as_ref()
                .is_some_and(|s| s.contains("Perl"))
        );
    }
    for argv in [
        vec!["perl", "-mFile::Copy", "-e", "copy('/a', '/b')"],
        vec!["perl", "-MOther", "-e", "unlink '/never'"],
        vec!["perl", "-M", "File::Copy", "-e", "copy('/a', '/b')"],
        vec!["perl", "-m", "File::Copy", "-e", "copy('/a', '/b')"],
        vec!["perl", "-MFile::Copy=move", "-e", "copy('/a', '/b')"],
        vec!["perl", "-z", "-e", "unlink '/never'"],
        vec!["perl", "-e"],
        vec!["perl-not-perl", "-e", "unlink '/never'"],
        vec!["perl5.38.2evil", "-e", "unlink '/never'"],
        vec!["perl5..2", "-e", "unlink '/never'"],
        vec!["perl", "-n", "-e", "", "rm /never|"],
    ] {
        let plan = perl(&argv);
        assert!(paths(&plan).is_empty(), "{argv:?}: {:?}", paths(&plan));
        assert!(!plan.boundaries.is_empty(), "{argv:?}");
    }
}

#[test]
fn refused_statements_keep_the_effects_around_them() {
    for (argv, expected, bounded) in [
        (
            vec![
                "perl",
                "-MFile::Path=remove_tree",
                "-e",
                r#"remove_tree("/etc") or die "failed: $!""#,
            ],
            vec![("filesystem.delete", "/etc")],
            true,
        ),
        (
            vec![
                "perl",
                "-e",
                r#"open(my $fh, ">>", "/etc/sudoers") || die; print $fh "x\n"; close $fh"#,
            ],
            vec![("filesystem.write", "/etc/sudoers")],
            true,
        ),
        (
            vec![
                "perl",
                "-e",
                r#"system("rm", "-rf", $ENV{HOME}) == 0 or die"#,
            ],
            vec![("filesystem.delete", "/home/test")],
            true,
        ),
        (
            vec![
                "perl",
                "-e",
                r#"open(F, ">>/etc/sudoers"); truncate("/etc/shadow", 0)"#,
            ],
            vec![
                ("filesystem.write", "/etc/sudoers"),
                ("filesystem.write", "/etc/shadow"),
            ],
            false,
        ),
        // A refused call publishes nothing, but earlier statements stand.
        (
            vec!["perl", "-e", "unlink '/a'; unlink('/never', die 'stop')"],
            vec![("filesystem.delete", "/a")],
            true,
        ),
        // Lexing stops at a pattern; statements completed before it stand.
        (
            vec!["perl", "-e", "unlink '/a'; print /x;/; unlink '/never'"],
            vec![("filesystem.delete", "/a")],
            true,
        ),
        (
            vec![
                "perl",
                "-e",
                "my $fh = '/never'; open(my $fh, '<', '/input'); unlink $fh",
            ],
            vec![("filesystem.read", "/input")],
            true,
        ),
        // Output changes no later fact, so compilation continues past it.
        (
            vec!["perl", "-e", "my $d = '/a'; print 'x'; unlink $d"],
            vec![("filesystem.delete", "/a")],
            true,
        ),
        (
            vec!["perl", "-e", "my $d = '/a'; $d = '/b' if $c; unlink $d"],
            vec![],
            true,
        ),
        (
            vec!["perl", "-e", "my $f = sub { unlink '/never' }; $f->()"],
            vec![],
            true,
        ),
        // Left-associative chains group last; `xor` runs both operands.
        (
            vec!["perl", "-e", r#"0 // 1 || unlink("/etc/passwd")"#],
            vec![("filesystem.delete", "/etc/passwd")],
            false,
        ),
        (
            vec!["perl", "-e", r#"1 or 0 xor unlink "/etc/passwd""#],
            vec![("filesystem.delete", "/etc/passwd")],
            false,
        ),
        (
            vec!["perl", "-e", r#"1 xor 0; unlink "/etc/passwd""#],
            vec![("filesystem.delete", "/etc/passwd")],
            false,
        ),
        // A constant operand decides whether the other one runs.
        (
            vec![
                "perl",
                "-e",
                "unlink '/never' if 0; 1 or unlink '/never'; unlink '/a' unless ''; \
                 1 or unlink('/never') or unlink('/never'); \
                 0 and unlink('/never') and unlink('/never'); \
                 1 xor 0 or unlink '/never'; unlink '/never' if 1 xor 1",
            ],
            vec![("filesystem.delete", "/a")],
            false,
        ),
    ] {
        let plan = perl(&argv);
        assert_eq!(paths(&plan), expected, "{argv:?}");
        assert_eq!(
            !plan.boundaries.is_empty(),
            bounded,
            "{argv:?}: {:?}",
            plan.boundaries
        );
    }
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "perl - <<'PL'\nunlink \"/etc/passwd\";\nPL".into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert_eq!(paths(&plan), [("filesystem.delete", "/etc/passwd")]);
    assert!(plan.boundaries.is_empty(), "{:?}", plan.boundaries);
}

#[test]
fn long_operator_chains_stay_bounded() {
    // Folding reads each operand once, so this finishes promptly.
    let plan = perl(&["perl", "-e", &vec!["0"; 28].join(" // ")]);
    assert!(paths(&plan).is_empty());
    assert!(plan.boundaries.is_empty(), "{:?}", plan.boundaries);
    // Beyond the folding and nesting limits the chain is refused, not lost.
    for operator in ["//", "or"] {
        let source = format!(
            "{} {operator} unlink '/never'",
            vec!["0"; 5000].join(&format!(" {operator} "))
        );
        let plan = perl(&["perl", "-e", &source]);
        assert!(paths(&plan).is_empty(), "{operator}");
        assert!(!plan.boundaries.is_empty(), "{operator}");
    }
}

#[test]
fn source_registration_environment_and_limits() {
    let mut source = Subject::Source {
        language: "perl".into(),
        dialect: None,
        source: "unlink '/tmp/direct'".into(),
        cwd: Some("/work".into()),
        context: Default::default(),
    };
    let plan = Engine::new().analyze(&source).unwrap();
    validate_plan(&plan).unwrap();
    assert_eq!(paths(&plan), [("filesystem.delete", "/tmp/direct")]);
    for limit in [
        "max_source_bytes",
        "max_analysis_steps",
        "max_analysis_bytes",
    ] {
        let mut limits = default_limits();
        limits.insert(limit.into(), 1);
        let plan = Engine::with_limits(limits)
            .unwrap()
            .analyze(&source)
            .unwrap();
        assert!(paths(&plan).is_empty());
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.class == effinterp_proto::BoundaryClass::Limit),
            "{limit}: {:?}",
            plan.boundaries
        );
    }
    if let Subject::Source { source, .. } = &mut source {
        *source = "".into();
    }
    let empty = Engine::new().analyze(&source).unwrap();
    assert!(empty.boundaries.is_empty());
    for domain in ["filesystem", "process"] {
        assert!(
            empty
                .coverage
                .is_full(&effinterp_proto::Domain::new(domain))
        );
    }
    for name in ["PERL5OPT", "PERL5LIB", "PERLLIB"] {
        let mut invocation = subject(&["perl", "-e", "unlink '/never'"]);
        if let Subject::Exec { context, .. } = &mut invocation {
            context.env.insert(name.into(), "-MOther".into());
        }
        let plan = Engine::new().analyze(&invocation).unwrap();
        assert!(paths(&plan).is_empty());
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.detail.as_deref().is_some_and(|s| s.contains(name)))
        );
    }
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: r#"HOME=/alternate perl -e 'unlink "$ENV{HOME}/file"'"#.into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(paths(&plan).contains(&("filesystem.delete", "/alternate/file")));
    let bootstrap = Engine::new()
        .analyze(&Subject::Exec {
            argv: vec![
                "perl".into(),
                "-e".into(),
                r#"unlink "$ENV{HOME}/file""#.into(),
            ],
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(bootstrap.effects.iter().any(|effect| {
        effect.operation.as_str() == "environment.read"
            && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::EnvironmentVariable { name } } if name == "HOME")
    }));
    assert!(paths(&bootstrap).is_empty());
    assert!(
        bootstrap
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == effinterp_proto::BoundaryReason::DYNAMIC_SOURCE)
    );
    let mut limits = default_limits();
    limits.insert("max_analysis_bytes".into(), 200_000);
    let expanded = Subject::Source {
        language: "perl".into(),
        dialect: None,
        source: format!("my $p = \"$ENV{{HOME}}/file\";{}", "unlink $p;".repeat(30)),
        cwd: Some("/work".into()),
        context: effinterp_proto::HostContext {
            env: [("HOME".into(), format!("/{}", "x".repeat(4096)))].into(),
            ..Default::default()
        },
    };
    let plan = Engine::with_limits(limits)
        .unwrap()
        .analyze(&expanded)
        .unwrap();
    assert!(paths(&plan).is_empty());
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.limit.as_deref() == Some("max_analysis_bytes"))
    );
    // Source admitted under max_source_bytes whose decoded environment value
    // exceeds it is saturation, not a dynamic-source refusal.
    let mut limits = default_limits();
    limits.insert("max_source_bytes".into(), 1024);
    let decoded = Subject::Source {
        language: "perl".into(),
        dialect: None,
        source: r#"unlink "$ENV{HOME}/file""#.into(),
        cwd: Some("/work".into()),
        context: effinterp_proto::HostContext {
            env: [("HOME".into(), format!("/{}", "x".repeat(2048)))].into(),
            ..Default::default()
        },
    };
    let plan = Engine::with_limits(limits)
        .unwrap()
        .analyze(&decoded)
        .unwrap();
    assert!(paths(&plan).is_empty());
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.limit.as_deref() == Some("max_source_bytes")),
        "{:?}",
        plan.boundaries
    );
    assert!(
        plan.boundaries
            .iter()
            .all(|b| b.reason != effinterp_proto::BoundaryReason::DYNAMIC_SOURCE)
    );
}

fn process_paths(argv: &[&str]) -> Vec<(String, String)> {
    let plan = perl(argv);
    assert!(
        plan.boundaries.is_empty(),
        "{argv:?}: {:?}",
        plan.boundaries
    );
    paths(&plan)
        .into_iter()
        .map(|(operation, path)| (operation.to_string(), path.to_string()))
        .collect()
}

#[test]
fn system_and_exec_run_one_string_as_shell_source() {
    for source in [
        "system('rm -rf /never')",
        "exec 'rm -rf /never'",
        "my $cmd = 'rm -rf /never'; system($cmd)",
    ] {
        assert!(
            process_paths(&["perl", "-e", source])
                .contains(&("filesystem.delete".into(), "/never".into())),
            "{source}"
        );
    }
}

#[test]
fn system_list_runs_exact_argv() {
    // A list is never re-split by a shell: `/never;x` stays one operand.
    let paths = process_paths(&["perl", "-e", "system('rm', '-rf', '/never;x')"]);
    assert_eq!(
        paths,
        vec![("filesystem.delete".to_string(), "/never;x".to_string())]
    );
}

/// Whether the nested `sh -c` child running `command` writes to the program's
/// own stdout, rather than into a captured value.
fn shell_child_inherits_stdout(plan: &Plan, command: &str) -> bool {
    plan.execution_graph
        .nodes
        .iter()
        .find(|node| matches!(&node.subject, Subject::Shell { source, .. } if source == command))
        .unwrap_or_else(|| panic!("no shell child runs {command}"))
        .streams
        .stdout
        .is_some()
}

#[test]
fn backticks_run_shell_source() {
    for source in ["`rm -rf /never`", "my $out = `rm -rf /never`"] {
        assert!(
            process_paths(&["perl", "-e", source])
                .contains(&("filesystem.delete".into(), "/never".into())),
            "{source}"
        );
        // A backtick captures the child's output, so nothing reaches a pipe.
        let plan = perl(&["perl", "-e", source]);
        assert!(
            !shell_child_inherits_stdout(&plan, "rm -rf /never"),
            "{source}"
        );
    }
    for source in ["system('rm -rf /never')", "exec 'rm -rf /never'"] {
        let plan = perl(&["perl", "-e", source]);
        assert!(
            shell_child_inherits_stdout(&plan, "rm -rf /never"),
            "{source}"
        );
    }
}

#[test]
fn file_path_remove_tree_follows_its_export_lists() {
    for source in [
        "use File::Path; rmtree('/never')",
        "use File::Path qw(remove_tree); remove_tree('/never')",
        "use File::Path (); File::Path::rmtree('/never')",
    ] {
        let plan = perl(&["perl", "-e", source]);
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.delete")
            .unwrap_or_else(|| panic!("{source}"));
        assert_eq!(
            delete.attributes.get("recursive"),
            Some(&effinterp_proto::AttrValue::Bool(true)),
            "{source}"
        );
    }
}

#[test]
fn named_sub_body_runs_only_when_called() {
    assert!(process_paths(&["perl", "-e", "sub f { unlink '/never' }"]).is_empty());
    for source in [
        "sub f { unlink '/never' } f();",
        "f(); sub f { unlink '/never' }",
        "my $d = '/never'; sub f { unlink $d } f()",
    ] {
        assert_eq!(
            process_paths(&["perl", "-e", source]),
            vec![("filesystem.delete".to_string(), "/never".to_string())],
            "{source}"
        );
    }
    // A variable the body rebinds is no longer a known literal after the call.
    let plan = perl(&[
        "perl",
        "-e",
        "my $d = '/a'; sub f { $d = '/b' } f(); unlink $d",
    ]);
    assert!(paths(&plan).is_empty());
    assert_eq!(plan.boundaries.len(), 1);
}

#[test]
fn string_eval_compiles_literal_source() {
    assert_eq!(
        process_paths(&["perl", "-e", r#"eval("unlink \"/never\"")"#]),
        vec![("filesystem.delete".to_string(), "/never".to_string())]
    );
}

#[test]
fn chmod_changes_metadata_like_every_other_frontend() {
    let plan = perl(&["perl", "-e", "chmod 0755, '/a', '/b'"]);
    assert_eq!(
        paths(&plan),
        vec![("filesystem.metadata", "/a"), ("filesystem.metadata", "/b")]
    );
    assert!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.metadata")
            .all(|effect| effect.attributes.get("action")
                == Some(&effinterp_proto::AttrValue::String("chmod".into())))
    );
}

#[test]
fn environment_subscripts_concatenate_into_paths() {
    for source in [
        r#"unlink $ENV{"HOME"}."/.nah/trust.json""#,
        r#"unlink($ENV{'HOME'} . '/.nah/' . "trust.json")"#,
        r#"unlink $ENV{HOME}."/.nah/trust.json""#,
    ] {
        let plan = perl(&["perl", "-e", source]);
        assert_eq!(
            paths(&plan),
            [("filesystem.delete", "/home/test/.nah/trust.json")],
            "{source}"
        );
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "environment.read"),
            "{source}"
        );
    }
    for source in [
        r#"unlink $ENV{MISSING}."/never""#,
        r#"unlink $ENV{$name}."/never""#,
        r#"unlink $ENV{"HOME'}."/never""#,
        r#"unlink $ENV{HOME}.."/never""#,
    ] {
        let plan = perl(&["perl", "-e", source]);
        assert!(paths(&plan).is_empty(), "{source}: {:?}", paths(&plan));
        assert_eq!(plan.boundaries.len(), 1, "{source}: {:?}", plan.boundaries);
    }
}

#[test]
fn undef_defined_or_runs_its_right_operand() {
    let plan = perl(&[
        "perl",
        "-e",
        r#"undef // unlink "$ENV{HOME}/.local/bin/nah""#,
    ]);
    assert_eq!(
        paths(&plan),
        [("filesystem.delete", "/home/test/.local/bin/nah")]
    );
    assert!(plan.boundaries.is_empty(), "{:?}", plan.boundaries);
    // A lone slash may begin a pattern.
    let plan = perl(&["perl", "-e", "unlink '/a' / 2"]);
    assert!(paths(&plan).is_empty());
    assert_eq!(plan.boundaries.len(), 1);
}

#[test]
fn in_place_script_file_still_rewrites_its_operands() {
    let shell = |source: &str| {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        plan
    };
    // The script's source is unknown, but -i opens every operand after it.
    let plan = shell(r#"perl -pi "$SCRIPT" /home/test/.nah/trust.json"#);
    assert!(
        paths(&plan).contains(&("filesystem.write", "/home/test/.nah/trust.json")),
        "{:#?}",
        plan.effects
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason == effinterp_proto::BoundaryReason::DYNAMIC_SOURCE)
    );
    let plan = perl(&["perl", "-i.bak", "-n", "script.pl", "/tmp/a"]);
    assert_eq!(
        paths(&plan),
        [
            ("filesystem.read", "/work/script.pl"),
            ("filesystem.read", "/tmp/a"),
            ("filesystem.write", "/tmp/a"),
            ("filesystem.write", "/tmp/a.bak"),
        ]
    );
    // Without -i or -n/-p the operands are only the script's @ARGV.
    let plan = perl(&["perl", "script.pl", "/tmp/a"]);
    assert_eq!(paths(&plan), [("filesystem.read", "/work/script.pl")]);
}
