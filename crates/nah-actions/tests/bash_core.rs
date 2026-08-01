mod support;

use nah_actions::finalize;
use nah_parse::normalize;
use nah_proto::action::{Coverage, EffectKind, FilesystemOperation, InvocationEffect, PathScope};
use nah_proto::observation::ObservationQuery;
use support::{absolute, bash_plan, observe};

#[test]
fn redirect_only_commands_emit_a_shell_stage_without_reclassifying_compounds() {
    let plan = bash_plan("> /home/test/.nah/config");
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert_eq!(stream.coverage(), Coverage::Full);
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Invocation {
            invocation: InvocationEffect::Known {
                program,
                operation,
                ..
            }
        } if program == "bash" && operation.as_str() == "null-command"
    )));
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Filesystem { effect }
            if effect.operation == FilesystemOperation::Write
                && effect.target == absolute("/home/test/.nah/config")
    )));

    let plan = bash_plan("{ echo hi; } > /tmp/out");
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert_eq!(stream.coverage(), Coverage::Full);
    assert!(!stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Invocation {
            invocation: InvocationEffect::Known { operation, .. }
        } if operation.as_str() == "null-command"
    )));
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Filesystem { effect }
            if effect.operation == FilesystemOperation::Write
                && effect.target == absolute("/tmp/out")
    )));
}

#[test]
fn simple_command_redirect_and_cwd_threading_finalize_from_the_draft() {
    let inspected = normalize("cd ./sub && echo hi > \"out file\"").unwrap();
    let plan = bash_plan("cd ./sub && echo hi > \"out file\"");
    assert!(
        plan.observation_request().queries().iter().any(|query| {
            matches!(query, ObservationQuery::Path { key, requested, cwd_key, .. }
                if key == "path-0" && requested == "/repo/sub/out file" && cwd_key == "cwd")
        }),
        "syntax={inspected:?}, queries={:?}",
        plan.observation_request().queries()
    );

    let observation = observe(plan.observation_request(), "echo");
    let stream = finalize(plan, observation);
    assert_eq!(stream.coverage(), Coverage::Full);
    assert_eq!(stream.effects().len(), 3);
    assert!(matches!(
        stream.effects()[0].kind(),
        EffectKind::Invocation {
            invocation: InvocationEffect::Known { program, operation, .. }
        } if program == "cd" && operation.as_str() == "local-utility"
    ));
    assert!(matches!(
        stream.effects()[1].kind(),
        EffectKind::Invocation {
            invocation: InvocationEffect::Known { program, operation, .. }
        } if program == "echo" && operation.as_str() == "local-utility"
    ));
    assert!(matches!(
        stream.effects()[2].kind(),
        EffectKind::Filesystem { effect }
            if effect.operation == FilesystemOperation::Write
                && effect.target == absolute("/repo/sub/out file")
                && effect.scope == PathScope::Project { root: absolute("/repo") }
    ));
}

#[test]
fn absolute_home_and_tilde_paths_do_not_resolve_under_cwd() {
    for (source, expected) in [
        ("echo hi > /tmp/out", "/tmp/out"),
        ("echo hi > ~/.cache/out", "/home/test/.cache/out"),
        ("echo hi > \"~/.cache/out\"", "/repo/~/.cache/out"),
        ("cd && echo hi > out", "/home/test/out"),
        ("cd /tmp && echo hi > out", "/tmp/out"),
        (
            "echo hi > ~/.nah/guards/../trust.json",
            "/home/test/.nah/guards/../trust.json",
        ),
    ] {
        let plan = bash_plan(source);
        assert!(
            plan.observation_request().queries().iter().any(|query| {
                matches!(query, ObservationQuery::Path { requested, .. } if requested == expected)
            }),
            "{source}: {:?}",
            plan.observation_request().queries()
        );
    }
}

#[test]
fn subshell_and_branch_cwd_cannot_be_mistaken_for_parent_cwd() {
    for source in ["cd sub | echo hi > out", "echo $(cd sub) > out"] {
        let plan = bash_plan(source);
        assert!(
            plan.observation_request().queries().iter().any(|query| {
                matches!(query, ObservationQuery::Path { requested, .. } if requested == "/repo/out")
            }),
            "{source}: {:?}",
            plan.observation_request().queries()
        );
    }

    for source in [
        "cd sub || echo hi > out",
        "cd sub; echo hi > out",
        "cd sub && true\necho hi > out",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        assert_eq!(finalize(plan, observation).coverage(), Coverage::Partial);
    }
}

#[test]
fn bare_relative_cd_fails_closed_because_cdpath_can_redirect_it() {
    let plan = bash_plan("cd etc && head -n 1 passwd");
    assert!(
        !plan.observation_request().queries().iter().any(|query| {
            matches!(query, ObservationQuery::Path { requested, .. }
                if requested == "/repo/etc/passwd")
        }),
        "{:?}",
        plan.observation_request().queries()
    );
    assert_eq!(
        finalize(plan.clone(), observe(plan.observation_request(), "echo")).coverage(),
        Coverage::Partial
    );

    let plan = bash_plan("cd ./src && cat lib.rs");
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert_eq!(stream.coverage(), Coverage::Full);
    assert!(stream.effects().iter().any(|effect| {
        matches!(effect.kind(), EffectKind::Filesystem { effect }
            if effect.target == absolute("/repo/src/lib.rs"))
    }));
}

#[test]
fn pipeline_and_substitution_flows_are_visible_but_chains_are_not() {
    let cases = [
        ("curl x | bash", Coverage::Full, 2, vec![("s0", "s1")]),
        ("curl x && bash", Coverage::Partial, 2, vec![]),
        (
            "echo $(curl x | sh)",
            Coverage::Partial,
            3,
            vec![("s0", "s1"), ("s1", "s2")],
        ),
        ("cat <(curl x)", Coverage::Partial, 2, vec![("s0", "s1")]),
        ("tee >(cat -n)", Coverage::Partial, 2, vec![("s1", "s0")]),
        (
            "echo $(cat secret; echo ok)",
            Coverage::Partial,
            3,
            vec![("s0", "s2"), ("s1", "s2")],
        ),
        (
            "tee >(echo $(date))",
            Coverage::Partial,
            3,
            vec![("s0", "s1"), ("s2", "s1")],
        ),
    ];
    for (source, coverage, stages, expected_flows) in cases {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert_eq!(
            stream.coverage(),
            coverage,
            "{source}: {:?}",
            normalize(source).unwrap()
        );
        assert_eq!(
            stream
                .effects()
                .iter()
                .map(|effect| effect.stage().as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            stages,
            "{source}"
        );
        let actual = stream
            .flows()
            .iter()
            .map(|flow| (flow.from_stage().as_str(), flow.to_stage().as_str()))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected_flows, "{source}");
    }
}

#[test]
fn grouped_redirects_apply_once_without_hiding_nested_invocations() {
    for (source, operation, target) in [
        (
            "(echo hi; date) > grouped.out",
            FilesystemOperation::Write,
            "/repo/grouped.out",
        ),
        (
            "{ cat; wc -l; } < src/lib.rs",
            FilesystemOperation::Read,
            "/repo/src/lib.rs",
        ),
        (
            "{ cd /tmp && echo hi; } > grouped.out",
            FilesystemOperation::Write,
            "/repo/grouped.out",
        ),
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert_eq!(stream.coverage(), Coverage::Full, "{source}");
        assert!(stream.effects().iter().any(|effect| {
            matches!(effect.kind(), EffectKind::Filesystem { effect }
                if effect.operation == operation && effect.target == absolute(target))
        }));
        assert!(
            stream
                .effects()
                .iter()
                .filter(|effect| matches!(effect.kind(), EffectKind::Invocation { .. }))
                .count()
                >= 2,
            "{source}: {:?}",
            stream.effects()
        );
    }

    let plan = bash_plan("{ echo hi; date; } 2>&1");
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert_eq!(stream.coverage(), Coverage::Full);

    let plan = bash_plan("cd /etc && { head -n 1; } < passwd");
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert_eq!(stream.coverage(), Coverage::Full);
    assert!(stream.effects().iter().any(|effect| {
        matches!(effect.kind(), EffectKind::Filesystem { effect }
            if effect.operation == FilesystemOperation::Read
                && effect.target == absolute("/etc/passwd"))
    }));
}

#[test]
fn typed_control_flow_allows_complete_effects_and_keeps_unknown_cwd_scoped() {
    for source in [
        "if true; then echo yes; else date; fi",
        "for x in a b; do echo \"$x\"; done",
        "while false; do pwd; done",
        "until true; do echo waiting; done",
        "case \"$MODE\" in fast) echo fast;; *) date;; esac",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert_eq!(
            stream.coverage(),
            Coverage::Full,
            "{source}: {:?}",
            normalize(source).unwrap()
        );
        assert!(stream.effects().iter().all(|effect| {
            matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::Known { operation, .. }
                } if operation.as_str() == "local-utility"
            )
        }));
    }

    let plan = bash_plan("for f in src/lib.rs README.md; do stat \"$f\"; done");
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert_eq!(stream.coverage(), Coverage::Full);
    assert_eq!(
        stream
            .effects()
            .iter()
            .filter(|effect| matches!(effect.kind(), EffectKind::Filesystem { .. }))
            .count(),
        2
    );

    let absolute_source = "if true; then cd ./sub; else cd ./other; fi; cat /repo/src/lib.rs";
    let plan = bash_plan(absolute_source);
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert_eq!(stream.coverage(), Coverage::Full);
    assert!(stream.effects().iter().any(|effect| {
        matches!(effect.kind(), EffectKind::Filesystem { effect }
            if effect.target == absolute("/repo/src/lib.rs"))
    }));

    for source in [
        "if true; then cd sub; else cd other; fi; cat file",
        "while true; do cd sub && cat file; done",
        "for x in a b; do cd sub && cat file; done",
        "case x in x) cd /tmp ;& y) cat file;; esac",
        "while true; do continue; done",
        "while true; do continue; break; done",
        "while true; do { continue; }; break; done",
        "while true; do if true; then continue; fi; break; done",
        "until false; do pwd; done",
        "while true; do break | cat src/lib.rs; done",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
    }

    for source in [
        "while true; do break; done",
        "until false; do { break; }; done",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert_eq!(stream.coverage(), Coverage::Full, "{source}");
    }

    let plan = bash_plan("for f in src/lib.rs .env; do cat \"$f\"; done");
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert_eq!(stream.coverage(), Coverage::Full);
    assert!(stream.effects().iter().any(|effect| {
        matches!(effect.kind(), EffectKind::Filesystem { effect }
            if effect.target == absolute("/repo/.env"))
    }));

    let plan = bash_plan("for f in ~/.ssh/config; do cat \"$f\"; done");
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert_eq!(stream.coverage(), Coverage::Full);
    assert!(stream.effects().iter().any(|effect| {
        matches!(effect.kind(), EffectKind::Filesystem { effect }
            if effect.target == absolute("/home/test/.ssh/config"))
    }));

    let plan = bash_plan("for f in \"~/.ssh/config\"; do cat \"$f\"; done");
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert_eq!(stream.coverage(), Coverage::Full);
    assert!(stream.effects().iter().any(|effect| {
        matches!(effect.kind(), EffectKind::Filesystem { effect }
            if effect.target == absolute("/repo/~/.ssh/config"))
    }));

    for source in [
        "for f in '*.md'; do cat $f; done",
        "for f; do cat \"$f\"; done",
        "for f in .env README.md; do break; done; cat \"$f\"",
        "for x in one; do continue; for f in README.md; do :; done; done; cat \"$f\"",
        "for x in one; do for f in .env README.md; do continue 2; done; done; cat \"$f\"",
        "(for f in README.md; do :; done); cat \"$f\"",
        "echo $(for f in README.md; do :; done); cat \"$f\"",
        "cat <(for f in README.md; do :; done); cat \"$f\"",
        "for f in README.md; do :; done | true; cat \"$f\"",
        "cd \"~/docs\" && cat concepts.md",
        "cd \\~/docs && cat concepts.md",
        "for d in \"~/docs\"; do cd \"$d\" && cat concepts.md; done",
    ] {
        let plan = bash_plan(source);
        assert_eq!(
            finalize(plan.clone(), observe(plan.observation_request(), "echo")).coverage(),
            Coverage::Partial
        );
    }

    for source in [
        "for f in README.md; do printf -v f .env; cat \"$f\"; done",
        "for f in README.md; do read f <<< .env; cat \"$f\"; done",
        // Exact mapfile input now resolves the assigned array element too.
        "for f in README.md; do mapfile -t f <<< .env; cat \"$f\"; done",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert_eq!(stream.coverage(), Coverage::Full, "{source}");
        assert!(stream.effects().iter().any(|effect| {
            matches!(effect.kind(), EffectKind::Filesystem { effect }
                if effect.target == absolute("/repo/.env"))
        }));
    }

    for source in [
        "case x in x) cat .env ;& esac",
        "case x in x) cat .env ;;& esac",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
        assert!(stream.effects().iter().any(|effect| {
            matches!(effect.kind(), EffectKind::Filesystem { effect }
                if effect.target == absolute("/repo/.env"))
        }));
    }
}
