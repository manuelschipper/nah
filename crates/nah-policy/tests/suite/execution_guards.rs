#![allow(clippy::disallowed_types)]

use crate::support;

use nah_proto::action::{
    ActionStream, Coverage, EffectKind, FilesystemEffect, FilesystemOperation, FlowOrdinals,
    InvocationInput, NetworkDirection, PathScope, Sensitivity,
};
use nah_proto::decision::Verdict;
use support::{filesystem, guard_policy, path, project_scope};

#[test]
fn execution_guards_match_visible_flow_paths_and_obfuscation_evidence() {
    let cases = [
        (
            "secrets-exfil",
            vec![
                vec![
                    EffectKind::known("cat", "local-utility").unwrap(),
                    filesystem(
                        FilesystemOperation::Read,
                        "/home/test/.aws/credentials",
                        PathScope::Home,
                        Sensitivity::OtherSensitive,
                    ),
                ],
                vec![
                    EffectKind::known("curl", "network-transfer").unwrap(),
                    EffectKind::network(None),
                ],
            ],
            vec![FlowOrdinals::new(0, 1)],
        ),
        (
            "secrets-exfil",
            vec![vec![
                EffectKind::known("curl", "network-transfer").unwrap(),
                filesystem(
                    FilesystemOperation::Read,
                    "/repo/.env",
                    project_scope(),
                    Sensitivity::EnvironmentSecret,
                ),
                EffectKind::network(None),
            ]],
            vec![],
        ),
        (
            "secrets-exfil",
            vec![
                vec![
                    EffectKind::known("mv", "move").unwrap(),
                    filesystem(
                        FilesystemOperation::Delete,
                        "/home/test/.aws/credentials",
                        PathScope::Home,
                        Sensitivity::CredentialSecret,
                    ),
                ],
                vec![
                    EffectKind::known("curl", "network-transfer").unwrap(),
                    EffectKind::network(None),
                ],
            ],
            vec![FlowOrdinals::new(0, 1)],
        ),
        (
            "exec-remote",
            vec![
                vec![
                    EffectKind::known("curl", "network-transfer").unwrap(),
                    EffectKind::network(None),
                ],
                vec![EffectKind::opaque("cat").unwrap()],
                vec![EffectKind::code_execution(Some("bash"), "shell-interactive").unwrap()],
            ],
            vec![FlowOrdinals::new(0, 1), FlowOrdinals::new(1, 2)],
        ),
        (
            "exec-decoded",
            vec![
                vec![EffectKind::known("base64", "decode").unwrap()],
                vec![EffectKind::code_execution(Some("sh"), "shell-interactive").unwrap()],
            ],
            vec![FlowOrdinals::new(0, 1)],
        ),
        (
            "exec-decoded",
            vec![vec![
                EffectKind::code_execution(Some("python"), "decoded-execution").unwrap(),
            ]],
            vec![],
        ),
        (
            "exec-obfuscated",
            vec![vec![
                EffectKind::code_execution(None, "encoded-command").unwrap(),
            ]],
            vec![],
        ),
        (
            "exec-obfuscated",
            vec![vec![
                EffectKind::code_execution(None, "shell-pattern").unwrap(),
            ]],
            vec![],
        ),
        (
            "exec-obfuscated",
            vec![vec![
                EffectKind::code_execution(None, "unresolved-command").unwrap(),
            ]],
            vec![],
        ),
        (
            "exec-network-shell",
            vec![
                vec![EffectKind::known("nc", "network-listener").unwrap()],
                vec![EffectKind::code_execution(Some("sh"), "shell-interactive").unwrap()],
            ],
            vec![FlowOrdinals::new(0, 1)],
        ),
        (
            "exec-network-shell",
            vec![vec![EffectKind::known("socat", "network-shell").unwrap()]],
            vec![],
        ),
    ];

    for (guard, stages, flows) in cases {
        let stream = ActionStream::new(Coverage::Partial, stages, flows).unwrap();
        let decision = nah_policy::decide(
            &stream,
            &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
            &guard_policy(guard, true),
            &[],
        )
        .unwrap();
        assert_eq!(decision.verdict(), Verdict::Block, "{guard}");
        assert_eq!(decision.policy_attributions()[0].name(), guard);
        if guard == "exec-remote" {
            assert!(
                decision
                    .reason()
                    .contains("save and inspect it, but do not execute it")
            );
            assert!(decision.reason().contains("prompt injection"));
        }
        assert_eq!(
            nah_policy::decide(
                &stream,
                &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                &guard_policy(guard, false),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Delegate,
            "{guard}"
        );
    }
}

#[test]
fn execution_guards_require_their_complete_positive_evidence() {
    let cases = [
        (
            "secrets-exfil",
            vec![
                vec![
                    EffectKind::known("cat", "local-utility").unwrap(),
                    filesystem(
                        FilesystemOperation::Read,
                        "/repo/readme",
                        project_scope(),
                        Sensitivity::None,
                    ),
                ],
                vec![
                    EffectKind::known("curl", "network-transfer").unwrap(),
                    EffectKind::network(None),
                ],
            ],
            vec![FlowOrdinals::new(0, 1)],
        ),
        (
            "secrets-exfil",
            vec![
                vec![
                    EffectKind::known("rm", "remove").unwrap(),
                    filesystem(
                        FilesystemOperation::Delete,
                        "/home/test/.aws/credentials",
                        PathScope::Home,
                        Sensitivity::CredentialSecret,
                    ),
                ],
                vec![
                    EffectKind::known("curl", "network-transfer").unwrap(),
                    EffectKind::network(None),
                ],
            ],
            vec![FlowOrdinals::new(0, 1)],
        ),
        (
            "exec-remote",
            vec![
                vec![
                    EffectKind::opaque("custom-fetch").unwrap(),
                    EffectKind::network(None),
                ],
                vec![EffectKind::code_execution(Some("bash"), "shell-file").unwrap()],
            ],
            vec![FlowOrdinals::new(0, 1)],
        ),
        (
            "exec-decoded",
            vec![
                vec![EffectKind::known("base64", "decode").unwrap()],
                vec![EffectKind::code_execution(Some("bash"), "shell-stdin").unwrap()],
            ],
            vec![],
        ),
        (
            "exec-obfuscated",
            vec![vec![
                EffectKind::code_execution(None, "evaluated-substitution").unwrap(),
            ]],
            vec![],
        ),
        (
            "exec-network-shell",
            vec![
                vec![EffectKind::known("nc", "network-listener").unwrap()],
                vec![EffectKind::code_execution(Some("sh"), "shell-stdin").unwrap()],
            ],
            vec![],
        ),
        (
            "exec-network-shell",
            vec![vec![EffectKind::known("nc", "network-listener").unwrap()]],
            vec![],
        ),
        (
            "exec-network-shell",
            vec![
                vec![EffectKind::code_execution(Some("bash"), "shell-stdin").unwrap()],
                vec![
                    EffectKind::known("curl", "network-transfer").unwrap(),
                    EffectKind::network(None),
                ],
            ],
            vec![FlowOrdinals::new(0, 1)],
        ),
    ];

    for (guard, stages, flows) in cases {
        let stream = ActionStream::new(Coverage::Partial, stages, flows).unwrap();
        assert_eq!(
            nah_policy::decide(
                &stream,
                &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                &guard_policy(guard, true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Delegate,
            "{guard}"
        );
    }
}

#[test]
fn exfiltration_accepts_only_the_new_proven_source_shapes() {
    let sink = vec![
        EffectKind::known("curl", "network-transfer").unwrap(),
        EffectKind::network(None),
    ];
    for (program, operation) in [
        ("env", "environment-disclosure"),
        ("echo", "credential-disclosure"),
        ("vault", "secrets-store-read"),
    ] {
        let source = ActionStream::new(
            Coverage::Full,
            vec![
                vec![EffectKind::known(program, operation).unwrap()],
                sink.clone(),
            ],
            vec![FlowOrdinals::new(0, 1)],
        )
        .unwrap();
        assert_eq!(
            nah_policy::decide(
                &source,
                &crate::support::evidence(&source, &nah_inline::InlineReport::default()),
                &guard_policy("secrets-exfil", true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Block,
            "{operation}"
        );
    }

    let recursive_read = |target: &str, selects_root: bool| EffectKind::Filesystem {
        effect: FilesystemEffect {
            operation: FilesystemOperation::Read,
            target: path(target),
            scope: project_scope(),
            sensitivity: Sensitivity::None,
            protection: None,
            host_integrity: None,
            selects_root,
            selects_home: false,
            recursive: true,
            pattern: false,
        },
    };
    for (target, selects_root, expected) in [
        ("/repo", true, Verdict::Block),
        ("/repo/src", false, Verdict::Delegate),
    ] {
        let search = ActionStream::new(
            Coverage::Full,
            vec![
                vec![
                    EffectKind::known("grep", "credential-search").unwrap(),
                    recursive_read(target, selects_root),
                ],
                sink.clone(),
            ],
            vec![FlowOrdinals::new(0, 1)],
        )
        .unwrap();
        assert_eq!(
            nah_policy::decide(
                &search,
                &crate::support::evidence(&search, &nah_inline::InlineReport::default()),
                &guard_policy("secrets-exfil", true),
                &[]
            )
            .unwrap()
            .verdict(),
            expected,
            "{target}"
        );
    }

    let disconnected = ActionStream::new(
        Coverage::Full,
        vec![
            vec![EffectKind::known("env", "environment-disclosure").unwrap()],
            sink,
        ],
        vec![],
    )
    .unwrap();
    assert_eq!(
        nah_policy::decide(
            &disconnected,
            &crate::support::evidence(&disconnected, &nah_inline::InlineReport::default()),
            &guard_policy("secrets-exfil", true),
            &[]
        )
        .unwrap()
        .verdict(),
        Verdict::Delegate
    );
}

#[test]
fn directional_shell_endpoints_are_execution_sources_and_exfiltration_sinks() {
    let remote_exec = ActionStream::new(
        Coverage::Partial,
        vec![vec![
            EffectKind::code_execution(Some("bash"), "shell-stdin").unwrap(),
            EffectKind::network_with_direction(NetworkDirection::Inbound, Some("evil.example")),
        ]],
        vec![],
    )
    .unwrap();
    assert_eq!(
        nah_policy::decide(
            &remote_exec,
            &crate::support::evidence(&remote_exec, &nah_inline::InlineReport::default()),
            &guard_policy("exec-remote", true),
            &[]
        )
        .unwrap()
        .verdict(),
        Verdict::Block
    );

    let exfiltration = ActionStream::new(
        Coverage::Partial,
        vec![vec![
            EffectKind::known("cat", "local-utility").unwrap(),
            filesystem(
                FilesystemOperation::Read,
                "/home/test/.ssh/id_rsa",
                PathScope::Home,
                Sensitivity::CredentialSecret,
            ),
            EffectKind::network_with_direction(NetworkDirection::Outbound, Some("evil.example")),
        ]],
        vec![],
    )
    .unwrap();
    assert_eq!(
        nah_policy::decide(
            &exfiltration,
            &crate::support::evidence(&exfiltration, &nah_inline::InlineReport::default()),
            &guard_policy("secrets-exfil", true),
            &[]
        )
        .unwrap()
        .verdict(),
        Verdict::Block
    );

    let output_only_shell = ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::code_execution(Some("bash"), "shell-interactive").unwrap(),
            EffectKind::network_with_direction(NetworkDirection::Outbound, Some("evil.example")),
        ]],
        vec![],
    )
    .unwrap();
    assert_eq!(
        nah_policy::decide(
            &output_only_shell,
            &crate::support::evidence(&output_only_shell, &nah_inline::InlineReport::default()),
            &guard_policy("exec-remote", true),
            &[]
        )
        .unwrap()
        .verdict(),
        Verdict::Delegate
    );
}

#[test]
fn evaluated_shell_is_an_execution_sink_only_when_its_code_is_unknown() {
    for (guard, source) in [
        (
            "exec-remote",
            vec![
                EffectKind::known("curl", "network-transfer").unwrap(),
                EffectKind::network(None),
            ],
        ),
        (
            "exec-decoded",
            vec![EffectKind::known("base64", "decode").unwrap()],
        ),
    ] {
        let unknown_eval = EffectKind::code_execution_with_input(
            "eval",
            None,
            "evaluated-shell",
            None,
            InvocationInput::shell("eval", vec!["eval".into(), "$CODE".into()], None),
        )
        .unwrap();
        let stream = ActionStream::new(
            Coverage::Partial,
            vec![source.clone(), vec![unknown_eval]],
            vec![FlowOrdinals::new(0, 1)],
        )
        .unwrap();
        assert_eq!(
            nah_policy::decide(
                &stream,
                &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                &guard_policy(guard, true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Block,
            "{guard}"
        );

        let known_eval = EffectKind::code_execution_with_input(
            "eval",
            None,
            "evaluated-shell",
            Some("printf safe".into()),
            InvocationInput::shell(
                "eval",
                vec!["eval".into(), "printf safe".into()],
                Some(vec!["eval".into(), "printf safe".into()]),
            ),
        )
        .unwrap();
        let stream = ActionStream::new(
            Coverage::Full,
            vec![source, vec![known_eval]],
            vec![FlowOrdinals::new(0, 1)],
        )
        .unwrap();
        assert_eq!(
            nah_policy::decide(
                &stream,
                &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                &guard_policy(guard, true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Delegate,
            "{guard}"
        );
    }
}

#[test]
fn shared_execution_causality_requires_an_established_data_path() {
    use nah_proto::effects::*;
    let stream = ActionStream::new(
        Coverage::Full,
        vec![
            vec![EffectKind::known("base64", "decode").unwrap()],
            vec![EffectKind::code_execution(Some("sh"), "shell-stdin").unwrap()],
        ],
        vec![FlowOrdinals::new(0, 1)],
    )
    .unwrap();
    let evidence = support::evidence(&stream, &nah_inline::InlineReport::default());
    let decide = |evidence: &GuardEvidence, enabled| {
        nah_policy::decide(
            &stream,
            evidence,
            &guard_policy("exec-decoded", enabled),
            &[],
        )
        .unwrap()
    };
    let matched = decide(&evidence, true);
    assert_eq!(matched.verdict(), Verdict::Block);
    assert_eq!(decide(&evidence, false).verdict(), Verdict::Delegate);
    for mutation in 0..10 {
        let mut graph = evidence.graph().clone();
        match mutation {
            0 => graph.relations.clear(),
            1 => {
                for edge in &mut graph.relations {
                    std::mem::swap(&mut edge.from, &mut edge.to);
                }
            }
            2 => {
                for edge in &mut graph.relations {
                    edge.kind = RelationKind::Control;
                }
            }
            3 => graph.facts[0].certainty = Certainty::Conservative,
            4 => graph.causality = CausalAvailability::Unavailable,
            5 | 6 => {
                graph.conditions.push(EffectCondition {
                    id: ConditionId(0),
                    complete: false,
                    expression: ConditionExpr::Literal { atom: 0 },
                    alternative_group: None,
                });
                let condition = Some(ConditionUse {
                    id: ConditionId(0),
                    positive: true,
                });
                if mutation == 5 {
                    for edge in &mut graph.relations {
                        edge.condition = condition.clone();
                    }
                } else {
                    graph.facts[0].condition = condition;
                }
            }
            7 => {
                graph.facts[1].realm = Realm::Remote {
                    identity: Knowledge::Known("other-host".into()),
                }
            }
            8 => graph.occurrences[1].port = PortKind::NetworkRequest,
            9 => {
                for edge in &mut graph.relations {
                    edge.kind = RelationKind::StateTransition;
                }
            }
            _ => unreachable!(),
        }
        let changed = GuardEvidence::new(graph, evidence.public_selection().clone()).unwrap();
        assert_eq!(
            decide(&changed, true).verdict(),
            Verdict::Delegate,
            "mutation {mutation}"
        );
    }
    // Unrelated missing coverage is not an execution fact and does not erase proof.
    let mut graph = evidence.graph().clone();
    graph.calls[0].coverage = Coverage::Partial;
    let partial = GuardEvidence::new(graph, evidence.public_selection().clone()).unwrap();
    assert_eq!(decide(&partial, true), matched);
}
