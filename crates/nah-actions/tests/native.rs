use nah_actions::{AnalysisInput, finalize, plan};
use nah_proto::action::{
    Coverage, EffectKind, FilesystemOperation, HostIntegrityClass, InvocationEffect,
    InvocationInput, NahProtectionTier, PathScope, Sensitivity,
};
use nah_proto::ctx::{AbsolutePath, Ctx, Platform, PolicyVersion, SchemaVersion, TrustProjection};
use nah_proto::observation::{
    Observation, ObservationFact, ObservationFailure, ObservationQuery, ObservationValue, Observed,
    PathKind, PathObservation, ProjectGuardDeclaration, ProjectGuardObservation, Root, RootKind,
    SymlinkTraversal,
};
use nah_proto::tool::ToolCallInput;
use serde_json::json;

#[test]
fn read_plan_requests_only_authoritative_call_site_facts() {
    let input = call("Read", json!({"file_path": "src/lib.rs"}));
    let call_site = input.call_site(Platform::Linux).unwrap();
    let plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);

    assert_eq!(
        plan.observation_request().queries(),
        &[
            ObservationQuery::Cwd {
                key: "cwd".into(),
                requested: absolute("/authoritative"),
            },
            ObservationQuery::ProjectGuards {
                key: "project-guards".into(),
                roots_key: "roots".into(),
            },
            ObservationQuery::Roots {
                key: "roots".into(),
                cwd_key: "cwd".into(),
            },
            ObservationQuery::Path {
                key: "target".into(),
                requested: "src/lib.rs".into(),
                cwd_key: "cwd".into(),
                inspect_descendants: false,
                symlink_traversal: SymlinkTraversal::None,
            },
        ]
    );
    assert_eq!(
        serde_json::to_string(plan.observation_request()).unwrap(),
        r#"{"v":1,"request_id":"native-v1","queries":[{"kind":"cwd","key":"cwd","requested":"/authoritative"},{"kind":"project-guards","key":"project-guards","roots_key":"roots"},{"kind":"roots","key":"roots","cwd_key":"cwd"},{"kind":"path","key":"target","requested":"src/lib.rs","cwd_key":"cwd","inspect_descendants":false,"symlink_traversal":"none"}]}"#
    );
    let stream = finalize(
        plan,
        successful_observation("Read", "src/lib.rs", "/repo/src/lib.rs"),
    );
    assert_eq!(
        stream.canonical_json().unwrap(),
        r#"{"v":1,"coverage":"full","effects":[{"id":"e0","stage":"s0","kind":{"kind":"invocation","invocation":{"kind":"known","program":"Read","operation":"read","input":{"kind":"native","value":{"file_path":"src/lib.rs"},"complete":true},"cwd":"/authoritative"}}},{"id":"e1","stage":"s0","kind":{"kind":"filesystem","operation":"read","target":"/repo/src/lib.rs","scope":{"kind":"project","root":"/repo"},"sensitivity":"none","selects_root":false,"selects_home":false,"recursive":false,"pattern":false}}],"flows":[]}"#
    );
}

#[test]
fn native_schemas_and_default_search_path_finalize_to_full_effects() {
    let cases = [
        (
            "Read",
            json!({"file_path":"file"}),
            "file",
            FilesystemOperation::Read,
            false,
        ),
        (
            "Write",
            json!({"file_path":"file", "content":"secret-looking content"}),
            "file",
            FilesystemOperation::Write,
            false,
        ),
        (
            "Delete",
            json!({"file_path":"file"}),
            "file",
            FilesystemOperation::Delete,
            false,
        ),
        (
            "Edit",
            json!({"file_path":"file", "old_string":"a", "new_string":"b", "replace_all":true}),
            "file",
            FilesystemOperation::Write,
            false,
        ),
        (
            "Edit",
            json!({"file_path":"file", "edits":[{"oldText":"a","newText":"b"},{"oldText":"c","newText":"d"}]}),
            "file",
            FilesystemOperation::Write,
            false,
        ),
        (
            "Glob",
            json!({"pattern":"file"}),
            "/authoritative/file",
            FilesystemOperation::Read,
            false,
        ),
        (
            "Grep",
            json!({"pattern":"password", "path":"file"}),
            "file",
            FilesystemOperation::Read,
            false,
        ),
        (
            "Find",
            json!({"pattern":"**/*.rs", "path":"src"}),
            "src",
            FilesystemOperation::Read,
            true,
        ),
        (
            "Ls",
            json!({"path":"src"}),
            "src",
            FilesystemOperation::Read,
            false,
        ),
    ];

    for (tool, body, requested, operation, recursive) in cases {
        let input = call(tool, body);
        let call_site = input.call_site(Platform::Linux).unwrap();
        let plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);
        assert!(plan.observation_request().queries().iter().any(|query| {
            matches!(query, ObservationQuery::Path { requested: value, .. } if value == requested)
        }));

        let stream = finalize(plan, successful_observation(tool, requested, "/repo/file"));
        assert_eq!(stream.coverage(), Coverage::Full);
        assert_eq!(stream.effects().len(), 2);
        assert!(matches!(
            stream.effects()[0].kind(),
            EffectKind::Invocation {
                invocation: InvocationEffect::Known { program, .. }
            } if program == tool
        ));
        assert!(matches!(
            stream.effects()[1].kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == operation
                    && effect.target == absolute("/repo/file")
                    && effect.scope == PathScope::Project { root: absolute("/repo") }
                    && effect.sensitivity == Sensitivity::None
                    && effect.recursive == recursive
        ));
    }
}

#[test]
fn native_invocation_preserves_original_runtime_input() {
    let original = json!({
        "path": "file",
        "content": "value",
        "runtimeSpecificFlag": true
    });
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "Write",
        json!({"file_path":"file","content":"value"}),
        "/authoritative",
        None,
    )
    .unwrap()
    .with_original_input(original.clone(), true);
    let call_site = input.call_site(Platform::Linux).unwrap();
    let plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);
    let stream = finalize(plan, successful_observation("Write", "file", "/repo/file"));

    assert_eq!(stream.coverage(), Coverage::Full);
    assert!(matches!(
        stream.effects()[0].kind(),
        EffectKind::Invocation {
            invocation: InvocationEffect::Known {
                input: InvocationInput::Native { value, complete: true },
                ..
            }
        } if value == &original
    ));
}

#[test]
fn undocumented_native_fields_make_direct_lowering_partial() {
    let input = call(
        "Read",
        json!({"file_path":"file","futureBehavior":"execute"}),
    );
    let call_site = input.call_site(Platform::Linux).unwrap();
    let plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);
    let stream = finalize(plan, successful_observation("Read", "file", "/repo/file"));

    assert_eq!(stream.coverage(), Coverage::Partial);
    assert_eq!(stream.effects().len(), 2);
}

#[test]
fn incomplete_runtime_normalization_cannot_be_cleared_as_full() {
    let original = json!({"path":"file","futureBehavior":"execute"});
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "Read",
        json!({"file_path":"file"}),
        "/authoritative",
        None,
    )
    .unwrap()
    .with_original_input(original, false);
    let call_site = input.call_site(Platform::Linux).unwrap();
    let plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);
    let stream = finalize(plan, successful_observation("Read", "file", "/repo/file"));

    assert_eq!(stream.coverage(), Coverage::Partial);
}

#[test]
fn oversized_native_evidence_is_not_sent_to_extensions() {
    let input = call(
        "Write",
        json!({"file_path":"file","content":"x".repeat(1024 * 1024 + 1)}),
    );
    let call_site = input.call_site(Platform::Linux).unwrap();
    let plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);
    let stream = finalize(plan, successful_observation("Write", "file", "/repo/file"));

    assert_eq!(stream.coverage(), Coverage::Partial);
    assert!(matches!(
        stream.effects()[0].kind(),
        EffectKind::Invocation {
            invocation: InvocationEffect::Known {
                input: InvocationInput::Native {
                    complete: false,
                    ..
                },
                ..
            }
        }
    ));
}

#[test]
fn thread_transfers_preserve_visible_local_paths_without_claiming_full_coverage() {
    for (tool, requested, canonical, operation, sensitivity, protection) in [
        (
            "AmpUpload",
            ".env",
            "/repo/.env",
            FilesystemOperation::Read,
            Sensitivity::EnvironmentSecret,
            None,
        ),
        (
            "AmpDownload",
            "/home/test/.config/amp/plugins/nah.ts",
            "/home/test/.config/amp/plugins/nah.ts",
            FilesystemOperation::Write,
            Sensitivity::None,
            None,
        ),
    ] {
        let input = call(tool, json!({"file_path":requested}));
        let call_site = input.call_site(Platform::Linux).unwrap();
        let plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);
        let stream = finalize(plan, successful_observation(tool, requested, canonical));
        assert_eq!(stream.coverage(), Coverage::Partial);
        assert_eq!(stream.effects().len(), 3);
        assert!(matches!(
            stream.effects()[0].kind(),
            EffectKind::Invocation {
                invocation: InvocationEffect::Known { program, operation, .. }
            } if program == tool && operation.as_str() == "network-transfer"
        ));
        assert!(matches!(
            stream.effects()[1].kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == operation
                    && effect.sensitivity == sensitivity
                    && effect.protection == protection
        ));
        assert!(matches!(
            stream.effects()[2].kind(),
            EffectKind::Network { .. }
        ));
    }
}

#[test]
fn apply_patch_requests_every_add_update_delete_and_move_path() {
    let input = call(
        "apply_patch",
        json!({
            "command": "*** Begin Patch\n*** Add File: /repo/added\n+added\n*** Update File: /repo/old\n*** Move to: /repo/moved\n@@\n-old\n+new\n*** Delete File: /repo/deleted\n*** End Patch"
        }),
    );
    let call_site = input.call_site(Platform::Linux).unwrap();
    let plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);

    assert_eq!(
        plan.observation_request()
            .queries()
            .iter()
            .filter_map(|query| match query {
                ObservationQuery::Path { key, requested, .. } => {
                    Some((key.as_str(), requested.as_str()))
                }
                _ => None,
            })
            .collect::<Vec<_>>(),
        [
            ("patch-target-0000", "/repo/added"),
            ("patch-target-0001", "/repo/old"),
            ("patch-target-0002", "/repo/moved"),
            ("patch-target-0003", "/repo/deleted"),
        ]
    );

    let stream = finalize(plan, observation_without_path("apply_patch"));
    assert_eq!(stream.coverage(), Coverage::Partial);
    assert!(stream.effects().is_empty());
}

#[test]
fn malformed_schema_or_observation_binding_is_empty_partial() {
    for (tool, body) in [
        ("Read", json!({})),
        ("Write", json!({"file_path":"file"})),
        ("Delete", json!({})),
        (
            "Edit",
            json!({"file_path":"file", "old_string":"a", "new_string":7}),
        ),
        ("Glob", json!({"pattern":7})),
        ("Grep", json!({"pattern":"x", "path":false})),
        ("apply_patch", json!({"command":7})),
    ] {
        let input = call(tool, body);
        let call_site = input.call_site(Platform::Linux).unwrap();
        let plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);
        let stream = finalize(plan, observation_without_path(tool));
        assert_eq!(stream.coverage(), Coverage::Partial);
        assert!(stream.effects().is_empty());
    }

    let input = call("Read", json!({"file_path":"file"}));
    let call_site = input.call_site(Platform::Linux).unwrap();
    let mismatched_plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);
    let stream = finalize(
        mismatched_plan,
        successful_observation("Read", "different", "/repo/file"),
    );
    assert_eq!(stream.coverage(), Coverage::Partial);
    assert!(stream.effects().is_empty());

    let input = call("Read", json!({"file_path":"file"}));
    let call_site = input.call_site(Platform::Linux).unwrap();
    let failed_plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);
    let stream = finalize(
        failed_plan,
        observation(Some((
            "file",
            Observed::Error {
                error: ObservationFailure::PermissionDenied,
            },
        ))),
    );
    assert_eq!(stream.coverage(), Coverage::Partial);
    assert!(stream.effects().is_empty());
}

#[test]
fn block_relevant_literal_paths_survive_permission_and_timeout_failures() {
    for failure in [
        ObservationFailure::PermissionDenied,
        ObservationFailure::Timeout,
    ] {
        for (tool, body, requested, expected) in [
            (
                "Write",
                json!({"file_path":"/home/test/.bashrc","content":"alias ll='ls -la'"}),
                "/home/test/.bashrc",
                Some(HostIntegrityClass::StartupPersistence),
            ),
            (
                "Delete",
                json!({"file_path":"/etc/passwd"}),
                "/etc/passwd",
                Some(HostIntegrityClass::AuthIdentity),
            ),
            (
                "Read",
                json!({"file_path":"/repo/.env"}),
                "/repo/.env",
                None,
            ),
        ] {
            let input = call(tool, body);
            let call_site = input.call_site(Platform::Linux).unwrap();
            let plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);
            let stream = finalize(
                plan,
                observation(Some((requested, Observed::Error { error: failure }))),
            );
            assert_eq!(stream.coverage(), Coverage::Partial, "{tool} {requested}");
            assert!(
                stream.effects().iter().any(|effect| matches!(
                    effect.kind(),
                    EffectKind::Filesystem { effect }
                        if effect.host_integrity == expected
                            && (expected.is_some() || effect.sensitivity != Sensitivity::None)
                )),
                "{tool} {requested}: {:?}",
                stream.effects()
            );
        }

        let input = call("Write", json!({"file_path":"/tmp/ordinary","content":"x"}));
        let call_site = input.call_site(Platform::Linux).unwrap();
        let plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);
        let stream = finalize(
            plan,
            observation(Some(("/tmp/ordinary", Observed::Error { error: failure }))),
        );
        assert!(stream.effects().is_empty(), "{failure:?}");
    }
}

#[test]
fn sensitivity_uses_requested_name_and_canonical_target() {
    let cases = [
        (
            ".env.staging",
            "/repo/.env.staging",
            Sensitivity::EnvironmentSecret,
        ),
        (
            "alias",
            "/home/test/.ssh/id_ed25519",
            Sensitivity::CredentialSecret,
        ),
        ("alias", "/home/test/.bashrc", Sensitivity::OtherSensitive),
        (
            "alias",
            "/home/test/.aws/credentials",
            Sensitivity::CredentialSecret,
        ),
        (
            "~/.ssh/id_ed25519",
            "/repo/literal-home/.ssh/id_ed25519",
            Sensitivity::CredentialSecret,
        ),
        (
            "/home/*/.aws/credentials",
            "/home/*/.aws/credentials",
            Sensitivity::CredentialSecret,
        ),
        (
            "alias",
            "/home/test/.nah/audit.jsonl",
            Sensitivity::OtherSensitive,
        ),
        (
            "alias",
            "/etc/systemd/system/demo.service",
            Sensitivity::OtherSensitive,
        ),
        (
            ".git/config",
            "/repo/.git/config",
            Sensitivity::OtherSensitive,
        ),
    ];

    for (requested, canonical, expected) in cases {
        let input = call("Read", json!({"file_path":requested}));
        let call_site = input.call_site(Platform::Linux).unwrap();
        let plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);
        let stream = finalize(plan, successful_observation("Read", requested, canonical));
        assert!(matches!(
            stream.effects()[1].kind(),
            EffectKind::Filesystem { effect } if effect.sensitivity == expected
        ));
    }
}

#[test]
fn unrepresentable_search_sets_are_partial_and_exact_sensitive_globs_are_unclaimed() {
    for pattern in [
        "**/.env*",
        ".e??",
        "../outside/*",
        "*.rs",
        "@(terraform.tfvars|safe)",
        "!(safe)",
        "terraform\\.tfvars",
    ] {
        let input = call("Glob", json!({"pattern":pattern, "path":"/repo"}));
        let call_site = input.call_site(Platform::Linux).unwrap();
        let plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);
        let stream = finalize(plan, observation_without_path("Glob"));
        assert_eq!(stream.coverage(), Coverage::Partial, "{pattern}");
        assert!(stream.effects().is_empty());
    }

    let glob = call("Glob", json!({"pattern":".env", "path":"/repo"}));
    let call_site = glob.call_site(Platform::Linux).unwrap();
    let glob_plan = plan(AnalysisInput::Native(&glob), &ctx(), &call_site);
    let stream = finalize(
        glob_plan,
        successful_observation("Glob", "/repo/.env", "/repo/.env"),
    );
    assert!(matches!(
        stream.effects()[1].kind(),
        EffectKind::Filesystem { effect }
            if effect.sensitivity == Sensitivity::EnvironmentSecret
    ));

    let grep = call("Grep", json!({"pattern":"password", "path":"/repo"}));
    let call_site = grep.call_site(Platform::Linux).unwrap();
    let grep_plan = plan(AnalysisInput::Native(&grep), &ctx(), &call_site);
    let stream = finalize(
        grep_plan,
        successful_observation_kind("/repo", "/repo", PathKind::Directory),
    );
    assert_eq!(stream.coverage(), Coverage::Partial);

    let escaped_base = call(
        "Glob",
        json!({"pattern":"secret.txt", "path":"/repo/escape\\"}),
    );
    let call_site = escaped_base.call_site(Platform::Linux).unwrap();
    let plan = plan(AnalysisInput::Native(&escaped_base), &ctx(), &call_site);
    assert!(plan.observation_request().queries().iter().any(|query| {
        matches!(query, ObservationQuery::Path { requested, .. }
            if requested == "/repo/escape\\/secret.txt")
    }));
}

#[test]
fn worktree_main_root_selection_is_tagged_without_losing_its_scope() {
    let input = call("Write", json!({"file_path":"/main", "content":"x"}));
    let call_site = input.call_site(Platform::Linux).unwrap();
    let plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);
    let project = Root::new(RootKind::Project, absolute("/worktree"));
    let main = Root::new(RootKind::WorktreeMain, absolute("/main"));
    let observation = Observation::new(
        SchemaVersion::V1,
        "native-v1",
        vec![
            ObservationFact::new(
                ObservationQuery::Cwd {
                    key: "cwd".into(),
                    requested: absolute("/authoritative"),
                },
                ObservationValue::Cwd {
                    observed: Observed::Ok {
                        value: absolute("/authoritative"),
                    },
                },
            )
            .unwrap(),
            ObservationFact::new(
                ObservationQuery::Roots {
                    key: "roots".into(),
                    cwd_key: "cwd".into(),
                },
                ObservationValue::Roots {
                    observed: Observed::Ok {
                        value: vec![project.clone(), main],
                    },
                },
            )
            .unwrap(),
            ObservationFact::new(
                ObservationQuery::Path {
                    key: "target".into(),
                    requested: "/main".into(),
                    cwd_key: "cwd".into(),
                    inspect_descendants: false,
                    symlink_traversal: SymlinkTraversal::None,
                },
                ObservationValue::Path {
                    observed: Observed::Ok {
                        value: PathObservation::new(
                            absolute("/main"),
                            Some(absolute("/main")),
                            PathKind::Directory,
                        ),
                    },
                },
            )
            .unwrap(),
            ObservationFact::new(
                ObservationQuery::ProjectGuards {
                    key: "project-guards".into(),
                    roots_key: "roots".into(),
                },
                ObservationValue::ProjectGuards {
                    observation: ProjectGuardObservation::new(
                        Some(project),
                        ProjectGuardDeclaration::Absent,
                    )
                    .unwrap(),
                },
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let stream = finalize(plan, observation);
    assert!(matches!(
        stream.effects()[1].kind(),
        EffectKind::Filesystem { effect }
            if effect.selects_root
                && effect.scope == PathScope::Project { root: absolute("/main") }
    ));
}

#[test]
fn native_mutations_tag_nah_critical_and_proposal_paths() {
    for (target, expected) in [
        (
            "/home/test/.nah/trust.json",
            Some(NahProtectionTier::Critical),
        ),
        (
            "/home/test/.nah/nap.json",
            Some(NahProtectionTier::Permanent),
        ),
        (
            "/home/test/.nah/guards/corp/run",
            Some(NahProtectionTier::Proposal),
        ),
        ("/repo/.nah/project.toml", Some(NahProtectionTier::Proposal)),
        ("/home/test/.copilot/hooks/nah.json", None),
        ("/repo/.github/hooks/nah.json", None),
        ("/home/test/.hermes/plugins/nah/__init__.py", None),
        ("/home/test/.openclaw/extensions/nah/index.js", None),
        ("/home/test/.config/opencode/plugins/nah.js", None),
        ("/home/test/.config/amp/plugins/nah.ts", None),
        ("/home/test/.pi/agent/extensions/nah/index.js", None),
        ("/home/test/Documents/Cline/Hooks/PreToolUse", None),
        ("/repo/.claude/settings.json", None),
        ("/home/test/.copilot/settings.json", None),
        (
            "/home/test/.copilot/installed-plugins/example/hooks.json",
            None,
        ),
        ("/repo/.github/extensions/example/index.js", None),
        ("/repo/.github/copilot/settings.local.json", None),
        ("/repo/.vscode/settings.json", None),
        ("/repo/.cursor/hooks.json", None),
        ("/repo/.agents/hooks.json", None),
        ("/home/test/.gemini/config/hooks.json", None),
        (
            "/home/test/.gemini/antigravity-cli/plugins/unsafe/hooks.json",
            None,
        ),
        ("/home/test/.gemini/config/plugins/unsafe/hooks.json", None),
        ("/repo/.agents/plugins/unsafe/hooks.json", None),
        ("/home/test/.pi/agent/settings.json", None),
    ] {
        let input = call("Write", json!({"file_path":"target", "content":"x"}));
        let call_site = input.call_site(Platform::Linux).unwrap();
        let plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);
        let stream = finalize(plan, successful_observation("Write", "target", target));
        assert!(
            matches!(
                stream.effects()[1].kind(),
                EffectKind::Filesystem { effect } if effect.protection == expected
            ),
            "{target}: {:?}",
            stream.effects()
        );
    }

    let input = call("Read", json!({"file_path":"target"}));
    let call_site = input.call_site(Platform::Linux).unwrap();
    let plan = plan(AnalysisInput::Native(&input), &ctx(), &call_site);
    let stream = finalize(
        plan,
        successful_observation("Read", "target", "/home/test/.nah/trust.json"),
    );
    assert!(matches!(
        stream.effects()[1].kind(),
        EffectKind::Filesystem { effect } if effect.protection.is_none()
    ));
}

fn call(tool: &str, input: serde_json::Value) -> ToolCallInput {
    ToolCallInput::new(SchemaVersion::V1, tool, input, "/authoritative", None).unwrap()
}

fn ctx() -> Ctx {
    Ctx::new(
        SchemaVersion::V1,
        Platform::Linux,
        absolute("/home/test"),
        vec![],
        vec![],
        TrustProjection::new(vec![]).unwrap(),
        PolicyVersion::V1,
    )
    .unwrap()
}

fn successful_observation(tool: &str, requested: &str, canonical: &str) -> Observation {
    let query_requested = if matches!(tool, "Glob" | "Grep") && requested == "/authoritative" {
        "/authoritative"
    } else {
        requested
    };
    successful_observation_kind(query_requested, canonical, PathKind::File)
}

fn successful_observation_kind(requested: &str, canonical: &str, kind: PathKind) -> Observation {
    observation(Some((
        requested,
        Observed::Ok {
            value: PathObservation::new(absolute("/repo/file"), Some(absolute(canonical)), kind),
        },
    )))
}

fn observation_without_path(_tool: &str) -> Observation {
    observation(None)
}

fn observation(path: Option<(&str, Observed<PathObservation>)>) -> Observation {
    let project = Root::new(RootKind::Project, absolute("/repo"));
    let mut facts = vec![
        ObservationFact::new(
            ObservationQuery::Cwd {
                key: "cwd".into(),
                requested: absolute("/authoritative"),
            },
            ObservationValue::Cwd {
                observed: Observed::Ok {
                    value: absolute("/authoritative"),
                },
            },
        )
        .unwrap(),
        ObservationFact::new(
            ObservationQuery::Roots {
                key: "roots".into(),
                cwd_key: "cwd".into(),
            },
            ObservationValue::Roots {
                observed: Observed::Ok {
                    value: vec![project.clone()],
                },
            },
        )
        .unwrap(),
        ObservationFact::new(
            ObservationQuery::ProjectGuards {
                key: "project-guards".into(),
                roots_key: "roots".into(),
            },
            ObservationValue::ProjectGuards {
                observation: ProjectGuardObservation::new(
                    Some(project),
                    ProjectGuardDeclaration::Absent,
                )
                .unwrap(),
            },
        )
        .unwrap(),
    ];
    if let Some((requested, observed)) = path {
        facts.push(
            ObservationFact::new(
                ObservationQuery::Path {
                    key: "target".into(),
                    requested: requested.into(),
                    cwd_key: "cwd".into(),
                    inspect_descendants: false,
                    symlink_traversal: SymlinkTraversal::None,
                },
                ObservationValue::Path { observed },
            )
            .unwrap(),
        );
    }
    Observation::new(SchemaVersion::V1, "native-v1", facts).unwrap()
}

fn absolute(path: &str) -> AbsolutePath {
    AbsolutePath::new(Platform::Linux, path).unwrap()
}
