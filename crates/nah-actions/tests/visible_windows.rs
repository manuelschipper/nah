use nah_actions::{AnalysisInput, VisibleCode, finalize, plan};
use nah_parse::normalize;
use nah_proto::action::{Coverage, EffectKind, FilesystemOperation, InvocationEffect};
use nah_proto::ctx::{AbsolutePath, Ctx, Platform, SchemaVersion, TrustProjection};
use nah_proto::observation::{
    EnvObservation, Observation, ObservationFact, ObservationQuery, ObservationRequest,
    ObservationValue, Observed, PathKind, PathObservation, ProjectGuardDeclaration,
    ProjectGuardObservation, Root, RootKind,
};
use nah_proto::tool::ToolCallInput;
use serde_json::json;

fn absolute(path: &str) -> AbsolutePath {
    AbsolutePath::new(Platform::Windows, path).unwrap()
}

fn context() -> Ctx {
    Ctx::new(
        Platform::Windows,
        absolute(r"C:\Users\test"),
        vec![],
        vec![],
        TrustProjection::new(vec![]).unwrap(),
    )
    .unwrap()
}

fn direct_plan<'a>(visible: VisibleCode<'a>, source: &'a str) -> nah_actions::AnalysisPlan {
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "execute_windows_code",
        json!({"code":source}),
        r"C:\repo",
        None,
    )
    .unwrap();
    let call_site = input.call_site(Platform::Windows).unwrap();
    plan(
        AnalysisInput::VisibleCode(visible, &input),
        &context(),
        &call_site,
    )
}

fn nested_plan(source: &str) -> nah_actions::AnalysisPlan {
    let syntax = normalize(source).unwrap();
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        json!({"command":source}),
        r"C:\repo",
        None,
    )
    .unwrap();
    let call_site = input.call_site(Platform::Windows).unwrap();
    plan(AnalysisInput::Bash(&syntax, &input), &context(), &call_site)
}

fn observe(request: &ObservationRequest, directory: Option<&str>) -> Observation {
    let project = Root::new(RootKind::Project, absolute(r"C:\repo"));
    let facts = request
        .queries()
        .iter()
        .cloned()
        .map(|query| {
            let value = match &query {
                ObservationQuery::Cwd { .. } => ObservationValue::Cwd {
                    observed: Observed::Ok {
                        value: absolute(r"C:\repo"),
                    },
                },
                ObservationQuery::Roots { .. } => ObservationValue::Roots {
                    observed: Observed::Ok {
                        value: vec![project.clone()],
                    },
                },
                ObservationQuery::Env { .. } => ObservationValue::Env {
                    observed: Observed::Ok {
                        value: EnvObservation::Unset,
                    },
                },
                ObservationQuery::Path { requested, .. } => {
                    let resolved = if requested.as_bytes().get(1) == Some(&b':') {
                        requested.clone()
                    } else {
                        format!(r"C:\repo\{requested}")
                    };
                    let kind = if directory.is_some_and(|path| path.eq_ignore_ascii_case(requested))
                    {
                        PathKind::Directory
                    } else {
                        PathKind::Missing
                    };
                    ObservationValue::Path {
                        observed: Observed::Ok {
                            value: PathObservation::new(absolute(&resolved), None, kind),
                        },
                    }
                }
                ObservationQuery::ProjectGuards { .. } => ObservationValue::ProjectGuards {
                    observation: ProjectGuardObservation::new(
                        Some(project.clone()),
                        ProjectGuardDeclaration::Absent,
                    )
                    .unwrap(),
                },
            };
            ObservationFact::new(query, value).unwrap()
        })
        .collect();
    Observation::new(SchemaVersion::V1, request.request_id(), facts).unwrap()
}

fn filesystem_effects(
    plan: nah_actions::AnalysisPlan,
    directory: Option<&str>,
) -> Vec<(FilesystemOperation, String, bool, bool)> {
    let observation = observe(plan.observation_request(), directory);
    finalize(plan, observation)
        .effects()
        .iter()
        .filter_map(|effect| match effect.kind() {
            EffectKind::Filesystem { effect } => Some((
                effect.operation,
                effect.target.as_str().to_owned(),
                effect.recursive,
                effect.pattern,
            )),
            _ => None,
        })
        .collect()
}

#[test]
fn top_level_and_nested_windows_shells_share_canonical_filesystem_effects() {
    let powershell = r"Remove-Item -Recurse -LiteralPath 'C:\Users\test'";
    let direct = filesystem_effects(
        direct_plan(VisibleCode::Pwsh { source: powershell }, powershell),
        None,
    );
    let nested = filesystem_effects(
        nested_plan(r#"pwsh -c "Remove-Item -Recurse -LiteralPath 'C:\Users\test'""#),
        None,
    );
    assert_eq!(direct, nested);

    let cmd = r"rd /s /q C:\Users\test";
    let direct = filesystem_effects(direct_plan(VisibleCode::Cmd { source: cmd }, cmd), None);
    let nested = filesystem_effects(nested_plan(r#"cmd /c 'rd /s /q C:\Users\test'"#), None);
    assert_eq!(direct, nested);
}

#[test]
fn nested_powershell_command_joins_static_argv() {
    let source = r"Remove-Item -Recurse -LiteralPath C:\Users\test";
    let direct = filesystem_effects(
        direct_plan(VisibleCode::PowerShell { source }, source),
        None,
    );
    let nested = filesystem_effects(
        nested_plan(
            r#"cmd /c "powershell -Command Remove-Item -Recurse -LiteralPath C:\Users\test""#,
        ),
        None,
    );
    assert_eq!(direct, nested);
}

#[test]
fn powershell_hash_words_preserve_following_effects() {
    let source = r"Write-Output x#y; Remove-Item -Recurse -LiteralPath C:\Users\test";
    let effects = filesystem_effects(direct_plan(VisibleCode::Pwsh { source }, source), None);
    assert_eq!(
        effects,
        [(
            FilesystemOperation::Delete,
            r"C:\Users\test".into(),
            true,
            false
        )]
    );

    let hash_path = r"Remove-Item -Recurse -LiteralPath C:\Users\test#backup";
    let effects = filesystem_effects(
        direct_plan(VisibleCode::Pwsh { source: hash_path }, hash_path),
        None,
    );
    assert_eq!(effects[0].1, r"C:\Users\test#backup");
}

#[test]
fn powershell_escaped_semicolon_does_not_fabricate_later_effects() {
    let source = r"Write-Output x`; Remove-Item -Recurse -LiteralPath C:\Users\test";
    for plan in [
        direct_plan(VisibleCode::Pwsh { source }, source),
        nested_plan(
            r#"pwsh -c 'Write-Output x`; Remove-Item -Recurse -LiteralPath C:\Users\test'"#,
        ),
    ] {
        let observation = observe(plan.observation_request(), None);
        let stream = finalize(plan, observation);
        assert_eq!(stream.coverage(), Coverage::Full);
        assert!(
            stream
                .effects()
                .iter()
                .all(|effect| !matches!(effect.kind(), EffectKind::Filesystem { .. }))
        );
    }
}

#[test]
fn attached_powershell_redirection_lowers_at_both_entry_points() {
    let source = r"Write-Output evil>C:\Users\test\.nah\config.toml";
    let direct = filesystem_effects(direct_plan(VisibleCode::Pwsh { source }, source), None);
    let nested = filesystem_effects(
        nested_plan(r#"pwsh -Command 'Write-Output evil>C:\Users\test\.nah\config.toml'"#),
        None,
    );
    let expected = [(
        FilesystemOperation::Write,
        r"C:\Users\test\.nah\config.toml".into(),
        false,
        false,
    )];
    assert_eq!(direct, expected);
    assert_eq!(nested, expected);
}

#[test]
fn cmd_numeric_output_redirection_lowers_at_both_entry_points() {
    let source = r"type C:\safe 2>C:\Users\test\.nah\config.toml";
    let direct = filesystem_effects(direct_plan(VisibleCode::Cmd { source }, source), None);
    let nested = filesystem_effects(
        nested_plan(r#"cmd /c 'type C:\safe 2>C:\Users\test\.nah\config.toml'"#),
        None,
    );
    assert_eq!(direct, nested);
    assert!(direct.contains(&(
        FilesystemOperation::Write,
        r"C:\Users\test\.nah\config.toml".into(),
        false,
        false,
    )));
}

#[test]
fn windows_shell_line_continuations_are_partial_at_both_entry_points() {
    for (visible, source, nested, expected_target) in [
        (
            VisibleCode::Pwsh {
                source: "Write-Output ok `\nRemove-Item -Recurse C:\\Users\\test",
            },
            "Write-Output ok `\nRemove-Item -Recurse C:\\Users\\test",
            "pwsh -c 'Write-Output ok `\nRemove-Item -Recurse C:\\Users\\test'",
            None,
        ),
        (
            VisibleCode::Pwsh {
                source: "Remove-Item -Recurse `\nC:\\Users\\test",
            },
            "Remove-Item -Recurse `\nC:\\Users\\test",
            "pwsh -c 'Remove-Item -Recurse `\nC:\\Users\\test'",
            Some(r"C:\Users\test"),
        ),
        (
            VisibleCode::Cmd {
                source: "del /q ^\nC:\\Users\\test\\secret.txt",
            },
            "del /q ^\nC:\\Users\\test\\secret.txt",
            "cmd /c 'del /q ^\nC:\\Users\\test\\secret.txt'",
            None,
        ),
    ] {
        for plan in [direct_plan(visible, source), nested_plan(nested)] {
            let observation = observe(plan.observation_request(), None);
            let stream = finalize(plan, observation);
            assert_eq!(stream.coverage(), Coverage::Partial, "{source:?}");
            let targets = stream
                .effects()
                .iter()
                .filter_map(|effect| match effect.kind() {
                    EffectKind::Filesystem { effect } => Some(effect.target.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(
                targets,
                expected_target.into_iter().collect::<Vec<_>>(),
                "{source:?}"
            );
        }
    }
}

#[test]
fn escaped_non_ascii_windows_paths_lower_at_both_entry_points() {
    for (visible, source, nested) in [
        (
            VisibleCode::Pwsh {
                source: r#"Remove-Item "C:\Users\José`é.txt""#,
            },
            r#"Remove-Item "C:\Users\José`é.txt""#,
            r#"pwsh -c 'Remove-Item "C:\Users\José`é.txt"'"#,
        ),
        (
            VisibleCode::Cmd {
                source: r"type C:\Users\José^é.txt",
            },
            r"type C:\Users\José^é.txt",
            r"cmd /c 'type C:\Users\José^é.txt'",
        ),
    ] {
        let direct_plan = direct_plan(visible, source);
        let nested_plan = nested_plan(nested);
        assert!(!direct_plan.inline_failed(), "{source}");
        assert!(!nested_plan.inline_failed(), "{source}");
        assert_eq!(
            filesystem_effects(direct_plan, None),
            filesystem_effects(nested_plan, None),
            "{source}"
        );
    }
}

#[test]
fn powershell_path_and_literal_path_keep_pattern_selection_distinct() {
    for (source, pattern) in [
        (r"Remove-Item -Path 'C:\repo\*'", true),
        (r"Remove-Item -LiteralPath 'C:\repo\*'", false),
    ] {
        let effects = filesystem_effects(
            direct_plan(VisibleCode::PowerShell { source }, source),
            None,
        );
        assert_eq!(effects[0].3, pattern, "{source}");
    }
}

#[test]
fn powershell_collection_targets_do_not_claim_full_coverage() {
    let source = r"Remove-Item -Recurse -LiteralPath 'C:\safe','C:\Users\test'";
    let plan = direct_plan(VisibleCode::PowerShell { source }, source);
    let observation = observe(plan.observation_request(), Some(r"C:\Users\test"));
    let stream = finalize(plan, observation);
    assert_eq!(stream.coverage(), Coverage::Partial);
}

#[test]
fn powershell_tilde_home_uses_canonical_effects_at_both_entry_points() {
    let source = r"Remove-Item -Recurse -LiteralPath '~'";
    let direct = filesystem_effects(direct_plan(VisibleCode::Pwsh { source }, source), None);
    let nested = filesystem_effects(
        nested_plan(r#"pwsh -c "Remove-Item -Recurse -LiteralPath '~'""#),
        None,
    );
    let expected = [(
        FilesystemOperation::Delete,
        r"C:\Users\test".into(),
        true,
        false,
    )];
    assert_eq!(direct, expected);
    assert_eq!(nested, expected);
}

#[test]
fn powershell_variable_prefixes_remain_unresolved() {
    for source in [
        r"Remove-Item -Recurse $homelab",
        r"Remove-Item -Recurse $HOMEWORK",
        r"Remove-Item -Recurse $env:userprofileX",
        r"Remove-Item -Recurse ${home}lab",
    ] {
        let plan = direct_plan(VisibleCode::Pwsh { source }, source);
        let observation = observe(plan.observation_request(), None);
        let stream = finalize(plan, observation);
        assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
        assert!(
            !stream
                .effects()
                .iter()
                .any(|effect| matches!(effect.kind(), EffectKind::Filesystem { .. }))
        );
    }
}

#[test]
fn cmd_del_does_not_claim_directory_deletion_and_rd_is_not_implicitly_recursive() {
    let target = r"C:\repo\directory";
    for (source, recursive) in [
        (r"del C:\repo\directory", false),
        (r"del /s /q C:\repo\directory", true),
    ] {
        let del = direct_plan(VisibleCode::Cmd { source }, source);
        let observation = observe(del.observation_request(), Some(target));
        let stream = finalize(del, observation);
        assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
        assert!(
            !stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Delete
            )),
            "{source}"
        );
        // `del` erases the files the directory holds, so the deletion stays
        // visible as an unresolved selection carrying its `/s` scope.
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::FilesystemUnresolved { operation, recursive: observed }
                    if *operation == FilesystemOperation::Delete && *observed == recursive
            )),
            "{source}"
        );
    }

    let rd = filesystem_effects(
        direct_plan(
            VisibleCode::Cmd {
                source: r"rd C:\repo\directory",
            },
            r"rd C:\repo\directory",
        ),
        Some(target),
    );
    assert_eq!(
        rd,
        [(FilesystemOperation::Delete, target.into(), false, false)]
    );
}

#[test]
fn cmd_del_s_recurses_over_files_without_claiming_directories() {
    let source = r"del /s /q C:\Users\test\*";
    let effects = filesystem_effects(direct_plan(VisibleCode::Cmd { source }, source), None);
    assert_eq!(
        effects,
        [(
            FilesystemOperation::Delete,
            r"C:\Users\test\*".into(),
            true,
            true
        )]
    );
}

#[test]
fn exact_external_windows_argv_reuses_existing_invocation_lowering() {
    let source = r"git status; curl.exe -o C:\payload https://example.test/x; nah.exe guards";
    let plan = direct_plan(VisibleCode::Pwsh { source }, source);
    let observation = observe(plan.observation_request(), None);
    let stream = finalize(plan, observation);

    for expected in ["git", "curl.exe", "nah.exe"] {
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::Known { program, .. }
                        | InvocationEffect::Opaque { program, .. }
                } if program.eq_ignore_ascii_case(expected)
            )),
            "missing canonical lowering for {expected}: {:?}",
            stream.effects()
        );
    }
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Filesystem { effect }
            if effect.operation == FilesystemOperation::Write
                && effect.target.as_str() == r"C:\payload"
    )));
}
