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
fn cmd_del_does_not_claim_directory_deletion_and_rd_is_not_implicitly_recursive() {
    let target = r"C:\repo\directory";
    for source in [r"del C:\repo\directory", r"del /s /q C:\repo\directory"] {
        let del = direct_plan(VisibleCode::Cmd { source }, source);
        let observation = observe(del.observation_request(), Some(target));
        let stream = finalize(del, observation);
        assert_eq!(stream.coverage(), Coverage::Partial);
        assert!(!stream.effects().iter().any(|effect| matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Delete
        )));
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
