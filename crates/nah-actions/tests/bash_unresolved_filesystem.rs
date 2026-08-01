mod support;

use nah_actions::{AnalysisInput, finalize, plan};
use nah_parse::normalize;
use nah_proto::action::{
    Coverage, EffectKind, FilesystemOperation, InvocationEffect, InvocationInput,
};
use nah_proto::ctx::{AbsolutePath, Ctx, Platform, PolicyVersion, SchemaVersion, TrustProjection};
use nah_proto::observation::{
    EnvObservation, Observation, ObservationFact, ObservationQuery, ObservationValue, Observed,
    PathKind, PathObservation, ProjectGuardDeclaration, ProjectGuardObservation, Root, RootKind,
};

fn platform_path(platform: Platform, value: &str) -> AbsolutePath {
    AbsolutePath::new(platform, value).unwrap()
}

fn lower_on(
    platform: Platform,
    cwd: &str,
    home: &str,
    source: &str,
) -> nah_proto::action::ActionStream {
    let syntax = normalize(source).unwrap();
    let input = nah_proto::tool::ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        serde_json::json!({"command": source}),
        cwd,
        None,
    )
    .unwrap();
    let call_site = input.call_site(platform).unwrap();
    let context = Ctx::new(
        SchemaVersion::V1,
        platform,
        platform_path(platform, home),
        vec![],
        vec![],
        TrustProjection::new(vec![]).unwrap(),
        PolicyVersion::V1,
    )
    .unwrap();
    let plan = plan(AnalysisInput::Bash(&syntax, &input), &context, &call_site);
    let project = Root::new(RootKind::Project, platform_path(platform, cwd));
    let facts = plan
        .observation_request()
        .queries()
        .iter()
        .map(|query| {
            let value = match query {
                ObservationQuery::Cwd { requested, .. } => ObservationValue::Cwd {
                    observed: Observed::Ok {
                        value: requested.clone(),
                    },
                },
                ObservationQuery::Roots { .. } => ObservationValue::Roots {
                    observed: Observed::Ok {
                        value: vec![project.clone()],
                    },
                },
                ObservationQuery::ProjectGuards { .. } => ObservationValue::ProjectGuards {
                    observation: ProjectGuardObservation::new(
                        Some(project.clone()),
                        ProjectGuardDeclaration::Absent,
                    )
                    .unwrap(),
                },
                ObservationQuery::Path { requested, .. } => ObservationValue::Path {
                    observed: Observed::Ok {
                        value: PathObservation::new(
                            platform_path(platform, requested),
                            None,
                            PathKind::Missing,
                        ),
                    },
                },
                ObservationQuery::Env { .. } => ObservationValue::Env {
                    observed: Observed::Ok {
                        value: EnvObservation::Unset,
                    },
                },
            };
            ObservationFact::new(query.clone(), value).unwrap()
        })
        .collect();
    let observation = Observation::new(
        SchemaVersion::V1,
        plan.observation_request().request_id(),
        facts,
    )
    .unwrap();
    finalize(plan, observation)
}

fn has_pattern(stream: &nah_proto::action::ActionStream, platform: Platform, target: &str) -> bool {
    stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Delete
                    && effect.target == platform_path(platform, target)
                    && effect.pattern
                    && effect.recursive
        )
    })
}

fn has_visible_dynamic_invocation(
    stream: &nah_proto::action::ActionStream,
    expected_program: &str,
) -> bool {
    stream.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Invocation {
                invocation:
                    InvocationEffect::Known {
                        program,
                        input: InvocationInput::Shell { words, argv },
                        ..
                    }
            } if program == expected_program
                && argv.is_none()
                && words.iter().any(|word| word.contains("$(target)"))
        )
    })
}

#[test]
fn unresolved_destructive_targets_stay_partial_without_inventing_a_scope() {
    for (platform, cwd, home, source, program) in [
        (
            Platform::Windows,
            r"C:\repo",
            r"C:\Users\Test",
            r#"target(){ printf D:/victim; }; rm -rf "$(target)""#,
            "rm",
        ),
        (
            Platform::Windows,
            r"\\server\share\repo",
            r"C:\Users\Test",
            r#"target(){ printf C:/victim; }; rm -rf "$(target)""#,
            "rm",
        ),
        (
            Platform::Windows,
            r"C:\repo",
            r"C:\Users\Test",
            r#"target(){ printf D:/victim; }; chmod -R 000 "$(target)""#,
            "chmod",
        ),
        (
            Platform::Linux,
            "/repo",
            "/home/test",
            r#"target(){ printf /etc; }; rm -rf "$(target)""#,
            "rm",
        ),
    ] {
        let stream = lower_on(platform, cwd, home, source);

        assert_eq!(stream.coverage(), Coverage::Partial, "{cwd}");
        assert!(
            !stream
                .effects()
                .iter()
                .any(|effect| matches!(effect.kind(), EffectKind::Filesystem { .. })),
            "{cwd}: {:?}",
            stream.effects()
        );
        assert!(
            has_visible_dynamic_invocation(&stream, program),
            "{cwd}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn windows_static_targets_and_patterns_do_not_gain_unresolved_evidence() {
    let target = lower_on(
        Platform::Windows,
        r"C:\repo",
        r"C:\Users\Test",
        "rm -rf D:/victim",
    );
    assert!(target.effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Delete
                    && effect.target == platform_path(Platform::Windows, "D:/victim")
                    && effect.recursive
                    && !effect.pattern
        )
    }));
    assert!(
        !target
            .effects()
            .iter()
            .any(|effect| matches!(effect.kind(), EffectKind::FilesystemUnresolved { .. }))
    );

    let pattern = lower_on(
        Platform::Windows,
        r"C:\repo",
        r"C:\Users\Test",
        "rm -rf D:/*",
    );
    assert!(has_pattern(&pattern, Platform::Windows, "D:/*"));
    assert!(
        !pattern
            .effects()
            .iter()
            .any(|effect| matches!(effect.kind(), EffectKind::FilesystemUnresolved { .. }))
    );
}
