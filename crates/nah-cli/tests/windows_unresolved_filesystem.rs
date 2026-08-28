mod support;

use nah_cli::decide_with;
use nah_proto::action::{
    Coverage, EffectKind, FilesystemOperation, InvocationEffect, InvocationInput,
};
use nah_proto::ctx::{AbsolutePath, Ctx, Platform, SchemaVersion, TrustProjection};
use nah_proto::decision::Verdict;
use nah_proto::observation::{
    EnvObservation, Observation, ObservationFact, ObservationQuery, ObservationRequest,
    ObservationValue, Observed, PathKind, PathObservation, ProjectGuardDeclaration,
    ProjectGuardObservation, Root, RootKind,
};
use nah_proto::tool::ToolCallInput;
use serde_json::json;

fn windows_path(value: &str) -> AbsolutePath {
    AbsolutePath::new(Platform::Windows, value).unwrap()
}

fn windows_context() -> Ctx {
    Ctx::new(
        Platform::Windows,
        windows_path(r"C:\Users\Test"),
        nah_cli::all_shipped_guard_states_enabled(),
        vec![],
        TrustProjection::new(vec![]).unwrap(),
    )
    .unwrap()
}

fn windows_input(cwd: &str, command: &str) -> ToolCallInput {
    ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        json!({"command": command}),
        cwd,
        None,
    )
    .unwrap()
}

fn observed(request: &ObservationRequest) -> Observation {
    let cwd = request
        .queries()
        .iter()
        .find_map(|query| match query {
            ObservationQuery::Cwd { requested, .. } => Some(requested.clone()),
            _ => None,
        })
        .unwrap();
    let project = Root::new(RootKind::Project, cwd);
    let facts = request
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
                            windows_path(requested),
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
    Observation::new(request.version(), request.request_id(), facts).unwrap()
}

fn has_visible_dynamic_invocation(result: &nah_cli::DecisionResult, program: &str) -> bool {
    result.action_stream().effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Invocation {
                invocation:
                    InvocationEffect::Known {
                        program: actual_program,
                        input: InvocationInput::Shell { words, argv },
                        ..
                    }
            } if actual_program == program
                && argv.is_none()
                && words.iter().any(|word| word.contains("$(target)"))
        )
    })
}

#[test]
fn windows_unresolved_destructive_targets_delegate_without_inventing_a_namespace() {
    for (cwd, command, program) in [
        (
            r"C:\repo",
            r#"target(){ printf D:/victim; }; rm -rf "$(target)""#,
            "rm",
        ),
        (
            r"\\server\share\repo",
            r#"target(){ printf C:/victim; }; rm -rf "$(target)""#,
            "rm",
        ),
        (
            r"C:\repo",
            r#"target(){ printf D:/victim; }; chmod -R 000 "$(target)""#,
            "chmod",
        ),
        (
            r"C:\repo",
            r#"target(){ printf D:/victim; }; rm -f "$(target)""#,
            "rm",
        ),
        (
            r"C:\repo",
            r#"target(){ printf D:/victim; }; chmod 000 "$(target)""#,
            "chmod",
        ),
    ] {
        let result = decide_with(
            &windows_input(cwd, command),
            &windows_context(),
            |request| Ok(observed(request)),
        );

        assert_eq!(result.core().verdict(), Verdict::Delegate, "{cwd}");
        assert_eq!(result.core().coverage(), Coverage::Partial, "{cwd}");
        assert!(
            !result
                .action_stream()
                .effects()
                .iter()
                .any(|effect| matches!(effect.kind(), EffectKind::Filesystem { .. })),
            "{cwd}: {:?}",
            result.action_stream().effects()
        );
        assert!(has_visible_dynamic_invocation(&result, program), "{cwd}");
    }
}

#[test]
fn windows_static_destructive_target_keeps_its_exact_effect() {
    let command = "rm -rf D:/victim";
    let result = decide_with(
        &windows_input(r"C:\repo", command),
        &windows_context(),
        |request| Ok(observed(request)),
    );
    assert_eq!(result.core().verdict(), Verdict::Delegate);
    assert!(result.action_stream().effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Delete
                    && effect.target == windows_path("D:/victim")
                    && effect.recursive
                    && !effect.pattern
        )
    }));
}
