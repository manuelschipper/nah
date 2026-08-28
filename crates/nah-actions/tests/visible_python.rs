mod support;

use nah_actions::{AnalysisInput, VisibleCode, finalize, plan};
use nah_proto::action::{
    Coverage, EffectKind, FilesystemOperation, HostIntegrityClass, InvocationEffect,
    InvocationInput, SemanticCode,
};
use nah_proto::ctx::{Platform, SchemaVersion};
use nah_proto::observation::{
    Observation, ObservationFact, ObservationQuery, ObservationValue, Observed, PathKind,
    PathObservation,
};
use nah_proto::tool::ToolCallInput;
use serde_json::json;
use support::{Change, absolute, ctx, facts, observe};

fn python_plan(source: &str) -> nah_actions::AnalysisPlan {
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "execute_code",
        json!({"code":source,"language":"python"}),
        "/repo",
        None,
    )
    .unwrap()
    .with_original_input(json!({"code":source}), true);
    let call_site = input.call_site(Platform::Linux).unwrap();
    plan(
        AnalysisInput::VisibleCode(VisibleCode::Python { source }, &input),
        &ctx(),
        &call_site,
    )
}

#[test]
fn direct_python_uses_native_outer_evidence_and_exact_absolute_effects() {
    let source = "import os; os.remove('/tmp/direct-target')";
    let plan = python_plan(source);
    assert!(plan.observation_request().queries().iter().any(|query| {
        matches!(
            query,
            ObservationQuery::Path { key, requested, .. }
                if key == "language-0000-path-0000-00"
                    && requested == "/tmp/direct-target"
        )
    }));
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert_eq!(stream.coverage(), Coverage::Full);
    assert!(matches!(
        stream.effects()[0].kind(),
        EffectKind::Invocation {
            invocation: InvocationEffect::CodeExecution {
                program,
                interpreter: Some(interpreter),
                source: effect_source,
                code: Some(code),
                input: InvocationInput::Native { value, complete: true },
                cwd: None,
            }
        } if program == "execute_code"
            && interpreter == "python"
            && effect_source == &SemanticCode::INTERPRETER_INLINE
            && code == source
            && value == &json!({"code":source})
    ));
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Invocation {
            invocation: InvocationEffect::Known {
                program,
                operation,
                ..
            }
        } if effect.stage().as_str() == "s1"
            && program == "python"
            && operation == &SemanticCode::DIRECT_FILE
    )));
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Filesystem { effect: filesystem }
            if effect.stage().as_str() == "s1"
                && filesystem.operation == FilesystemOperation::Delete
                && filesystem.target.as_str() == "/tmp/direct-target"
    )));
}

#[test]
fn direct_python_filesystem_writes_carry_host_integrity_classification() {
    for (source, expected) in [
        (
            "from pathlib import Path; Path('/home/test/.bashrc').write_text('alias ll=ls')",
            HostIntegrityClass::ShellProfile,
        ),
        (
            "from pathlib import Path; Path('/home/test/.ssh/authorized_keys').write_text('key')",
            HostIntegrityClass::AuthIdentity,
        ),
    ] {
        let plan = python_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Write
                        && effect.host_integrity == Some(expected)
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn direct_python_keeps_relative_cwd_unknown_and_reuses_child_lowering() {
    let source =
        "import os, subprocess; os.remove('cache'); subprocess.run(['rm', '-f', '/tmp/child'])";
    let plan = python_plan(source);
    assert!(!plan.observation_request().queries().iter().any(|query| {
        matches!(query, ObservationQuery::Path { requested, .. } if requested == "/repo/cache")
    }));
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert_eq!(stream.coverage(), Coverage::Partial);
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::FilesystemUnresolved {
            operation: FilesystemOperation::Delete,
            recursive: false,
        } if effect.stage().as_str() == "s1"
    )));
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Invocation {
            invocation: InvocationEffect::Known { program, .. }
        } if effect.stage().as_str() == "s3" && program == "rm"
    )));
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Filesystem { effect: filesystem }
            if effect.stage().as_str() == "s3"
                && filesystem.operation == FilesystemOperation::Delete
                && filesystem.target.as_str() == "/tmp/child"
    )));
}

#[test]
fn direct_python_preserves_no_follow_final_symlink_targets() {
    let source = "import os; os.symlink('/tmp/source', '/tmp/alias')";
    let plan = python_plan(source);
    let observation = Observation::new(
        SchemaVersion::V1,
        plan.observation_request().request_id(),
        facts(plan.observation_request(), "echo", Change::None)
            .into_iter()
            .map(|fact| match fact.query() {
                ObservationQuery::Path { requested, .. } if requested == "/tmp/alias" => {
                    ObservationFact::new(
                        fact.query().clone(),
                        ObservationValue::Path {
                            observed: Observed::Ok {
                                value: PathObservation::new(
                                    absolute("/tmp/alias"),
                                    Some(absolute("/tmp/referent")),
                                    PathKind::Symlink,
                                )
                                .with_target_kind(PathKind::File),
                            },
                        },
                    )
                    .unwrap()
                }
                _ => fact,
            })
            .collect(),
    )
    .unwrap();
    let stream = finalize(plan, observation);
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Filesystem { effect: filesystem }
            if filesystem.operation == FilesystemOperation::Write
                && filesystem.target.as_str() == "/tmp/alias"
    )));
    assert!(!stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Filesystem { effect: filesystem }
            if filesystem.target.as_str() == "/tmp/referent"
    )));
}

#[test]
fn direct_python_keeps_observed_hardlink_identity_queries() {
    let source = "import os; os.link('/tmp/source', '/tmp/alias', follow_symlinks=False)";
    let plan = python_plan(source);
    assert!(
        plan.observation_request()
            .queries()
            .iter()
            .any(|query| matches!(
                query,
                ObservationQuery::Path { key, requested, .. }
                    if key == "language-0000-identity-0000-01" && requested == "/tmp/source"
            ))
    );
}

#[test]
fn unknown_python_calls_add_no_capabilities() {
    let plan = python_plan("plugin.remove('/tmp/not-an-effect')");
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert_eq!(stream.coverage(), Coverage::Full);
    assert_eq!(stream.effects().len(), 1);
    assert!(matches!(
        stream.effects()[0].kind(),
        EffectKind::Invocation {
            invocation: InvocationEffect::CodeExecution { .. }
        }
    ));
}
