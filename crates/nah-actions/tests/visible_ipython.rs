mod support;

use nah_actions::{AnalysisInput, VisibleCode, finalize, plan};
use nah_proto::action::{
    Coverage, EffectKind, FilesystemOperation, InvocationEffect, InvocationInput, SemanticCode,
};
use nah_proto::ctx::{Platform, SchemaVersion};
use nah_proto::observation::ObservationQuery;
use nah_proto::tool::ToolCallInput;
use serde_json::json;
use support::{ctx, observe};

fn ipython_plan(source: &str) -> nah_actions::AnalysisPlan {
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "ipython",
        json!({"code":source}),
        "/repo",
        None,
    )
    .unwrap()
    .with_original_input(json!({"code":source}), true);
    let call_site = input.call_site(Platform::Linux).unwrap();
    plan(
        AnalysisInput::VisibleCode(VisibleCode::Ipython { source }, &input),
        &ctx(),
        &call_site,
    )
}

#[test]
fn direct_ipython_uses_current_cell_imports() {
    let source = "import os; os.remove('/tmp/direct-target')";
    let plan = ipython_plan(source);
    assert!(plan.observation_request().queries().iter().any(|query| {
        matches!(query, ObservationQuery::Path { requested, .. } if requested == "/tmp/direct-target")
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
        } if program == "ipython"
            && interpreter == "ipython"
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
            && program == "ipython"
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
fn persistent_names_shell_dialect_and_rewritten_cells_stay_unknown() {
    for source in [
        "get_ipython().system('rm -rf /tmp/prior-shell')",
        "prior_callable()",
        "prior_object.method()",
        "!rm -rf /tmp/prior-shell",
        "from IPython import get_ipython\n!rm -rf /tmp/current-import-shell",
        "from IPython import get_ipython\n!!rm -rf /tmp/current-import-shell",
        "%%bash\nrm -rf /tmp/rewritten-cell",
    ] {
        let plan = ipython_plan(source);
        assert!(
            !plan.observation_request().queries().iter().any(
                |query| matches!(query, ObservationQuery::Env { name, .. } if name == "SHELL")
            )
        );
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
        assert_eq!(stream.effects().len(), 1, "{source}");
        assert!(matches!(
            stream.effects()[0].kind(),
            EffectKind::Invocation {
                invocation: InvocationEffect::CodeExecution { .. }
            }
        ));
    }
}

#[test]
fn direct_ipython_keeps_relative_kernel_cwd_unknown() {
    let source = "import os; os.remove('cache')";
    let plan = ipython_plan(source);
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
}
