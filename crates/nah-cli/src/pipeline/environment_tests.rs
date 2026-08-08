use nah_proto::action::{
    Coverage, EffectKind, FilesystemOperation, InvocationEffect, InvocationInput, SemanticCode,
};
use nah_proto::ctx::{AbsolutePath, Ctx, Platform, SchemaVersion, TrustProjection};
use nah_proto::decision::Verdict;
use nah_proto::observation::{
    EnvObservation, Observation, ObservationFact, ObservationFailure, ObservationQuery,
    ObservationRequest, ObservationValue, Observed, PathKind, PathObservation,
    ProjectGuardDeclaration, ProjectGuardObservation, Root, RootKind,
};
use nah_proto::tool::ToolCallInput;
use serde_json::json;

use super::{
    ConsultedExtensions, decide_with, decide_with_code, decide_with_extensions,
    decide_with_extensions_mode,
};
use crate::catalog::POLICY_VERSION;
use crate::code_input::CodeInput;

fn context() -> Ctx {
    Ctx::new(
        SchemaVersion::V1,
        Platform::Linux,
        absolute("/home/test"),
        vec![],
        vec![],
        TrustProjection::new(vec![]).unwrap(),
        POLICY_VERSION,
    )
    .unwrap()
}

fn input(command: &str) -> ToolCallInput {
    ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        json!({"command": command}),
        "/repo",
        None,
    )
    .unwrap()
}

fn python_input(source: &str) -> ToolCallInput {
    ToolCallInput::new(
        SchemaVersion::V1,
        "execute_code",
        json!({"code":source,"language":"python"}),
        "/repo",
        None,
    )
    .unwrap()
    .with_original_input(json!({"code":source}), true)
}

fn openclaw_code_input(source: &str, language: &str) -> ToolCallInput {
    ToolCallInput::new(
        SchemaVersion::V1,
        "OpenClawCodeModeExec",
        json!({"code":source,"language":language}),
        "/repo",
        None,
    )
    .unwrap()
    .with_original_input(json!({"code":source,"command":source}), true)
}

fn absolute(path: &str) -> AbsolutePath {
    AbsolutePath::new(Platform::Linux, path).unwrap()
}

fn environment_names(request: &ObservationRequest) -> Vec<&str> {
    request
        .queries()
        .iter()
        .filter_map(|query| match query {
            ObservationQuery::Env { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect()
}

fn env_only(request: &ObservationRequest) -> bool {
    !request.queries().is_empty()
        && request
            .queries()
            .iter()
            .all(|query| matches!(query, ObservationQuery::Env { .. }))
}

fn observed<F>(request: &ObservationRequest, mut environment: F) -> Observation
where
    F: FnMut(&str) -> Observed<EnvObservation>,
{
    observed_with_id(request, request.request_id(), &mut environment)
}

fn observed_with_id<F>(
    request: &ObservationRequest,
    request_id: &str,
    mut environment: F,
) -> Observation
where
    F: FnMut(&str) -> Observed<EnvObservation>,
{
    let project = Root::new(RootKind::Project, absolute("/repo"));
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
                ObservationQuery::Env { name, .. } => ObservationValue::Env {
                    observed: environment(name),
                },
                ObservationQuery::Path { requested, .. } => {
                    let resolved = AbsolutePath::new(Platform::Linux, requested)
                        .unwrap_or_else(|_| absolute(&format!("/repo/{requested}")));
                    ObservationValue::Path {
                        observed: Observed::Ok {
                            value: PathObservation::new(resolved, None, PathKind::Missing),
                        },
                    }
                }
            };
            ObservationFact::new(query.clone(), value).unwrap()
        })
        .collect();
    Observation::new(request.version(), request_id, facts).unwrap()
}

fn value(text: impl Into<String>) -> Observed<EnvObservation> {
    Observed::Ok {
        value: EnvObservation::Value { text: text.into() },
    }
}

fn has_delete(result: &super::DecisionResult, target: &str) -> bool {
    result.action_stream().effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Filesystem { effect }
                if effect.operation == FilesystemOperation::Delete
                    && effect.target.as_str() == target
        )
    })
}

#[test]
fn calls_without_environment_dependencies_observe_once() {
    let mut calls = 0;
    let result = decide_with(&input("echo hello"), &context(), |request| {
        calls += 1;
        assert!(!env_only(request));
        Ok(observed(request, |_| value("unused")))
    });

    assert_eq!(calls, 1);
    assert_eq!(result.core().verdict(), Verdict::Delegate);
}

#[test]
fn direct_python_pipeline_keeps_absolute_and_unresolved_relative_effects_distinct() {
    let source = "import os; os.remove('/tmp/exact'); os.remove('relative')";
    let input = python_input(source);
    let code = CodeInput::Python {
        source: source.into(),
    };
    let result = decide_with_code(&input, &code, &context(), |request| {
        assert!(request.queries().iter().any(|query| {
            matches!(query, ObservationQuery::Path { requested, .. } if requested == "/tmp/exact")
        }));
        assert!(!request.queries().iter().any(|query| {
            matches!(query, ObservationQuery::Path { requested, .. } if requested == "/repo/relative")
        }));
        Ok(observed(request, |_| value("unused")))
    });

    assert_eq!(result.action_stream().coverage(), Coverage::Partial);
    assert!(matches!(
        result.action_stream().effects()[0].kind(),
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
    assert!(has_delete(&result, "/tmp/exact"));
    assert!(
        result
            .action_stream()
            .effects()
            .iter()
            .any(|effect| matches!(
                effect.kind(),
                EffectKind::FilesystemUnresolved {
                    operation: FilesystemOperation::Delete,
                    recursive: false,
                }
            ))
    );
}

#[test]
fn direct_openclaw_code_uses_the_proven_language_without_node_ownership() {
    for (source, language, code) in [
        (
            "return require('fs').rmSync('/tmp/not-node')",
            "javascript",
            CodeInput::OpenClawJavaScript {
                source: "return require('fs').rmSync('/tmp/not-node')".into(),
                restart_safe: None,
            },
        ),
        (
            "const value: number = 1; return value",
            "typescript",
            CodeInput::OpenClawTypeScript {
                source: "const value: number = 1; return value".into(),
                restart_safe: None,
            },
        ),
        (
            "await tools.call('read_file',{path:'/tmp/not-direct'}); return 1",
            "javascript",
            CodeInput::OpenClawJavaScript {
                source: "await tools.call('read_file',{path:'/tmp/not-direct'}); return 1".into(),
                restart_safe: None,
            },
        ),
    ] {
        let input = openclaw_code_input(source, language);
        let result = decide_with_code(&input, &code, &context(), |request| {
            assert!(!request.queries().iter().any(|query| {
                matches!(query, ObservationQuery::Path { requested, .. } if requested == "/tmp/not-node")
            }));
            Ok(observed(request, |_| value("unused")))
        });
        assert!(matches!(
            result.action_stream().effects()[0].kind(),
            EffectKind::Invocation {
                invocation: InvocationEffect::CodeExecution {
                    program,
                    interpreter: Some(interpreter),
                    source: effect_source,
                    code: Some(actual),
                    ..
                }
            } if program == "OpenClawCodeModeExec"
                && interpreter == language
                && effect_source == &SemanticCode::INTERPRETER_INLINE
                && actual == source
        ));
        assert_eq!(result.action_stream().effects().len(), 1);
        assert!(!has_delete(&result, "/tmp/not-node"));
    }
}

#[test]
fn visible_python_is_never_inferred_without_the_typed_code_input() {
    let source = "import os; os.remove('/tmp/not-routed')";
    let input = python_input(source);
    let result = decide_with(&input, &context(), |request| {
        assert!(
            !request
                .queries()
                .iter()
                .any(|query| matches!(query, ObservationQuery::Path { .. }))
        );
        Ok(observed(request, |_| value("unused")))
    });

    assert_eq!(result.action_stream().effects().len(), 1);
    assert!(matches!(
        result.action_stream().effects()[0].kind(),
        EffectKind::Invocation {
            invocation: InvocationEffect::Opaque { program, .. }
        } if program == "execute_code"
    ));
}

#[test]
fn ambient_program_and_operand_gain_canonical_path_observation() {
    let mut calls = 0;
    let result = decide_with(&input("$TOOL $TARGET"), &context(), |request| {
        calls += 1;
        if calls == 1 {
            assert!(env_only(request));
            assert_eq!(environment_names(request), ["TARGET", "TOOL"]);
        } else {
            assert_eq!(environment_names(request), ["TARGET", "TOOL"]);
            assert!(request.queries().iter().any(|query| {
                matches!(
                    query,
                    ObservationQuery::Path { requested, .. } if requested == "/repo/victim"
                )
            }));
        }
        Ok(observed(request, |name| match name {
            "TOOL" => value("rm"),
            "TARGET" => value("victim"),
            _ => value(""),
        }))
    });

    assert_eq!(calls, 2);
    assert!(has_delete(&result, "/repo/victim"));
    assert!(result.action_stream().effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Invocation {
                invocation: InvocationEffect::Known { program, .. }
            } if program == "rm"
        )
    }));
}

#[test]
fn preflight_repeats_for_environment_names_discovered_inside_payloads() {
    let command = "bash -c \"$PAYLOAD\"";
    let mut requests = Vec::new();
    let result = decide_with(&input(command), &context(), |request| {
        requests.push(
            environment_names(request)
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        );
        Ok(observed(request, |name| match name {
            "PAYLOAD" => value("rm -f \"$TARGET\""),
            "TARGET" => value("victim"),
            _ => value(""),
        }))
    });

    assert_eq!(
        requests,
        [
            vec!["PAYLOAD"],
            vec!["PAYLOAD", "TARGET"],
            vec!["PAYLOAD", "TARGET"],
        ]
    );
    assert!(has_delete(&result, "/repo/victim"));
}

#[test]
fn full_observation_drift_replans_before_one_extension_consultation() {
    let mut observation_calls = 0;
    let mut consultation_calls = 0;
    let result = decide_with_extensions(
        &input("$TOOL victim"),
        &context(),
        |request| {
            observation_calls += 1;
            let tool = if observation_calls == 1 { "echo" } else { "rm" };
            Ok(observed(request, |name| match name {
                "TOOL" => value(tool),
                _ => value(""),
            }))
        },
        |_, _| {
            consultation_calls += 1;
            ConsultedExtensions::default()
        },
    );

    assert_eq!(observation_calls, 3);
    assert_eq!(consultation_calls, 1);
    assert!(has_delete(&result, "/repo/victim"));
}

#[test]
fn runtime_self_protection_survives_environment_replanning_and_obeys_nap_mode() {
    let self_protection = nah_actions::SelfProtectionProjection::new(vec![absolute(
        "/home/test/.kiro/hooks/nah.json",
    )]);
    for (mode, expected) in [
        (nah_policy::EnforcementMode::Normal, Verdict::Block),
        (
            nah_policy::EnforcementMode::SelfProtectionPaused,
            Verdict::Delegate,
        ),
    ] {
        let mut calls = 0;
        let result = decide_with_extensions_mode(
            &input("$TOOL \"$TARGET\""),
            None,
            &context(),
            &self_protection,
            mode,
            |request| {
                calls += 1;
                Ok(observed(request, |name| match name {
                    "TOOL" => value("rm"),
                    "TARGET" => value("/home/test/.kiro/hooks/nah.json"),
                    _ => value(""),
                }))
            },
            |_, _| ConsultedExtensions::default(),
            false,
        );
        assert_eq!(calls, 2);
        assert_eq!(result.core().verdict(), expected);
    }
}

#[test]
fn runtime_self_protection_tracks_static_python_path_variables() {
    let self_protection = nah_actions::SelfProtectionProjection::new(vec![absolute(
        "/home/test/.config/amp/plugins/nah.ts",
    )]);
    for (command, expected) in [
        (
            "python3 - <<'PY'\nfrom pathlib import Path\nplugin = Path('/home/test/.config/amp/plugins/nah.ts')\nprobe = plugin.with_name('nah.ts.probe')\nplugin.rename(probe)\nprobe.rename(plugin)\nPY",
            Verdict::Block,
        ),
        (
            "python3 - <<'PY'\nfrom pathlib import Path\nplugins = Path('/home/test/.config/amp/plugins')\nprobe = plugins.with_name('plugins.probe')\nplugins.rename(probe)\nprobe.rename(plugins)\nPY",
            Verdict::Block,
        ),
        (
            "python3 - <<'PY'\nfrom pathlib import Path\nplugin = Path('/home/test/.config/amp/plugins/nah.ts')\nother = Path('/tmp/example')\nother.rename('/tmp/renamed')\nPY",
            Verdict::Delegate,
        ),
        (
            "python3 - <<'PY'\nfrom pathlib import Path\nplugins = Path('/home/test/.config/amp/plugins')\nplugins.mkdir(exist_ok=True)\nPY",
            Verdict::Delegate,
        ),
    ] {
        let result = decide_with_extensions_mode(
            &input(command),
            None,
            &context(),
            &self_protection,
            nah_policy::EnforcementMode::Normal,
            |request| {
                Ok(observed(request, |_| Observed::Ok {
                    value: EnvObservation::Unset,
                }))
            },
            |_, _| ConsultedExtensions::default(),
            false,
        );
        assert_eq!(result.core().verdict(), expected, "{command}");
    }
}

#[test]
fn unset_and_failed_environment_reads_stabilize_conservatively() {
    for environment in [
        Observed::Ok {
            value: EnvObservation::Unset,
        },
        Observed::Error {
            error: ObservationFailure::Unavailable,
        },
    ] {
        let mut calls = 0;
        let result = decide_with(&input("$TOOL victim"), &context(), |request| {
            calls += 1;
            Ok(observed(request, |_| environment.clone()))
        });
        assert_eq!(calls, 2);
        assert_eq!(result.core().verdict(), Verdict::Delegate);
        assert_eq!(
            result.core().coverage(),
            nah_proto::action::Coverage::Partial
        );
    }
}

#[test]
fn invalid_full_observation_delegates_with_a_failure_without_finalization() {
    let mut calls = 0;
    let result = decide_with(&input("$TOOL victim"), &context(), |request| {
        calls += 1;
        let request_id = if calls == 1 {
            request.request_id()
        } else {
            "wrong-request"
        };
        Ok(observed_with_id(request, request_id, |_| value("rm")))
    });

    assert_eq!(calls, 2);
    assert_eq!(result.core().verdict(), Verdict::Delegate);
    assert_eq!(result.failures()[0].component(), "observation");
    assert!(result.observation().is_none());
}

#[test]
fn oscillating_environment_delegates_with_a_warning() {
    let mut calls = 0;
    let result = decide_with(&input("$TOOL victim"), &context(), |request| {
        calls += 1;
        let tool = if calls % 2 == 1 { "echo" } else { "rm" };
        Ok(observed(request, |_| value(tool)))
    });

    assert_eq!(calls, 3);
    assert_eq!(result.core().verdict(), Verdict::Delegate);
    assert!(
        result
            .warnings()
            .iter()
            .any(|warning| warning.contains("changed repeatedly"))
    );
    assert_eq!(result.refusals()[0].component(), "environment");
    assert_eq!(result.refusals()[0].code(), "oscillation");
    assert!(result.observation().is_none());
}

#[test]
fn environment_name_and_value_bounds_delegate_with_a_warning() {
    let names = (0..=super::MAX_ENVIRONMENT_NAMES)
        .map(|index| format!("${{ENV_{index:03}}}"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut name_calls = 0;
    let name_result = decide_with(&input(&format!("echo {names}")), &context(), |_| {
        name_calls += 1;
        unreachable!("name saturation must be refused before observation")
    });
    assert_eq!(name_calls, 0);
    assert_eq!(name_result.core().verdict(), Verdict::Delegate);
    assert!(
        name_result
            .warnings()
            .iter()
            .any(|warning| warning.contains("analysis limits"))
    );
    assert_eq!(name_result.refusals()[0].component(), "environment");
    assert_eq!(name_result.refusals()[0].code(), "name-limit");

    let mut value_calls = 0;
    let value_result = decide_with(&input("echo \"$BIG\""), &context(), |request| {
        value_calls += 1;
        Ok(observed(request, |_| {
            value("x".repeat(super::MAX_ENVIRONMENT_VALUE_BYTES + 1))
        }))
    });
    assert_eq!(value_calls, 1);
    assert_eq!(value_result.core().verdict(), Verdict::Delegate);
    assert!(
        value_result
            .warnings()
            .iter()
            .any(|warning| warning.contains("analysis limits"))
    );
    assert_eq!(value_result.refusals()[0].component(), "environment");
    assert_eq!(value_result.refusals()[0].code(), "value-limit");
}

#[test]
fn environment_round_bound_stops_unique_drift() {
    let mut calls = 0;
    let result = decide_with(&input("$TOOL victim"), &context(), |request| {
        calls += 1;
        Ok(observed(request, |_| value(format!("tool-{calls}"))))
    });

    assert_eq!(calls, super::MAX_ENVIRONMENT_ROUNDS);
    assert_eq!(result.core().verdict(), Verdict::Delegate);
    assert!(
        result
            .warnings()
            .iter()
            .any(|warning| warning.contains("analysis limits"))
    );
    assert_eq!(result.refusals()[0].component(), "environment");
    assert_eq!(result.refusals()[0].code(), "round-limit");
}
