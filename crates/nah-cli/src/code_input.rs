//! Strict runtime payloads normalized for later language analysis.

use serde_json::{Map, Value, json};

use nah_proto::tool::ToolCallInput;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CodeInput {
    Python {
        source: String,
    },
    Ipython {
        source: String,
    },
    #[allow(dead_code)]
    PowerShell {
        source: String,
    },
    #[allow(dead_code)]
    Pwsh {
        source: String,
    },
    #[allow(dead_code)]
    Cmd {
        source: String,
    },
    OpenClawJavaScript {
        source: String,
        restart_safe: Option<bool>,
    },
    OpenClawTypeScript {
        source: String,
        restart_safe: Option<bool>,
    },
}

impl CodeInput {
    pub(crate) fn canonical_input(&self) -> Value {
        let (language, source, restart_safe) = match self {
            Self::Python { source } => ("python", source, None),
            Self::Ipython { source } => ("ipython", source, None),
            Self::PowerShell { source } => ("powershell", source, None),
            Self::Pwsh { source } => ("pwsh", source, None),
            Self::Cmd { source } => ("cmd", source, None),
            Self::OpenClawJavaScript {
                source,
                restart_safe,
            } => ("javascript", source, *restart_safe),
            Self::OpenClawTypeScript {
                source,
                restart_safe,
            } => ("typescript", source, *restart_safe),
        };
        let mut input = json!({"code":source,"language":language});
        if let Some(restart_safe) = restart_safe {
            input["restartSafe"] = Value::Bool(restart_safe);
        }
        input
    }
}

pub(crate) struct HookDecisionInput<'a> {
    request: ToolCallInput,
    code: Option<&'a CodeInput>,
}

impl<'a> HookDecisionInput<'a> {
    pub(crate) fn into_parts(self) -> (ToolCallInput, Option<&'a CodeInput>) {
        (self.request, self.code)
    }
}

impl<'a> From<ToolCallInput> for HookDecisionInput<'a> {
    fn from(request: ToolCallInput) -> Self {
        Self {
            request,
            code: None,
        }
    }
}

impl<'a> From<(ToolCallInput, Option<&'a CodeInput>)> for HookDecisionInput<'a> {
    fn from((request, code): (ToolCallInput, Option<&'a CodeInput>)) -> Self {
        Self { request, code }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CodeIntake {
    NotCode,
    Code(CodeInput),
    Invalid,
}

pub(crate) fn hermes(tool: &str, input: &Value) -> CodeIntake {
    if tool != "execute_code" {
        return CodeIntake::NotCode;
    }
    let Some(object) = input.as_object() else {
        return CodeIntake::Invalid;
    };
    if !only_fields(object, &["code"]) {
        return CodeIntake::Invalid;
    }
    match non_blank_string(object, "code") {
        Some(source) => CodeIntake::Code(CodeInput::Python { source }),
        None => CodeIntake::Invalid,
    }
}

pub(crate) fn prime_agent(tool: &str, input: &Value) -> CodeIntake {
    if tool != "ipython" {
        return CodeIntake::NotCode;
    }
    let Some(object) = input.as_object() else {
        return CodeIntake::Invalid;
    };
    match non_blank_string(object, "code") {
        Some(source) => CodeIntake::Code(CodeInput::Ipython { source }),
        None => CodeIntake::Invalid,
    }
}

pub(crate) fn openclaw(
    tool: &str,
    tool_kind: Option<&str>,
    tool_input_kind: Option<&str>,
    input: &Value,
) -> CodeIntake {
    let object = input.as_object();
    let has_code_field = tool == "exec"
        && object.is_some_and(|object| {
            ["code", "language", "restartSafe"]
                .iter()
                .any(|field| object.contains_key(*field))
        });
    if tool_kind.is_none() && tool_input_kind.is_none() && !has_code_field {
        return CodeIntake::NotCode;
    }
    let Some(object) = object else {
        return CodeIntake::Invalid;
    };
    if tool != "exec"
        || tool_kind != Some("code_mode_exec")
        || !only_fields(object, &["code", "command", "language", "restartSafe"])
        || object
            .get("restartSafe")
            .is_some_and(|value| !value.is_boolean())
    {
        return CodeIntake::Invalid;
    }
    let Some(source) = non_blank_string(object, "code") else {
        return CodeIntake::Invalid;
    };
    if object.get("command").and_then(Value::as_str) != Some(source.as_str()) {
        return CodeIntake::Invalid;
    }
    let restart_safe = object.get("restartSafe").and_then(Value::as_bool);
    match (tool_input_kind, object.get("language")) {
        (Some("javascript"), None) => CodeIntake::Code(CodeInput::OpenClawJavaScript {
            source,
            restart_safe,
        }),
        (Some("javascript"), Some(Value::String(language))) if language == "javascript" => {
            CodeIntake::Code(CodeInput::OpenClawJavaScript {
                source,
                restart_safe,
            })
        }
        (Some("typescript"), Some(Value::String(language))) if language == "typescript" => {
            CodeIntake::Code(CodeInput::OpenClawTypeScript {
                source,
                restart_safe,
            })
        }
        _ => CodeIntake::Invalid,
    }
}

fn non_blank_string(object: &Map<String, Value>, field: &str) -> Option<String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
}

fn only_fields(object: &Map<String, Value>, allowed: &[&str]) -> bool {
    object.keys().all(|field| allowed.contains(&field.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_verified_runtime_code_payloads() {
        assert_eq!(
            hermes("execute_code", &json!({"code":"print('ok')"})),
            CodeIntake::Code(CodeInput::Python {
                source: "print('ok')".into()
            })
        );
        assert_eq!(
            prime_agent("ipython", &json!({"code":"print('ok')"})),
            CodeIntake::Code(CodeInput::Ipython {
                source: "print('ok')".into()
            })
        );
        assert_eq!(
            openclaw(
                "exec",
                Some("code_mode_exec"),
                Some("javascript"),
                &json!({"code":"return 1","command":"return 1"}),
            ),
            CodeIntake::Code(CodeInput::OpenClawJavaScript {
                source: "return 1".into(),
                restart_safe: None,
            })
        );
        assert_eq!(
            openclaw(
                "exec",
                Some("code_mode_exec"),
                Some("typescript"),
                &json!({
                    "code":"const value: number = 1",
                    "command":"const value: number = 1",
                    "language":"typescript",
                    "restartSafe":true
                }),
            ),
            CodeIntake::Code(CodeInput::OpenClawTypeScript {
                source: "const value: number = 1".into(),
                restart_safe: Some(true),
            })
        );
    }

    #[test]
    fn windows_shell_dialects_have_distinct_canonical_tags() {
        for (input, language, source) in [
            (
                CodeInput::PowerShell {
                    source: "Write-Output ok".into(),
                },
                "powershell",
                "Write-Output ok",
            ),
            (
                CodeInput::Pwsh {
                    source: "Write-Output ok".into(),
                },
                "pwsh",
                "Write-Output ok",
            ),
            (
                CodeInput::Cmd {
                    source: "echo ok".into(),
                },
                "cmd",
                "echo ok",
            ),
        ] {
            assert_eq!(
                input.canonical_input(),
                json!({"code":source,"language":language})
            );
        }
    }

    #[test]
    fn rejects_non_exact_hermes_code_payloads() {
        for input in [
            json!({}),
            json!({"code":7}),
            json!({"code":"  \n"}),
            json!({"code":"print('ok')","futureBehavior":"execute"}),
        ] {
            assert_eq!(hermes("execute_code", &input), CodeIntake::Invalid);
        }
        assert_eq!(
            hermes("terminal", &json!({"command":"pwd"})),
            CodeIntake::NotCode
        );
    }

    #[test]
    fn rejects_prime_agent_payloads_without_valid_code() {
        for input in [json!({}), json!({"code":7}), json!({"code":"  \n"})] {
            assert_eq!(prime_agent("ipython", &input), CodeIntake::Invalid);
        }
        assert_eq!(
            prime_agent("custom", &json!({"code":"print('ok')"})),
            CodeIntake::NotCode
        );
    }

    #[test]
    fn retains_prime_agent_code_with_additional_fields() {
        assert_eq!(
            prime_agent(
                "ipython",
                &json!({"code":"print('ok')","futureBehavior":"execute"})
            ),
            CodeIntake::Code(CodeInput::Ipython {
                source: "print('ok')".into()
            })
        );
    }

    #[test]
    fn rejects_openclaw_discriminator_and_payload_mismatches() {
        let source = "await tools.read({path: '.env'})";
        for (tool, tool_kind, input_kind, input) in [
            (
                "exec",
                None,
                Some("javascript"),
                json!({"code":source,"command":source}),
            ),
            (
                "exec",
                Some("code_mode_exec"),
                None,
                json!({"code":source,"command":source}),
            ),
            (
                "exec",
                Some("future_exec"),
                Some("javascript"),
                json!({"code":source,"command":source}),
            ),
            (
                "read",
                Some("code_mode_exec"),
                Some("javascript"),
                json!({"code":source,"command":source}),
            ),
            (
                "exec",
                Some("code_mode_exec"),
                Some("python"),
                json!({"code":source,"command":source}),
            ),
            (
                "exec",
                Some("code_mode_exec"),
                Some("javascript"),
                json!({"code":source,"command":"different"}),
            ),
            (
                "exec",
                Some("code_mode_exec"),
                Some("javascript"),
                json!({"code":source,"command":source,"language":"typescript"}),
            ),
            (
                "exec",
                Some("code_mode_exec"),
                Some("typescript"),
                json!({"code":source,"command":source}),
            ),
            (
                "exec",
                Some("code_mode_exec"),
                Some("javascript"),
                json!({"code":source,"command":source,"restartSafe":"yes"}),
            ),
            (
                "exec",
                Some("code_mode_exec"),
                Some("javascript"),
                json!({"code":source,"command":source,"futureBehavior":"execute"}),
            ),
        ] {
            assert_eq!(
                openclaw(tool, tool_kind, input_kind, &input),
                CodeIntake::Invalid
            );
        }
        assert_eq!(
            openclaw("exec", None, None, &json!({"command":"pwd"})),
            CodeIntake::NotCode
        );
    }
}
