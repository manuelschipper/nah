//! Prime Agent tool-call adapter over the shared `nah decide` seam.

use std::io::{Read, Write};

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    code_input::{CodeInput, CodeIntake},
    hook_adapter,
    runtime::{FailurePolicy, Runtime},
};

const OPAQUE_TOOL: &str = "prime-agent-opaque";

#[derive(Deserialize)]
struct PrimeAgentHookInput {
    tool_name: String,
    tool_input: Value,
    cwd: String,
    tool_source: Option<String>,
    tool_path: Option<String>,
}

pub(crate) fn run<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
    failure_policy: FailurePolicy,
) -> u8 {
    let request = serde_json::from_reader::<_, PrimeAgentHookInput>(stdin)
        .map_err(|error| error.to_string())
        .and_then(normalize);
    let output = match request {
        Ok((request, code)) => match hook_adapter::decide_input(
            (request, code.as_ref()),
            stderr,
            Runtime::PrimeAgent,
            failure_policy,
        ) {
            hook_adapter::HookOutcome::Decision(decision)
                if decision.verdict() == Verdict::Block =>
            {
                json!({
                    "block": true,
                    "reason": format!("nah - {}", hook_adapter::feedback(&decision)),
                    "evaluation_failed":decision.evaluation_failed()
                })
            }
            hook_adapter::HookOutcome::Decision(decision) => {
                json!({"block": false, "evaluation_failed":decision.evaluation_failed()})
            }
            hook_adapter::HookOutcome::IrrelevantEvent => return 0,
            hook_adapter::HookOutcome::MalformedInput => unavailable(
                failure_policy,
                hook_adapter::IntegrationUnavailable::MalformedInput,
            )
            .unwrap_or_else(|| delegated(false)),
            hook_adapter::HookOutcome::EvaluationUnavailable(kind) => {
                unavailable(failure_policy, kind).unwrap_or_else(|| delegated(true))
            }
        },
        Err(_) => unavailable(
            failure_policy,
            hook_adapter::IntegrationUnavailable::MalformedInput,
        )
        .unwrap_or_else(|| delegated(false)),
    };
    let _ = serde_json::to_writer(&mut *stdout, &output);
    let _ = writeln!(stdout);
    0
}

fn unavailable(
    failure_policy: FailurePolicy,
    unavailable: hook_adapter::IntegrationUnavailable,
) -> Option<Value> {
    hook_adapter::unavailable_feedback(failure_policy, Runtime::PrimeAgent, unavailable).map(
        |reason| json!({"block":true,"reason":format!("nah - {reason}"),"evaluation_failed":true}),
    )
}

fn normalize(input: PrimeAgentHookInput) -> Result<(ToolCallInput, Option<CodeInput>), String> {
    let builtin_ipython = input.tool_name == "ipython"
        && input.tool_source.as_deref() == Some("builtin")
        && input.tool_path.as_deref() == Some("<builtin:ipython>");
    if !builtin_ipython {
        let original = json!({
            "tool_name":input.tool_name,
            "tool_input":input.tool_input,
        });
        return ToolCallInput::new(SchemaVersion::V1, OPAQUE_TOOL, json!({}), input.cwd, None)
            .map(|input| input.with_original_input(original, false))
            .map(|input| (input, None))
            .map_err(|error| error.to_string());
    }

    let original_input = input.tool_input.clone();
    let (tool_input, code, normalization_complete) =
        match crate::code_input::prime_agent(&input.tool_name, &input.tool_input) {
            CodeIntake::Code(code) => (
                code.canonical_input(),
                Some(code),
                crate::adapter_fields::complete("prime-agent", &input.tool_name, &original_input),
            ),
            CodeIntake::NotCode | CodeIntake::Invalid => (original_input.clone(), None, false),
        };
    ToolCallInput::new(
        SchemaVersion::V1,
        input.tool_name,
        tool_input,
        input.cwd,
        None,
    )
    .map(|input| input.with_original_input(original_input, normalization_complete))
    .map(|input| (input, code))
    .map_err(|error| error.to_string())
}

fn delegated(evaluation_failed: bool) -> Value {
    json!({"block": false, "evaluation_failed":evaluation_failed})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_ipython_input_carries_typed_code_and_tracks_completeness() {
        let (request, code) = normalize(PrimeAgentHookInput {
            tool_name: "ipython".into(),
            tool_input: json!({"code":"import os"}),
            cwd: "/repo".into(),
            tool_source: Some("builtin".into()),
            tool_path: Some("<builtin:ipython>".into()),
        })
        .unwrap();
        assert_eq!(
            code,
            Some(CodeInput::Ipython {
                source: "import os".into()
            })
        );
        assert!(request.normalization_complete());

        let (request, code) = normalize(PrimeAgentHookInput {
            tool_name: "ipython".into(),
            tool_input: json!({"code":"import os","futureBehavior":"execute"}),
            cwd: "/repo".into(),
            tool_source: Some("builtin".into()),
            tool_path: Some("<builtin:ipython>".into()),
        })
        .unwrap();
        assert!(matches!(code, Some(CodeInput::Ipython { .. })));
        assert!(!request.normalization_complete());

        let (request, code) = normalize(PrimeAgentHookInput {
            tool_name: "ipython".into(),
            tool_input: json!({"code":7}),
            cwd: "/repo".into(),
            tool_source: Some("builtin".into()),
            tool_path: Some("<builtin:ipython>".into()),
        })
        .unwrap();
        assert!(code.is_none());
        assert!(!request.normalization_complete());
    }

    #[test]
    fn unadmitted_tools_share_one_opaque_identity() {
        for (tool_name, tool_input, tool_source, tool_path) in [
            (
                "ipython",
                json!({"code":"import os; os.remove('/')"}),
                "local",
                "/repo/.prime/agent/extensions/override.ts",
            ),
            (
                "bash",
                json!({"command":"rm -rf /"}),
                "builtin",
                "<builtin:bash>",
            ),
            (
                "Read",
                json!({"file_path":"/repo/secret"}),
                "local",
                "/repo/.prime/agent/extensions/read.ts",
            ),
            (
                "Write",
                json!({"file_path":"/repo/secret","content":"value"}),
                "sdk",
                "<sdk:Write>",
            ),
            (
                "Edit",
                json!({"file_path":"/repo/secret","old_string":"a","new_string":"b"}),
                "builtin",
                "<builtin:Edit>",
            ),
        ] {
            let original = json!({"tool_name":tool_name,"tool_input":tool_input});
            let (request, code) = normalize(PrimeAgentHookInput {
                tool_name: tool_name.into(),
                tool_input,
                cwd: "/repo".into(),
                tool_source: Some(tool_source.into()),
                tool_path: Some(tool_path.into()),
            })
            .unwrap();
            assert_eq!(request.tool(), OPAQUE_TOOL);
            assert_eq!(request.input(), &json!({}));
            assert_eq!(request.invocation_input(), &original);
            assert!(code.is_none());
            assert!(!request.normalization_complete());
        }
    }
}
