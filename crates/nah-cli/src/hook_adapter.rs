//! Shared runtime-hook input normalization over the `nah decide` seam.

use std::io::{Read, Write};

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::{DecisionOutput, ExitCode, Verdict};
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::dispatch::run_decide_for_runtime;
use crate::runtime::Runtime;

pub(crate) const DELEGATED_FAILURE_MESSAGE: &str =
    "nah - evaluation failed; this call was delegated to the runtime";
pub(crate) const BLOCK_FAILURE_MESSAGE: &str =
    "nah - evaluation was incomplete; another guard blocked this call";

#[derive(Deserialize)]
struct HookInput {
    #[serde(rename = "hook_event_name")]
    _hook_event_name: String,
    tool_name: String,
    tool_input: Value,
    cwd: String,
    #[serde(default)]
    session_id: Option<String>,
}

pub(crate) enum HookOutcome {
    Decision(HookDecision),
    IrrelevantEvent,
    MalformedInput,
    EvaluationUnavailable,
}

pub(crate) struct HookDecision {
    output: DecisionOutput,
    audit_recorded: bool,
    evaluation_failed: bool,
}

impl HookDecision {
    pub(crate) const fn verdict(&self) -> Verdict {
        self.output.verdict()
    }

    pub(crate) const fn evaluation_failed(&self) -> bool {
        self.evaluation_failed
    }
}

/// Each adapter names itself, so the decision it produces is recorded against
/// the runtime that sent it.
pub(crate) fn decide<R: Read, E: Write>(
    stdin: &mut R,
    stderr: &mut E,
    runtime: Runtime,
) -> HookOutcome {
    let input = match read_event::<_, HookInput>(stdin, "hook_event_name", "PreToolUse") {
        Ok(Some(input)) => input,
        Ok(None) => return HookOutcome::IrrelevantEvent,
        Err(error) => return fail(&error.to_string(), stderr, HookOutcome::MalformedInput),
    };
    let request = match ToolCallInput::new(
        SchemaVersion::V1,
        input.tool_name,
        input.tool_input,
        input.cwd,
        input.session_id,
    ) {
        Ok(request) => request,
        Err(error) => return fail(&error.to_string(), stderr, HookOutcome::MalformedInput),
    };
    decide_input(request, stderr, runtime)
}

pub(crate) fn read_event<R: Read, T: DeserializeOwned>(
    stdin: &mut R,
    field: &str,
    expected: &str,
) -> Result<Option<T>, serde_json::Error> {
    // `None` means only that the runtime named a different lifecycle event.
    let value = serde_json::from_reader::<_, Value>(stdin)?;
    if irrelevant_event(&value, field, expected) {
        return Ok(None);
    }
    serde_json::from_value(value).map(Some)
}

pub(crate) fn irrelevant_event(value: &Value, field: &str, expected: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|actual| actual != expected)
}

pub(crate) fn decide_input<E: Write>(
    request: ToolCallInput,
    stderr: &mut E,
    runtime: Runtime,
) -> HookOutcome {
    let request = serde_json::to_vec(&request).expect("validated tool input serializes");
    let mut decision_bytes = Vec::new();
    let outcome = run_decide_for_runtime(
        &mut request.as_slice(),
        &mut decision_bytes,
        stderr,
        Some(runtime),
    );
    let code = outcome.code;
    if code == ExitCode::UNAVAILABLE.value() {
        // `nah decide` reports no decision body when it cannot decide at all.
        return fail(
            "decision unavailable",
            stderr,
            HookOutcome::EvaluationUnavailable,
        );
    }
    match serde_json::from_slice::<DecisionOutput>(&decision_bytes) {
        Ok(decision) if code == ExitCode::from(decision.verdict()).value() => {
            HookOutcome::Decision(HookDecision {
                output: decision,
                audit_recorded: outcome.audit_recorded,
                evaluation_failed: outcome.evaluation_failed,
            })
        }
        Ok(_) => fail(
            "inconsistent nah decision",
            stderr,
            HookOutcome::EvaluationUnavailable,
        ),
        Err(error) => fail(
            &error.to_string(),
            stderr,
            HookOutcome::EvaluationUnavailable,
        ),
    }
}

pub(crate) fn feedback(decision: &HookDecision) -> String {
    if decision.audit_recorded {
        format!(
            "{}; if they want details, give them `nah why {}`",
            decision.output.reason(),
            decision.output.id()
        )
    } else {
        format!("{}; id {}", decision.output.reason(), decision.output.id())
    }
}

fn fail<E: Write>(_error: &str, _stderr: &mut E, outcome: HookOutcome) -> HookOutcome {
    outcome
}

#[cfg(test)]
mod tests {
    #[test]
    fn shared_adapter_stays_small() {
        assert!(include_str!("hook_adapter.rs").lines().count() <= 164);
    }
}
