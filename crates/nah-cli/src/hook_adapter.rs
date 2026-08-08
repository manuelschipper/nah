//! Shared runtime-hook input normalization over the `nah decide` seam.

use std::io::{Read, Write};

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::{DecisionOutput, ExitCode, Verdict};
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::dispatch::{decision_id, run_decide_for_runtime, timestamp_rfc3339};
use crate::runtime::{FailurePolicy, Runtime};
use crate::{live_state, records};

pub(crate) const DELEGATED_FAILURE_MESSAGE: &str =
    "nah - evaluation failed; this call was delegated to the runtime";
pub(crate) const BLOCK_FAILURE_MESSAGE: &str =
    "nah - evaluation was incomplete; another guard blocked this call";

#[derive(Clone, Copy)]
pub(crate) enum IntegrationUnavailable {
    MalformedInput,
    Evaluation,
    InternalEvaluation,
}

impl IntegrationUnavailable {
    const fn component(self) -> &'static str {
        match self {
            Self::MalformedInput => "hook-input",
            Self::Evaluation | Self::InternalEvaluation => "decision",
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::MalformedInput => "malformed",
            Self::Evaluation => "unavailable",
            Self::InternalEvaluation => "internal",
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::MalformedInput => {
                "nah could not validate the runtime hook input; ask the operator to inspect the nah integration; do not retry through another tool or change nah state"
            }
            Self::Evaluation => {
                "nah could not complete required safety evaluation; retry once; if it is blocked again, ask the operator; do not bypass nah through another tool"
            }
            Self::InternalEvaluation => {
                "nah could not complete required safety evaluation; ask the operator to inspect the nah integration; do not retry through another tool or change nah state"
            }
        }
    }
}

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
    EvaluationUnavailable(IntegrationUnavailable),
}

pub(crate) struct HookDecision {
    output: DecisionOutput,
    audit_recorded: bool,
    evaluation_failed: bool,
    fail_closed_block: bool,
}

impl HookDecision {
    pub(crate) const fn verdict(&self) -> Verdict {
        self.output.verdict()
    }

    pub(crate) const fn evaluation_failed(&self) -> bool {
        self.evaluation_failed
    }

    pub(crate) const fn guard_block_incomplete(&self) -> bool {
        self.evaluation_failed && !self.fail_closed_block
    }
}

/// Each adapter names itself, so the decision it produces is recorded against
/// the runtime that sent it.
pub(crate) fn decide<R: Read, E: Write>(
    stdin: &mut R,
    stderr: &mut E,
    runtime: Runtime,
    failure_policy: FailurePolicy,
) -> HookOutcome {
    let input = match read_event::<_, HookInput>(stdin, "hook_event_name", "PreToolUse") {
        Ok(Some(input)) => input,
        Ok(None) => return HookOutcome::IrrelevantEvent,
        Err(error) => return fail(&error.to_string(), stderr, HookOutcome::MalformedInput),
    };
    let normalization_complete =
        crate::adapter_fields::complete(runtime.cli_name(), &input.tool_name, &input.tool_input);
    let original_input = input.tool_input.clone();
    let request = match ToolCallInput::new(
        SchemaVersion::V1,
        input.tool_name,
        input.tool_input,
        input.cwd,
        input.session_id,
    ) {
        Ok(request) if normalization_complete => request,
        Ok(request) => request.with_original_input(original_input, false),
        Err(error) => return fail(&error.to_string(), stderr, HookOutcome::MalformedInput),
    };
    decide_input(request, stderr, runtime, failure_policy)
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

pub(crate) fn decide_input<'a, E: Write>(
    request: impl Into<crate::code_input::HookDecisionInput<'a>>,
    stderr: &mut E,
    runtime: Runtime,
    failure_policy: FailurePolicy,
) -> HookOutcome {
    let (request, code) = request.into().into_parts();
    let request = serde_json::to_vec(&request).expect("validated tool input serializes");
    let mut decision_bytes = Vec::new();
    let outcome = run_decide_for_runtime(
        &mut request.as_slice(),
        &mut decision_bytes,
        stderr,
        Some(runtime),
        failure_policy,
        code,
    );
    if outcome.code == ExitCode::UNAVAILABLE.value() {
        // `nah decide` reports no decision body when it cannot decide at all.
        return fail(
            "decision unavailable",
            stderr,
            HookOutcome::EvaluationUnavailable(if outcome.operator_required_unavailable {
                IntegrationUnavailable::InternalEvaluation
            } else {
                IntegrationUnavailable::Evaluation
            }),
        );
    }
    match serde_json::from_slice::<DecisionOutput>(&decision_bytes) {
        Ok(decision) if outcome.code == ExitCode::from(decision.verdict()).value() => {
            HookOutcome::Decision(HookDecision {
                output: decision,
                audit_recorded: outcome.audit_recorded,
                evaluation_failed: outcome.evaluation_failed,
                fail_closed_block: outcome.fail_closed_block,
            })
        }
        Ok(_) => fail(
            "inconsistent nah decision",
            stderr,
            HookOutcome::EvaluationUnavailable(IntegrationUnavailable::Evaluation),
        ),
        Err(error) => fail(
            &error.to_string(),
            stderr,
            HookOutcome::EvaluationUnavailable(IntegrationUnavailable::Evaluation),
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

pub(crate) fn unavailable_feedback(
    failure_policy: FailurePolicy,
    runtime: Runtime,
    unavailable: IntegrationUnavailable,
) -> Option<String> {
    if failure_policy == FailurePolicy::Delegate {
        return None;
    }
    let id = decision_id();
    let envelope = nah_proto::decision::DecisionEnvelope::new(&id, &timestamp_rfc3339(), 0)
        .expect("generated decision envelope is valid");
    let platform = live_state::host_platform();
    let recorded = live_state::home(platform).ok().is_some_and(|home| {
        records::append_unavailable(
            &home,
            platform,
            envelope,
            runtime,
            unavailable.component(),
            unavailable.code(),
            unavailable.reason(),
        )
        .is_ok()
    });
    Some(if recorded {
        format!(
            "{}; if they want details, give them `nah why {id}`",
            unavailable.reason()
        )
    } else {
        format!("{}; id {id}", unavailable.reason())
    })
}

fn fail<E: Write>(_error: &str, _stderr: &mut E, outcome: HookOutcome) -> HookOutcome {
    outcome
}

#[cfg(test)]
mod tests {
    use super::IntegrationUnavailable;

    #[test]
    fn internal_and_adapter_unavailability_have_distinct_recovery() {
        let retryable = IntegrationUnavailable::Evaluation.reason();
        assert!(retryable.contains("retry once"));
        let internal = IntegrationUnavailable::InternalEvaluation.reason();
        assert!(internal.contains("ask the operator"));
        assert!(!internal.contains("retry once"));
    }

    #[test]
    fn shared_adapter_stays_small() {
        assert!(include_str!("hook_adapter.rs").lines().count() <= 266);
    }
}
