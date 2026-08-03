//! Native Claude Code PreToolUse adapter over the `nah decide` seam.

use std::io::{Read, Write};

use nah_proto::decision::Verdict;
use serde_json::{Value, json};

use crate::{
    hook_adapter,
    runtime::{FailurePolicy, Runtime},
};

pub(crate) fn run<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
    failure_policy: FailurePolicy,
) -> u8 {
    match hook_adapter::decide(stdin, stderr, Runtime::Claude, failure_policy) {
        hook_adapter::HookOutcome::Decision(decision) => match decision.verdict() {
            Verdict::Block => emit(
                stdout,
                deny(
                    &hook_adapter::feedback(&decision),
                    decision.guard_block_incomplete(),
                ),
            ),
            Verdict::Delegate if decision.evaluation_failed() => emit(
                stdout,
                json!({"systemMessage":hook_adapter::DELEGATED_FAILURE_MESSAGE}),
            ),
            Verdict::Delegate => {}
        },
        hook_adapter::HookOutcome::IrrelevantEvent => {}
        hook_adapter::HookOutcome::MalformedInput => {
            if let Some(reason) = hook_adapter::unavailable_feedback(
                failure_policy,
                Runtime::Claude,
                hook_adapter::IntegrationUnavailable::MalformedInput,
            ) {
                emit(stdout, deny(&reason, false));
            }
        }
        hook_adapter::HookOutcome::EvaluationUnavailable(kind) => {
            match hook_adapter::unavailable_feedback(failure_policy, Runtime::Claude, kind) {
                Some(reason) => emit(stdout, deny(&reason, false)),
                None => emit(
                    stdout,
                    json!({"systemMessage":hook_adapter::DELEGATED_FAILURE_MESSAGE}),
                ),
            }
        }
    }
    0
}

fn emit<W: Write>(stdout: &mut W, value: Value) {
    let _ = serde_json::to_writer(&mut *stdout, &value);
    let _ = writeln!(stdout);
}

fn deny(reason: &str, incomplete: bool) -> Value {
    let mut output = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": format!("nah - {reason}")
        }
    });
    if incomplete {
        output["systemMessage"] = json!(hook_adapter::BLOCK_FAILURE_MESSAGE);
    }
    output
}

#[cfg(test)]
mod tests {
    #[test]
    fn native_adapter_stays_thin() {
        assert!(include_str!("claude_adapter.rs").lines().count() <= 86);
    }
}
