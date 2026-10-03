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
            Verdict::Block => hook_adapter::write_hook_reply_line(
                stdout,
                claude_deny_reply(
                    &hook_adapter::feedback(&decision),
                    decision.guard_block_incomplete(),
                ),
            ),
            Verdict::Delegate if decision.evaluation_failed() => {
                hook_adapter::write_hook_reply_line(
                    stdout,
                    json!({"systemMessage":hook_adapter::DELEGATED_FAILURE_MESSAGE}),
                )
            }
            Verdict::Delegate => {}
        },
        hook_adapter::HookOutcome::IrrelevantEvent => {}
        hook_adapter::HookOutcome::MalformedInput => {
            if let Some(reason) = hook_adapter::unavailable_feedback(
                failure_policy,
                Runtime::Claude,
                hook_adapter::IntegrationUnavailable::MalformedInput,
            ) {
                hook_adapter::write_hook_reply_line(stdout, claude_deny_reply(&reason, false));
            }
        }
        hook_adapter::HookOutcome::EvaluationUnavailable(kind) => {
            match hook_adapter::unavailable_feedback(failure_policy, Runtime::Claude, kind) {
                Some(reason) => {
                    hook_adapter::write_hook_reply_line(stdout, claude_deny_reply(&reason, false))
                }
                None => hook_adapter::write_hook_reply_line(
                    stdout,
                    json!({"systemMessage":hook_adapter::DELEGATED_FAILURE_MESSAGE}),
                ),
            }
        }
    }
    0
}

fn claude_deny_reply(reason: &str, incomplete: bool) -> Value {
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
