//! Native Claude Code PreToolUse adapter over the `nah decide` seam, and the
//! post-call events: save-then-run's refresh after `PostToolUse`, and the
//! session memory's account of how each call ended.

use std::io::{Read, Write};

use serde_json::{Value, json};

use crate::{
    hook_adapter,
    runtime::{FailurePolicy, Runtime},
    session_memory,
};

/// `settle_hook` marks the `--settle` hook: session memory's synchronous
/// post-call handler, which leaves the rolling copy's refresh to the
/// background one.
pub(crate) fn run<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
    project_dir: Option<&str>,
    failure_policy: FailurePolicy,
    settle_hook: bool,
) -> u8 {
    let mut payload = Vec::new();
    if stdin.read_to_end(&mut payload).is_err() {
        // An empty payload is malformed input, which `decide` reports.
        payload.clear();
    }
    if let Ok(event) = serde_json::from_slice::<Value>(&payload) {
        match event["hook_event_name"].as_str() {
            Some("PreToolUse") => {
                if let Some(call) = event["tool_use_id"].as_str() {
                    session_memory::set_call(call, event["agent_id"].as_str());
                }
            }
            Some("PostToolUse" | "PostToolUseFailure" | "PostToolBatch") => {
                hook_adapter::post_call(&event, Runtime::Claude, settle_hook);
                return 0;
            }
            _ => {}
        }
    }
    match hook_adapter::decide(
        &mut payload.as_slice(),
        stderr,
        Runtime::Claude,
        project_dir,
        failure_policy,
    ) {
        hook_adapter::HookOutcome::Decision(decision) => {
            if let Some(reply) = hook_adapter::pre_tool_use_reply(&decision) {
                hook_adapter::write_hook_reply_line(stdout, reply);
            }
        }
        hook_adapter::HookOutcome::IrrelevantEvent => {}
        hook_adapter::HookOutcome::MalformedInput => {
            if let Some(reason) = hook_adapter::unavailable_feedback(
                failure_policy,
                Runtime::Claude,
                hook_adapter::IntegrationUnavailable::MalformedInput,
            ) {
                hook_adapter::write_hook_reply_line(
                    stdout,
                    hook_adapter::pre_tool_use_deny(&reason, false),
                );
            }
        }
        hook_adapter::HookOutcome::EvaluationUnavailable(kind) => {
            match hook_adapter::unavailable_feedback(failure_policy, Runtime::Claude, kind) {
                Some(reason) => hook_adapter::write_hook_reply_line(
                    stdout,
                    hook_adapter::pre_tool_use_deny(&reason, false),
                ),
                None => hook_adapter::write_hook_reply_line(
                    stdout,
                    json!({"systemMessage":hook_adapter::DELEGATED_FAILURE_MESSAGE}),
                ),
            }
        }
    }
    0
}
