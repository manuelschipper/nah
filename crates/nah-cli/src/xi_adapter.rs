//! Xi before-bash adapter over the shared decision seam.

use std::io::{Read, Write};

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::json;

use crate::hook_adapter::{self, HookOutcome};
use crate::runtime::{FailurePolicy, Runtime};

#[derive(Deserialize)]
struct XiHookInput {
    #[serde(rename = "event")]
    _event: String,
    command: String,
    cwd: String,
}

pub(crate) fn run<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
    failure_policy: FailurePolicy,
) -> u8 {
    let request = hook_adapter::read_event::<_, XiHookInput>(stdin, "event", "before-bash")
        .map_err(|error| error.to_string())
        .and_then(|input| input.map(normalize).transpose());
    match request {
        Ok(Some(request)) => {
            match hook_adapter::decide_input(request, stderr, Runtime::Xi, failure_policy) {
                HookOutcome::Decision(decision) if decision.verdict() == Verdict::Block => {
                    let _ = writeln!(stdout, "nah - {}", hook_adapter::feedback(&decision));
                    if decision.guard_block_incomplete() {
                        let _ = writeln!(stdout, "{}", hook_adapter::BLOCK_FAILURE_MESSAGE);
                    }
                    2
                }
                HookOutcome::Decision(_) | HookOutcome::IrrelevantEvent => 0,
                HookOutcome::MalformedInput => deny_unavailable(
                    stdout,
                    failure_policy,
                    hook_adapter::IntegrationUnavailable::MalformedInput,
                ),
                HookOutcome::EvaluationUnavailable(kind) => {
                    deny_unavailable(stdout, failure_policy, kind)
                }
            }
        }
        Ok(None) => 0,
        Err(_) => deny_unavailable(
            stdout,
            failure_policy,
            hook_adapter::IntegrationUnavailable::MalformedInput,
        ),
    }
}

fn deny_unavailable<W: Write>(
    stdout: &mut W,
    failure_policy: FailurePolicy,
    unavailable: hook_adapter::IntegrationUnavailable,
) -> u8 {
    match hook_adapter::unavailable_feedback(failure_policy, Runtime::Xi, unavailable) {
        Some(reason) => {
            let _ = writeln!(stdout, "nah - {reason}");
            2
        }
        None => 0,
    }
}

fn normalize(input: XiHookInput) -> Result<ToolCallInput, String> {
    ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        json!({"command":input.command}),
        input.cwd,
        None,
    )
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_before_bash_as_a_complete_bash_call() {
        let request = normalize(XiHookInput {
            _event: "before-bash".into(),
            command: "git status".into(),
            cwd: "/repo".into(),
        })
        .unwrap();
        assert_eq!(request.tool(), "Bash");
        assert_eq!(request.input(), &json!({"command":"git status"}));
        assert_eq!(request.cwd(), "/repo");
        assert!(request.normalization_complete());
    }

    #[test]
    fn malformed_input_follows_the_installed_failure_policy() {
        let mut malformed = br#"{"event":"before-bash"}"#.as_slice();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            run(
                &mut malformed,
                &mut stdout,
                &mut stderr,
                FailurePolicy::Delegate
            ),
            0
        );
        assert!(stdout.is_empty());

        let mut malformed = br#"{"event":"before-bash"}"#.as_slice();
        assert_eq!(
            run(
                &mut malformed,
                &mut stdout,
                &mut stderr,
                FailurePolicy::Block
            ),
            2
        );
        assert!(!stdout.is_empty());
    }

    #[test]
    fn ignores_other_hook_events() {
        let mut input = br#"{"event":"before-turn","prompt":"hi","cwd":"/repo"}"#.as_slice();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            run(
                &mut input,
                &mut stdout,
                &mut stderr,
                FailurePolicy::Delegate
            ),
            0
        );
        assert!(stdout.is_empty());
    }
}
