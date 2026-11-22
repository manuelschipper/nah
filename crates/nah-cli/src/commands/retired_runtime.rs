//! `nah hook` for the runtimes Nah 2.0 dropped (`RetiredRuntime`). A user who
//! upgrades from 1.x may still have one hooked, and some of those runtimes
//! deny every call whose hook fails, so `run` answers each call with the
//! runtime's own "go on" reply, and says once per session that Nah no longer
//! checks it. `uninstall` removes the 1.x wiring; install and status do no
//! more than say the runtime is no longer supported.

mod amp;
mod cline;
mod copilot;
mod devin;
mod droid;
mod kiro;

use std::io::{Read, Write};
use std::time::Instant;

use nah_proto::decision::ExitCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::args::HookAction;
use crate::hook_adapter::write_hook_reply_line;
use crate::ignored_project_file::{CLAIM_WAIT, claim};
use crate::live_state;
use crate::runtime::RetiredRuntime;
use crate::state_protection::nah_state_file_path;

use super::RuntimeMutation;

pub(crate) fn dispatch<R: Read, W: Write, E: Write>(
    runtime: RetiredRuntime,
    action: &HookAction,
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let name = runtime.cli_name();
    let display = runtime.display_name();
    match action {
        HookAction::Run(_) => run(runtime, stdin, stdout, stderr),
        HookAction::Status => {
            let _ = writeln!(stdout, "{display}: no longer supported");
            let _ = writeln!(stdout, "remove: nah hook {name} uninstall");
            0
        }
        HookAction::Install(_) => {
            let _ = writeln!(
                stderr,
                "nah: Nah 2.0 no longer supports {display}; Nah 1.x still does"
            );
            ExitCode::COMMAND_FAILURE.value()
        }
        HookAction::Uninstall => match uninstall(runtime) {
            Ok(mutation) => {
                for line in mutation.lines() {
                    let _ = writeln!(stdout, "{line}");
                }
                0
            }
            Err(error) => {
                let _ = writeln!(stderr, "nah: {error}");
                ExitCode::COMMAND_FAILURE.value()
            }
        },
    }
}

fn uninstall(runtime: RetiredRuntime) -> Result<RuntimeMutation, String> {
    match runtime {
        RetiredRuntime::Amp => amp::uninstall(),
        RetiredRuntime::Cline => cline::uninstall(),
        RetiredRuntime::Copilot => copilot::uninstall(),
        RetiredRuntime::Devin => devin::uninstall(),
        RetiredRuntime::Droid => droid::uninstall(),
        RetiredRuntime::Kiro => kiro::uninstall(),
    }
}

/// Answers one hook event so that the runtime lets the call go on, whatever
/// its own failure handling would do. The notice goes on a pre-call event
/// only, since a runtime may drop what a post-call hook prints.
fn run<R: Read, W: Write, E: Write>(
    runtime: RetiredRuntime,
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let mut payload = Vec::new();
    let _ = stdin.read_to_end(&mut payload);
    let event = serde_json::from_slice::<Value>(&payload).unwrap_or(Value::Null);
    let notice = (pre_call(&event) && notice_due(runtime, session(&event))).then(|| {
        format!(
            "nah · Nah 2.0 no longer supports {display}, so this hook checks no calls. Remove it with `nah hook {name} uninstall`, or keep Nah 1.x for {display}.",
            display = runtime.display_name(),
            name = runtime.cli_name(),
        )
    });
    match runtime {
        // The plugin shows the reason of a failed evaluation as a warning
        // and allows the call.
        RetiredRuntime::Amp => {
            let reply = match &notice {
                Some(notice) => json!({"block":false,"evaluation_failed":true,"reason":notice}),
                None => json!({"block":false,"evaluation_failed":false}),
            };
            write_hook_reply_line(stdout, reply);
            0
        }
        RetiredRuntime::Cline => {
            let reply = match &notice {
                Some(notice) => json!({"cancel":false,"contextModification":notice}),
                None => json!({"cancel":false}),
            };
            write_hook_reply_line(stdout, reply);
            0
        }
        // The CLI's payload names no event and shows a progress message;
        // VS Code's names one and shows a system message.
        RetiredRuntime::Copilot => {
            if let Some(notice) = notice {
                let reply = if event.get("hook_event_name").is_some() {
                    json!({"systemMessage":notice})
                } else {
                    json!({"type":"progress","message":notice})
                };
                write_hook_reply_line(stdout, reply);
            }
            0
        }
        RetiredRuntime::Devin => {
            if let Some(notice) = notice {
                let _ = writeln!(stderr, "{notice}");
            }
            0
        }
        RetiredRuntime::Droid => {
            if let Some(notice) = notice {
                let _ = writeln!(stdout, "{notice}");
            }
            0
        }
        // Kiro shows a hook's stderr as a warning when it exits 1, and lets
        // the call go on; only exit 2 blocks.
        RetiredRuntime::Kiro => match notice {
            Some(notice) => {
                let _ = writeln!(stderr, "{notice}");
                1
            }
            None => 0,
        },
    }
}

/// Whether `event` comes before a call: every one of these runtimes names a
/// post-call event in `hook_event_name` or `hookName`, but for Copilot CLI,
/// whose post-call events carry `toolResult` or `error` instead, and Amp
/// 1.x, which sends none.
fn pre_call(event: &Value) -> bool {
    let named = event
        .get("hook_event_name")
        .or_else(|| event.get("hookName"))
        .and_then(Value::as_str);
    named.is_none_or(|name| matches!(name, "PreToolUse" | "preToolUse" | "tool_call"))
        && event.get("toolResult").is_none()
        && event.get("error").is_none()
}

/// The session `event` belongs to, in the field each runtime names it by.
fn session(event: &Value) -> Option<&str> {
    ["session_id", "sessionId", "taskId"]
        .into_iter()
        .find_map(|field| event.get(field).and_then(Value::as_str))
        .filter(|session| !session.is_empty())
}

/// Whether this call is the first of its session to claim the notice. Each
/// session claims a marker under `~/.nah/retired-<runtime>-sessions/`, so
/// interleaved sessions are each told once and two first calls of one session
/// cannot both claim it. A call that names no session is always told.
fn notice_due(runtime: RetiredRuntime, session: Option<&str>) -> bool {
    let Some(session) = session else {
        return true;
    };
    let platform = live_state::host_platform();
    let Ok(home) = live_state::home(platform) else {
        return true;
    };
    let marker = nah_state_file_path(
        &home,
        platform,
        &format!("retired-{}-sessions", runtime.cli_name()),
    )
    .join(format!("{:x}", Sha256::digest(session.as_bytes())));
    nah_observe::observe_within_deadline(Instant::now() + CLAIM_WAIT, move || claim(&marker))
        .unwrap_or(true)
}
