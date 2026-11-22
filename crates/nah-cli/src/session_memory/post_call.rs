//! The post-call half of session memory: how each call ended, as its
//! runtime's post-call event reports it, and which of the changes it
//! proposed the disk confirms. The pre-call half (`super::apply`) proposes
//! them; [`settle`] keeps the confirmed ones in the session's state.

use serde_json::Value;

use nah_proto::ctx::{AbsolutePath, Platform};

use super::base_name;
use super::ledger::{self, Change, Intent, Outcome, Record, Row};
use super::world::{self, World};
use crate::runtime::Runtime;

/// Keeps what finished calls of `runtime` left, as its post-call events
/// report them: a call that ran settles in its own `PostToolUse` event, or
/// in Claude Code's `PostToolUseFailure`, and Claude Code's
/// `PostToolBatch`, which fires once every call of an agent's turn has
/// resolved, settles each call of that agent still in flight as not run: the
/// user or a rule denied it. The batch's responses are no evidence, since it
/// lists a failure's or a denial's text as one. The other runtimes'
/// adapters hand it their event in Claude Code's shape. None of them says
/// whether a shell command it reports as `PostToolUse` exited zero: Codex
/// reports every end that way, Cursor does not say, and Hermes, OpenClaw,
/// OpenCode, Pi and Antigravity report a failure the runtime states as
/// `PostToolUseFailure`. So such a command's changes are kept only where
/// the disk shows them, as for a failed one; their file tools report
/// success there. It never answers the runtime.
pub(crate) fn settle(event: &Value, runtime: Runtime) {
    let platform = crate::live_state::host_platform();
    let Ok(home) = crate::live_state::home(platform) else {
        return;
    };
    let _recorded = settle_in(event, runtime, &home, platform, &world::Live);
    #[cfg(debug_assertions)]
    crate::session_replay::debug_facts(|| serde_json::json!({ "recorded": _recorded }));
}

/// `settle` with the ledgers under `ledgers`, confirming changes in `world`.
/// Returns the records it appended.
pub(crate) fn settle_in(
    event: &Value,
    runtime: Runtime,
    ledgers: &AbsolutePath,
    platform: Platform,
    world: &dyn World,
) -> Vec<Record> {
    let key = ledger::session_key(
        runtime.cli_name(),
        event["session_id"].as_str(),
        event["cwd"].as_str().unwrap_or_default(),
    );
    let Ok(mut ledger) = ledger::Locked::open(&ledger::log_path(ledgers, platform, &key)) else {
        return Vec::new();
    };
    let one = |outcome| {
        event["tool_use_id"]
            .as_str()
            .map(|call| vec![(call.to_owned(), outcome)])
            .unwrap_or_default()
    };
    let ended: Vec<(String, Outcome)> = match event["hook_event_name"].as_str() {
        Some("PostToolUse") if runtime != Runtime::Claude => one(Outcome::Ended),
        Some("PostToolUse") => one(Outcome::Succeeded),
        Some("PostToolUseFailure") => one(Outcome::Failed),
        Some("PostToolBatch") => {
            let agent = event["agent_id"].as_str();
            ledger
                .state
                .in_flight
                .iter()
                .filter(|intent| intent.agent.as_deref() == agent)
                .map(|intent| (intent.call.clone(), Outcome::NotRun))
                .collect()
        }
        _ => Vec::new(),
    };
    let at = crate::dispatch::current_timestamp_rfc3339();
    let mut rows = Vec::new();
    for (call, outcome) in ended {
        let Some(position) = ledger
            .state
            .in_flight
            .iter()
            .position(|intent| intent.call == call)
        else {
            continue;
        };
        let intent = ledger.state.in_flight.remove(position);
        let outcome = match outcome {
            Outcome::Ended if intent.file_tool => Outcome::Succeeded,
            outcome => outcome,
        };
        let kept: Vec<Change> = intent
            .changes
            .iter()
            .filter(|change| confirmed(change, &intent, outcome, world))
            .cloned()
            .collect();
        for change in &kept {
            ledger.state.apply(change, world);
        }
        rows.push(Row {
            at: at.clone(),
            record: Record::Settled {
                call,
                outcome,
                kept,
            },
        });
    }
    if !rows.is_empty() {
        let _ = ledger.record(&rows, world);
    }
    rows.into_iter().map(|row| row.record).collect()
}

/// Whether the disk confirms a change a call proposed, now that it ended.
fn confirmed(change: &Change, intent: &Intent, outcome: Outcome, world: &dyn World) -> bool {
    // A file tool that failed wrote nothing; a shell command that failed,
    // or whose success its event does not say, may have done part of its
    // work, which the disk shows.
    if outcome == Outcome::NotRun || outcome == Outcome::Failed && intent.file_tool {
        return false;
    }
    match change {
        Change::Wrote { path, digest } | Change::Unlabel { path, digest } => {
            world.digest(path).as_ref() == Some(digest)
        }
        // A launch in the foreground ran and ended with the call. One that
        // failed counts only where it is still there to run: a process that
        // names its file, or a crontab entry.
        Change::Launch {
            path,
            via,
            scheduled,
        } => match (outcome, scheduled) {
            (Outcome::Succeeded, _) => *scheduled || intent.background,
            (_, true) if via == "crontab" => installed_in_crontab(path, world),
            // A load nothing lists by path counts as done.
            (_, true) => true,
            (_, false) => intent.background && still_running(path, world),
        },
        // A shell command that failed before its write, such as a refused
        // redirection, left the file as it was.
        Change::Label { path, found } => {
            let now = file_state(path, world);
            now.is_some() && (outcome == Outcome::Succeeded || now != *found)
        }
        // A failed clone, download or extraction counts only if it changed
        // what the path held.
        Change::Fetched {
            path, tree, found, ..
        } => {
            let now = fingerprint(path, *tree, world);
            now.is_some() && (outcome == Outcome::Succeeded || now != *found)
        }
    }
}

/// What `path` holds, to tell whether a call changed it: a file's digest,
/// or a folder's modification time. The pre-call hook records it as a
/// change's `found`, and [`settle`] compares it with the disk.
pub(super) fn fingerprint(path: &str, tree: bool, world: &dyn World) -> Option<String> {
    if !tree {
        return world.digest(path);
    }
    Some(format!("mtime:{}", world.modified_ns(path)?))
}

/// A file's digest and modification time, to tell whether a call wrote it,
/// identical bytes too.
pub(super) fn file_state(path: &str, world: &dyn World) -> Option<String> {
    let modified = fingerprint(path, true, world)?;
    Some(match world.digest(path) {
        Some(digest) => format!("{digest} {modified}"),
        None => modified,
    })
}

/// Whether a running process's command line names `path`'s file. Unknown
/// counts as running.
pub(super) fn still_running(path: &str, world: &dyn World) -> bool {
    world
        .running_commands()
        .is_none_or(|commands| commands.contains(base_name(path)))
}

/// Whether the user's crontab names `path`. Unknown counts as installed.
fn installed_in_crontab(path: &str, world: &dyn World) -> bool {
    world.crontab().is_none_or(|crontab| crontab.contains(path))
}
