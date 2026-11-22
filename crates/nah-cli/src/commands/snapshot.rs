//! The snapshot commands, each acting on the project holding the current
//! directory: `nah undo` and `nah snapshots`, which save-then-run's notes
//! tell the agent to run; `nah snapshots prune`, maintenance only the
//! operator may run (`dispatch::operator_action`); and the experimental
//! `nah snapshot save` and `nah snapshot fresh`, which drive `nah-snapshot`
//! directly.

use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nah_proto::decision::{ExitCode, Verdict};
use nah_snapshot::{
    Budget, Context, Freshness, Manifest, Prune, RETENTION, Refusal, Retention, UndoPoint,
};
use serde_json::json;

use super::shell_word::quote_posix_shell_word;
use crate::dispatch::decide_live_for_runtime;
use crate::hook_adapter;
use crate::runtime::Runtime;

use crate::args::{PruneArgs, SnapshotAction, SnapshotBudgetArgs, UndoArgs};
use crate::live_state;
use crate::state_protection::nah_state_file_path;

/// `nah snapshot save` and `nah snapshot fresh`, experimental.
pub(crate) fn snapshot_action<W: Write, E: Write>(
    action: SnapshotAction,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let started = Instant::now();
    let (context, project) = match context() {
        Ok(found) => found,
        Err(error) => return fail(stderr, &error),
    };
    let (json, result) = match action {
        SnapshotAction::Save(args) => {
            let named = args
                .paths
                .iter()
                .map(|path| project.join(path))
                .collect::<Vec<_>>();
            let result = nah_snapshot::save(
                &context,
                &project,
                &named,
                budget(&args.budget, Budget::pre_call()),
            );
            (
                args.budget.json,
                result.map(|snapshot| Freshness::Saved { snapshot }),
            )
        }
        SnapshotAction::Fresh(args) => (
            args.json,
            nah_snapshot::fresh(&context, &project, budget(&args, Budget::pre_call())),
        ),
    };
    let elapsed_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(freshness) if json => {
            let mut value = serde_json::to_value(&freshness).expect("freshness serializes");
            value["elapsed_ms"] = json!(elapsed_ms);
            let _ = writeln!(stdout, "{value}");
            0
        }
        Ok(Freshness::Current { snapshot }) => {
            let _ = writeln!(
                stdout,
                "snapshot {} is current ({elapsed_ms} ms)",
                snapshot.id
            );
            0
        }
        Ok(Freshness::Saved { snapshot }) => {
            let _ = writeln!(
                stdout,
                "saved snapshot {}: {} ({elapsed_ms} ms)",
                snapshot.id,
                describe(&snapshot)
            );
            0
        }
        Err(refusal) => refuse(json, &refusal, elapsed_ms, stdout, stderr),
    }
}

/// `nah snapshots`: the project's snapshots, newest first.
pub(crate) fn list_snapshots<W: Write, E: Write>(json: bool, stdout: &mut W, stderr: &mut E) -> u8 {
    let (context, project) = match context() {
        Ok(found) => found,
        Err(error) => return fail(stderr, &error),
    };
    let deadline = Instant::now() + nah_snapshot::DEFAULT_DEADLINE;
    match nah_snapshot::list(&context, &project, deadline) {
        Ok(snapshots) if json => {
            let listed = snapshots
                .iter()
                .map(|listed| {
                    let snapshot = &listed.snapshot;
                    json!({
                        "id": snapshot.id,
                        "created_ms": snapshot.created_ms,
                        "root": snapshot.root,
                        "repository": snapshot.repository,
                        "summary": snapshot.summary,
                        "not_saved": snapshot.not_saved.len(),
                        "commits": snapshot.commits,
                        "undo": listed.undo,
                    })
                })
                .collect::<Vec<_>>();
            let _ = writeln!(stdout, "{}", json!(listed));
            0
        }
        Ok(snapshots) => {
            for listed in &snapshots {
                let snapshot = &listed.snapshot;
                let undo = match &listed.undo {
                    Some(UndoPoint {
                        command: Some(command),
                        ..
                    }) => {
                        // A control character in the command would move the
                        // terminal's cursor and garble the line.
                        let shown = command
                            .chars()
                            .map(|character| {
                                if character.is_control() {
                                    character.escape_default().to_string()
                                } else {
                                    character.to_string()
                                }
                            })
                            .collect::<String>();
                        format!("  undo for `{shown}`")
                    }
                    Some(UndoPoint { command: None, .. }) => "  undo point".to_owned(),
                    None => String::new(),
                };
                let _ = writeln!(
                    stdout,
                    "{}  {}  {}{undo}",
                    snapshot.id,
                    created(snapshot.created_ms),
                    describe(snapshot)
                );
            }
            if snapshots.is_empty() {
                let _ = writeln!(stdout, "no snapshots of {}", project.display());
            }
            0
        }
        Err(refusal) => refuse(json, &refusal, 0, stdout, stderr),
    }
}

/// `nah snapshots prune`, which the operator alone may run.
pub(crate) fn prune_snapshots<W: Write, E: Write>(
    args: PruneArgs,
    json: bool,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let (context, project) = match context() {
        Ok(found) => found,
        Err(error) => return fail(stderr, &error),
    };
    let prune = match args.older_than {
        _ if args.all => Prune::All,
        Some(days) => Prune::Retain(Retention {
            age: Duration::from_secs(days.saturating_mul(24 * 60 * 60)),
            bytes: u64::MAX,
        }),
        None => Prune::Retain(RETENTION),
    };
    let deadline = Instant::now() + nah_snapshot::BACKGROUND_DEADLINE;
    let unfinished = crate::save_then_run::unfinished::unfinished_decisions();
    match nah_snapshot::prune(&context, &project, prune, &unfinished, deadline) {
        Ok(pruned) if json => {
            let _ = writeln!(stdout, "{}", json!(pruned));
            0
        }
        Ok(pruned) => {
            let _ = writeln!(
                stdout,
                "removed {} of {} snapshots; the store holds {} bytes",
                pruned.removed.len(),
                pruned.removed.len() + pruned.kept,
                pruned.bytes
            );
            for id in &pruned.removed {
                let _ = writeln!(stdout, "  removed {id}");
            }
            0
        }
        Err(refusal) => refuse(json, &refusal, 0, stdout, stderr),
    }
}

/// `nah undo ID`, and `nah undo ID --into DIR`.
pub(crate) fn undo_snapshot<W: Write, E: Write>(
    args: UndoArgs,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let (mut context, project) = match context() {
        Ok(found) => found,
        Err(error) => return fail(stderr, &error),
    };
    // What the undo replaces is saved first, as the undo of this command.
    context.undo_for = Some(format!("nah undo {}", args.id));
    let into = args.into.as_ref().map(|into| project.join(into));
    let result = nah_snapshot::undo_refusing(
        &context,
        &project,
        &args.id,
        into.as_deref(),
        // The agent runs undo as its own command, which no hook waits for.
        budget(
            &args.budget,
            Budget {
                bytes: nah_snapshot::BACKGROUND_BUDGET_BYTES,
                deadline: Instant::now() + nah_snapshot::BACKGROUND_DEADLINE,
            },
        ),
        refused_writes,
    );
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(refusal) => return refuse(args.budget.json, &refusal, 0, stdout, stderr),
    };
    // The undo saved first.
    crate::save_then_run::retain_in_background(std::slice::from_ref(&project));
    if args.budget.json {
        let _ = writeln!(stdout, "{}", json!(outcome));
    } else {
        let _ = writeln!(stdout, "restored snapshot {}", outcome.snapshot);
        if let Some(before) = &outcome.before_undo {
            let _ = writeln!(
                stdout,
                "the state it replaced is snapshot {before}; undo with: nah undo {before}"
            );
        }
        let clean_destinations = outcome.clean_restored.values().collect::<HashSet<_>>();
        for (label, paths) in [
            ("wrote", &outcome.written),
            ("removed", &outcome.removed),
            ("staged", &outcome.staged),
        ] {
            for path in paths {
                if (label == "wrote" && clean_destinations.contains(path))
                    || (label == "staged" && outcome.clean_restored.contains_key(path))
                {
                    continue;
                }
                let _ = writeln!(stdout, "  {label} {path}");
            }
        }
        if !outcome.clean_restored.is_empty() {
            let count = outcome.clean_restored.len();
            let names = outcome
                .clean_restored
                .keys()
                .take(5)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            let more = if count > 5 { ", …" } else { "" };
            let paths = if count == 1 { "path" } else { "paths" };
            let _ = writeln!(stdout, "  restored {count} clean {paths} ({names}{more})");
        }
        for restored in &outcome.refs {
            let _ = writeln!(stdout, "  {restored}");
        }
        for conflict in &outcome.conflicts {
            let _ = writeln!(stdout, "  left {}: {}", conflict.path, conflict.reason);
        }
        if into.is_none() && !outcome.conflicts.is_empty() {
            let _ = writeln!(
                stdout,
                "Recover the saved versions with `nah undo {} --into DIR` using a new empty folder for DIR.",
                outcome.snapshot
            );
        }
    }
    if outcome.conflicts.is_empty() {
        0
    } else {
        ExitCode::COMMAND_FAILURE.value()
    }
}

/// How many paths one checked write names.
const WRITES_PER_CHECK: usize = 100;

/// The paths among `paths`, relative to `root`, that Nah would block the
/// agent from writing directly (its own state, the agent's configuration,
/// login and startup files), each with the reason. The agent may run
/// `nah undo`, so a restore must not write what a direct write could not.
/// Each batch is decided as one shell command that writes every path in it;
/// a batch that blocks is halved until each blocked path is found.
fn refused_writes(root: &Path, paths: &[&str]) -> BTreeMap<String, String> {
    let mut refused = BTreeMap::new();
    let state = match live_state::load() {
        Ok(state) => state,
        Err(error) => {
            for path in paths {
                refused.insert(
                    (*path).to_owned(),
                    format!("nah could not check the write: {error}"),
                );
            }
            return refused;
        }
    };
    let Some(cwd) = root.to_str() else {
        for path in paths {
            refused.insert((*path).to_owned(), "its folder is not UTF-8".to_owned());
        }
        return refused;
    };
    let mut pending = paths
        .chunks(WRITES_PER_CHECK)
        .map(<[&str]>::to_vec)
        .collect::<Vec<_>>();
    while let Some(batch) = pending.pop() {
        let command = batch
            .iter()
            .map(|path| format!(": > {}", quote_posix_shell_word(path)))
            .collect::<Vec<_>>()
            .join("\n");
        let blocked = match hook_adapter::normalize_call(
            Runtime::Claude,
            "Bash".to_owned(),
            json!({ "command": command }),
            cwd.to_owned(),
            None,
        ) {
            Ok(input) => {
                let decided = decide_live_for_runtime(
                    &input,
                    None,
                    &state,
                    Some(Runtime::Claude),
                    crate::save_then_run::SaveMode::withheld(Some(Runtime::Claude)),
                );
                (decided.core().verdict() == Verdict::Block || decided.evaluation_failed())
                    .then(|| decided.core().reason().to_owned())
            }
            Err(error) => Some(format!("nah could not check the write: {error}")),
        };
        match (blocked, batch.as_slice()) {
            (None, _) => {}
            (Some(reason), [path]) => {
                refused.insert(
                    (*path).to_owned(),
                    format!("a direct write there would be blocked: {reason}"),
                );
            }
            (Some(_), _) => {
                let (left, right) = batch.split_at(batch.len() / 2);
                pending.push(left.to_vec());
                pending.push(right.to_vec());
            }
        }
    }
    refused
}

/// The snapshot store under the user's Nah state directory, and the current
/// directory.
fn context() -> Result<(Context, PathBuf), String> {
    let project = std::env::current_dir()
        .map_err(|error| format!("the current directory is unreadable: {error}"))?;
    Ok((
        snapshot_context(crate::session_memory::labelled_paths)?,
        project,
    ))
}

/// The context of the snapshot store under the user's Nah state directory.
/// `labelled` reads the files the agents'
/// sessions label as secret, which no save copies.
pub(crate) fn snapshot_context(
    labelled: impl Fn() -> Result<Vec<PathBuf>, String> + Send + Sync + 'static,
) -> Result<Context, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    Ok(Context {
        snapshots_dir: nah_state_file_path(&home, platform, "snapshots"),
        home,
        git: PathBuf::from("git"),
        builtin_fsmonitor: true,
        labelled: Box::new(labelled),
        may_publish: Box::new(|_| true),
        undo_for: None,
    })
}

/// `default`, with what the arguments override.
fn budget(args: &SnapshotBudgetArgs, default: Budget) -> Budget {
    Budget {
        bytes: args.budget_bytes.unwrap_or(default.bytes),
        deadline: args.deadline_ms.map_or(default.deadline, |deadline| {
            Instant::now() + Duration::from_millis(deadline)
        }),
    }
}

fn describe(snapshot: &Manifest) -> String {
    let summary = &snapshot.summary;
    let plural = |count: usize, one: &str, many: &str| {
        format!("{count} {}", if count == 1 { one } else { many })
    };
    if let Some(commits) = &snapshot.commits {
        let entries = commits
            .refs
            .iter()
            .filter(|saved| saved.stash.is_some())
            .count();
        let refs = commits.refs.len() - entries;
        let mut held = Vec::new();
        if entries > 0 {
            held.push(plural(entries, "stash entry", "stash entries"));
        }
        if refs > 0 || entries == 0 {
            held.push(plural(refs, "ref", "refs"));
        }
        held.push(plural(commits.count as usize, "commit", "commits"));
        return format!("{}, {} bytes", held.join(", "), summary.bytes);
    }
    let lines = summary
        .lines_changed
        .map_or_else(String::new, |lines| format!(", {lines} lines"));
    format!(
        "{}, {} bytes ({} new){lines}, {} not saved",
        plural(summary.files as usize, "file", "files"),
        summary.bytes,
        summary.new_bytes,
        snapshot.not_saved.len()
    )
}

fn created(created_ms: u64) -> String {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64);
    format!("{}s ago", now_ms.saturating_sub(created_ms) / 1000)
}

fn refuse<W: Write, E: Write>(
    json: bool,
    refusal: &Refusal,
    elapsed_ms: u64,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    if json {
        let mut value = json!({ "state": "refused", "elapsed_ms": elapsed_ms });
        value["refusal"] = serde_json::to_value(refusal).expect("a refusal serializes");
        let _ = writeln!(stdout, "{value}");
    } else {
        let _ = writeln!(stderr, "nah: snapshot refused: {refusal}");
    }
    ExitCode::COMMAND_FAILURE.value()
}

fn fail<E: Write>(stderr: &mut E, error: &str) -> u8 {
    let _ = writeln!(stderr, "nah: {error}");
    ExitCode::COMMAND_FAILURE.value()
}
