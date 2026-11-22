//! After a tool call: bring the rolling copy up to date, so a discard that
//! follows finds it current.

use std::ffi::OsStr;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use nah_snapshot::{Budget, Freshness, Prune, RETENTION};
use serde_json::Value;

use nah_proto::ctx::GuardLevel;

use crate::catalog::rule_ids;
use crate::commands::snapshot_context;
use crate::runtime::Runtime;
use crate::shipped_state::{ShippedState, state_path};

/// Refreshes the rolling copy of the work tree a post-call event's call,
/// in Claude Code's shape, may have changed: the written file's entry after
/// a file tool, the session's folder after a shell command or a patch, which may touch
/// several files, unless no work rule saves at core. When that saves a
/// snapshot, the store then sheds what retention no longer keeps. It never
/// answers the runtime.
pub(crate) fn refresh(event: &Value) {
    if !saving() {
        return;
    }
    let input = &event["tool_input"];
    let (directory, file) = match event["tool_name"].as_str() {
        Some(tool @ ("Write" | "Edit" | "MultiEdit" | "NotebookEdit")) => {
            let key = if tool == "NotebookEdit" {
                "notebook_path"
            } else {
                "file_path"
            };
            // Some runtimes send a path relative to the call's directory.
            let Some(file) = input[key]
                .as_str()
                .map(|file| Path::new(event["cwd"].as_str().unwrap_or_default()).join(file))
            else {
                return;
            };
            (file.parent().map(Path::to_path_buf), Some(file))
        }
        Some("Bash" | "PowerShell" | "apply_patch") => {
            (event["cwd"].as_str().map(PathBuf::from), None)
        }
        _ => return,
    };
    // Only git work trees: a snapshot of any other folder reads every file.
    let Some(directory) = directory.filter(|directory| {
        directory.is_absolute()
            && directory
                .ancestors()
                .any(|ancestor| std::fs::symlink_metadata(ancestor.join(".git")).is_ok())
    }) else {
        return;
    };
    let Ok(context) = snapshot_context(crate::session_memory::labelled_paths) else {
        return;
    };
    // It runs off the critical path, so it may take far more than the
    // pre-call save. A refusal leaves no journal mark, which is what marks
    // the copy stale: the pre-call check then walks the tree itself.
    let budget = Budget {
        bytes: nah_snapshot::BACKGROUND_BUDGET_BYTES,
        deadline: Instant::now() + nah_snapshot::BACKGROUND_DEADLINE,
    };
    let refreshed = match file {
        Some(file) => nah_snapshot::refresh_file(&context, &file, budget),
        None => nah_snapshot::fresh(&context, &directory, budget),
    };
    if let Ok(Freshness::Saved { .. }) = refreshed {
        retain_in_background(&[directory]);
    }
}

/// Starts [`run_detached_post_call`] for `event` as `nah hook RUNTIME run
/// --post-call`, in a process group of its own that nothing waits for:
/// `hook_adapter::post_call_detached`, for a runtime that waits for its
/// post-call hook.
pub(crate) fn start_detached_post_call(event: &Value, runtime: Runtime) {
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let Ok(mut child) = Command::new(executable)
        .args(["hook", runtime.cli_name(), "run", "--post-call"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
    else {
        return;
    };
    // `event` holds no file content, so the pipe takes it whole.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = serde_json::to_writer(&mut stdin, event);
    }
}

/// The process [`start_detached_post_call`] starts:
/// `hook_adapter::lowered_post_call_event` for the event on its stdin.
pub(crate) fn run_detached_post_call(stdin: &mut impl std::io::Read, runtime: Runtime) -> u8 {
    if let Ok(event) = serde_json::from_reader::<_, Value>(stdin) {
        crate::hook_adapter::lowered_post_call_event(&event, runtime);
    }
    0
}

/// Starts retention of the stores of `directories`, which a save just
/// wrote, in a process of its own that nothing waits for: the hook's save
/// child ends as soon as it answers, a refresh may run while the runtime
/// waits, and the next refresh, if any, may find nothing to save.
pub(crate) fn retain_in_background(directories: &[PathBuf]) {
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let Ok(mut child) = Command::new(executable)
        .args(["hook", "claude", "run"])
        .args(
            directories
                .iter()
                .flat_map(|directory| [OsStr::new("--retain"), directory.as_os_str()]),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
    else {
        return;
    };
    // The pipe stays open until this hook ends, which `retain` waits for.
    std::mem::forget(child.stdin.take());
}

/// The process `retain_in_background` starts, with a deadline of its own.
/// It first waits for the hook that started it to end: until then that
/// hook's decision is unfinished, and its marker would keep every snapshot
/// since the one latest when it began.
pub(crate) fn retain(stdin: &mut impl std::io::Read, directories: &[PathBuf]) -> u8 {
    let _ = std::io::copy(stdin, &mut std::io::sink());
    let Ok(context) = snapshot_context(|| Ok(Vec::new())) else {
        return 1;
    };
    for directory in directories {
        let _ = nah_snapshot::prune(
            &context,
            directory,
            Prune::Retain(RETENTION),
            &super::unfinished::unfinished_decisions(),
            Instant::now() + nah_snapshot::BACKGROUND_DEADLINE,
        );
    }
    0
}

/// Whether the operator's settings run a work rule at core, where a discard
/// is saved. Settings that do not load count: the refresh only reads.
fn saving() -> bool {
    let platform = crate::live_state::host_platform();
    let Ok(home) = crate::live_state::home(platform) else {
        return true;
    };
    match ShippedState::load(&state_path(&home, platform), rule_ids()) {
        Ok((state, _)) => super::RULES
            .iter()
            .any(|rule| state.settings().rule_level(rule) == GuardLevel::Core),
        Err(_) => true,
    }
}
