//! The unfinished-decision markers: a hook writes one before the pre-call
//! save and removes it once it has answered, so a marker left behind under
//! `save-then-run/unfinished` in Nah's state directory means a hook was
//! killed or timed out mid-save. The next reply reports it once
//! (`unfinished_report`), and retention keeps the snapshots such a decision
//! may have left the agent to undo with (`unfinished_decisions`).

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::Discards;
use super::pre_call::{short, store_stall_for_tests};
use crate::commands::snapshot_context;
use crate::live_state;
use crate::state_protection::nah_state_file_path;

/// How long a dropped marker waits for its removal, which a healthy store
/// finishes at once.
const MARKER_REMOVAL: Duration = Duration::from_millis(100);

/// How long one reply spends naming the snapshots its leftover markers keep,
/// however many there are.
const REPORT_BUDGET: Duration = Duration::from_millis(500);

/// A marker younger than this may belong to a hook still deciding.
const MARKER_GRACE: Duration = Duration::from_secs(10);

/// Written before the pre-call save and removed when dropped, which the
/// adapter does once it has answered. One left behind means the hook was
/// killed or timed out first, and the runtime may have run the command
/// without a fresh copy.
pub(crate) struct UnfinishedMarker {
    path: PathBuf,
}

impl Drop for UnfinishedMarker {
    /// The store may be what stalled the save, so the removal waits only
    /// briefly; a marker it leaves is reported next time.
    fn drop(&mut self) {
        let path = std::mem::take(&mut self.path);
        let (done, removed) = mpsc::channel();
        std::thread::spawn(move || {
            store_stall_for_tests();
            let _ = fs::remove_file(&path);
            let _ = done.send(());
        });
        let _ = removed.recv_timeout(MARKER_REMOVAL);
    }
}

#[derive(Deserialize, Serialize)]
struct UnfinishedRecord {
    pid: u32,
    started_ms: u64,
    command: String,
    directory: PathBuf,
}

impl UnfinishedMarker {
    pub(crate) fn begin(found: &Discards, command: &str) -> Result<Self, String> {
        let dir = unfinished_dir()?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|error| format!("nah could not record the save it starts: {error}"))?;
        let record = UnfinishedRecord {
            pid: std::process::id(),
            started_ms: now_ms(),
            command: short(command),
            directory: found.discards[0].directory.clone(),
        };
        let path = dir.join(format!("{}-{}.json", record.pid, now_ns()));
        fs::write(
            &path,
            serde_json::to_vec(&record).expect("a marker serializes"),
        )
        .map_err(|error| format!("nah could not record the save it starts: {error}"))?;
        Ok(UnfinishedMarker { path })
    }
}

fn unfinished_dir() -> Result<PathBuf, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    Ok(nah_state_file_path(
        &home,
        platform,
        "save-then-run/unfinished",
    ))
}

/// What the agent is told about the decisions earlier hooks left
/// unfinished, which it reports once and forgets; `None` when there are none.
pub(crate) fn unfinished_report() -> Option<String> {
    let dir = unfinished_dir().ok()?;
    let entries = fs::read_dir(&dir).ok()?;
    let deadline = Instant::now() + REPORT_BUDGET;
    let mut reports = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(record) = fs::read(&path)
            .map_err(drop)
            .and_then(|bytes| serde_json::from_slice::<UnfinishedRecord>(&bytes).map_err(drop))
        else {
            continue;
        };
        let young = now_ms().saturating_sub(record.started_ms) < MARKER_GRACE.as_millis() as u64;
        // A marker the reply's budget has no time left for stays for a later
        // reply, which can still name its undo point.
        if record.pid == std::process::id()
            || young && alive(record.pid)
            || Instant::now() >= deadline
        {
            continue;
        }
        // Named before the marker that keeps it goes, so retention keeps the
        // snapshot this report gives its full age from now; one it cannot
        // name is not given.
        let latest = snapshot_context(|| Ok(Vec::new()))
            .ok()
            .and_then(|mut context| {
                context.undo_for = Some(record.command.clone());
                // A refusal, such as a store held past the deadline, is
                // reported as one rather than as having no snapshot.
                let latest = match nah_snapshot::list(&context, &record.directory, deadline) {
                    Ok(listings) => listings.into_iter().next()?.snapshot,
                    Err(refusal) => return Some(Err(refusal)),
                };
                Some(nah_snapshot::name_undo(&context, &latest, deadline).map(|()| latest.id))
            });
        let _ = fs::remove_file(&path);
        let latest = match latest {
            Some(Ok(id)) => format!("the latest snapshot there is {id}; undo with: nah undo {id}"),
            Some(Err(refusal)) => format!(
                "nah could not keep its latest snapshot there for an undo ({refusal}); `nah snapshots` lists what remains"
            ),
            None => "there is no snapshot there".to_owned(),
        };
        reports.push(format!(
            "nah · work: an earlier hook was stopped before it finished saving a copy, so `{}` in {} may have run without one; {latest}",
            record.command,
            record.directory.display()
        ));
    }
    (!reports.is_empty()).then(|| reports.join("\n"))
}

/// The decisions earlier hooks began and have not finished, the one this
/// process may be deciding included: retention keeps the snapshots each may
/// have left the agent to undo with.
pub(crate) fn unfinished_decisions() -> Vec<nah_snapshot::Unfinished> {
    let Some(entries) = unfinished_dir().ok().and_then(|dir| fs::read_dir(dir).ok()) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let bytes = fs::read(entry.path()).ok()?;
            let record = serde_json::from_slice::<UnfinishedRecord>(&bytes).ok()?;
            Some(nah_snapshot::Unfinished {
                directory: record.directory,
                started_ms: record.started_ms,
            })
        })
        .collect()
}

fn alive(pid: u32) -> bool {
    let Some(pid) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return false;
    };
    !matches!(
        rustix::process::test_kill_process(pid),
        Err(rustix::io::Errno::SRCH)
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos())
}
