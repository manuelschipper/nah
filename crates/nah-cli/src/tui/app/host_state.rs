//! Host state the TUI reads and writes outside nah's own configuration
//! commands: the live decision log, the snapshots the stores keep, the
//! global nap, and what the nah 1.x import left to say. Every function here
//! touches the real home directory.

use super::{NapStatus, UndoPoints};
use crate::nap;
use crate::records::{DecisionLogView, LogSummary};
use crate::{live_state, records};

/// Bounds the browsable window so huge decision logs stay responsive.
const LOG_LIMIT: usize = 200;

/// Reads the newest window of the live decision log. Browsing
/// can archive and rewrite a log holding an invalid record; see
/// `records::recent_decisions` for that recovery contract.
pub(super) fn recent_log() -> Result<DecisionLogView, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    records::recent_decisions(&home, platform, LOG_LIMIT).map_err(|error| error.to_string())
}

/// Which of the snapshots `summary`'s saved calls made every project's
/// store still keeps; `None` when the stores cannot be read, or on a host
/// where nothing saves.
pub(super) fn undo_points(summary: &LogSummary) -> Option<UndoPoints> {
    #[cfg(unix)]
    {
        let platform = live_state::host_platform();
        let home = live_state::home(platform).ok()?;
        let stores = crate::state_protection::nah_state_file_path(&home, platform, "snapshots");
        let kept = nah_snapshot::kept_ids(&stores).ok()?;
        Some(UndoPoints::of(summary, &kept))
    }
    #[cfg(not(unix))]
    {
        let _ = summary;
        None
    }
}

/// Reads the same global nap state the decision path enforces, so an expired
/// or absent nap reads as none without a write, and says whether the nap
/// file holds a nap another Nah version wrote.
pub(super) fn nap_status() -> (Option<NapStatus>, bool) {
    let platform = live_state::host_platform();
    let Ok(home) = live_state::home(platform) else {
        return (None, false);
    };
    match nap::load(&home, platform) {
        Ok(nap) => (nap.map(NapStatus::of), false),
        Err(error) => (None, error == nap::NapError::UnsupportedVersion),
    }
}

/// The mutation behind `nah wake`; it only ever restores enforcement.
pub(super) fn wake_nap() -> Result<(), String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    nap::wake(&home, platform)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Size of the live decision log, used to notice appended decisions.
pub(super) fn log_size() -> Option<u64> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform).ok()?;
    records::decision_log_size(&home, platform)
}

/// The home directory, which the screens write as `~` in the paths under it.
pub(super) fn home_path() -> Option<String> {
    let home = live_state::home(live_state::host_platform()).ok()?;
    Some(home.as_str().to_owned())
}

/// Says that the nah 1.x import could not carry some choices exactly.
/// `nah guards` prints each one, so this only counts them.
/// The TUI line naming the nah 1.x custom guards that no longer run.
pub(super) fn stopped_custom_guards() -> Option<String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform).ok()?;
    crate::legacy_custom_guards::StoppedCustomGuards::find(&home, platform)
        .map(|stopped| stopped.banner())
}

pub(super) fn import_notice() -> Option<String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform).ok()?;
    let notices =
        crate::shipped_state::import_notices(&crate::shipped_state::state_path(&home, platform))
            .ok()??;
    let count = notices.lines().filter(|line| !line.is_empty()).count();
    (count > 0).then(|| {
        format!(
            "the nah 1.x import could not carry {count} choice(s) exactly; `nah guards` lists them"
        )
    })
}
