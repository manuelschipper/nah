//! Host state the TUI reads and writes outside nah's own configuration
//! commands: the live decision log, the global nap, and the current project
//! with its guard declaration. Every function here touches the real home
//! directory or working directory.

use nah_proto::ctx::AbsolutePath;

use super::NapStatus;
use crate::nap;
use crate::records::DecisionLogView;
use crate::{live_state, records};

/// Bounds the browsable window so huge audit logs stay responsive.
const LOG_LIMIT: usize = 200;

/// Reads the newest decision-log window from the live audit file. Browsing
/// can archive and rewrite a log holding an invalid record; see
/// `records::recent_decisions` for that recovery contract.
pub(super) fn recent_log() -> Result<DecisionLogView, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    records::recent_decisions(&home, platform, LOG_LIMIT).map_err(|error| error.to_string())
}

/// Reads the same global nap state the decision path enforces, so an expired
/// or absent nap reads as none without a write.
pub(super) fn nap_status() -> Option<NapStatus> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform).ok()?;
    nap::load(&home, platform).ok().flatten().map(NapStatus::of)
}

/// The mutation behind `nah wake`; it only ever restores enforcement.
pub(super) fn wake_nap() -> Result<(), String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    nap::wake(&home, platform).map_err(|error| error.to_string())
}

/// Size of the live audit file, used to notice appended decisions.
pub(super) fn log_size() -> Option<u64> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform).ok()?;
    records::decision_log_size(&home, platform)
}

/// Canonicalizes the working directory as the current project and observes
/// the built-in guards its project declaration names, through `nah_observe`.
/// Any observation failure reads as no declared guards.
pub(super) fn current_project() -> (Option<String>, Vec<String>) {
    use nah_proto::ctx::SchemaVersion;
    use nah_proto::observation::{ObservationQuery, ObservationRequest, ProjectGuardDeclaration};

    let cwd = std::fs::canonicalize(".").ok();
    let current = cwd.as_ref().map(|path| path.display().to_string());
    let Some(declared) = (|| {
        let platform = live_state::host_platform();
        let cwd = AbsolutePath::new(platform, cwd?.to_str()?.to_owned()).ok()?;
        let request = ObservationRequest::new(
            SchemaVersion::V1,
            "tui-project-guards",
            vec![
                ObservationQuery::Cwd {
                    key: "cwd".into(),
                    requested: cwd,
                },
                ObservationQuery::Roots {
                    key: "roots".into(),
                    cwd_key: "cwd".into(),
                },
                ObservationQuery::ProjectGuards {
                    key: "project-guards".into(),
                    roots_key: "roots".into(),
                },
            ],
        )
        .ok()?;
        let observation = nah_observe::fulfill_observation_request(&request).ok()?;
        Some(match observation.project_guard_declaration().ok()? {
            ProjectGuardDeclaration::Present { names } => names.clone(),
            ProjectGuardDeclaration::Absent
            | ProjectGuardDeclaration::Malformed
            | ProjectGuardDeclaration::ReadFailure => Vec::new(),
        })
    })() else {
        return (current, Vec::new());
    };
    (current, declared)
}
