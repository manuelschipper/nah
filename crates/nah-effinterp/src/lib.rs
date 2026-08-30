// UNDOCUMENTED-EFFINTERP: private planner bridge; no public product surface yet.

// UNDOCUMENTED-EFFINTERP: engine builds expose the private analyzer adapter.
#[cfg(feature = "engine")]
mod bridge;
// UNDOCUMENTED-EFFINTERP: background snapshot publication for trusted roots. The daemon
// owns process, filesystem, and signal effects that the rest of this crate must not have.
#[cfg(feature = "engine")]
#[allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]
mod daemon;
mod render;

// UNDOCUMENTED-EFFINTERP: no planner API exists in feature-off builds.
#[cfg(feature = "engine")]
pub use {
    bridge::analyze_shell,
    daemon::{
        DaemonRunOptions, PublishedSnapshotVerification, build_daemon_snapshot, daemon_status,
        run_daemon, stop_daemon, verify_published_snapshot,
    },
    render::render,
};
