// UNDOCUMENTED-EFFINTERP: private planner bridge; no public product surface yet.

// UNDOCUMENTED-EFFINTERP: engine builds expose the private analyzer adapter.
#[cfg(feature = "effinterp")]
mod annotate;
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
#[cfg(feature = "effinterp")]
pub mod labels;
#[cfg(feature = "effinterp")]
mod observe;
mod render;
// UNDOCUMENTED-EFFINTERP: demanded source bytes for the private engine. It serves the
// files the engine asks for and nothing else. The engine's resolver contract is
// Send + Sync and calls back re-entrantly during one analysis, so this module owns
// shared state; the filesystem effects themselves stay in nah-observe.
#[cfg(feature = "engine")]
#[allow(clippy::disallowed_types)]
mod source_observation;

// UNDOCUMENTED-EFFINTERP: no planner API exists in feature-off builds.
#[cfg(feature = "effinterp")]
pub use {
    annotate::annotate,
    effinterp_proto::{CoverageLevel, Plan, display_resource},
    observe::request,
};
#[cfg(feature = "engine")]
pub use {
    bridge::{
        AdapterRefusal, EvidenceBudget, EvidencePlan, RefusalKind, SelectedInput, SourceLanguage,
        analyze_shell, finalize_evidence, observed_environment, plan_evidence,
    },
    daemon::{
        DaemonRunOptions, PublishedSnapshotVerification, build_daemon_snapshot, daemon_status,
        run_daemon, stop_daemon, verify_published_snapshot,
    },
    render::render,
    source_observation::SourceObservation,
};
