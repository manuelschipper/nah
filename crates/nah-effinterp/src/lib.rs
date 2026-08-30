// UNDOCUMENTED-EFFINTERP: private planner bridge; no public product surface yet.

// UNDOCUMENTED-EFFINTERP: engine builds expose the private analyzer adapter.
#[cfg(feature = "effinterp")]
mod annotate;
#[cfg(feature = "engine")]
mod bridge;
#[cfg(feature = "effinterp")]
pub mod labels;
#[cfg(feature = "effinterp")]
mod observe;
mod render;

// UNDOCUMENTED-EFFINTERP: no planner API exists in feature-off builds.
#[cfg(feature = "effinterp")]
pub use {
    annotate::annotate,
    effinterp_proto::{CoverageLevel, Plan, display_resource},
    observe::request,
};
#[cfg(feature = "engine")]
pub use {bridge::analyze_shell, render::render};
