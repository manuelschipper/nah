// UNDOCUMENTED-EFFINTERP: private planner bridge; no public product surface yet.

// UNDOCUMENTED-EFFINTERP: engine builds expose the private analyzer adapter.
#[cfg(feature = "engine")]
mod bridge;
mod render;

// UNDOCUMENTED-EFFINTERP: no planner API exists in feature-off builds.
#[cfg(feature = "engine")]
pub use {bridge::analyze_shell, render::render};
