//! Four independently measured groups: invocation correctness, invocation
//! coverage, repository coverage, and performance. Authored expectations and
//! consumer parity belong to correctness; completeness claims remain coverage.
// Development bench: measures, spawns children, and records runs on disk.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

pub mod fingerprint;
pub mod invocation;
pub mod latency;
pub mod layered;
pub mod nah;
pub mod repos;
pub mod run;
pub mod unmodeled;
