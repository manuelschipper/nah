#![forbid(unsafe_code)]
#![forbid(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Shared contracts for the pipeline, extension protocol, and decisions. This
//! crate owns data shapes and their pure semantic validation, not parser
//! syntax, policy decisions, I/O, or application orchestration.

pub mod action;
pub mod action_v2;
pub mod ctx;
pub mod decision;
pub mod exec_v1;
pub mod extension;
pub mod labels;
pub mod observation;
#[cfg(feature = "effinterp")]
pub mod stream;
pub mod tool;
