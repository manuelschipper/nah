#![forbid(unsafe_code)]
#![forbid(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Shared contracts for the pipeline, extension protocol, and decisions. This
//! crate owns data shapes and their pure semantic validation, not parser
//! syntax, policy decisions, I/O, or application orchestration.

/// The engine's plan contract, re-exported so Nah crates name it `effinterp_proto`.
pub use effinterp_proto;

pub mod action;
pub mod ctx;
pub mod decision;
pub mod effect_annotation;
pub mod effects;
pub mod exec_v2;
pub mod extension;
pub mod guard_host;
pub mod labels;
pub mod observation;
pub mod runtime;
pub mod runtime_protection;
pub mod tool;
