#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Application composition root for nah.

mod adapter_fields;
mod antigravity_adapter;
mod args;
mod catalog;
mod claude_adapter;
mod code_input;
mod codex_adapter;
mod cpu_clock;
// The browser engine excludes the TUI, so its CLI-only helpers have no WASM callers.
#[cfg_attr(target_arch = "wasm32", allow(dead_code, unused_imports))]
mod commands;
mod cursor_adapter;
mod dispatch;
mod docs;
mod guard_knowledge;
mod hermes_adapter;
mod hook_adapter;
mod ignored_project_file;
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
mod legacy_custom_guards;
mod legacy_import;
mod live_state;
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
mod nap;
mod openclaw_adapter;
mod opencode_adapter;
mod pi_adapter;
mod pipeline;
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
mod private_files;
#[cfg_attr(target_arch = "wasm32", allow(dead_code, unused_imports))]
mod records;
mod runtime;
mod save_then_run;
mod session_memory;
mod session_replay;
mod shipped_state;
mod state_protection;
pub mod supplied_state;
// the TUI's terminal backend has no wasm target; the homepage demo compiles
// this crate to wasm32 for the browser "try it" pipeline
#[cfg(not(target_arch = "wasm32"))]
mod tui;

pub use catalog::all_rules_enabled;
pub use dispatch::run;
pub use guard_knowledge::{BlockExample, GuardKnowledge, PassCause, PassExample, guard_knowledge};
pub use legacy_import::{ImportNotice, ImportedNap, ImportedSettings, import_nap, import_settings};
pub use nah_effinterp::{DeclaredSource, DeclaredSourceObservations, SourceProvider};
pub use pipeline::{
    AnalysisRefusal, DecisionResult, EvaluationFailure, EvidenceProvenance, decide_replay,
    decide_replay_code, decide_replay_with_protection, decide_with,
};
pub use runtime::hook_runtime_shells;
pub use save_then_run::RULES as SAVED_RULES;

pub use nah_effinterp::{ObservationBudget, ObservationResolver};
