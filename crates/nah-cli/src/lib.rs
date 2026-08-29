#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Application composition root for nah.

mod adapter_fields;
mod amp_adapter;
mod antigravity_adapter;
mod args;
mod catalog;
mod claude_adapter;
mod cline_adapter;
mod code_input;
mod codex_adapter;
// The browser engine excludes the TUI, so its CLI-only helpers have no WASM callers.
#[cfg_attr(target_arch = "wasm32", allow(dead_code, unused_imports))]
mod commands;
mod copilot_adapter;
mod cursor_adapter;
mod devin_adapter;
mod dispatch;
mod docs;
mod droid_adapter;
mod hermes_adapter;
mod hook_adapter;
mod kiro_adapter;
mod live_state;
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
mod nap;
mod openclaw_adapter;
mod opencode_adapter;
mod pi_adapter;
mod pipeline;
mod prime_agent_adapter;
#[cfg_attr(target_arch = "wasm32", allow(dead_code, unused_imports))]
mod records;
mod runtime;
mod shipped_state;
mod state_protection;
// the TUI's terminal backend has no wasm target; the homepage demo compiles
// this crate to wasm32 for the browser "try it" pipeline
#[cfg(not(target_arch = "wasm32"))]
mod tui;

pub use catalog::{all_shipped_guard_states_enabled, shipped_guard_states, shipped_guards};
pub use dispatch::run;
pub use pipeline::{DecisionResult, decide_with};
