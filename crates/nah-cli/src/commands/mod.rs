//! Human mutation commands invoked by the CLI dispatcher.

mod antigravity_installation;
mod claude_installation;
mod codex_installation;
mod cursor_installation;
mod engine_plan_rendering;
mod guard_config;
mod hermes_installation;
mod hook_config;
mod hook_paths;
mod interactive_nap;
mod javascript_bridge;
mod openclaw_installation;
mod opencode_installation;
mod pi_installation;
pub(crate) mod retired_runtime;
mod runtime;
mod shell_word;
mod shipped_guard;
#[cfg(unix)]
mod snapshot;
mod test;

pub(crate) use antigravity_installation::{
    antigravity_hook_status, antigravity_self_protection_paths, mutate_antigravity_hook,
};
pub(crate) use claude_installation::{
    claude_hook_status, claude_self_protection_paths, mutate_claude_hook,
};
pub(crate) use codex_installation::{
    codex_hook_status, codex_self_protection_paths, mutate_codex_hook,
};
pub(crate) use cursor_installation::{
    cursor_hook_status, cursor_self_protection_paths, mutate_cursor_hook,
};
pub(crate) use guard_config::{
    GuardChange, GuardEntry, GuardStatus, GuardTarget, RuleState, apply_guard_change,
    entry_settings, guard_entries, reset_guard_setting, reset_rule, set_guard_setting,
    set_rule_enabled, validate_guard_change,
};
pub(crate) use hermes_installation::{
    hermes_hook_status, hermes_self_protection_paths, mutate_hermes_hook,
};
pub(crate) use interactive_nap::{interactive_nap_request, nap_mode, run_interactive_nap};
pub(crate) use openclaw_installation::{
    mutate_openclaw_hook, openclaw_hook_status, openclaw_self_protection_paths,
};
pub(crate) use opencode_installation::{
    mutate_opencode_hook, opencode_hook_status, opencode_self_protection_paths,
};
pub(crate) use pi_installation::{mutate_pi_hook, pi_hook_status, pi_self_protection_paths};
pub(crate) use runtime::{
    RuntimeEntry, RuntimeHookStatus, RuntimeMutation, runtime_entries, runtime_entry,
    runtime_self_protection, set_runtime_configured,
};
pub(crate) use shell_word::quote_posix_shell_word;
pub(crate) use shipped_guard::{
    applies_at, list_shipped_guards, set_shipped_guard, set_shipped_rule, shipped_guard_entries,
};
#[cfg(unix)]
pub(crate) use snapshot::{
    list_snapshots, prune_snapshots, snapshot_action, snapshot_context, undo_snapshot,
};
pub(crate) use test::{TestError, runtime_tool_call, test_command};
