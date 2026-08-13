//! Human mutation commands invoked by the CLI dispatcher.

mod amp_installation;
mod antigravity_installation;
mod claude_installation;
mod cline_installation;
mod codex_installation;
mod copilot_installation;
mod cursor_installation;
mod custom_guard;
mod devin_installation;
mod droid_installation;
mod guard_config;
mod hermes_installation;
mod hook_config;
mod kiro_installation;
mod openclaw_installation;
mod opencode_installation;
mod pi_installation;
mod prime_agent_installation;
mod runtime;
mod shipped_guard;
mod test;
mod trust;

pub(crate) use amp_installation::{amp_hook_status, amp_self_protection_paths, mutate_amp_hook};
pub(crate) use antigravity_installation::{
    antigravity_hook_status, antigravity_self_protection_paths, mutate_antigravity_hook,
};
pub(crate) use claude_installation::{
    claude_hook_status, claude_self_protection_paths, mutate_claude_hook,
};
pub(crate) use cline_installation::{
    cline_hook_status, cline_self_protection_paths, mutate_cline_hook,
};
pub(crate) use codex_installation::{
    codex_hook_status, codex_self_protection_paths, mutate_codex_hook,
};
pub(crate) use copilot_installation::{
    copilot_hook_status, copilot_self_protection_paths, mutate_copilot_hook,
};
pub(crate) use cursor_installation::{
    cursor_hook_status, cursor_self_protection_paths, mutate_cursor_hook,
};
pub(crate) use custom_guard::{
    GuardSource, GuardSourceFile, custom_guard_entries, disable_custom_guard,
    disable_custom_guard_scoped, disable_guard_identity, enable_custom_guard,
    enable_custom_guard_scoped, enable_guard_identity, guard_source, list_custom_guards, new_guard,
    validate_guard_identity,
};
pub(crate) use devin_installation::{
    devin_hook_status, devin_self_protection_paths, mutate_devin_hook,
};
pub(crate) use droid_installation::{
    droid_hook_status, droid_self_protection_paths, mutate_droid_hook,
};
pub(crate) use guard_config::{
    GuardChange, GuardEntry, GuardSelector, GuardStatus, GuardTarget, apply_guard_change,
    guard_entries, scope_name, set_guard_enabled, validate_guard_change,
};
pub(crate) use hermes_installation::{
    hermes_hook_status, hermes_self_protection_paths, mutate_hermes_hook,
};
pub(crate) use kiro_installation::{
    kiro_hook_status, kiro_self_protection_paths, mutate_kiro_hook,
};
pub(crate) use openclaw_installation::{
    mutate_openclaw_hook, openclaw_hook_status, openclaw_self_protection_paths,
};
pub(crate) use opencode_installation::{
    mutate_opencode_hook, opencode_hook_status, opencode_self_protection_paths,
};
pub(crate) use pi_installation::{mutate_pi_hook, pi_hook_status, pi_self_protection_paths};
pub(crate) use prime_agent_installation::{
    mutate_prime_agent_hook, prime_agent_hook_status, prime_agent_self_protection_paths,
};
pub(crate) use runtime::{
    RuntimeEntry, RuntimeHookStatus, RuntimeMutation, runtime_entries, runtime_entry,
    runtime_self_protection, set_runtime_configured,
};
pub(crate) use shipped_guard::{
    list_shipped_guards, reset_shipped_guard, set_shipped_guard, shipped_guard_entries,
};
pub(crate) use test::test_command;
pub(crate) use trust::{
    GuardProposals, TrustedProject, canonical_project_root, guard_proposals, trust_root,
    trusted_projects, untrust_root,
};
