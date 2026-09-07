// One integration test binary for this crate. Every file under tests/suite/
// is a module here rather than its own linked executable, which keeps each
// worktree's target/ small. Add new integration tests as modules below and run
// one module with `cargo test -p nah-cli --test suite <module>::`.

mod support;

mod amp_adapter;
mod amp_installation;
mod antigravity_installation;
mod audit;
mod catalog;
mod claude_adapter;
mod claude_installation;
mod cline_adapter;
mod cline_installation;
mod codex_installation;
mod command;
mod copilot_adapter;
mod copilot_installation;
mod cursor_installation;
mod daemon;
mod degraded_state;
mod devin_installation;
mod docs;
mod droid_adapter;
mod droid_installation;
mod effinterp_switch;
mod execution;
mod extensions;
mod failure_policy_installation;
mod filesystem;
mod git;
mod guard_registry;
mod hermes_adapter;
mod hermes_installation;
mod host_integrity;
mod json_contracts;
mod kiro_adapter;
mod kiro_installation;
mod latency;
mod live_state;
mod lowering;
mod nap;
mod openclaw_adapter;
mod openclaw_installation;
mod opencode_adapter;
mod opencode_installation;
mod pi_adapter;
mod pi_installation;
mod prime_agent_adapter;
mod prime_agent_installation;
mod secrets;
mod self_protection;
mod shell_resolution;
mod trust;
mod tui;
mod unavailable;
mod windows_extensions;
mod windows_unresolved_filesystem;
mod windows_unsupported_installation;
mod xi_installation;
