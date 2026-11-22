// One integration test binary for this crate. Every file under tests/suite/
// is a module here rather than its own linked executable, which keeps each
// worktree's target/ small. Add new integration tests as modules below and run
// one module with `cargo test -p nah-cli --test suite <module>::`.

mod support;

mod antigravity_installation;
mod audit;
mod block_messages;
mod catalog;
mod claude_adapter;
mod claude_installation;
mod codex_adapter;
mod codex_installation;
mod command;
mod coverage;
mod cursor_installation;
mod degraded_state;
mod docs;
mod engine_provenance;
mod execution;
mod failure_policy;
mod failure_policy_installation;
mod filesystem;
mod git;
mod guard_registry;
mod hermes_adapter;
mod hermes_installation;
mod host_integrity;
mod json_contracts;
mod latency;
mod live_state;
mod nap;
mod openclaw_adapter;
mod openclaw_installation;
mod opencode_adapter;
mod opencode_installation;
mod operator_checks;
mod pi_adapter;
mod pi_installation;
mod post_call_runtimes;
mod retired_runtimes;
mod save_then_run;
mod secrets;
mod self_protection;
mod session_memory;
mod shell_resolution;
mod test_command;
mod tui;
mod windows_unresolved_filesystem;
mod windows_unsupported_installation;
mod wired_runtimes;
