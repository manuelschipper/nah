// One integration test binary for this crate. Every file under tests/suite/
// is a module here rather than its own linked executable, which keeps each
// worktree's target/ small. Add new integration tests as modules below and run
// one module with `cargo test -p nah-policy --test suite <module>::`.

mod support;

mod execution_guards;
mod filesystem_guards;
mod git;
mod infrastructure_guards;
mod inline_findings;
mod reducer;
mod registry_guards;
mod secret_guards;
mod storage_guards;
mod structural;
mod system_guards;
