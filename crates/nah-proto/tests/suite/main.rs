// One integration test binary for this crate. Every file under tests/suite/
// is a module here rather than its own linked executable, which keeps each
// worktree's target/ small. Add new integration tests as modules below and run
// one module with `cargo test -p nah-proto --test suite <module>::`.

mod action;
mod ctx;
mod decision;
mod decision_output;
mod exec;
mod extension;
mod observation;
mod stream;
mod tool;
mod validated_response_compile_fail;
