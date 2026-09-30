#![allow(clippy::disallowed_macros, clippy::disallowed_methods)]

// One integration test binary for this crate. Every file under tests/suite/
// is a module here rather than its own linked executable, which keeps each
// worktree's target/ small. Add new integration tests as modules below and run
// one module with `cargo test -p nah-corpus --test suite <module>::`.

mod guard_floor;
mod harness;
