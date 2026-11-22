// One integration test binary for this crate. Every file under tests/suite/
// is a module here rather than its own linked executable, which keeps each
// worktree's target/ small. Add new integration tests as modules below and run
// one module with `cargo test -p nah-snapshot --test suite <module>::`.
#![cfg(unix)]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod commits;
mod freshness;
mod refusals;
mod retention;
mod round_trip;
mod safety;
mod support;
