// One integration test binary for this crate. Every file under tests/suite/
// is a module here rather than its own linked executable, which keeps each
// worktree's target/ small. Add new integration tests as modules below and run
// one module with `cargo test -p nah-extensions --test suite <module>::`.

mod support;

mod bundles;
mod cache;
mod effinterp_stream;
mod lifecycle;
mod transport;
mod windows_bundles;
mod windows_cache;
mod windows_lifecycle;
mod windows_transport;
