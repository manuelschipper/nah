// One integration test binary for this crate. Every file under tests/suite/
// is a module here rather than its own linked executable, which keeps each
// worktree's target/ small. Add new integration tests as modules below and run
// one module with `cargo test -p nah-inline --test suite <module>::`.

mod ipython_golden;
mod javascript_runtime_profiles;
mod language_effects;
mod python_golden;
mod runtime_oracle;
mod windows_languages;
