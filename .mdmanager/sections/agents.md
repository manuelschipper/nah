# Agent instructions

## Contributor search conventions

- For pipeline, feature ownership, or verification, start with
  [docs/architecture.md](docs/architecture.md).
- `bash_*` names in `crates/nah-actions/src/lib.rs` are crate-root aliases
  for modules under `crates/nah-actions/src/bash/features/`; search the
  unprefixed name there (for example, `bash_git` → `git.rs`).
- Private effinterp integration lives in `crates/nah-effinterp/` and is
  marked `UNDOCUMENTED-EFFINTERP`. `.cargo/config.toml` replaces the private
  dependency with `vendor/effinterp-stubs/` for feature-off builds; the stubs
  contain no engine implementation. The `effinterp` job in
  `.github/workflows/ci.yml` owns checkout and source replacement for private
  feature checks. Keep these features out of public product documentation.
- Effinterp annotations are produced in `crates/nah-effinterp/src/annotate.rs`;
  `crates/nah-proto/src/action_v2.rs` owns their types and
  `crates/nah-proto/src/stream.rs` owns stream validation. Follow
  `crates/nah-cli/src/pipeline.rs` for runtime composition.

Edit this guidance in `.mdmanager/sections/agents.md`, then run
`mdmanager project apply agents`. `.mdmanager/project.toml` owns the
composition; `AGENTS.md` is generated and `CLAUDE.md` links to it.

## Build and test layout

Integration tests are one binary per crate: `crates/<crate>/tests/suite/main.rs`
declares each sibling file as a module. Add new integration tests there, not
as top-level `tests/*.rs` files, and run one module with
`cargo test -p <crate> --test suite <module>::`.

Build output stays under one profile. Never set `CARGO_PROFILE_*` or
`CARGO_INCREMENTAL` environment variables and do not pass `--release`: every
distinct profile value makes Cargo link a second full copy of every test
binary under `target/`, and each sddr worktree carries its own `target/`.

## Built-in guard design

Build guards around a concrete loss or exposure that Nah can establish from
modeled evidence. State what the guard catches, which legitimate workflows it
interrupts, and what context Nah cannot determine.

### Factory defaults

Ship on when a human handoff is justified by proven broad loss of working
state, destruction of recovery paths, raw credential exposure, or bypassing
checks that prevent substantial loss.

Ship off when the same operation is routine legitimate work and its danger
depends on context Nah cannot establish. Whole-stack teardown, for example,
may be ordinary cleanup of a disposable environment.

Judge the interruption when the guard matches. Users who never invoke the
affected operation are not a reason to ship it off. Conversely, severity alone
does not justify default-on: examine realistic legitimate uses and recovery.

### Granularity

One guard should represent a protection a user can meaningfully choose.

Extend an existing guard when the new behavior protects against the same
kind of loss. Split only when a concrete workflow needs independent controls
or different defaults. Separate commands, providers, or internal effect codes
do not by themselves justify separate guards.

Prefer the fewest controls that preserve useful choices. Keep applicable
protections independent: matching one guard must not suppress another.

### Review

Before adding or widening a guard, explain:

- The consequential mistake it prevents.
- A realistic legitimate workflow it could interrupt.
- Why its scope and factory default fit those cases.
- Why an existing guard can or cannot own the behavior.

Keep the full guard inventory in the README accurate. Keep contributor
reasoning here; command behavior and options belong in help and product docs.

## Documentation scope

Keep documentation changes proportional. Edit the README or homepage only when
a change makes them inaccurate, and then make the smallest factual correction.
Do not expand surrounding copy or refresh demos and recordings unless requested.

## Keep the changelog curated

`CHANGELOG.md` is the public news feed on nahguard.ai, not a development log.
Add an entry only when an existing user might change how they use or upgrade
Nah, or a prospective user would care that the capability exists.

- Keep one concise `Unreleased` bullet per user outcome, with a bold label and
  plain technical summary. Fold related follow-up work into that bullet.
- Omit docs and copy edits, site polish, internal work, tests, and minor edge
  case or message fixes.
- Keep newest releases first and never rewrite shipped entries.
