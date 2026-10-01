# Agent instructions

## Contributor search conventions

- For pipeline, feature ownership, or verification, start with
  [docs/architecture.md](docs/architecture.md).
- The effect engine is the `crates/effinterp-*` packages, an unconditional
  dependency. `crates/nah-effinterp/` is Nah's bridge to it. `nah test`
  (`crates/nah-cli/src/commands/test.rs`) is the one dry-run command and
  renders the engine plan through `commands/engine_plan_rendering.rs`.
- Source bytes for the engine are served by
  `crates/nah-effinterp/src/source_observation.rs`, which owns admission and the
  observation manifest; the filesystem reads themselves belong to
  `crates/nah-observe/src/source_files.rs`. Keep filesystem effects out of
  `crates/nah-effinterp/`.
- Effinterp annotations are produced in `crates/nah-effinterp/src/annotate.rs`;
  `crates/nah-proto/src/effect_annotation.rs` owns their types, and no later stage
  re-validates them. The pure path classifiers the bridge uses live in
  `crates/nah-proto/src/labels/`; extend them there rather than copying them
  into the bridge.
- Nah crates name the engine's plan contract `nah_proto::effinterp_proto`; do
  not alias it. Each runtime adapter is entered as `<runtime>_adapter::run` in
  `crates/nah-cli/src/`, and its hook installation exposes
  `mutate_<runtime>_hook`, `<runtime>_hook_status`, and
  `<runtime>_self_protection_paths` in `commands/<runtime>_installation.rs`.
- Production decides every call with the engine alone:
  `crates/nah-cli/src/pipeline.rs` composes the engine plan, the bridge's
  evidence and observations, and `nah-policy`. Two separate gates hold it.
  Nah decision qualification runs `corpus/*.jsonl` fixtures through
  `crates/nah-corpus`, with reviewed exceptions in `corpus/TRIAGE.md`
  (Expected-fail). Frozen engine effect and flow parity runs in
  `effinterp-bench` against `bench/nah/goldens/effects.json`,
  `bench/nah/ceilings.json`, and `bench/scoreboard.json`. The bench scores the engine's plan, not the decision
  the bridge reaches from it, so it never substitutes for the corpus gate.
- `effinterp-bench` has two verbs over a run record in `bench/runs/<id>/`:
  `measure` records it and prints its verdict, and `publish` makes it the
  baseline; `publish --dry-run` computes the verdict alone. Search `publish`,
  not accept, promote or check: `crates/effinterp-bench/src/run/publish.rs`
  owns verdicts and publication. A plane is one measured group (correctness,
  coverage, repositories, performance), selected with `--group`; the
  `bench/invocation` rows are the invocation corpus, not a plane.
- The coverage headline, "understood what it could", counts successfully
  analysed plans outside the `gap` bucket, so a boundary reason's tier in
  `crates/effinterp-bench/src/bench/tiers.rs` sets that number. Move a reason
  out of `gap` only when every site that emits it qualifies: no static
  analyser given the fixture's inputs, including the files and context the
  fixture supplies, could resolve it. A reason with any resolvable site stays
  in `gap` until that site emits a different reason. State the per-site
  evidence in the commit and review; a better number alone is never the
  reason.
- Engine frontends recover a `SemanticValue`
  (`crates/effinterp-engine/src/value.rs`), which lowers to a protocol
  `ResourceExpr` where it reaches an effect. `substitute_value` binds call
  arguments into semantic values; `substitute_resource_expr` (`summary.rs`)
  binds them into resource expressions. Model document types belong to
  `crates/effinterp-model-schema`; import them from `effinterp_model_schema`,
  not through `effinterp_engine`, which compiles them in
  `src/models/registry/`.

Edit this guidance in `.mdmanager/sections/agents.md`, then run
`mdmanager project apply agents`. `.mdmanager/project.toml` owns the
composition; `AGENTS.md` is generated and `CLAUDE.md` links to it.

## Build and test layout

Integration tests are one binary per crate: `crates/<crate>/tests/suite/main.rs`
declares each sibling file as a module. Add new integration tests there, not
as top-level `tests/*.rs` files, and run one module with
`cargo test -p <crate> --test suite <module>::`. The layout gate
`tools/gates/tests/suite/test_layout.rs` fails on any other test binary.

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

A guard's prose and examples live only in its record,
`crates/nah-cli/guards/<guard>.toml`, which generates the TUI text,
`nah docs guards`, and `docs/guard-reference.md`. Each example names a corpus
row; `crates/nah-corpus/tests/suite/guard_knowledge.rs` holds the rules that row
must meet.

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
