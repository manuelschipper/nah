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
- Effinterp annotations are produced in `crates/nah-effinterp/src/annotate.rs`,
  which owns the path label of one effect (`annotate_path_relation`). Its
  submodules answer one question each: `annotate/process_protection.rs`, the
  self-protection tier of a launched process (`process_protection_tier`,
  `nah_control`); `annotate/executed_identity.rs`, which file a launched path
  names when the plan rewrote it first; `annotate/listed_selection.rs`, the
  entries a selection reaches from a listing, and `followed_through_links`, the
  one reading of a link-following listing. In `bridge/`,
  `label_propagation.rs` propagates sensitivity, `observed_labels.rs` serves
  the labels the matcher reads, and `recursive_read_filters.rs` owns the
  `--exclude` and `--pattern` filters of a recursive read and the hidden,
  `--glob` and `--type` rules of a ripgrep-style search
  (`skipped_by_search_filters`).
  `crates/nah-proto/src/effect_annotation.rs` owns the annotation types, and no later stage
  re-validates them. The pure path classifiers the bridge uses live in
  `crates/nah-proto/src/labels/`; extend them there rather than copying them
  into the bridge. What an effect's selection takes is answered once, in
  `crates/nah-effinterp/src/observation_request.rs`: link following
  (`reads_through_links`, `opens_through_links`, `writes_through_links`), a
  producer's narrowing (`selection_narrowing`, `subtree_reached_whole`), and
  the read or delete a move states (`stated_by_move`). Call these instead of
  re-reading effect attributes; `reads_through_links` has a twin over
  occurrences in `crates/effinterp-matcher/src/evaluate.rs` that must stay
  identical.
- Nah crates name the engine's plan contract `nah_proto::effinterp_proto`; do
  not alias it. Each runtime adapter is entered as `<runtime>_adapter::run` in
  `crates/nah-cli/src/`, and its hook installation exposes
  `mutate_<runtime>_hook`, `<runtime>_hook_status`, and
  `<runtime>_self_protection_paths` in `commands/<runtime>_installation.rs`.
  Installers take their hook lock through `acquire_hook_lock` in
  `commands/hook_paths.rs`, and adapters read tool input through the
  `tool_input_*` readers in `adapter_fields.rs`; a private copy exists only
  where its behavior differs.
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
  owns verdicts and publication; `run/measure.rs` (`measure_run`) owns
  measurement. A plane is one measured group (correctness,
  coverage, repositories, performance), selected with `--group`; the
  `bench/invocation` rows are the invocation corpus, not a plane.
- The coverage headline, "understood what it could", counts successfully
  analysed plans outside the `gap` bucket, so a boundary reason's tier in
  `crates/effinterp-bench/src/invocation/tiers.rs` sets that number. Move a reason
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
  binds them into resource expressions; build an unresolved one with
  `value::unresolved_resource(family)`, a concrete path with
  `fs_path_resource` and an endpoint with `url_endpoint_resource`, never a
  per-file helper. Frontend types
  carry their language (`<Lang>ControlFlowBuilder`, `<Lang>Walker`), while the
  entry points keep the shared names `analyze` and `summarize_ast`. Model document types belong to
  `crates/effinterp-model-schema`; import them from `effinterp_model_schema`,
  not through `effinterp_engine`, which compiles them in
  `src/models/registry/`.
- The git command model is `crates/effinterp-engine/src/models/git.rs`: global
  options, alias expansion, the `SubCtx` effect emitters and the `dispatch`
  table. A subcommand's effects live in the `models/git/git_<question>.rs`
  module its `dispatch` arm calls, in a function named for the subcommand
  (`gc`, `reflog`, `history_rewrite`); a few short arms (`commit`, `init`,
  `clone`, and `merge`/`cherry-pick`/`revert`/`am`/`apply`) stay inline, and
  the `config` arm calls `git/git_config_command.rs`.
- The shell frontend is `crates/effinterp-engine/src/shell/`: `mod.rs` holds
  the entry points (`analyze_shell`), limits and shared word values, and
  `item_walk.rs` (`walk_items`) is the statement walker, dispatching to one
  module per construct (`pipeline_walk.rs`, `redirected_group_walk.rs`,
  `conditional_walk.rs`, `for_list_iterations.rs`). Shell state is
  `shell_env.rs` (`ShellEnv`, `VarEntry`, `ArrayValue`) with
  `child_shell_env.rs`, `name_tables.rs` and `function_definition.rs`. One
  simple command is `shell/eval/`: `simple_command.rs`
  (`eval_simple_command`) expands and resolves the head, `eval.rs` owns
  `dispatch_argv` (builtin, alias and function dispatch, deliberately one
  function), and each further question has its module (`function_call.rs`,
  `process_execution.rs`, `producer_wiring.rs`, `deferred_process.rs`,
  `nested_shell_source.rs`, `obfuscated_command.rs`). Credential output
  marking is `disclosed_environment_reads.rs`; which earlier writes a
  variable use observes, including across loop iterations (`walk_loop`), is
  `observed_producers.rs`.
- `effinterp-repo` composition and linking must not dispatch on source
  language; `tests/suite/effect_ir_linker.rs` checks an explicit list of
  `compose/*.rs` and `linker/*.rs` files, so add a new file there.

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
