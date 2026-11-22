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
  `crates/nah-effinterp/`. Where a source may live is
  `nah_observe::SourceAdmission` (a launched script is admitted anywhere);
  `effinterp-bench`'s `FixtureResolver` (`src/nah/corpus.rs`) mirrors it and
  changes with it.
- A filesystem call can block without end, as on a File Provider folder
  whose provider does not answer. Every hook-path call into `nah-observe`
  therefore runs on the threads of `crates/nah-observe/src/bounded.rs` and is
  abandoned at its deadline: `DecisionObservation::fulfill` itself, and the
  bridge's calls through `nah_observe::observe_within_deadline` with the
  invocation deadline's `wall_stop`. A `nah-observe` reader checks
  `io_paths::dataless` before it opens, lists or reads an item, and Git runs
  through `roots::git_command`, which turns materialization of dataless items
  off for it.
- Effinterp annotations are produced in `crates/nah-effinterp/src/annotate.rs`,
  which owns the path label of one effect (`annotate_path_relation`). Its
  submodules answer one question each: `annotate/process_protection.rs`, the
  self-protection tier of a launched process (`process_protection_tier`,
  `nah_control`); `annotate/executed_identity.rs`, which file a launched path
  names when the plan rewrote it first; `annotate/listed_selection.rs`, the
  entries a selection reaches from a listing, the paths a delete's wildcard
  directories reach through the links it lists (`readings_through_links`),
  `followed_through_links`, the one reading of a link-following
  listing, and `leaves_tree_through_link`, whether such a listing leaves its
  root and every project through a link (the `LinkedOutsideTree` label
  `label_propagation.rs` records). In `bridge/`,
  `label_propagation.rs` propagates sensitivity, `observed_labels.rs` serves
  the labels the matcher reads, `git_content_selection.rs` binds Git content
  selections to observed filenames, decides when an earlier change leaves
  a `git add` selection as observed (`change_leaves_add_candidates`) and
  which earlier writes and deletes it is asked after (`staging_changes`,
  each `finishes_before` it or not); the observer answers for the disk they
  leave in `crates/nah-observe/src/staged_after.rs`,
  `retyped_credentials.rs` finds credentials typed out in the call's text,
  reading a native patch's additions and file headers with the lexical scan
  beside the engine's patch parser (`toolcall/patch.rs`, `patch_added_lines`
  and `patch_header_lines`), which also sees forms a runtime applies but the
  parser rejects, and
  `recursive_read_filters.rs` owns the `--exclude` and `--pattern` filters of
  a recursive read and the hidden, `--glob` and `--type` rules of a
  ripgrep-style search (`skipped_by_search_filters`).
  `crates/nah-proto/src/effect_annotation.rs` owns the annotation types, and no later stage
  re-validates them. The pure path classifiers the bridge uses live in
  `crates/nah-proto/src/labels/`; extend them there rather than copying them
  into the bridge. What an effect's selection takes is answered once, in
  `crates/nah-effinterp/src/observation_request.rs`: link following
  (`reads_through_links`, `opens_through_links`, `writes_through_links`,
  `deletes_through_wildcard_directories`, `follows_final_link`), a
  producer's narrowing (`selection_narrowing`, `subtree_reached_whole`), and
  the read or delete a move states (`stated_by_move`). Call these instead of
  re-reading effect attributes; `reads_through_links` has a twin over
  occurrences in `crates/effinterp-matcher/src/evaluate.rs` that must stay
  identical.
- Startup code is what a write puts in a file a later program start runs: a
  user shell or PowerShell profile, or a `.pth` or `*customize.py` file in a
  Python site directory. `startup_file` in
  `crates/nah-proto/src/labels/host_integrity.rs` is the one classifier of
  those files. `plan_evidence` in `crates/nah-effinterp/src/bridge/mod.rs`
  collects it as `StartupCode` and builds its one subject
  (`startup_subject`, with no working directory), both for the profile plan
  the `RemoteWrittenContent` qualifier reads and for
  `SelectedInput::Startup`, which the startup loop in
  `decide_with_evidence_budget` (`crates/nah-cli/src/pipeline.rs`) decides
  as a call of its own with the shipped guards, and again for the
  startup code that decision writes, each `StartupCode::level` counted
  against the engine's `max_execution_depth`. Its public
  projection is the one every call gets; `project_invocation_calls` in
  `bridge/invocation_calls.rs` publishes its calls only when the writing
  request supplied its bytes (`StartupCode::written_from_request`: the
  engine's `written_from_subject` mark, which a native Write, Edit or patch
  sets, and a shell writer sets where `Shell::spells_subject` and every word
  or here-document it writes is literal; code that startup code writes
  also needs its writer's mark). Its
  verdicts are the `startup-code.*` rows of `corpus/filesystem.jsonl`.
- A dependency a call adds is judged against the packages its project
  already has (`untrusted-code/lookalike-package`). The engine's
  package-manager model states an install's literal operands as
  `requested_packages` (`requested_package_attrs` in
  `crates/effinterp-engine/src/models/pkgmgr.rs`; uv's declarative model
  gains them through `with_uv_requested_packages`), which an installer whose
  model states none needs before it is judged;
  `crates/nah-effinterp/src/bridge/lookalike_packages.rs` reads them and the
  manifest text a write leaves, and asks
  `crates/nah-observe/src/installed_packages.rs` for the project's packages;
  `crates/nah-proto/src/labels/dependency.rs` owns names, manifests and the
  one `lookalike` test.
- Nah crates name the engine's plan contract `nah_proto::effinterp_proto`; do
  not alias it. Each runtime adapter is entered as `<runtime>_adapter::run` in
  `crates/nah-cli/src/`, and its hook installation exposes
  `mutate_<runtime>_hook`, `<runtime>_hook_status`, and
  `<runtime>_self_protection_paths` in `commands/<runtime>_installation.rs`.
  Installers take their hook lock through `acquire_hook_lock` in
  `commands/hook_paths.rs`, and adapters read tool input through the
  `tool_input_*` readers in `adapter_fields.rs`; a private copy exists only
  where its behavior differs. A finished call reaches one of
  `hook_adapter`'s post-call handlers, which refresh save-then-run's
  rolling copy and settle session memory: Claude Code and Codex call
  `post_call` (refresh after a success only); Cursor calls
  `lowered_post_call` from its private `post_call` (refresh after a failure
  too, in this process); Antigravity settles in its private `post_call` and
  then calls `post_call_detached` (refresh and settle in a process of its
  own), which Hermes calls alone and the OpenCode, OpenClaw and Pi plugins'
  events reach through `PluginEvent::call_to_decide`. The `--settle` hook
  reaches an adapter as `settle_hook`. The runtimes 2.0 dropped
  (`RetiredRuntime`) answer `nah hook` in `commands/retired_runtime.rs`: a
  `run` that never blocks and the 1.x `uninstall`. The
  real-hook tests of this wiring are `tests/suite/wired_runtimes.rs` and
  `post_call_runtimes.rs`, beside Claude Code's and Codex's in
  `save_then_run.rs`, `session_memory.rs` and `codex_adapter.rs`.
- Production decides every call with the engine alone:
  `crates/nah-cli/src/pipeline.rs` composes the engine plan, the bridge's
  evidence and observations, and `nah-policy`. Two separate gates hold it.
  Nah decision qualification runs `corpus/*.jsonl` fixtures through
  `crates/nah-corpus`, with reviewed exceptions in `corpus/TRIAGE.md`
  (Expected-fail). Engine effect and flow parity runs in
  `effinterp-bench` against `bench/nah/goldens/effects.json`,
  `bench/nah/ceilings.json`, and `bench/scoreboard.json`. The bench scores the engine's plan, not the decision
  the bridge reaches from it, so it never substitutes for the corpus gate.
  A task branch runs the no-regression checks and commits only reviewed
  expectations: corpus rows, `corpus/TRIAGE.md`, `bench/nah/goldens/` and
  `bench/nah/ceilings.json` (`block_gaps`, `guard_silent`, `guard_splits`). It never runs
  `effinterp-bench publish` and never commits `bench/scoreboard.json` or
  `bench/scoreboard.md`; in a merge it takes the target's copies of both. The
  lead publishes on `mschipper/nah-2` after a batch of tasks lands:
  `effinterp-bench measure --group correctness`, then `effinterp-bench
  publish RUN`, with `--rebaseline` when the verdict reports a changed scope,
  as its own commit.
- Save-then-run, `work`'s core answer to Git discards on Unix hosts in every
  runtime whose hook says where its commands run
  (`Runtime::states_where_commands_run`), is
  `crates/nah-cli/src/save_then_run.rs`: `available` names where it runs,
  `RULES` the rules it answers, `discards` reads the discards a snapshot
  covers from the plan, and `unsaveable` drops the core parts whose 1.x guard
  shipped off where nothing saves. Claude Code and Codex share
  `hook_adapter::pre_tool_use_reply`. Whether a discard can lose anything is
  answered once, by `git_discard_loses_nothing` in
  `crates/nah-effinterp/src/bridge/git_loss.rs`, for what it reaches
  (`discard_states`): nothing is lost only when every tracked file there
  already holds what it would write and no untracked or ignored entry is
  reached, whatever its name. `crates/nah-observe/src/git_state.rs` asks Git
  plumbing (`ls-files`, `check-attr`, `diff-index`), never `status` or
  `diff`, whose output configuration changes, and hashes each working copy's
  own bytes (`hash-object --no-filters`) rather than trusting the metadata
  `diff-files` compares. The rules' `GitLossPossible`
  qualifier and save-then-run (the analysis's `lossless`) read the one
  answer, so no runtime or level can be laxer than another. The
  pipeline's `saves` flag
  (`decide_selected`) and `dispatch.rs` (`save_before_run`) wire it in;
  `save_then_run/pre_call.rs` owns the save (`save_discards`, in the save
  child `run_save_child`) and every reason it blocks, `post_call.rs` the
  refresh after a call, and `unfinished.rs` the unfinished-decision marker
  (`UnfinishedMarker`) a hook killed mid-save leaves for the next reply to
  report. Snapshots themselves (save, list, undo) belong to
  `crates/nah-snapshot/`: a save never writes the project's repository. An
  undo (`undo.rs`) writes its work tree and index or, for a snapshot of
  commits (`commits.rs`, which saves what deleted refs and stash entries
  alone reach), adds the saved objects to its object store and recreates
  the missing refs and stash entries.
  `commands/snapshot.rs` serves `nah snapshots` and `nah undo`.
  `corpus/hook/` rows prove it through the real hook.
- Session memory is `crates/nah-cli/src/session_memory.rs`, whose module
  doc names each rule by the id its blocks and `nah session` print
  (`flagged-content-run`, `secret-label`, ...) and where production enters:
  `apply` and `record_final_block` before a call, `post_call::settle` after
  it. Its submodules answer one question each: `facts.rs` what a call's plan
  does (`CallFacts`), `flow.rs` where its content flows, `judge.rs` how
  written content judges when run (`judge_written_content`), `rules.rs` the
  rules and the changes a call proposes, `ledger.rs` the session's log and
  `SessionState` under `~/.nah/sessions/` and the label index snapshots read
  (`labelled_paths`), and `post_call.rs` which proposals the disk confirms.
  It reads the world only through `world.rs` (`World`): live, by
  `nah_observe::session_reads`; in a replay, from supplied state.
  `nah test --session` is `crates/nah-cli/src/session_replay.rs`, which
  decides each call from `crates/nah-cli/src/supplied_state.rs` (the corpus
  fixtures' `ObservationFixture` and `ContextFixture`) and prints the facts
  export; `nah-corpus`'s `tests/suite/session_replay.rs` holds it to the live
  hook through `src/hook_sessions.rs`. Only the replay states where a name
  was first seen, what a write changed and which deletes `rm` asks about
  first (`session_replay/asks.rs`): `session_replay/names.rs` (the
  names a plan uses) reads the record `session_memory/seen.rs` keeps of
  prompts, outputs, calls and written files as keyed term hashes, never
  text, and `session_replay/edits.rs` the line changes, with
  `effinterp_engine::sed_line_edits` reading a sed edit's line addresses.
  `tests/suite/session_memory.rs` drives it through Claude Code's hook;
  `codex_adapter.rs`, `post_call_runtimes.rs` and `wired_runtimes.rs` through
  the other runtimes.
- The decision log is `audit.jsonl` in Nah's state directory, one audit
  record (`AuditRecordV1`, schema `nah/audit/v1`) per decided call; code and
  messages call the file the decision log and one line an audit record, and
  `AuditError` with its `audit-*` codes is the log's. Both live in
  `crates/nah-cli/src/records/`: `decision_log.rs` (`DecisionLog`) appends,
  compacts and recovers the file, `audit_record.rs` defines the record and
  its redaction, `audit_record/presentation.rs` renders it for `nah log`,
  `nah why` and the TUI, and `mod.rs` names the production appends and the
  readers. The TUI reads the projection `DecisionRecord` through
  `tui/app/host_state.rs`; `tui/app/decision_log.rs` holds its log screen
  state and `render_log` (`tui/view.rs`) draws it.
  `tests/suite/audit.rs` covers the log end to end.
- `effinterp-bench` has two verbs over a run record in `bench/runs/<id>/`:
  `measure` records it and prints its verdict, and `publish` makes it the
  baseline; `publish --dry-run` computes the verdict alone. On a task branch
  use only `measure` and `publish --dry-run`; publishing belongs to the lead,
  as the gates bullet says. Search `publish`,
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
- In `crates/effinterp-engine/src/lang/rust/`, follow `RustFrontend` into `walker.rs`, `call_resolution.rs`, and `value_facts.rs`.
- Go analysis enters `crates/effinterp-engine/src/lang/go/mod.rs`. Search `GoWalker` for traversal and `GoCallee` for call resolution, with engine tests in `crates/effinterp-engine/tests/suite/go.rs`.
- Python effect analysis enters `crates/effinterp-engine/src/python/mod.rs`
  (`PythonFrontend`). Its module declarations lead to the domain owners, and
  `crates/effinterp-engine/tests/suite/python.rs` exercises the invocation walk.
- Java frontend wiring is in `crates/effinterp-engine/src/lang/java/mod.rs` (`JavaFrontend`). In that crate, `tests/suite/java.rs` covers execution and summaries, and `src/lang/java/summary/tests.rs` holds the summary unit tests.
- In `crates/effinterp-engine/src/lang/php/`, invocation analysis enters
  `walker/mod.rs` (`walk_php_file`) and repository indexing enters
  `summary/mod.rs` (`summarize_ast`).
- The Ruby frontend in `crates/effinterp-engine/src/lang/ruby/` shares
  `RubyFileContext` between the live walk and summary capture. Tests are in
  the engine's `tests/suite/ruby.rs` and `effinterp-repo`'s
  `tests/suite/ruby_compose.rs`.
- The git command model is `crates/effinterp-engine/src/models/git.rs`: global
  options, alias expansion, the `SubCtx` effect emitters and the `dispatch`
  table. A subcommand's effects live in the `models/git/git_<question>.rs`
  module its `dispatch` arm calls, in a function named for the subcommand
  (`gc`, `reflog`, `history_rewrite`); a few short arms (`commit`, `init`,
  `clone`, and `merge`/`cherry-pick`/`revert`/`am`/`apply`) stay inline, and
  the `config` arm calls `git/git_config_command.rs`.
- Datastore models register in `crates/effinterp-engine/src/models/datastore/mod.rs`. Redis keyspace flushes enter through `RedisCli` and Elasticsearch deletes through `Curl`.
- Network command models and the HTTPie and SFTP extensions are indexed in `crates/effinterp-engine/src/models/net/mod.rs`. Engine suites `net_models` and `network_handlers` cover their effects and socket handler wiring.
- For cloud CLI models, start at `crates/effinterp-engine/src/models/cloud/mod.rs`
  (`cloud_models`) for provider registration and `tests/suite/cloud_models.rs`
  for plan checks.
- The shell frontend is `crates/effinterp-engine/src/shell/`: `mod.rs` holds
  the entry points (`analyze_shell`), limits and shared word values, and
  `item_walk.rs` (`walk_items`) is the statement walker, dispatching to one
  module per construct (`pipeline_walk.rs`, `redirected_group_walk.rs`,
  `conditional_walk.rs`, and `loop_values.rs`, which walks each value a
  `for` list, `while read` loop or `select` menu binds as an iteration of
  its own, the `loop-values.*` corpus rows, and whose `finite_for_value`
  also expands a for-list glob from the served listing). Before the real
  walk of a pipeline, job or loop, `race_probe.rs` (`probe_racing_writes`)
  probes it for the writes that race its reads. Shell state is
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
  `observed_producers.rs`. A `$(cat FILE)` capture is `captured_file.rs`:
  `CapturedFile` (the file, the host writes before the capture, and whether
  bash makes exactly those first), its `text` for an argv word and its
  `script_text` for a here-string or process substitution run as code, which
  fails closed where the walk cannot order a write that reaches the file
  (`stdin_after_assignments` re-marks a here-string after the prefix
  assignments), the `CapturedOperands` a launching shell lends a model and
  its wrappers, and the shell spelling (`captured_file_path`). Script bytes
  read from stdin are recovered in one order, `StdinValue::script_text`
  (`models/mod.rs`), for models (`InvocationCtx::stdin_source`) and
  `source /dev/stdin` alike.
  `nocaseglob` and `dotglob` are spelled into a glob where words expand
  (`shell/eval/word_expansion.rs`: `fold_wildcard_components`,
  `dotglob_patterns`), so a pattern's readers apply bash's default matching
  and never read those options themselves.
- The JavaScript frontend enters in `crates/effinterp-engine/src/js/mod.rs`. Follow `walk_js_program` in `js/walker.rs` for execution and `summarize_ast` in `js/summarize.rs` for summaries the repository linker consumes.
- A JavaScript module load is classified once, by
  `crates/effinterp-engine/src/js/module_load.rs` (`module_load::collect`,
  `ModuleLoads`): every `require` form, `createRequire`, `import()` and a
  static `import` or `export ... from` (`static_load`); its module doc names
  each reader. The file a load names is found by `Nest::follow_dependency`
  in `crates/effinterp-engine/src/nest/dependency_sources.rs`, which owns
  Node's CommonJS search and is shared with Ruby, and a repository module
  summary records loads in `js/summary_load_sites.rs` (`LoadSites`). Its
  tests are `every_loader_form_*` and `loader_base_*` in the engine's
  `tests/suite/js.rs`, `path_dependencies_*` in `tests/suite/nesting.rs`
  and `every_module_load_the_loader_owner_names_*` in `effinterp-repo`'s
  `cross_module.rs`; its corpus rows are the `fs-home.code-javascript-*`
  loader rows (`require-call`, `create-require`, `dynamic-import`, ...).
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

A debug build gives every decision the replay evidence budget
(`cfg!(debug_assertions)` in `crates/nah-cli/src/pipeline.rs`), so it has no
analysis deadline of its own: never install one as a live hook, where a slow
analysis meets the runtime's hook timeout and the call is blocked. Live checks
use a release build.

## Probing commands

Nah's work is judging dangerous commands, so its probes are dangerous by
design. These rules bind every author, reviewer and lead, in every task.

- **Ask `nah test`, and only `nah test`.** It plans a command and never runs
  it. It is the one way to learn how Nah judges a command.
- **A command under test never runs.** Not through a shell, `node`, `python`
  or any other runtime, not through a live hook or another agent, and not in
  a scratch directory, a container or with a temporary `HOME`. The same holds
  for any file a probe reads: a probe file is read by `nah test` and never
  loaded, imported, sourced or executed.
- **A real target exists only as text.** A command or payload that names
  `~`, `$HOME`, `os.homedir()`, `/`, a path outside the scratch directory, a
  real credential or a real remote appears only as an argument to `nah test`
  or as data in a corpus fixture. Any probe file written to disk names
  stand-in targets inside its own scratch directory, such as `./victim-dir`
  or `./fake-credentials`, so that running it by mistake loses nothing.
- **Learn a tool's behaviour from its documentation or source,** not by
  running the command under test to compare. Building a fixture is fine:
  `git init`, commits and file writes inside a fresh scratch directory. So
  are the project's own suites (`cargo test`, the corpus and bench harnesses).
- **When `nah test` cannot answer, stop.** Report what you could not test and
  why. When unsure whether something counts as running a command under test,
  it does.

## Built-in guard design

Nah ships nine guards, each named for what it protects; the set is fixed. A
guard holds rules (`guard/rule`), and a rule is made of parts: each shipped
`GuardDefinition` in `crates/nah-policy` is one part with its `applies_at`
(`core` or `strict`) and the one 1.x guard it `replaces`. A part blocks when
its rule's level reaches its `applies_at`. Only the 1.x import, the CLI's
1.x-name error and save-then-run's `unsaveable` read `replaces`.

Build rules around a concrete loss or exposure that Nah can establish from
modeled evidence. State what the rule catches, which legitimate workflows it
interrupts, and what context Nah cannot determine.

### Core and strict

Apply a part at core when a human handoff is justified by proven broad loss
of working state, destruction of recovery paths, raw credential exposure, or
bypassing checks that prevent substantial loss.

Apply it only at strict when the same operation is routine legitimate work and
its danger depends on context Nah cannot establish. Whole-stack teardown, for
example, may be ordinary cleanup of a disposable environment.

Judge the interruption when the part matches. Users who never invoke the
affected operation are not a reason to move it to strict. Conversely, severity
alone does not justify core: examine realistic legitimate uses and recovery.

### Granularity

One rule should represent a protection a user can meaningfully override.

Extend an existing rule when the new behavior protects against the same kind
of loss; give it a strict part when the new behavior is noisier. Split only
when a concrete workflow needs independent overrides. Separate commands,
providers, or internal effect codes do not by themselves justify separate
rules.

Prefer the fewest rules that preserve useful choices. Keep applicable
protections independent: matching one rule must not suppress another.

### Review

Before adding or widening a rule, explain:

- The consequential mistake it prevents.
- A realistic legitimate workflow it could interrupt.
- Why its scope and `applies_at` fit those cases.
- Why an existing rule can or cannot own the behavior.

Keep the full rule inventory in the README accurate. Keep contributor
reasoning here; command behavior and options belong in help and product docs.

Guard and rule prose lives only in the records, which generate the TUI text,
`nah docs guards`, and `docs/guard-reference.md`:
`crates/nah-cli/guards/<guard>.toml` says what a guard protects, its response,
and what each setting does; `crates/nah-cli/guards/<guard>/<rule>.toml` gives
a rule's summary, what strict adds, the 1.x guards it replaces, its
description, limits, why it applies where it does, and its examples. The
`guard_knowledge` tests hold `strict_adds` and `replaces` to the rule's parts.
Each example names a corpus row;
`crates/nah-corpus/tests/suite/guard_knowledge.rs` holds the rules that row
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
