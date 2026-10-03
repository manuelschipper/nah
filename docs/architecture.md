# Architecture

nah is a Rust workspace with one pipeline and explicit runtime ownership.

## Decision path

```text
tool call
  -> validate call site; select shell, native, or typed source input
  -> the engine plans typed effects, reading demanded source through the bridge
  -> the bridge plans required observations
  -> observe; replan (bounded) until environment values are stable
  -> the bridge projects labels, host reach, and evidence
  -> shipped guards query the projected plan
  -> the bridge adds their gaps, then attributes coverage
  -> derive policy context
  -> unless all enforcement is paused, select and consult custom guards
  -> reduce structural protection, built-ins, and validated custom blocks
  -> fail-closed conversion, then block or delegate
```

`nah-cli` is the composition root; adapters, the corpus, and the homepage demo
reuse its pipeline. Only live dispatch appends a redacted audit record, and
its failure never changes the verdict.

## Effect engine

The engine returns evidence, never a verdict: typed effects on outside state,
each with a resource expression, provenance, may/must modality, and
conditions. Coverage records what was preserved; a boundary states where and
why analysis stopped. It never invents a resource or reads missing evidence as
no effect, and is bounded and deterministic: a limit yields a boundary.
Planning is pure: host facts arrive through bridge resolvers. Repository
inference indexes source off the latency path and never runs it. The engine
carries no guard name, trust state, or verdict; labels are consumer-supplied.

## Crates

| Crate | Owns |
| --- | --- |
| `nah-proto` | Validated shared and wire/storage contracts |
| `nah-observe` | Requested host and project facts |
| `nah-policy` | Structural protection, built-in guards, and verdict reduction |
| `nah-extensions` | Custom-guard lifecycle, selection, templates, execution, and cache |
| `nah-effinterp` | Engine bridge |
| `nah-cli` | Live composition, records, commands, and runtime adapters |
| `nah-corpus` | Frozen fixtures, execution, and triage reconciliation |
| `nah-corpus-schema` | Corpus row schema shared with the bench |
| `effinterp-proto` | Consumer-neutral plan contract |
| `effinterp-engine` | Invocation planning and its models |
| `effinterp-model-schema` | Model documents and digests |
| `effinterp-repo` | Repository index and queries for the bench |
| `effinterp-trace`, `effinterp-matcher` | Reachability and assertions over a plan |
| `effinterp-conformance` | Repository-query JSON conformance |
| `effinterp-model-factory` | Model authoring tool |
| `effinterp-bench` | Measured runs and publication |
| `effinterp-testkit` | Test fixtures |

Non-dev dependencies (`allowed_nah_deps`, `tools/gates/src/lib.rs`): proto
→ effinterp-proto; observe/extensions → proto; policy → proto and
effinterp-matcher/proto; bridge → proto/observe and the engine, never
policy or extensions; CLI → proto/observe/policy/extensions/bridge; corpus →
CLI/proto/policy/corpus-schema. Engine packages never depend on Nah except
`effinterp-bench` reading `nah-corpus-schema`. Ambient I/O stays out of
`nah-proto` and `nah-policy`. `tools/gates` is workspace/CI validation tooling,
not a runtime crate.

Crate paths omit `crates/`; other paths are repository-relative.

Each `nah-effinterp/src/bridge/` file answers one question: `mod.rs`, plan,
project and complete; `input_selection`, input; `invocation_calls`, calls and
gaps (codes from `effinterp_proto::BOUNDARY_REASONS`); `fact_projection`,
facts; `resource_projection`, resources; `content_flow`, flows;
`label_propagation`, labels; `guard_host_facts`, host facts.

`nah-cli/src/pipeline.rs` composes project, evaluate
(`nah-policy/src/guard_evaluation.rs` over `nah-proto/src/guard_host.rs`),
complete. The evidence graph
(`nah_proto::effects`) also backs host facts, structural self-protection,
custom guards (exec/v2), and records.

## Feature ownership

| Area | Owning module |
| --- | --- |
| Shared contracts | `nah-proto/src/{tool,ctx,observation,action,effects,decision,exec_v2,extension}.rs` |
| Engine bridge | `nah-effinterp/src/{plan_view,source_observation,path_observation,observe,annotate}.rs`, `nah-effinterp/src/bridge/`, `nah-observe/src/source_files.rs` |
| Host and project fact fulfillment | `nah-observe/src/{io_paths,path_facts,roots,project_guards,descendants}.rs` |
| Built-in guards and reduction | `nah-policy/src/{registry,*_guards,shared_queries,guard_evaluation,lib}.rs` |
| Self-protection, runtime-CLI recognition, nap | `nah-proto/src/{runtime_protection,labels/tier}.rs`, `nah-effinterp/src/runtime_cli.rs`, `nah-cli/src/{commands/runtime,nap}.rs`, `nah-policy/src/structural.rs` |
| Custom guards | `nah-extensions/src/{trust,activation,bundle,selection,execution,transport,cache}.rs` |
| Runtime translation and wiring | `nah-cli/src/<runtime>_adapter.rs`, shared `nah-cli/src/{hook_adapter,code_input,adapter_fields}.rs`, `nah-cli/src/commands/<runtime>_installation.rs` |
| Live state, pipeline, dispatch, and records | `nah-cli/src/{live_state,pipeline,dispatch,runtime}.rs`, `nah-cli/src/records/` |
| Guard configuration and TUI | `nah-cli/src/commands/{custom_guard,shipped_guard,guard_config}.rs`, `nah-cli/src/{catalog,shipped_state}.rs`, `nah-cli/src/tui/` |
| Corpus: rows plus `corpus/TRIAGE.md` Expected-fail, the verdict contract | `nah-corpus-schema/src/lib.rs`, `nah-corpus/src/{case,fixtures,runner}.rs` |
| Engine parity; goldens: reviewed evidence lower bounds | `effinterp-bench/src/nah/`, `bench/nah/`, `bench/scoreboard.json` |

## Find a change

- Shell, source, or native tool interpretation: `effinterp-engine`, then the
  bridge's evidence projection. `nah-cli/src/code_input.rs` owns typed runtime
  intake.
- A built-in guard: its `nah-policy` definition and default (`*_guards.rs`),
  `shipped_guard_definitions` (`registry.rs`), its
  `nah-cli/guards/<guard>.toml` record (source of its
  `docs/guard-reference.md` section), and its `corpus/*.jsonl` family.
- Observation: the named module in `nah-observe` and its protocol contract.
- A custom guard: `nah-extensions`, `nah-proto` execution contracts, and the
  matching `nah-cli` command.

Integration tests are one `tests/suite/main.rs` binary per crate
(`tools/gates/tests/suite/test_layout.rs`).

## Verify

Run the owning crate first, then:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

`homepage/wasm` is standalone; follow `homepage/README.md` for its checks.
CI also gates dependencies, purity, test layout, and the corpus.
