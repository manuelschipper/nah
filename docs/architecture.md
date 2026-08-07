# Architecture

nah is a Rust workspace with one decision pipeline and explicit ownership.

## Decision path

```text
tool call
  -> validate the call site; normalize Bash or accept typed native input
  -> plan typed effects; exact inline child commands re-enter Bash lowering
  -> plan required observations
  -> bounded environment-only preflight and replanning
  -> capture a request-bound observation with stable requested environment values
  -> derive policy context and finalize typed effects
  -> unless all enforcement is paused, select and consult custom guards
  -> reduce structural protection, built-in guards, and validated custom blocks
  -> fail-closed conversion, then block or delegate
```

`nah-cli` is the composition root; runtime adapters, the corpus harness, and the
homepage demo reuse its pipeline. Calls without environment dependencies observe
once. Environment drift causes bounded replanning and another observation before
custom guards run. Live dispatch then attempts a redacted audit append; audit
failure never changes the verdict. Dry runs, corpus cases, and the demo do not
write audit records.

## Crates

| Crate | Owns |
| --- | --- |
| `nah-proto` | Validated shared and wire/storage contracts |
| `nah-parse` | Bash syntax model and normalization |
| `nah-inline` | Bounded language findings and exact child-execution descriptors |
| `nah-actions` | Pure plan/finalize lowering, including proven inline children |
| `nah-observe` | Requested host and project facts |
| `nah-policy` | Structural protection, built-in guards, and verdict reduction |
| `nah-extensions` | Custom-guard lifecycle, selection, templates, execution, and cache |
| `nah-cli` | Live composition, records, commands, and runtime adapters |
| `nah-corpus` | Frozen fixtures, execution, oracle audit, and reconciliation |

Internal dependencies are: inline → proto; actions → inline/parse/proto;
policy → inline/proto; observe and extensions → proto; CLI → all seven library
crates; corpus → CLI/proto. Parse and proto have no internal dependencies.
Ambient I/O stays out of `nah-proto`, `nah-parse`, `nah-inline`, `nah-actions`,
and `nah-policy`. `tools/gates` is
workspace/CI validation tooling, not a runtime crate.

Paths below beginning with `nah-*` start under `crates/`; every path names its
crate. Tests and other paths are repository-relative.

## Feature ownership

| Area | Owning module |
| --- | --- |
| Shared tool, context, observation, action, decision, and guard contracts | `nah-proto/src/{tool,ctx,observation,action,decision,exec_v1,extension}.rs` |
| Bash syntax and fork-bomb graph parsing | `nah-parse/src/{model,parser}.rs`, `nah-parse/src/parser/fork_bomb.rs` |
| Inline language findings, child descriptors, and protected-state recognition | `nah-inline/src/{lib,finding,syntax}.rs`, `nah-inline/src/languages/` |
| Plan/finalize entry points and native tools | `nah-actions/src/{lib,native,codex_patch}.rs` |
| Ordered Bash lowering and shell/command phases | `nah-actions/src/bash.rs`, `nah-actions/src/bash/` |
| Feature-specific Bash planning, effects, and finalization | `nah-actions/src/bash_*.rs`, `nah-actions/src/{paths,shell_word}.rs`, `nah-actions/src/shell_word/` |
| Host and project fact fulfillment | `nah-observe/src/{io_paths,path_facts,roots,project_guards,descendants}.rs` |
| Built-in guards and reduction | `nah-policy/src/{lib,filesystem_guards,git_guards,secret_guards,execution_guards}.rs` |
| Self-protection projection, shell recognition, nap, and reduction | `nah-actions/src/{bash_self_protection,self_protection_tiers}.rs`, `nah-inline/src/languages/`, `nah-cli/src/{commands/runtime,nap}.rs`, `nah-policy/src/structural.rs` |
| Custom-guard trust, activation, selection, execution, and cache | `nah-extensions/src/{trust,activation,bundle,selection,execution,transport,cache}.rs` |
| Runtime translation and wiring | `nah-cli/src/*_adapter.rs`, `nah-cli/src/{hook_adapter,adapter_fields}.rs`, `nah-cli/src/commands/*_installation.rs`; matching or inline tests |
| Live state, pipeline, dispatch, runtime identity, and records | `nah-cli/src/{live_state,pipeline,dispatch,runtime}.rs`, `nah-cli/src/records/` |
| Guard configuration and TUI | `nah-cli/src/commands/{custom_guard,shipped_guard,guard_config}.rs`, `nah-cli/src/{catalog,shipped_state}.rs`, `nah-cli/src/tui/` |
| Corpus fixtures, runner, oracle, and reconciliation | `nah-corpus/src/{case,fixtures,runner,oracle}.rs` |

`bash.rs` orders state transitions; child modules own each phase and
feature-named `bash_*.rs` files own semantics. Pure lowering never observes the
host; finalization consumes bound facts supplied by `nah-observe`.

## Find a change

- Bash interpretation: `nah-parse`, then `nah-actions/src/bash/` or the
  matching `bash_*.rs` analyzer.
- Python interpretation: `nah-inline/src/languages/python/{parser,engine}.rs`;
  other inline signatures remain under `nah-inline/src/languages/`. Exact
  children re-enter `nah-actions`, and private findings reach `nah-policy`.
- Native tool shapes: the runtime adapter, `nah-actions/src/native.rs`, and
  `codex_patch.rs` for `apply_patch`.
- A built-in guard: its semantic lowering in `nah-actions`, reducer in `nah-policy`,
  focused tests, and matching `corpus/*.jsonl` family.
- Observation: the named module in `nah-observe` and its protocol contract.
- A custom guard: `nah-extensions`, `nah-proto` execution contracts, and the
  matching `nah-cli` command.
- CLI, records, or runtime installation: the feature-named `nah-cli` module.
- Interactive configuration: `nah-cli/src/tui/`; mutations remain in their
  owning command modules.

Prefer feature-named modules and focused tests; add no abstraction for one use.

## Verify

Run the owning crate first, then:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo bench --workspace --no-run --locked
```

`homepage/wasm` is standalone; follow `homepage/README.md` for its checks.
CI also checks dependency direction, purity, corpus integrity/reconciliation,
and the standalone parser spike.
