# Architecture

nah is a Rust workspace with one pipeline and explicit runtime ownership.

## Decision path

```text
tool call
  -> validate call site; normalize Bash, native, or typed visible code
  -> plan typed effects; bounded effect interpreters emit drafts and nested executions
  -> only proven Bash child source re-enters Bash lowering
  -> plan required observations
  -> bounded environment-only preflight and replanning
  -> capture an observation with stable requested environment values
  -> derive policy context and finalize public and language-safety effect streams
  -> unless all enforcement is paused, select and consult custom guards
  -> reduce structural protection, built-ins, and validated custom blocks
  -> fail-closed conversion, then block or delegate
```

`nah-cli` is the composition root; adapters, the corpus, and the homepage demo
reuse its pipeline. Calls without environment dependencies observe once.
Environment drift causes bounded replanning before custom guards run. Live
dispatch attempts a redacted audit append; failure never changes the verdict.
Dry runs, corpus cases, and the demo do not write records.

## Crates

| Crate | Owns |
| --- | --- |
| `nah-proto` | Validated shared and wire/storage contracts |
| `nah-parse` | Bash syntax model and normalization |
| `nah-inline` | Bounded Python/JS/TS effect interpretation, detection, and nested execution |
| `nah-actions` | Plan/finalize lowering and language/Bash integration |
| `nah-observe` | Requested host and project facts |
| `nah-policy` | Structural protection, built-in guards, and verdict reduction |
| `nah-extensions` | Custom-guard lifecycle, selection, templates, execution, and cache |
| `nah-cli` | Live composition, records, commands, and runtime adapters |
| `nah-corpus` | Frozen fixtures, execution, and triage reconciliation |

Internal dependencies are: inline → proto; actions → inline/parse/proto; policy
→ inline/proto; observe/extensions → proto; CLI → all libraries; corpus →
CLI/proto. Parse and proto have no internal dependencies.
Ambient I/O stays out of `nah-proto`, `nah-parse`, `nah-inline`, `nah-actions`,
and `nah-policy`. `tools/gates` is
workspace/CI validation tooling, not a runtime crate.

Crate paths start under `crates/`; other paths are repository-relative.

## Feature ownership

| Area | Owning module |
| --- | --- |
| Shared tool, context, observation, action, decision, and guard contracts | `nah-proto/src/{tool,ctx,observation,action,decision,exec_v1,extension}.rs` |
| Bash syntax and fork-bomb graph parsing | `nah-parse/src/{model,parser}.rs`, `nah-parse/src/parser/fork_bomb.rs` |
| Python/JS/TS effect interpreter, detectors, HIRs, drafts, and nested executions | `nah-inline/src/{lib,language_effects,finding,syntax}.rs`, `nah-inline/src/languages/` |
| Plan/finalize, language integration, and native tools | `nah-actions/src/{lib,language_effects,native,codex_patch}.rs` |
| Ordered Bash lowering and shell/command phases | `nah-actions/src/bash/mod.rs`, `nah-actions/src/bash/phases/` |
| Bash feature semantics | `nah-actions/src/bash/features/`, `nah-actions/src/{paths,shell_word}.rs`, `nah-actions/src/shell_word/` |
| Host and project fact fulfillment | `nah-observe/src/{io_paths,path_facts,roots,project_guards,descendants}.rs` |
| Built-in guards and reduction | `nah-policy/src/{lib,filesystem_guards,git_guards,secret_guards,execution_guards}.rs` |
| Self-protection projection, shell recognition, nap, and reduction | `nah-actions/src/{bash/features/self_protection,self_protection_tiers}.rs`, `nah-inline/src/languages/`, `nah-cli/src/{commands/runtime,nap}.rs`, `nah-policy/src/structural.rs` |
| Custom-guard trust, activation, selection, execution, and cache | `nah-extensions/src/{trust,activation,bundle,selection,execution,transport,cache}.rs` |
| Runtime translation and wiring | `nah-cli/src/*_adapter.rs`, `nah-cli/src/{code_input,hook_adapter,adapter_fields}.rs`, `nah-cli/src/commands/*_installation.rs` |
| Live state, pipeline, dispatch, runtime identity, and records | `nah-cli/src/{live_state,pipeline,dispatch,runtime}.rs`, `nah-cli/src/records/` |
| Guard configuration and TUI | `nah-cli/src/commands/{custom_guard,shipped_guard,guard_config}.rs`, `nah-cli/src/{catalog,shipped_state}.rs`, `nah-cli/src/tui/` |
| Corpus fixtures, runner, oracle, and reconciliation | `nah-corpus/src/{case,fixtures,runner,oracle}.rs` |

`bash/mod.rs` orders transitions, `bash/phases/` lowers, and `bash/features/`
owns semantics. Finalization consumes `nah-observe` facts; lowering does no I/O.

## Find a change

- Bash interpretation: `nah-parse`, then `nah-actions/src/bash/{phases,features}/`.
- Python and JavaScript/TypeScript effect interpretation, including IPython/TSX:
  `nah-inline/src/languages/` and the matching `engine/` module, then
  `nah-actions/src/language_effects.rs`. `nah-cli/src/code_input.rs` owns typed runtime
  intake. Other language modules provide narrower detection. Exact nested
  commands return to actions; private findings reach policy.
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

Prefer feature-named modules and focused tests.

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
