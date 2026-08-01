# Corpus workflow

The corpus is the behavioral oracle for policy version 1. No test imports or
executes nah 0.x.

## Ownership

```text
corpus/threat-model.jsonl          reviewed first-principles threat cases
corpus/native.jsonl                reviewed native-tool cases
corpus/execution-flows.jsonl       reviewed execution-flow cases
corpus/filesystem.jsonl            reviewed filesystem cases
corpus/git.jsonl                   reviewed Git cases
corpus/local-utilities.jsonl       reviewed local-utility cases
corpus/project.jsonl               reviewed project-operation cases
corpus/secrets.jsonl               reviewed secret-handling cases
corpus/shell-resolution.jsonl      reviewed shell-resolution cases
corpus/self-protection.jsonl       reviewed structural-protection cases
corpus/FIXTURES.json               frozen contexts and observations
             ↓
crates/nah-corpus/src/case.rs      typed case decoder
crates/nah-corpus/src/fixtures.rs  frozen observation builder
crates/nah-corpus/src/runner.rs    cases through nah-cli::decide_with
crates/nah-corpus/src/oracle.rs    reviewed historical provenance gate
             +
corpus/TRIAGE.md                   implementation-state ledger
corpus/ORACLE.json                 selected 0.x verdict provenance
```

`threat-model.jsonl` reimplements useful attacks directly with stable 1.0
case IDs. `ORACLE.json` freezes reviewed 0.x verdicts for
security cases shared by both generations. It is provenance, not executable
legacy code: the Rust harness reruns each native case and enforces two monotonic
invariants:

- every reviewed 0.x block remains a 1.x block;
- every reviewed security-relevant 0.x delegate remains non-allowing.

The gate covers invariant, wrapper, storage, Git, secret, flow,
self-protection, and runtime-adapter families. Its pinned case and family counts
prevent accidental coverage shrinkage.

Add cases for demonstrated threats and boundaries, not to preserve historical
test volume. `TRIAGE.md` tracks implementation progress independently of the
historical comparison.

Each JSONL row is self-contained: its descriptive ID, tool input, fixtures, and
exact expected verdict, guard, and coverage define the behavior under test.

## Check

```sh
cargo test -p nah-corpus --locked
```
