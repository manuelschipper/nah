# Corpus workflow

The corpus is the behavioral oracle for the current shipped policy.
No test imports or executes nah 0.x.

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
             +
corpus/TRIAGE.md                   implementation-state ledger
```

Add cases for demonstrated threats and boundaries, not to preserve historical
test volume. `TRIAGE.md` tracks implementation progress.

Each JSONL row is self-contained: its descriptive ID, tool input, fixtures, and
exact expected verdict, guard, and coverage define the behavior under test.
Context fixtures name either the compiled factory posture or the intentionally
all-enabled posture; tests must not assume those are equivalent.

## Check

```sh
cargo test -p nah-corpus --locked
```
