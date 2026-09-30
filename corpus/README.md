# Corpus workflow

The corpus is the behavioral oracle for the current shipped policy.
No test imports or executes nah 0.x.

## Ownership

```text
corpus/threat-model.jsonl          reviewed first-principles threat cases
corpus/native.jsonl                reviewed native-tool cases
corpus/code.jsonl                  reviewed code-input cases
corpus/compound.jsonl              reviewed compound agent-command cases
corpus/database.jsonl              reviewed database-destruction cases
corpus/database-services.jsonl     reviewed data-store, framework and managed-database cases
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

### Row shape

A row carries exactly one input form:

```text
"command": "rm -rf /etc"                                Bash command
"tool": "Write", "input": {"file_path": "..."}          native tool call
"language": "python", "code": "import shutil\n..."      code tool source
```

`language` is `python`, `ipython`, `powershell`, `javascript`, or `typescript`.
A code row replays through the route the runtime's code hook takes, not as a
Bash command.

### Depth budget

A new corpus row or lowering branch that only refines an already-blocked shape
(another spelling, encoding, hostname form, or option cluster) must cite the threat
it closes in the row ID or a `TRIAGE.md` note; do not add a row that only proves a
parser variant when the shape is already blocked under every posture.
Breadth work for a family with zero rows needs no such justification.

## Check

```sh
cargo test -p nah-corpus --locked
```
