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

corpus/hook/save-then-run.jsonl    reviewed save-then-run hook rows
             ↓
crates/nah-corpus/src/hook_rows.rs rows through `nah hook <runtime> run`
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

`language` is `python`, `powershell`, `javascript`, or `typescript`.
A code row replays through the route the runtime's code hook takes, not as a
Bash command.

### Hook rows

A row under `corpus/hook/` decides through the runtime's real hook instead
of frozen fixtures, for behavior that depends on the host: save-then-run
saves a real repository before a discard runs. The runner builds the row's
repository in a fresh folder and sends `command` as a Bash call to
`nah hook <runtime> run` under a scratch HOME. Hook rows run on Unix hosts
only, must pass (`TRIAGE.md` lists none), and are not read by the bench.

```text
"runtime": "claude"                       claude (saves) or codex (never saves)
"work": "core"                            core (the default) or strict
"env": {"NAH_TEST_STORE_STALL": "1"}      added to the hook's environment
"repository": {                          built in this order, on branch main
  "config": {"core.logAllRefUpdates":     git settings, set before the first
             "false"},                    commit
  "committed": {"src/lib.rs": "..."},     the first commit
  "commits": [{"src/lib.rs": "..."}],     further commits on main
  "stash": [{"message": "m",              stash entries, oldest first: files
             "files": {"a.md": "..."}}],  written, then `git stash push -u`
  "branches": [{"name": "topic",          branches made at `at` (default
                "at": "stash@{0}",        HEAD), with their own commits
                "commits": [{...}]}],
  "refs": [{"name": "refs/tags/v1",       refs by full name, at `at` with
            "commits": [{...}],           commits only they reach; with
            "message": "release"}],       `message`, an annotated tag
  "worktree": {"big.log": {"bytes": N}},  then written: text, or N bytes
                                          (`"noise": true`: incompressible)
  "links": {"out": "./other"},             then made, each to its target
  "staged": ["src/new.rs"],               then added to the index
  "repositories": ["checkout"],           repositories of their own
  "git": [["update-ref", "refs/x",        git commands, each its arguments,
           "HEAD"]],                      run last
  "index_lock": true,                     .git/index.lock held
  "store_lock": true,                     Nah's snapshot store locked while
                                          the hook runs
  "folder": true                          no Git repository: worktree only
}
"expected": {"verdict": "delegate", "saved": "work/changes-discard"}
"expected": {"verdict": "delegate"}
"expected": {"verdict": "block", "guard": "work/untracked-clean", "reason": ".env"}
```

A saved delegate must tell the agent the snapshot and its `nah undo`
command, and the snapshot must be in the store. A plain delegate must save
nothing. A block must name its rule and contain `reason`. The hook runs in
the scratch folder, so a relative path in `env` lands there.

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
