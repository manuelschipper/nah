# nah

Context aware safety guard for coding agents. Guards Claude Code tools and local interactive Codex sessions, with an optional bash/zsh terminal guard as a bonus. Deterministic, zero tokens, milliseconds.

**Tagline:** "Safeguard your vibes. Keep your flow state."

## GitHub Communication

**Never post comments, replies, or reviews on GitHub issues or PRs without explicit approval.** When a response is needed, draft the proposed comment and present it for review first. Only post after the user approves the wording and gives the go-ahead.

## Project Structure

- `src/nah/` — Python package (pip-installable, CLI entry point: `nah`)
- `tests/` — pytest test suite
- `docs/features/` — Feature documentation

## Conventions

- **Python 3.10+**, zero external dependencies for the core hook (stdlib only)
- **LLM layer** uses `urllib.request` (stdlib) — no `requests` dependency
- **Entry point**: `nah` CLI via `nah.cli:main`
- **Config format**: YAML (`~/.config/nah/config.yaml` + `.nah.yaml` per project)
- **Claude direct hooks**: settings entries call the installed `nah` executable with `_claude-hook`
- **Testing commands**: Always use `nah test "..."` — never `python -m nah ...` (nah flags the latter as `lang_exec`)

## Error Handling

**No silent pass-through.** Do not swallow exceptions with bare `except: pass` or empty fallbacks unless there is a clear, documented reason. Silent failures hide bugs and make debugging painful.

When a silent pass-through or config fallback **is** justified, it must have a comment explaining:
1. **Why** the failure is expected or harmless
2. **What** the fallback behavior is
3. **Why** surfacing the error would be worse than swallowing it

Good — justified and explained:
```python
except OSError:
    # Read is best-effort optimization; if it fails (race with
    # deletion, permissions, disk), the safe default is to fall
    # through to the write path which will surface real errors.
    pass
```

Bad — silent and unexplained:
```python
except Exception:
    pass
```

**Guidelines:**
- Prefer narrow exception types (`OSError`, `json.JSONDecodeError`) over broad `Exception`
- Functions that must never crash (e.g. `log_decision`) should catch broadly but log to stderr: `sys.stderr.write(f"nah: log: {exc}\n")`
- Config fallbacks to defaults are fine, but log a warning if the config was present but malformed
- Never silence errors in the hot path (hook classification) — if something is wrong, the user should know

## CLI Quick Reference

```bash
# Setup
nah run claude           # launch claude with nah active (this session only)
nah run codex            # launch codex with nah active (this session only)
nah install claude       # install direct Claude Code hooks (permanent)
nah install bash         # install interactive bash guard
nah uninstall claude     # clean direct Claude Code removal
nah update claude        # update hook after package-manager upgrade

# Dry-run classification (no side effects)
nah test "rm -rf /"                        # test a Bash command
nah test "git push --force"                # see action type + policy
nah test --tool Read ~/.ssh/id_rsa         # test Read tool path check
nah test --tool Write ./out.txt --content "BEGIN PRIVATE KEY"  # test write payload review
nah test --tool Grep --pattern "password"  # test credential search detection

# Inspect
nah types                # list all 40 action types with default policies
nah log                  # show recent hook decisions
nah log --blocks         # show only blocked decisions
nah log --asks           # show only ask decisions
nah log --llm            # show only decisions with LLM metadata
nah codex doctor         # inspect Codex approval-memory/MCP preflight state
nah codex setup          # install or fix supported Codex setup state
nah config show          # show effective merged config
nah config path          # show config file locations

# Manage rules
nah allow <type>         # allow an action type
nah deny <type>          # block an action type
nah classify "cmd" <type>  # teach nah a command
nah trust <host|path>    # trust a network host or path
nah status               # show all custom rules
nah forget <type>        # remove a rule
```

## Release Checklist

When cutting a new release:

1. **Run full test suite** — `pytest tests/ --ignore=tests/test_llm_live.py`
2. **Bump version in BOTH places:**
   - `pyproject.toml` → `version = "X.Y.Z"`
   - `src/nah/__init__.py` → `__version__ = "X.Y.Z"`
3. **Update CHANGELOG.md** — change `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD`
4. **Build and validate release artifacts locally:**
   - `python3 scripts/build_claude_plugin.py --marketplace-out dist/claude-marketplace`
   - `python3 scripts/build_claude_plugin.py --check --marketplace-out dist/claude-marketplace`
   - `python3 scripts/check_release.py --tag vX.Y.Z --marketplace-root dist/claude-marketplace`
   - `claude plugin validate dist/claude-marketplace`
   - `python3 -m build` in a venv with `build` installed
5. **Commit** — `git commit -m "vX.Y.Z — <summary>"`
6. **Tag** — `git tag vX.Y.Z`
7. **Push main, then the tag** — `git push origin main` followed by `git push origin vX.Y.Z`
8. **Verify release workflow** — `gh run watch <run-id> --exit-status`
   - The `publish.yml` workflow publishes PyPI, GitHub Release, `claude-marketplace`, and `claude-plugin-vX.Y.Z`
   - If the tag workflow fails before publication, rerun the existing tag with `gh workflow run publish.yml --ref main -f release_tag=vX.Y.Z`
9. **Post-release verify:**
   - `pip install --upgrade nah` and verify `nah --version` matches
   - `claude plugin marketplace add manuelschipper/nah@claude-marketplace --scope user`
   - `claude plugin install nah@nah --scope user`
   - Confirm the installed plugin reports the released version

The self-hosted Claude plugin marketplace lives on the `claude-marketplace`
branch and uses immutable plugin distribution tags named `claude-plugin-vX.Y.Z`.
The public source release tag remains `vX.Y.Z`.

<!-- molds:managed-section:begin -->

---

# Molds Workflow

Molds is the workflow source of truth for repos with a `.molds/` directory.
Postgres is canonical. All task reads and
writes go through the `molds` CLI (`molds show|update|note|section ...`).
Never edit `.molds/*.md` as task state — `.molds/` holds only local config,
runtime files, and artifacts.

A mold is durable work state: title, lifecycle stage, problem, plan,
verification, notes, and audit events — enough for agents and humans to
continue work without relying on chat history.

The lifecycle and skills are the default discipline, not a mandate: when the
operator asks, you may use molds as a lightweight tracker — capture a mold, do
the work in-session, and close it — without running the design/build/qa skills.
The structural gates hold either way: only the operator approves design ->
build, land is always human, and foundry works only poured molds.

Deep dives: run `molds docs` to list topics and `molds docs <topic>` to read
one (e.g. `molds docs lifecycle`, `molds docs foundry`).

## Sections

One flat section vocabulary, decoupled from stages: `TL;DR`, `Problem`,
`Solution`, `Files to Modify`, `Verification`, `Open Questions`,
`Next Step`, `Implementation Notes`, `Notes`. Any section may appear on any
mold and all are optional; `TL;DR` always renders as the document anchor.
There is no profile system and no per-stage section contract — stage moves
never rewrite or convert sections. The only mechanical section check in the
product is the pour gate (below). Exploratory work usually leans on
`TL;DR`/`Notes`/`Open Questions`/`Next Step`; build-ready specs lean on
`Problem`/`Solution`/`Files to Modify`/`Verification` — by convention, not
enforcement.

## Lifecycle

```text
context | research | design -> build -> qa -> land -> closed
```

`blocked` and `deferred` are side stages. `closed` and `wontdo` are
terminal: `closed` means an accepted outcome (for exploratory work,
possibly without producing a buildable spec); `wontdo` means deliberate
rejection or abandonment.

Legal stage transitions:

| From | Legal targets |
| --- | --- |
| `context` | `context`, `research`, `design`, `blocked`, `deferred`, `closed`, `wontdo` |
| `research` | `research`, `design`, `blocked`, `deferred`, `closed`, `wontdo` |
| `design` | `design`, `research`, `build`, `blocked`, `deferred`, `closed`, `wontdo` |
| `build` | `build`, `qa`, `design`, `blocked`, `deferred`, `closed`, `wontdo` |
| `qa` | `qa`, `land`, `build`, `design`, `blocked`, `deferred`, `closed`, `wontdo` |
| `land` | `land`, `build`, `design`, `blocked`, `deferred`, `closed`, `wontdo` |
| `blocked` | `blocked`, `context`, `research`, `design`, `build`, `qa`, `land`, `deferred`, `closed`, `wontdo` |
| `deferred` | `deferred`, `context`, `research`, `design`, `build`, `qa`, `land`, `blocked`, `closed`, `wontdo` |
| `closed` | `closed`, `wontdo` |
| `wontdo` | `wontdo`, `closed` |

Examples: `build -> land` is illegal, `context -> build` is illegal, and
`qa -> build` is legal for a send-back.

## Human Gates

`design` is the human design and signoff queue. `molds build <id>` approves
a design mold into `build` — approval only, never execution; build readiness
is the operator's judgment with no mechanical gate. From `build` onward,
foundry build/QA runs use dedicated worktrees under `.worktrees/<id>`.
`land` is always human: foundry is structurally unable to enter it, so
reviewing the diff and landing is the operator's re-entry point.

## Traces

Traces are the observability contract for unattended work — a land-stage
human must be able to reconstruct the whole episode from `molds show`
alone.

- During `/build-mold`, keep a required `### Build Trace` under
  `Implementation Notes` with short plain bullets for non-obvious
  decisions, tradeoffs, surprises, extra verification details, or
  follow-ups. Do not create sidecar notes files.
- Every QA verdict carries a `QA Trace` (what was checked, what was run,
  what was found). Foundry QA returns it in the verdict's `qa_trace` field
  and the runtime writes it under `Implementation Notes -> ### QA Trace`;
  `molds stamp` records the manual equivalent automatically.
- QA rejects a missing, empty, or perfunctory Build Trace as a
  build-process issue (the runtime also refuses a foundry QA pass without
  one) while still reviewing the code independently.

## Skills

- Capture and explore: `/handoff-mold` (carry-forward memory in `context`),
  `/research-mold` (stateful investigation in `research`), `/new-mold`
  (create after checking for duplicates; links dependencies only to open
  molds — closed matches become provenance notes), `/slice-mold`
  (decompose broad work into dependency-aware molds), `/grill-mold`
  (pressure-test a mold, plan, or idea one question at a time).
- Design: `/design-mold` (shape a build-ready spec in your design session).
- Execute: `/build-mold`, `/qa-mold`, `/land-mold`. Foundry is the
  pipeline for unattended build+QA; there is no foreground pipeline skill.
- Operate: `/close-mold` (manual closeout/disposition; owns the CHANGELOG
  update), `/explain-mold` (read-only context recovery), `/html-mold`
  (human-friendly HTML summary under `.molds/artifacts/<id>/` for
  `molds browse`), `/explore-project` (deep audit of the codebase, active
  molds, and recent activity).

Common flow: rough idea -> `/research-mold` or `/design-mold` ->
`/grill-mold` or `/slice-mold` as needed -> `molds pour <id> -a` ->
foundry builds and QAs unattended -> review at `land` with `/land-mold` ->
`/close-mold`.

## Foundry And Pour

Foundry schedules exactly two lanes — `build` and `qa` — booting with repo
startup defaults (`foundry_provider`, `foundry_interval_seconds`). Its
reach is fixed by structure: a QA pass always parks the mold at `land` for
human review; foundry never touches `context`, `research`, `design`, or
`land`.

- One per-mold boolean, `poured`, answers the only remaining question: may
  foundry work this mold at all. The stage picks the lane.
- `molds pour <id> [-a|--approve]` sets the flag and starts a coordinator
  if needed; `-a` approves a design mold and pours in one gesture (plain
  pour refuses design molds). This is the workflow's primary verb.
- The pour gate is the product's only section validation: pour refuses a
  mold whose `Verification` or `Files to Modify` section is empty —
  presence only; quality stays operator judgment.
- `molds take <id>` clears the flag (the active stage finishes cleanly).
- Failure routing: a QA implementation failure sends the mold back to
  `build` once (`foundry_max_qa_sendbacks`, default 1); the next failure
  parks it in `blocked` with `resume_stage` set and the feedback and
  traces in the mold. Design-flavored failures park immediately — foundry
  never reopens `design`; a human decides that from `blocked`.

## Land Requests

A land request (LR) is the local review record for a landable diff — not a
GitHub PR and not a lifecycle stage. Land entry (including `molds stamp`
moving `qa -> land`) creates or refreshes one automatically when a
`code_branch` diff exists. `molds lr open|show|diff|files <id>` manage it
without moving lifecycle stages: `molds lr open <id>` explicitly refreshes
after new branch work, and `molds lr show <id>` is read-only. Landing the
diff is the approval; `molds update <id> --stage build` is the send-back;
`molds wontdo` abandons. `molds close` refuses an unresolved landable LR.
`molds stamp <id> --verification "..."` is the foreground QA verdict: it
records structured manual QA freshness and moves `qa -> land`;
`--fail implementation|design` records the fail verdict and routes the
send-back instead.

## Git Hosting

Do not create or open pull requests unless the user explicitly asks for a
PR. If a git host prints a PR creation URL after `git push`, treat it as
informational output only.

## CLI Quick Reference

```bash
molds create "<title>" [--stage context|design|research]
molds context|research|design|build|qa|land|block|defer <id>
molds section get|set|append <id> "<section>" --stdin|--file <path>
molds stamp <id> --verification "..."
molds lr show <id>
molds pour <id> [-a|--approve]
molds take <id>
molds update <id> --stage <stage>
molds update <id> --poured true|false
molds show <id> [--json]
molds docs [<topic>|search <query>]
molds list [--json]
molds browse [<id>]
molds note <id> "message"
molds status
molds foundry status
```

Raw stage aliases are state changes only: no worktrees, verification,
merging, or closing.

Lines starting with `%%` inside mold files are agent instructions. Address
each one, then remove the line.
<!-- molds:managed-section:end -->
