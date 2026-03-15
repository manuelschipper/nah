# nah

Context-aware safety guard for Claude Code. Guards all tools (Bash, Read, Write, Edit, Glob, Grep), not just shell commands. Deterministic, zero tokens, milliseconds.

**Tagline:** "A permission system you control."

## GitHub Communication

**Never post comments, replies, or reviews on GitHub issues or PRs without explicit approval.** When a response is needed, draft the proposed comment and present it for review first. Only post after the user approves the wording and gives the go-ahead.

## Project Structure

- `src/nah/` — Python package (pip-installable, CLI entry point: `nah`)
- `tests/` — pytest test suite
- `docs/features/` — Feature design tracking (FD system, local only)

## Conventions

- **Python 3.10+**, zero external dependencies for the core hook (stdlib only)
- **LLM layer** uses `urllib.request` (stdlib) — no `requests` dependency
- **Commit format**: `FD-XXX: Brief description` for feature work
- **Entry point**: `nah` CLI via `nah.cli:main`
- **Config format**: YAML (`~/.config/nah/config.yaml` + `.nah.yaml` per project)
- **Hook script**: `~/.claude/hooks/nah_guard.py` (installed read-only, chmod 444)
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
nah install              # install the PreToolUse hook
nah uninstall            # clean removal
nah update               # update hook after pip upgrade

# Dry-run classification (no side effects)
nah test "rm -rf /"                        # test a Bash command
nah test "git push --force"                # see action type + policy
nah test --tool Read ~/.ssh/id_rsa         # test Read tool path check
nah test --tool Write ./out.txt --content "BEGIN PRIVATE KEY"  # test content inspection
nah test --tool Grep --pattern "password"  # test credential search detection

# Inspect
nah types                # list all 20 action types with default policies
nah log                  # show recent hook decisions
nah log --blocks         # show only blocked decisions
nah log --asks           # show only ask decisions
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

---

## Feature Design (FD) Management

Features are tracked in `docs/features/`. Each FD has a dedicated file (`FD-XXX_TITLE.md`) and is indexed in `FEATURE_INDEX.md`.

### FD Lifecycle

| Stage | Description |
|-------|-------------|
| **Planned** | Identified but not yet designed |
| **Design** | Actively designing (exploring code, writing plan) |
| **Open** | Designed and ready for implementation |
| **In Progress** | Currently being implemented |
| **Pending Verification** | Code complete, awaiting verification |
| **Complete** | Verified working, ready to archive |
| **Deferred** | Postponed (low priority or blocked) |
| **Closed** | Won't implement (superseded or not needed) |

### Slash Commands

| Command | Purpose |
|---------|---------|
| `/fd-new` | Create a new feature design |
| `/fd-explore` | Explore project - overview, FD history, recent activity |
| `/fd-deep` | Deep parallel analysis — 4 agents explore a hard problem from different angles, verify claims, synthesize |
| `/fd-status` | Show active FDs with status and grooming |
| `/fd-verify` | Post-implementation: commit, proofread, verify |
| `/fd-close` | Complete/close an FD, archive file, update index, update changelog |

### Conventions

- **FD files**: `docs/features/FD-XXX_TITLE.md` (XXX = zero-padded number)
- **Commit format**: `FD-XXX: Brief description`
- **Numbering**: Next number = highest across all index sections + 1
- **Source of truth**: FD file status > index (if discrepancy, file wins)
- **Archive**: Completed FDs move to `docs/features/archive/`

### Managing the Index

The `FEATURE_INDEX.md` file has four sections:

1. **Active Features** — All non-complete FDs, sorted by FD number
2. **Completed** — Completed FDs, newest first
3. **Deferred / Closed** — Items that won't be done
4. **Backlog** — Low-priority or blocked items parked for later

### Inline Annotations (`%%`)

Lines starting with `%%` in any file are **inline annotations from the user**. When you encounter them:
- Treat each `%%` annotation as a direct instruction — answer questions, develop further, provide feedback, or make changes as requested
- Address **every** `%%` annotation in the file; do not skip any
- After acting on an annotation, remove the `%%` line from the file
- If an annotation is ambiguous, ask for clarification before acting

### Changelog

- **Format**: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) with [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
- **Updated by**: `/fd-close` (complete disposition only) adds entries under `[Unreleased]`
- **FD references**: Entries end with `(FD-XXX)` for traceability
- **Subsections**: Added, Changed, Fixed, Removed
- **Releasing**: Rename `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD`, add fresh `[Unreleased]` header

---

## Design Workflow (mold)

Design specs use beads with working files in `.mold/` (gitignored).

### Beads (`bd`)

Beads is the task database underneath prep. Bead IDs look like `<prefix>-<hash>` (e.g., `nah-a3f8`, `prep-yz9`). The prefix matches the project.

**Statuses:** `open`, `in_progress`, `blocked`, `deferred`, `closed`
**Priority:** 0-4 (P0 = highest, P2 = default)

#### Common commands

```bash
# Querying
bd list                          # open beads (default view)
bd list --pretty                 # tree view with status symbols
bd list --status open --json     # JSON output for parsing
bd list --all                    # include closed
bd list --label <label>          # filter by label
bd ready                         # unblocked beads ready to work on
bd ready --label design          # design-phase beads
bd ready --label build           # build-phase beads
bd show <id>                     # full bead details
bd show <id> --json              # JSON output
bd search "query"                # full-text search

# Creating & updating
bd create "<title>" --json                    # create bead, get ID
bd create "<title>" -p 1 -d "description"     # with priority and description
bd update <id> --body-file - < file.md        # set body from file
bd update <id> --add-label <label>            # add label
bd update <id> --remove-label <label>         # remove label
bd update <id> --status in_progress           # change status
bd update <id> --priority 1                   # change priority
bd update <id> --assignee "<name>"            # assign
bd update <id> --claim                        # atomically claim (assign + in_progress)

# Closing & lifecycle
bd close <id> --reason "Completed"            # close with reason
bd reopen <id>                                # reopen closed bead
bd delete <id>                                # permanently delete

# Labels & comments
bd label list-all                             # all labels in database
bd comments <id>                              # view comments
bd comments add <id> "comment text"           # add comment

# Dependencies
bd update <id> --deps "blocks:<other-id>"     # add dependency
bd children <id>                              # list child beads
```

### Labels
- `design` — spec phase (working file exists in `.mold/`)
- `build` — signed off, ready to implement

### Lifecycle
`/monew` → `/mosync` → `/moready` → implement → `/moreview` → `/moclose`

### Skills
| Skill | Purpose |
|-------|---------|
| `/monew` | Create bead (label: design) + working file |
| `/mosync` | Bidirectional sync .mold/ ↔ beads |
| `/moready` | Pre-flight + label design→build + delete working file |
| `/moclose` | Close bead + changelog + commit |
| `/mostatus` | Sync + PM dashboard |
| `/moexplore` | Project overview + bead state + activity |
| `/moreview` | Adversarial review + quality gate |
| `/modeep` | 4-agent parallel analysis (Claude Code only) |
| `/modemo` | Full lifecycle test + onboarding walkthrough |

### Inline Annotations (`%%`)
Lines starting with `%%` are instructions to the agent. Address every one, then remove the line.
