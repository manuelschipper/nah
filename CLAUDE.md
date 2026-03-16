# nah

Context-aware safety guard for Claude Code. Guards all tools (Bash, Read, Write, Edit, Glob, Grep), not just shell commands. Deterministic, zero tokens, milliseconds.

**Tagline:** "A permission system you control."

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
- **Hook script**: `~/.claude/hooks/nah_guard.py` (installed read-only, chmod 444)
- **Testing commands**: Always use `nah test "..."` — never `python -m nah ...` (nah flags the latter as `lang_exec`)
- **Branch protection**: `main` is protected — all changes require a PR. Create a feature branch, push, and open a PR via `gh pr create`

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
nah types                # list all 23 action types with default policies
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

## Design Workflow (molds)

Design specs use beads with working files in `.molds/` (gitignored).

### Beads (`bd`)

Beads is the task database underneath molds. Bead IDs look like `<prefix>-<hash>` (e.g., `nah-a3f8`, `molds-yz9`). The prefix matches the project.

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
- `design` — spec phase (working file exists in `.molds/`)
- `build` — signed off, ready to implement

### Lifecycle
`/monew` → `/moready` → implement → `/moreview` → `/moclose`

### Skills
| Skill | Purpose |
|-------|---------|
| `/monew` | Create bead (label: design) + working file |
| `/moready` | Pre-flight + label design→build + delete working file |
| `/moclose` | Close bead + changelog + commit |
| `/mostatus` | Dashboard grouped by phase |
| `/moexplore` | Project overview + bead state + activity |
| `/moreview` | Adversarial review + quality gate |
| `/modeep` | 4-agent parallel analysis (Claude Code only) |
| `/modemo` | Full lifecycle test + onboarding walkthrough |

### Inline Annotations (`%%`)
Lines starting with `%%` are instructions to the agent. Address every one, then remove the line.
