# nah

Context-aware safety guard for Claude Code. Guards all tools (Bash, Read, Write, Edit, Glob, Grep), not just shell commands. Deterministic, zero tokens, milliseconds.

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
nah claude               # launch claude with nah active (this session only)
nah install              # install the PreToolUse hook (permanent)
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

## Release Checklist

When cutting a new release:

1. **Run full test suite** — `pytest tests/ --ignore=tests/test_llm_live.py`
2. **Bump version in BOTH places:**
   - `pyproject.toml` → `version = "X.Y.Z"`
   - `src/nah/__init__.py` → `__version__ = "X.Y.Z"`
3. **Update CHANGELOG.md** — change `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD`
4. **Commit** — `git commit -m "vX.Y.Z — <summary>"`
5. **Tag** — `git tag vX.Y.Z`
6. **Push** — `git push origin main --tags`
7. **Verify** — `gh run watch` to confirm PyPI publish + GitHub Release succeed
8. **Post-release** — `pip install --upgrade nah` and verify `nah --version` matches

---

## Design Workflow (molds)

Design specs live in `.molds/` as markdown files. Each spec goes through a lifecycle: design → build → archive.

### Statuses
- `design` — spec is being written (working file in `.molds/`)
- `build` — spec signed off, ready to implement (file stays in `.molds/`)

### Lifecycle
`/new-mold` → `/design-mold` → `/ready-mold` → `/build-mold` → `/review-code` → `/close-mold`

### Skills
| Skill | Purpose |
|-------|---------|
| `/new-mold` | Create mold + scaffolded working file |
| `/design-mold` | Design copilot — explore, propose, critique specs |
| `/ready-mold` | Pre-flight checks + sign off design → build |
| `/build-mold` | Spec-driven implementation — walks Files to Modify, commits, verifies |
| `/close-mold` | Close mold + archive + changelog |
| `/explore-project` | Project overview + mold state + activity |
| `/review-code` | Adversarial code review against spec |
| `/deep-analysis` | Deep parallel research (Claude Code only) |
| `/handoff` | Context dump to mold for next session |
| `/groom-molds` | Audit open molds against codebase — detect stale/done/superseded |

### CLI
```bash
molds create "<title>"            # create a new mold
molds update <id> --status <s>    # update mold status
molds close <id>                  # close and archive
molds status                      # dashboard
```

### Inline Annotations (`%%`)
Lines starting with `%%` are instructions to the agent. Address every one, then remove the line.
