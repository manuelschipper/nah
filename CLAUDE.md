# nah

Context-aware safety guard for Claude Code. Guards all tools (Bash, Read, Write, Edit, Glob, Grep), not just shell commands. Deterministic, zero tokens, milliseconds.

**Tagline:** "A permission system you control."

## Project Structure

- `src/nah/` — Python package (pip-installable, CLI entry point: `nah`)
- `tests/` — pytest test suite

## Conventions

- **Python 3.10+**, zero external dependencies for the core hook (stdlib only)
- **LLM layer** uses `urllib.request` (stdlib) — no `requests` dependency
- **Entry point**: `nah` CLI via `nah.cli:main`
- **Config format**: YAML (`~/.config/nah/config.yaml` + `.nah.yaml` per project)
- **Hook script**: `~/.claude/hooks/nah_guard.py` (installed read-only, chmod 444)

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
