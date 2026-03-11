# Installation

## Requirements

- Python 3.10+
- Claude Code (or compatible coding agent)

## Install

```bash
pip install nah
nah install
```

That's it. nah registers itself as a [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) in Claude Code's `settings.json` and creates a read-only hook script at `~/.claude/hooks/nah_guard.py`.

### Optional dependencies

```bash
pip install nah[config]    # YAML config support (pyyaml)
```

The core hook has **zero external dependencies** — it runs on Python's stdlib only. The `config` extra adds `pyyaml` for YAML config file parsing.

## Agent selection

By default, nah installs for Claude Code:

```bash
nah install                # Claude Code (default)
nah install --agent claude # explicit
```

## Update

After upgrading nah via pip:

```bash
pip install --upgrade nah
nah update
```

`nah update` unlocks the hook script, overwrites it with the new version, and re-locks it (chmod 444).

## Uninstall

```bash
nah uninstall
pip uninstall nah
```

`nah uninstall` removes hook entries from `settings.json` and deletes the hook script.

## Verify installation

```bash
nah --version              # check installed version
nah test "git status"      # dry-run classification
nah config path            # show config file locations
```

## Important: don't use bypass mode

!!! warning
    **Don't use `--dangerously-skip-permissions`.**

    In bypass mode, hooks [fire asynchronously](https://github.com/anthropics/claude-code/issues/20946) — commands execute before nah can block them. Use Claude Code's permission system (`acceptEdits` or default mode) as the first layer and nah as defense-in-depth on top. They're complementary, not substitutes.
