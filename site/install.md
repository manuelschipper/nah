# Installation

## Requirements

- Python 3.10+

## Install

```bash
pip install nah
nah install
```

That's it. nah registers itself as a [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) in Claude Code's `settings.json` and creates a read-only hook script at `~/.claude/hooks/nah_guard.py`.

!!! warning "Don't use bypass mode"
    **Don't use `--dangerously-skip-permissions`.** In bypass mode, hooks [fire asynchronously](https://github.com/anthropics/claude-code/issues/20946) — commands execute before nah can block them.

## Recommended setup

Allow-list the read and execute tools — nah guards them via hooks:

```json
{
  "permissions": {
    "allow": ["Bash", "Read", "Glob", "Grep"]
  }
}
```

For **Write** and **Edit**, your call — nah's content inspection runs either way.

### Optional dependencies

```bash
pip install nah[config]    # YAML config support (pyyaml)
```

The core hook has **zero external dependencies** — it runs on Python's stdlib only. The `config` extra adds `pyyaml` for YAML config file parsing.

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

---

<p align="center">
  <code>--dangerously-skip-permissions?</code><br><br>
  <img src="../assets/logo_hammock.png" alt="nah" width="280" class="invertible">
</p>

