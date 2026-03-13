# Installation

## Requirements

- Python 3.10+

## Install

```bash
pip install nah
nah install
```

nah registers itself as a [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) in Claude Code's `settings.json` and creates a read-only hook script at `~/.claude/hooks/nah_guard.py`.

### Optional dependencies

```bash
pip install nah[config]    # YAML config support (pyyaml)
```

The core hook has **zero external dependencies** — it runs on Python's stdlib only. The `config` extra adds `pyyaml` for YAML config file parsing.

## How permissions work

Once installed, nah takes over permissions for Bash, Read, Write, Edit, Glob, Grep, and all MCP tools. Safe operations go through automatically, dangerous ones are blocked, ambiguous ones ask.

WebFetch and WebSearch are not guarded by nah. Claude Code handles those with its own permission prompts.

**Don't use `--dangerously-skip-permissions`** — just run `claude` in default mode. In `--dangerously-skip-permissions` mode, hooks [fire asynchronously](https://github.com/anthropics/claude-code/issues/20946) and commands execute before nah can block them.

### active_allow

By default nah actively allows safe operations for all guarded tools. You can control this per tool:

```yaml
# ~/.config/nah/config.yaml

# Only actively allow these tools (Write/Edit fall back to Claude Code's prompts)
active_allow: [Bash, Read, Glob, Grep]

# Disable active allow entirely (nah still blocks/asks, but safe operations
# fall through to Claude Code's permission system)
active_allow: false
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

## See it in action

Clone the repo and run the security demo inside Claude Code:

```bash
git clone https://github.com/manuelschipper/nah.git
cd nah
# inside Claude Code:
/nah-demo
```

25 live cases across 8 threat categories — remote code execution, data exfiltration, obfuscated commands, and more. Takes ~5 minutes.

---

<p align="center">
  <code>--dangerously-skip-permissions?</code><br><br>
  <img src="../assets/logo_hammock.png" alt="nah" width="280" class="invertible">
</p>

