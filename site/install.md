# Installation

## Requirements

- Python 3.10+

## Quick start

```bash
pip install nah
nah claude              # try it — hooks active for this session only
```

`nah claude` writes the hook script to `~/.claude/hooks/nah_guard.py` and passes hooks inline via Claude Code's `--settings` flag, scoped to that process.

## Permanent install

```bash
nah install
```

Registers nah as a [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) in Claude Code's `settings.json`. Every `claude` session runs through nah.

### Optional dependencies

```bash
pip install nah[config]    # YAML config support (pyyaml)
```

The core hook has **zero external dependencies** — it runs on Python's stdlib only. The `config` extra adds `pyyaml` for YAML config file parsing.

## How permissions work

When active (via `nah claude` or `nah install`), nah takes over permissions for Bash, Read, Write, Edit, Glob, Grep, and all MCP tools. Safe operations go through automatically, dangerous ones are blocked, ambiguous ones ask.

WebFetch and WebSearch are not guarded by nah. Claude Code handles those with its own permission prompts.

**Don't use `--dangerously-skip-permissions`** — just run `claude` in default mode. In `--dangerously-skip-permissions` mode, hooks [fire asynchronously](https://github.com/anthropics/claude-code/issues/20946) and commands execute before nah can block them.

### active_allow

When nah classifies a tool call as safe, it emits an explicit `"allow"` response so Claude Code skips its own permission prompt. This is **active allow** — nah takes over the permission decision entirely.

Sometimes you want nah's protection (blocking dangerous commands, flagging sensitive paths) but still want Claude Code to prompt you before writes or edits. Set `active_allow` to a list of tool names to control which tools nah actively allows:

```yaml
# ~/.config/nah/config.yaml

# nah handles Bash/Read/Glob/Grep; Write/Edit fall back to Claude Code's prompts
active_allow: [Bash, Read, Glob, Grep]
```

nah still classifies **all** tool calls regardless of this setting — it will still block or ask for dangerous operations on Write/Edit. The only difference is that *safe* Write/Edit calls won't get an automatic allow from nah, so Claude Code shows its normal permission prompt.

| Value | Behavior |
|-------|----------|
| `true` (default) | Actively allow all guarded tools |
| `false` | Never actively allow — nah only blocks and asks |
| list of tool names | Actively allow only the listed tools |

Valid tool names: `Bash`, `Read`, `Write`, `Edit`, `Glob`, `Grep`.

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

