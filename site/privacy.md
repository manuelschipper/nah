# Privacy Policy

Effective date: April 22, 2026

nah is a local safety guard for coding agents. It protects Claude Code and
local interactive Codex sessions, with a bash/zsh guard for commands you type
yourself. This page describes what nah itself collects, stores, and sends.

## Summary

- nah's deterministic classifier runs locally on your machine.
- The Claude Code plugin does not create a nah account and does not send tool
  input to a network service by default.
- `nah run codex` uses local Codex hooks and local preflight checks; it does
  not create a nah account.
- Decision logs and configuration are stored locally.
- Optional LLM credentials can be stored locally in your OS keychain or
  keyring when you use `nah key ...` from a CLI install with usable keyring
  support.
- Optional LLM review only runs when you configure it. If you use a remote LLM
  provider, prompt context is sent to that provider.
- nah does not redact secret-looking content before the LLM classify call.
  Only the Bash command text (plus nah's fixed action-type list) is sent to the
  configured provider as-is, so treat any remote LLM provider as receiving any
  secrets present in that command. Write/edit content is never sent to an LLM.

## Local Processing

nah inspects tool inputs so it can decide whether to allow, ask, or block an
operation. Depending on how you use nah, this can include:

- Bash commands and shell structure
- file paths for reads, writes, edits, searches, and notebook edits
- literal text written by shell output redirections (e.g. `echo ... > file`, heredocs)
- MCP tool names and arguments exposed to Claude Code hooks
- Codex Bash, MCP, and `apply_patch` hook payloads when you use `nah run codex`
- Codex approval-memory rule files and MCP approval settings during Codex
  preflight scans

The deterministic classifier processes this information locally.

## Local Storage

nah stores user-controlled configuration and logs on your machine. Typical
locations include:

- `~/.config/nah/config.yaml`
- `~/.config/nah/nah.log`
- `~/.config/nah/hook-errors.log`
- target-specific files under `~/.config/nah/`
- Codex rule/config backups created by `nah setup codex` when it fixes
  supported Codex drift
- OS keychain/keyring entries for remote LLM secrets if you use `nah key ...`
  from a CLI install with usable keyring support

If you install direct Claude Code hooks, nah may also write Claude hook settings
under Claude Code's local configuration directory and remove old legacy hook
scripts during migration. If you use the Claude Code plugin, Claude Code's
plugin manager handles plugin installation and state. If you use `nah run codex`,
nah passes session-scoped Codex config
overrides on the Codex command line and may inspect Codex config/rule files
during preflight. nah does not copy LLM secret values into its YAML config files
or decision logs.

## Network Use

By default, nah's deterministic classifier does not send tool input to a network
service.

Network calls can happen when you explicitly configure optional features, such
as:

- a remote LLM provider for ambiguous decision review
- CLI commands that you run yourself, such as package installation, release, or
  update workflows outside the deterministic classifier

For the optional LLM classify call, nah sends prompt context to the provider and
model you configure. The prompt contains only the flagged Bash command plus nah's
fixed action-type list — no working directory, structural reason, transcript, or
conversation context. The command is sent without secret-pattern redaction, so any
secrets present in the command itself reach the configured provider. Write/edit
content is never sent to an LLM. Treat the LLM provider as receiving
security-sensitive context, and rely on structural controls (sensitive paths)
rather than content redaction.

## Claude Code Plugin

The Claude Code plugin bundles nah's Python runtime and runs through Claude
Code's hook system. The plugin does not run `pip`, install PyYAML, download
packages, or fetch code when enabled.

The plugin requires Python 3.10 or newer on `PATH`. If Python is missing or the
plugin runtime errors, the hook fails closed by asking for confirmation instead
of silently allowing the tool call.

## Documentation Site

The docs site at [nah.build](https://nah.build/) is a static documentation
site.
Normal hosting infrastructure may create standard access logs, such as requested
URL, IP address, user agent, referrer, and timestamp. nah does not use those logs
to make safety decisions.

## Your Controls

You can:

- disable optional LLM review by leaving `llm.mode` off or setting it to `off`
- use a local LLM provider such as Ollama instead of a remote provider
- remove stored provider keys with `nah key rm <provider>` from a CLI install
  with usable keyring support
- uninstall the Claude Code plugin with `claude plugin uninstall nah@nah`
- uninstall direct hooks with `nah uninstall claude`
- delete local nah logs and config files from `~/.config/nah/`

## Contact

For privacy or security questions, [open an issue](https://github.com/manuelschipper/nah/issues).
