# Privacy Policy

Effective date: April 22, 2026

nah is a local safety guard for Claude Code. The beta terminal guard can also
protect opt-in interactive shell sessions. This page describes what nah itself
collects, stores, and sends.

## Summary

- nah's deterministic classifier runs locally on your machine.
- The Claude Code plugin does not create a nah account and does not send tool
  input to a network service by default.
- Decision logs and configuration are stored locally.
- Optional LLM credentials can be stored locally in your OS keychain or
  keyring when you use `nah key ...` from a PyPI install.
- Optional LLM review only runs when you configure it. If you use a remote LLM
  provider, prompt context is sent to that provider.
- nah applies best-effort redaction for known secret patterns in transcript and
  write/edit content before LLM prompt enrichment, but external LLM providers
  should still be treated as receiving security-sensitive context.

## Local Processing

nah inspects tool inputs so it can decide whether to allow, ask, or block an
operation. Depending on how you use nah, this can include:

- Bash commands and shell structure
- file paths for reads, writes, edits, searches, and notebook edits
- write/edit content snippets for content inspection
- MCP tool names and arguments exposed to Claude Code hooks
- recent Claude Code transcript context when optional LLM review is enabled

The deterministic classifier processes this information locally.

## Local Storage

nah stores user-controlled configuration and logs on your machine. Typical
locations include:

- `~/.config/nah/config.yaml`
- `~/.config/nah/nah.log`
- `~/.config/nah/hook-errors.log`
- target-specific files under `~/.config/nah/`
- OS keychain/keyring entries for remote LLM secrets if you use `nah key ...`
  from a PyPI install

If you install direct Claude Code hooks, nah may also write Claude hook settings
or hook scripts under Claude Code's local configuration directory. If you use the
Claude Code plugin, Claude Code's plugin manager handles plugin installation and
state. nah does not copy LLM secret values into its YAML config files or
decision logs.

## Network Use

By default, nah's deterministic classifier does not send tool input to a network
service.

Network calls can happen when you explicitly configure optional features, such
as:

- a remote LLM provider for ambiguous decision review
- CLI commands that you run yourself, such as package installation, release, or
  update workflows outside the deterministic classifier

For optional LLM review, nah sends prompt context to the provider and model you
configure. The prompt can include the flagged operation, structural reason,
working directory, relevant write/edit content, and recent transcript context.
nah applies best-effort redaction for known secret patterns in transcript and
write/edit content before prompt enrichment, but this is not a guarantee that
every possible secret is removed.

## Claude Code Plugin

The Claude Code plugin bundles nah's Python runtime and runs through Claude
Code's hook system. The plugin does not run `pip`, install PyYAML, download
packages, or fetch code when enabled.

The plugin requires Python 3.10 or newer on `PATH`. If Python is missing or the
plugin runtime errors, the hook fails closed by asking for confirmation instead
of silently allowing the tool call.

## Documentation Site

The docs site at `https://schipper.ai/nah/` is a static documentation site.
Normal hosting infrastructure may create standard access logs, such as requested
URL, IP address, user agent, referrer, and timestamp. nah does not use those logs
to make safety decisions.

## Your Controls

You can:

- disable optional LLM review by leaving `llm.mode` off or setting it to `off`
- use a local LLM provider such as Ollama instead of a remote provider
- reduce or disable transcript context with `llm.context_chars`
- remove stored provider keys with `nah key rm <provider>` from a PyPI install
- uninstall the Claude Code plugin with `claude plugin uninstall nah@nah`
- uninstall direct hooks with `nah uninstall claude`
- delete local nah logs and config files from `~/.config/nah/`

## Contact

For privacy or security questions, open an issue at:

https://github.com/manuelschipper/nah/issues
