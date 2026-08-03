# Kiro CLI

## Install

Kiro's user-wide hooks require Kiro CLI 3:

```sh
nah hook kiro install
kiro-cli --v3
```

To deny explicit evaluation failures and bounded analysis refusals, install
with `--fail-closed`. Ordinary unknown or opaque calls still delegate.
`--fail-open` restores the default; flagless reinstall preserves a recognized
mode. The guarantee requires the loaded nah process to return a response;
missing hooks/binaries, runtime timeout, process termination, bypass, and
broken output pipes remain outside it.

The installer writes the nah-owned hook at `~/.kiro/hooks/nah.json`, or under
an existing canonical `KIRO_HOME` when that absolute path is configured. It
refuses symlinked Kiro roots and hook paths. Inspect its bytes and test a safe
block before relying on it. Remove only that file with:

```sh
nah hook kiro uninstall
```

## Behavior

The global `PreToolUse` hook sees built-in and MCP tool calls. Shell calls use
nah's complete Bash analysis. Kiro CLI 3's `read_file` calls and documented
single-operation reads and writes expose their path to filesystem guards;
Kiro's batched filesystem calls and unmapped built-in or MCP tools remain
opaque and delegate. nah never approves a call, so every delegate continues
into Kiro's normal permission flow.

Definite blocks exit 2 with nah-branded feedback. In the default mode,
malformed calls and evaluation failure delegate. A missing or unexpectedly
failing nah binary exits 1 with fixed feedback; Kiro treats it as a warning
and proceeds. nah does not impose an adapter-specific input-size limit.

## Boundaries

This adapter targets Kiro CLI 3 because its global `~/.kiro/hooks/` support
applies across workspaces. Kiro CLI 2 embeds hooks in individual custom-agent
files; it cannot give nah equivalent coverage for the built-in default agent
and is not supported. Start the current Early Access engine with `--v3`.

Outside an intercepted call, a hook can be disabled with `"enabled": false`,
removed, shadowed by an alternate `KIRO_HOME`, or bypassed by a runtime surface
that does not load Kiro CLI 3 global hooks. Workspace hooks run alongside the
global hook. Delegated and subagent calls are covered only when Kiro emits
`PreToolUse` for them. The hook deadline is five seconds; runtime failures
other than exit 2 are non-blocking.

While active, this adapter blocks visible lifecycle commands and direct
mutations to its nah-owned hook. Visible child launches with an alternate
`KIRO_HOME` also block. A Kiro process started with a different home outside
the intercepted session remains the user's choice. The agent is told not to
retry protected changes; an operator can use `nah nap` from another terminal.

This integration is best effort: runtime APIs and hook behavior can change.
Users are responsible for keeping the hook loaded and testing it after runtime
upgrades; verify the latest official upstream documentation, including Kiro's
current
[CLI 3 overview](https://kiro.dev/docs/cli/v3/),
[CLI 3 hook reference](https://kiro.dev/docs/cli/v3/hooks/),
[hook payload reference](https://kiro.dev/docs/cli/hooks/), and
[CLI changelog](https://kiro.dev/changelog/cli/) before relying on nah.
