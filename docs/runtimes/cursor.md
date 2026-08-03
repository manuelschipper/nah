# Cursor

## Install

```sh
nah hook cursor install
```

To deny explicit evaluation failures and bounded analysis refusals, install
with `--fail-closed`. Ordinary unknown or opaque calls still delegate.
`--fail-open` restores the default; flagless reinstall preserves a recognized
mode. The guarantee requires the loaded nah process to return a response;
missing hooks/binaries, runtime timeout, process termination, bypass, and
broken output pipes remain outside it.

Remove only nah's hook with:

```sh
nah hook cursor uninstall
```

The installer preserves unrelated `~/.cursor/hooks.json` and is idempotent.

## Behavior

The local `preToolUse` hook covers Cursor Shell, Read, Write, Delete, Grep, and
List tools. Other tools, including MCP, Task, and web tools, remain opaque to
nah and delegate. Shell uses the tool's resolved working directory as the
authoritative cwd. Definite blocks return a native deny response and exit 2.
Every other call delegates by emitting no permission decision, preserving
Cursor's normal permission flow.

## Boundaries

The user hook covers local Agent, Cmd+K, and Cursor CLI. `agent --yolo` and
`--force` remove native approval prompts but do not document disabling hooks;
delegated calls may therefore execute immediately. The user hook does not
cover Cursor cloud agents or Tab, which has separate file hooks. Cloud agents
load project hooks only after a writable environment is created, not during
their initial read-only exploration.

Cursor documents `preToolUse` for more tool families than nah currently
understands; unknown tools remain opaque and delegate. In the default mode,
malformed known tools also delegate. With `--fail-closed`, an incomplete known
tool shape is denied. nah does not install Cursor's separate `failClosed`
option. Its own policy blocks only while the nah process can return a native
deny. Other hook sources, loading, and runtime failures remain outside nah.

While active, this adapter blocks visible lifecycle commands and mutations to
the shared user `hooks.json` that keeps nah loaded. Permission modes such as
`--yolo` do not disable hooks and are not self-protection findings. The agent
is told not to retry protected changes; an operator can use `nah nap` from
another terminal.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream documentation linked below,
inspect the loaded hook, and test it before relying on nah. See Cursor's
[hooks documentation](https://cursor.com/docs/hooks) and
[CLI changelog](https://cursor.com/docs/cli/changelog).
