# Cursor

## Install

```sh
nah hook cursor install
```

Nesting-limit refusals block by default. To deny other explicit evaluation
failures and bounded analysis refusals, install with `--fail-closed`. Ordinary
unknown or opaque calls still delegate.
`--fail-open` restores the default; flagless reinstall preserves a recognized
mode. The guarantee requires the loaded nah process to return a response;
missing hooks/binaries, runtime timeout, process termination, bypass, and
broken output pipes remain outside it.

The installer also adds `postToolUse` and `postToolUseFailure` hooks, which
keep saved copies and session memory current; `status` reports `reinstall
required` without them. Remove only nah's hooks with:

```sh
nah hook cursor uninstall
```

The installer preserves unrelated `~/.cursor/hooks.json` and is idempotent.

On Windows, install, status, reinstall, uninstall, and typed filesystem tools
are supported natively. Cursor's `Shell` tool follows the user's selected
terminal profile; when the payload does not name that dialect, nah keeps the
command partial and delegates without shell effects.

## Behavior

The local `preToolUse` hook covers Cursor Shell, Read, Write, Delete, Grep, and
List tools. Other tools, including MCP, Task, and web tools, remain opaque to
nah and delegate. Shell uses the tool's resolved working directory as the
authoritative cwd. Definite blocks return a native deny response and exit 2.
Every other call delegates by emitting no permission decision, preserving
Cursor's normal permission flow.

Save then run and session memory (`nah docs concepts`) work here where
`nah docs runtimes` says. Cursor sends an allowed call no message, so the
undo note goes only to the Hooks output channel. A delegate replies `{}`,
which decides nothing. A crashed or timed-out nah lets the call run under
fail-open, as in 1.x, so a discard may run without a fresh save;
`--fail-closed` sets Cursor's `failClosed` to block it.

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
tool shape is denied. Other hook sources, loading, and runtime failures
remain outside nah. Post-call hooks have no background option, so the refresh
may add up to 30 seconds to a call. Cursor does not say whether a failing
Shell call fires `postToolUse`, so memory keeps only what the disk shows,
nor whether it waits for a post-call hook before the next call, so a refresh
may land after it. Whether a subagent's tool hooks or a resumed conversation
keep the `conversation_id` is not documented; where not, they get a session
memory of their own.

While active, this adapter blocks visible lifecycle commands and mutations to
the shared user `hooks.json` that keeps nah loaded. A visible `agent` or
`cursor-agent` launch whose `HOME` is empty or names another directory also
blocks. Permission modes such as `--yolo` do not disable hooks and are not
self-protection findings. The agent
is told not to retry protected changes; an operator can use `nah nap` from
another terminal.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream documentation linked below,
inspect the loaded hook, and test it before relying on nah. See Cursor's
[hooks documentation](https://cursor.com/docs/hooks) and
[CLI changelog](https://cursor.com/docs/cli/changelog).
