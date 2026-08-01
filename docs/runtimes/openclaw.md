# OpenClaw

## Install

```sh
nah hook openclaw install
```

Restart the OpenClaw Gateway. Remove nah through the managed lifecycle:

```sh
nah hook openclaw uninstall
```

The installer writes only nah's native ESM plugin under
`~/.openclaw/extensions/nah`; it does not run OpenClaw's install or enable
commands and never changes `openclaw.json`, `plugins.allow`, `plugins.deny`, or
plugin entries. OpenClaw may warn that the nah plugin is discovered while the
allowlist is empty. Users who manage an explicit allowlist or disabled plugin
entries must enable `nah` themselves alongside every plugin they intend
OpenClaw to load.

## Behavior

The Gateway `before_tool_call` hook sends visible exec commands, read, write,
multi-edit, apply-patch, grep, find, and ls calls through nah. Definite blocks
return OpenClaw's terminal block result. Every other call delegates to
OpenClaw's tool policy and approval flow. Optional exec controls beyond the
command are not fully modeled: a definite command block survives, while other
such calls delegate conservatively. Process actions, missing workspace
identity, and malformed known input remain opaque and delegate. Adapter failure
also delegates and writes a warning when OpenClaw provides its logger.

Code mode's outer exec remains opaque; inner tool calls are intercepted when
they re-enter known tools. Browser, code execution, process control,
node/device actions, the OpenClaw system-agent tool, plugins, and future tools
remain opaque unless their calls re-enter a known tool.

## Boundaries

The plugin and nah run on the Gateway host. Remote node filesystems, sandbox
paths, browser/code execution, device actions, and state not visible to the
Gateway may remain opaque. Each remote Gateway needs its own installation.
Gateway and node exec currently default to `tools.exec.mode = "full"`, with no
approval gate. Elevated full mode also skips approval for sandbox escapes.
Neither disables plugin hooks, but delegated calls may execute immediately.

The generated plugin gives its nah child five seconds and registers a six-second
outer hook budget. Child failure delegates. If OpenClaw's outer
`before_tool_call` budget expires first, current OpenClaw fails closed and does
not cancel the timed-out handler. Trusted-tool policies run first, and nah sees
their adjusted call. Ordinary handlers run by descending priority; nah uses a
low priority. Their returned parameter rewrites are merged after the handlers,
so another ordinary plugin can change the executed call without another nah
check. A nah block is terminal and prevents lower-priority handlers from
running.

Custom homes, state directories, config paths, and non-default profiles are
rejected so nah can protect the exact managed wiring. A legacy-only
`~/.clawdbot` state is rejected rather than silently changing which state
directory is active.
Disabled plugins, reload failure, human actions, and direct trusted-plugin work
remain outside nah.

While active, this adapter blocks visible lifecycle commands, direct mutations
to its nah extension or standard `openclaw.json`, explicit native removal or
disable commands naming nah, and child launches using `--dev`, a non-default
profile, or alternate home/state/config selectors. The agent is told not to
retry; an operator can use `nah nap` from another terminal.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream documentation linked below,
run `openclaw plugins inspect nah --runtime --json`, and test safe and blocked
tool calls before relying on nah. The runtime report should show a loaded
`before_tool_call` hook at priority `-1000`. See OpenClaw's
[plugin documentation](https://docs.openclaw.ai/plugins),
[hook contract](https://docs.openclaw.ai/plugins/hooks), and
[exec/process documentation](https://docs.openclaw.ai/tools/exec).
