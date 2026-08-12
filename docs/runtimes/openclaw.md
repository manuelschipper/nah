# OpenClaw

## Install

```sh
nah hook openclaw install
```

`--fail-closed` denies explicit failures/refusals; uncertainty
delegates. `--fail-open` restores the default; flagless reinstall preserves it.
The loaded nah process must be able to respond.

Restart the OpenClaw Gateway. Remove nah through the managed lifecycle:

```sh
nah hook openclaw uninstall
```

The installer writes only nah's ESM plugin under
`~/.openclaw/extensions/nah`. It never changes `openclaw.json`, allow/deny
lists, or plugin entries. Users with an explicit allowlist or disabled entry
must enable `nah` themselves.

## Behavior

The Gateway `before_tool_call` hook sends visible exec, read, write, multi-edit,
apply-patch, grep, find, and ls calls through nah. Definite blocks are terminal;
everything else returns to OpenClaw policy and approval. Optional exec controls
beyond `command` are not fully modeled: a definite command finding still blocks,
while other such calls stay partial. Process actions, missing workspace identity,
malformed known input, and adapter failure delegate.

Exact Code Mode exec payloads use the JavaScript/TypeScript side of nah's
bounded effect interpreter under a QuickJS profile. Direct references and
provenance-tracked aliases of `tools.call` and `tools.callValue` are recognized
only as bridge invocations; nah does not infer the nested tool's filesystem or
shell effects from the outer cell because OpenClaw hooks the actual nested call
separately. Node globals, other bridge namespaces, shadowed or dormant calls,
browser/process/device actions, plugins, and future tools remain unowned. A
valid `restartSafe` boolean is retained as
input metadata; it does not prove that code is read-only or grant additional
ownership.

## Boundaries

The plugin and nah run on the Gateway. Remote nodes, sandboxes, devices, and
hidden state may remain opaque; each remote Gateway needs an installation.
Gateway and node exec default to `tools.exec.mode = "full"` without approval;
elevated full mode also skips sandbox-escape approval. Hooks still run, but a
delegated call may execute immediately.

Ordinary exec events expose only a command string, not the final shell dialect
or argv. The adapter currently applies Bash analysis to that string even though
OpenClaw may execute it with `sh`, zsh, PowerShell, a custom shell, a remote
node, or a sandbox. Shell-specific findings on ordinary exec are therefore best
effort. Code Mode's discriminators do prove its QuickJS syntax profile.

The plugin gives nah five seconds inside a six-second hook budget. Child failure
delegates; an outer timeout currently fails closed without cancelling the child.
Trusted-tool policy runs first. Ordinary handlers run by descending priority;
nah uses `-1000`. Returned rewrites merge afterward, so a later plugin can
change an allowed call without another nah check. A nah block is terminal.

Custom homes, state/config paths, non-default profiles, and legacy-only
`~/.clawdbot` state are rejected so nah can protect exact wiring. Disabled
plugins, reload failure, human actions, and direct trusted-plugin work remain
outside nah.

While active, this adapter blocks visible lifecycle commands, direct mutations
to its nah extension or standard `openclaw.json`, explicit native removal or
disable commands naming nah, and child launches using `--dev`, a non-default
profile, or alternate home/state/config selectors. The agent is told not to
retry; an operator can use `nah nap` from another terminal.

After upgrades, run `openclaw plugins inspect nah --runtime --json` and retest.
The report should show `before_tool_call` at priority `-1000`. See OpenClaw's
[plugin documentation](https://docs.openclaw.ai/plugins),
[hook contract](https://docs.openclaw.ai/plugins/hooks), and
[exec/process documentation](https://docs.openclaw.ai/tools/exec).
