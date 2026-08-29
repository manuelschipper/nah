# OpenCode

## Install

```sh
nah hook opencode install
```

OpenCode installation is not supported on Windows. Install and uninstall
return `runtime-platform-unsupported` before writing, and status reports `not
configured`.

To deny explicit evaluation failures and bounded analysis refusals, install
with `--fail-closed`. Ordinary unknown or opaque calls still delegate.
`--fail-open` restores the default; flagless reinstall preserves a recognized
mode. The guarantee requires the loaded nah process to return a response;
missing hooks/binaries, runtime timeout, process termination, bypass, and
broken output pipes remain outside it.

Restart OpenCode. Remove only nah's plugin with:

```sh
nah hook opencode uninstall
```

The installer writes one dependency-free ESM plugin at
`~/.config/opencode/plugins/nah.js`. Its `tool.execute.before` hook invokes nah
without a shell.

## Behavior

Bash, read, write, edit, apply-patch, glob, and grep calls use the shared
policy. Other built-in, MCP, and custom tools remain opaque to nah and
delegate. Blocks throw a nah-branded error before OpenCode's permission check.
Every other call delegates to OpenCode's native `allow`/`ask`/`deny` flow.
`--auto` and the TUI's auto-approve mode automatically approve calls that
would otherwise ask, but do not disable plugins or explicit `deny` rules.
Delegated calls can therefore execute without another prompt in auto mode.

## Boundaries

OpenCode loads local plugins at startup. `--pure`, `OPENCODE_PURE=1`, remote
servers without the plugin, plugin load failures, name shadowing, and trusted
plugins that act directly remain outside nah. OpenCode runs plugin handlers
sequentially; later plugins see and can mutate a call after nah delegates it.
Plugin hook errors normally abort the tool, but the nah plugin catches adapter
failure in the default mode, delegates, and requests a warning toast when the
client API is available.

This installer targets the OpenCode V1 `opencode` executable and plugin API.
It does not support the OpenCode 2.0 beta `opencode2` executable; upstream
documents that V1 plugins do not work with V2. V2 sessions therefore remain
outside nah until a V2 adapter is implemented against its still-changing API.

A nonstandard `XDG_CONFIG_HOME` is rejected because the installer owns only
the standard plugin path. Other plugin lifecycle and configuration remain
runtime-owned.

While active, this adapter blocks visible lifecycle commands and direct
mutations to its nah-owned plugin. Visible child launches using `--pure`,
`OPENCODE_PURE=1`, or an alternate `XDG_CONFIG_HOME` also block. Other runtime
configuration remains user-owned. The agent is told not to retry protected
changes; an operator can use `nah nap` from another terminal.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream documentation linked below,
inspect the loaded hook, and test it before relying on nah. See OpenCode's
[plugin documentation](https://opencode.ai/docs/plugins/) and
[permission documentation](https://opencode.ai/docs/permissions/). See the
[V2 migration guide](https://opencode.ai/v2/docs/migrate-v1) for the beta's
plugin compatibility boundary.
