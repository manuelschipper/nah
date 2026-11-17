# OpenCode

## Install

```sh
nah hook opencode install
```

OpenCode installation is not supported on Windows. Install and uninstall
return `runtime-platform-unsupported` before writing, and status reports `not
configured`.

Nesting-limit refusals block by default; `--fail-closed` blocks other
explicit failures/refusals. Unknown or opaque calls still delegate.
`--fail-open` restores the default; flagless reinstall preserves a recognized
mode. The guarantee requires the loaded nah process to return a response;
missing hooks/binaries, runtime timeout, process termination, bypass, and
broken output pipes remain outside it.

Restart OpenCode. Remove only nah's plugin with:

```sh
nah hook opencode uninstall
```

The installer writes one dependency-free ESM plugin at
`~/.config/opencode/plugins/nah.js`. OpenCode 2.x loads it as plugin ID `nah`,
and its `execute.before` tool hook invokes nah without a shell.

`nah hook opencode status` checks only this file, not whether OpenCode loaded
it. `opencode plugin list --builtin` lists `nah` once loaded (it starts
OpenCode's background service); load errors log `failed to load plugin`.

Nah supports OpenCode 2.x only; 2.0.18 was live-verified on 2026-09-27.
OpenCode 1.x rejects the plugin, so 1.x sessions run without nah even though
status reports current wiring. Upgrade to 2.x (`@opencode/cli`, which installs
`opencode` and `opencode2`), then reinstall; an older nah plugin reports
`reinstall required`.

## Behavior

Shell, read, write, edit, patch, glob, and grep calls use the shared policy. A
shell call's `workdir` is resolved against its session directory. A glob with
`hidden: true` is analyzed but reported incomplete, because nah treats a
leading `*` as skipping hidden entries; `--fail-closed` therefore blocks it.
Other built-in, MCP, and custom tools remain opaque to nah and delegate. Blocks
throw a nah-branded error before OpenCode's permission check.
Every other call delegates to OpenCode's native `allow`/`ask`/`deny` flow.
`--auto` and the TUI's auto-approve mode automatically approve calls that
would otherwise ask, but do not disable plugins or explicit `deny` rules.
Delegated calls can therefore execute without another prompt in auto mode.

## Boundaries

OpenCode loads global plugins at server start and reloads watched plugin
files. `plugin`/`plugins` with `-nah`/`-*` and no later `nah`/`*` blocks writes
to `opencode.json`, `opencode.jsonc`, and global `config.json`.
Unparseable whole configs or `{env:...}`/`{file:...}` substitutions block.
Other configuration stays user-owned. An `OPENCODE_CONFIG` file, servers
started without the plugin, including remote ones, load failures, and trusted
plugins that act directly remain outside nah.
OpenCode runs hook handlers sequentially; later plugins see and can mutate a
call after nah delegates it. Plugin hook errors abort the tool, but the nah
plugin catches adapter failure in the default mode and delegates with a
synthetic session message explaining that evaluation could not finish and
pointing to `nah why`.

A nonstandard `XDG_CONFIG_HOME` is rejected because the installer owns only
the standard plugin path.

While active, this adapter blocks visible lifecycle commands and direct
mutations of its nah-owned plugin. Visible `opencode` and `opencode2`
launches, including `npx`/`bunx`/`bun x @opencode/cli`, block on another
`XDG_CONFIG_HOME` or `OPENCODE_CONFIG_DIR`, with `HOME` set to
another account home while `XDG_CONFIG_HOME` is unset, or with
nonblank `OPENCODE_CONFIG_CONTENT` matching these checks.
The agent must not retry; an operator can `nah nap` in another terminal.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream documentation linked below,
inspect the loaded hook, and test it before relying on nah. See OpenCode's
[plugin documentation](https://opencode.ai/v2/docs/plugins/),
[permission documentation](https://opencode.ai/v2/docs/permissions/), and the
[V1 plugin migration guide](https://opencode.ai/v2/docs/build/plugins/migrate-v1).
