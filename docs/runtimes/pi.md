# Pi

## Install

```sh
nah hook pi install
```

To deny explicit evaluation failures and bounded analysis refusals, install
with `--fail-closed`. Ordinary unknown or opaque calls still delegate.
`--fail-open` restores the default; flagless reinstall preserves a recognized
mode. The guarantee requires the loaded nah process to return a response;
missing hooks/binaries, runtime timeout, process termination, bypass, and
broken output pipes remain outside it.

Run `/reload` in Pi. Remove only nah's extension with:

```sh
nah hook pi uninstall
```

The installer writes one dependency-free extension at
`~/.pi/agent/extensions/nah/index.js` and preserves Pi settings.

## Behavior

The extension invokes nah without a shell and covers Pi's Bash, read, write,
multi-edit, grep, find, ls, and custom tool calls. Blocks stop the call. Every
other call delegates to Pi.

## Boundaries

Pi has no native approval prompt behind this extension, so delegates normally
execute unless another permission-gate extension blocks them. Pi exposes
human `!` and `!!` shell input through a separate `user_bash` event; nah does
not register it. Extensions still run in print, JSON, and RPC modes unless
`--no-extensions` is used; explicit `-e` extension paths can still load in that
mode. `PI_CODING_AGENT_DIR` changes Pi's agent directory, while nah currently
installs only in the standard `~/.pi/agent` directory, so a custom value does
not load the installed extension. Pi also loads sibling global, project, and
package extensions. For parallel tool batches, Pi runs each call's preflight
handlers in sequence before executing nonblocked siblings concurrently. After
nah delegates, later handlers can still mutate the call. A `tool_call` handler
error blocks the tool, but in the default mode nah catches adapter failure,
delegates, and requests a UI warning when Pi exposes one. Disabled or unloaded
extensions and trusted extensions that act directly remain outside nah.

While active, this adapter blocks visible lifecycle commands and direct
mutations to its nah-owned extension. Visible child launches using
`--no-extensions` or an alternate `PI_CODING_AGENT_DIR` also block. Other
runtime configuration remains user-owned. The agent is told not to retry
protected changes; an operator can use `nah nap` from another terminal.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream documentation linked below,
inspect the loaded hook, and test it before relying on nah. See Pi's
[extension documentation](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md).
