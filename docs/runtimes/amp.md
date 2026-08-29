# Amp

## Install

```sh
nah hook amp install
```

Amp installation is not supported on Windows. Install and uninstall return
`runtime-platform-unsupported` before writing, and status reports `not
configured`.

To deny explicit evaluation failures and bounded analysis refusals, install
with `--fail-closed`. Ordinary unknown or opaque calls still delegate.
`--fail-open` restores the default; flagless reinstall preserves a recognized
mode. The guarantee requires the loaded nah process to return a response;
missing hooks/binaries, runtime timeout, process termination, bypass, and
broken output pipes remain outside it.

Restart Amp or run `plugins: reload`. There is no `nah run` wrapper. Remove
only nah's plugin with:

```sh
nah hook amp uninstall
```

The installer writes one dependency-free TypeScript plugin at
`~/.config/amp/plugins/nah.ts`.

## Behavior

Amp's `tool.call` handler sends shell commands, patches, file creation, and
file edits through the shared policy. Visible thread-file upload sources and
explicit download destinations retain filesystem and network effects. If Amp
omits a download destination, nah resolves the documented default basename
against the hook call's working directory. Web, MCP, skill, status, plugin, and
custom tools remain opaque. Blocks return Amp's `reject-and-continue` response
with nah-branded feedback. Amp's current `tool.call` API has no neutral or
abstain result, so the bridge expresses a nah `delegate` with Amp's
runtime-native `{ action: "allow" }` continuation token. Nah has no Allow
verdict or policy path. Under the default mode, malformed calls remain opaque. If evaluation fails,
the plugin delegates with that same token and shows a warning when Amp exposes
its UI feedback channel.

## Boundaries

Amp does not ask before tools by default, so calls that nah delegates normally
execute. Amp's required continuation token and default permission behavior do
not disable the nah plugin, but plugin handler order is undefined; do not rely
on a second plugin to add a prompt after nah delegates. `PLUGINS=off`, plugin
loading, direct work by trusted plugins, and opaque tools remain outside nah.
The system plugin covers local interactive, execute, IDE, and runner processes
on that machine; each Orb or remote executor needs its own nah installation
and wiring.

While active, this adapter blocks visible lifecycle commands, direct mutations
to its nah-owned plugin, and explicit plugin removal commands naming nah.
A visible child `amp` launch with `PLUGINS=off` also blocks. An Amp process
started that way outside the intercepted session never loads nah. The agent is
told not to retry; an operator can use `nah nap` from another terminal.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream documentation linked below,
inspect the loaded hook, and test it before relying on nah. See Amp's
[plugin documentation](https://ampcode.com/manual#plugins),
[Plugin API](https://ampcode.com/manual/plugin-api), and
[Orbs documentation](https://ampcode.com/manual/orbs).
