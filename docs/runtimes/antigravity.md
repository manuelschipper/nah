# Google Antigravity

## Install

```sh
nah hook antigravity install
```

To deny explicit evaluation failures and bounded analysis refusals, install
with `--fail-closed`. Ordinary unknown or opaque calls still delegate.
`--fail-open` restores the default; flagless reinstall preserves a recognized
mode. The guarantee requires the loaded nah process to return a response;
missing hooks/binaries, runtime timeout, process termination, bypass, and
broken output pipes remain outside it.

Restart Antigravity and inspect the `nah` entry with `/hooks`. The managed
global hook is shared by Antigravity CLI (`agy`) and the Antigravity desktop
application. Remove only nah's entry with:

```sh
nah hook antigravity uninstall
```

The installer atomically updates `~/.gemini/config/hooks.json`, preserves
other named hooks, and refuses to replace a non-nah entry named `nah`.

## Behavior

The global `PreToolUse` hook matches commands, reads, writes, single and
multi-edits, directory listings, filename searches, and content searches.
Blocks return Antigravity's native `deny` response with nah-branded feedback.
For calls nah does not block, it returns Antigravity's native `ask` decision.

Antigravity does not provide a delegate decision for `PreToolUse`: its hook
API requires `allow`, `deny`, `ask`, or `force_ask`. nah uses `ask` rather
than `allow` because nah only blocks or returns control to the runtime; it
must not auto-approve a call. Antigravity's normal approval flow and its
Always Allow cache can then approve the request. Tools outside the matcher do
not invoke nah and use Antigravity's normal permission flow directly.

Task operations, web and browser tools, MCP tools, permission requests,
scheduling, agent coordination, media generation, and future tools are
outside the matcher and remain runtime-owned. Under the default mode,
malformed known inputs and evaluation failures return `ask`; they also write
fixed feedback to the hook diagnostic channel. With `--fail-closed`, incomplete
known inputs are denied.

## Boundaries

`ask` respects Antigravity's Always Allow cache; `force_ask` does not.
`always-proceed` changes Antigravity's native permission prompt but does not
document disabling hooks.

Hook loading, the hook's `enabled` setting, `/hooks`, workspace trust, and
runtime failure or timeout behavior remain Antigravity-owned. Google does not
document whether hook errors and timeouts fail open or closed. Workspace hooks
and plugins under `.agents/` or `_agents/`, and global plugins under either
documented Antigravity plugin directory, can add interception paths. nah does
not protect those additional workspace or plugin paths and cannot inspect
work performed directly inside a trusted plugin. Human `!` terminal commands,
headless/print-mode hook
coverage that Google has not documented, remote environments without the
installed nah binary, and tool effects outside the intercepted call path
remain outside nah. Gemini CLI is a separate legacy and enterprise runtime and
is not covered by this integration.

While active, this adapter blocks visible lifecycle commands, explicit native
removal or disable commands naming nah, and mutations to the shared
`hooks.json` that keeps nah loaded. Other runtime and plugin configuration
remains user-owned. The agent is told not to retry; an operator can use `nah
nap` from another terminal.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream documentation linked below,
inspect the loaded hook, and test it before relying on nah. See Google's
[hook reference](https://antigravity.google/docs/hooks),
[CLI overview](https://antigravity.google/docs/cli/overview),
[plugin reference](https://antigravity.google/docs/plugins), and
[Antigravity CLI changelog](https://github.com/google-antigravity/antigravity-cli/blob/main/CHANGELOG.md).
