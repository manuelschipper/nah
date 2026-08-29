# Claude Code

## Install

```sh
nah hook claude install
```

To deny explicit evaluation failures and bounded analysis refusals, install
with `--fail-closed`. Ordinary unknown or opaque calls still delegate.
`--fail-open` restores the default; flagless reinstall preserves a recognized
mode. The guarantee requires the loaded nah process to return a response;
missing hooks/binaries, runtime timeout, process termination, bypass, and
broken output pipes remain outside it.

Restart Claude Code and inspect the active PreToolUse hook with `/hooks`.
Remove only nah's entry with:

```sh
nah hook claude uninstall
```

The installer preserves unrelated `~/.claude/settings.json` content and is
idempotent. It uses Claude Code's native executable-and-arguments form, with no
copied script, shell quoting, or Python dependency.

On Windows, install, status, reinstall, uninstall, and typed filesystem tools
are supported natively. Claude Code requires Git Bash on Windows, so its
intercepted `Bash` payloads continue through nah's Bash analysis.

## Behavior

Known Bash, read, write, edit, search, and related tool calls enter the shared
nah pipeline. A definite violation is returned as a block with nah-branded
feedback. Everything else returns no decision and continues through Claude
Code's normal permission flow. nah never returns Claude's explicit `allow`, so
it never skips a permission prompt.

## Boundaries

`PreToolUse` runs before Claude's permission layer. Current Claude Code
documentation does not say that `bypassPermissions`
(`--dangerously-skip-permissions`, often called YOLO mode) disables hooks. It
skips normal permission prompts, so delegated calls can execute immediately.
Explicit `ask` rules, selected connector and MCP interactions, and root/home
removal circuit breakers can still prompt. Treat the hook as a guardrail, not
as a sandbox guarantee.

`--safe-mode` disables all customizations, including hooks. `--bare` skips
automatic hook discovery. Neither mode loads nah's user hook.

Claude continues a tool call when a command hook exits with anything other
than the blocking exit code 2, including ordinary errors and timeouts.
Under the default mode, evaluation failure delegates and returns a fixed
`systemMessage`; malformed
outer input returns no decision. Other matching hooks run in parallel,
including hooks bundled by enabled plugins, and one hook cannot prevent another
from starting. Users can set `disableAllHooks`; administrators can set
`allowManagedHooksOnly`, which excludes this user hook unless nah is installed
as managed configuration.

Hook coverage and loading remain runtime-owned. Inspect `/hooks` after
installation and configuration changes. Remote Claude Code environments need
their own installation. Trusted hooks or tools that perform work directly
without the intercepted call remain outside nah.

While active, this adapter blocks visible lifecycle commands, mutations to its
shared user `settings.json`, and visible child launches using `--safe-mode` or
`--bare`. Permission modes such as `--dangerously-skip-permissions` do not
disable hooks and are not self-protection findings. The agent is told not to
retry protected changes; an operator can use `nah nap` from another terminal.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream documentation linked below,
inspect the loaded hook, and test it before relying on nah. See Claude Code's
[hooks reference](https://code.claude.com/docs/en/hooks),
[permission modes](https://code.claude.com/docs/en/permissions), and
[settings reference](https://code.claude.com/docs/en/settings).
