# Claude Code

## Install

```sh
nah hook claude install
```

Nesting-limit refusals block by default. To deny other explicit evaluation
failures and bounded analysis refusals, install with `--fail-closed`. Ordinary
unknown or opaque calls still delegate.
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

Save then run and session memory (`nah docs concepts`) work here where
`nah docs runtimes` says. For save then run, the installer adds an async
`PostToolUse` hook that keeps the saved copy current. A hook that dies or
times out before answering lets the call run under fail-open, as in 1.x, so a
discard may run without a fresh save; `--fail-closed` sets `onFailure: block`
(Claude Code 2.1.295 or later) to block it. For session memory, it adds the
`PostToolUse`, `PostToolBatch`, and `PostToolUseFailure` hooks that settle
each call. Rerun `nah hook claude install` after upgrading to add them.

## Boundaries

`PreToolUse` runs before Claude's permission layer. Current Claude Code
documentation does not say that `bypassPermissions`
(`--dangerously-skip-permissions`, often called YOLO mode) disables hooks. It
skips normal permission prompts, so delegated calls can execute immediately.
Explicit `ask` rules, selected connector and MCP interactions, and root/home
removal circuit breakers can still prompt. Treat the hook as a guardrail, not
as a sandbox guarantee.

Unsupported: session memory across `--fork-session`. A fork
(`--fork-session`, `/branch`, `/fork`) gets a new session ID, and Claude
Code's hooks do not name the session it came from, so the fork starts with
empty session memory: the parent's pending launches, flagged content and
secret labels no longer block calls there, though snapshots still leave out
files any session labelled secret. `--continue` and `--resume` without
`--fork-session` keep the session and its memory.

`--safe-mode` disables all customizations, including hooks. `--bare` skips
automatic hook discovery. Neither mode loads nah's user hook.

Claude continues a tool call when a command hook exits with anything other
than the blocking exit code 2, including ordinary errors and timeouts, unless
fail-closed set `onFailure: block`.
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
shared user `settings.json`, and visible child launches using `--safe-mode`,
`--bare`, inline `--settings` that sets `disableAllHooks`, `--setting-sources`
without `user`, an alternate `CLAUDE_CONFIG_DIR`, or a `HOME` that is empty
or names another directory. Permission modes such as
`--dangerously-skip-permissions` do not disable hooks and are not
self-protection findings. The agent is told not to retry protected changes; an
operator can use `nah nap` from another terminal.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream documentation linked below,
inspect the loaded hook, and test it before relying on nah. See Claude Code's
[hooks reference](https://code.claude.com/docs/en/hooks),
[permission modes](https://code.claude.com/docs/en/permissions), and
[settings reference](https://code.claude.com/docs/en/settings).
