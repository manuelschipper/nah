# Codex

## Install

```sh
nah hook codex install
```

Nesting-limit refusals block by default. To deny other explicit evaluation
failures and bounded analysis refusals, install with `--fail-closed`. Ordinary
unknown or opaque calls still delegate.
`--fail-open` restores the default; flagless reinstall preserves a recognized
mode. The guarantee requires the loaded nah process to return a response;
missing hooks/binaries, runtime timeout, process termination, bypass, and
broken output pipes remain outside it.

Open local Codex, run `/hooks`, and trust the new hooks: `PreToolUse`, which
decides, and `PostToolUse`, which keeps saved copies and session memory
current. Codex skips each new or changed hook definition until you trust it,
and says so at its next start, for example "Hooks need review: 2 hooks are new
or changed" after an upgrade added two post-call hooks. `status` cannot see
that and still says `wiring current`. Rerun the install after upgrading; `status` reports `reinstall
required` while a post-call hook is missing. Remove only nah's entries with:

```sh
nah hook codex uninstall
```

The installer preserves unrelated `~/.codex/hooks.json` content and installs
the native `nah hook codex run` command without a copied script or interpreter.

On Windows, install, status, reinstall, uninstall, and typed filesystem tools
are supported natively. Codex's `Bash` hook payload does not identify the
actual Windows shell dialect, so nah keeps that command partial and delegates
without Bash, PowerShell, or cmd effects.

## Behavior

Blocks stop definite policy violations. Everything else delegates and
continues through Codex's own sandbox and approval flow. Canonical
`apply_patch` input becomes per-file add, update, delete, and move effects, so
sensitive path guards and nah self-protection use the same policy as other file
tools. Malformed, future, and multi-environment patch forms delegate.

Save then run and session memory (`nah docs concepts`) work here where
`nah docs runtimes` says.

Codex has no fail-closed hook setting: a pre-call hook that crashes or times
out lets the command run, possibly unsaved, and the next call reports it.
Codex sends no post-call event for a failed MCP call or `apply_patch`, or a
denied call, so session memory keeps what it proposed and the copy is not
refreshed after it.

## Boundaries

The standard configuration is shared by local Codex CLI, IDE, and desktop
clients. Codex also supports inline `[hooks]` configuration, but the standard
user `hooks.json` installed by nah remains a current native source. It does not
run in Codex cloud. Custom `CODEX_HOME` is rejected because installation owns
only the standard hook path. The shared `hooks.json` file is runtime-owned
but is protected as a whole from visible mutation while this adapter is
active. Hook trust, loading, UI actions, opt-out paths that never invoke nah,
and runtime failures remain Codex/user responsibilities.

Codex runs `PreToolUse` before its sandbox and approval flow. `--yolo`
(`--dangerously-bypass-approvals-and-sandbox`) does not document disabling
hooks, but it removes the fallback protections after nah; delegated calls can
execute immediately. MCP tool calls now receive `PreToolUse`; nah treats
unknown MCP names as opaque and delegates. Hosted tools such as web search, `write_stdin` continuations of an
already-checked command, code-mode waits, and specialized paths that opt out
do not receive a new check.

Non-managed hooks are skipped until their exact definition is trusted. Trust is
recorded against the definition hash, so a changed or reinstalled entry needs
review again. `/hooks` can disable individual non-managed hooks; users can
disable all hooks with `features.hooks = false`. Administrators can require
`allow_managed_hooks_only`, which excludes this user hook. Hooks from enabled
plugins load alongside other sources. Multiple matching hooks start
concurrently, so nah cannot stop a sibling hook from acting. Unsupported hook
output, hook errors, and timeouts do not provide a nah block and can fail open
into Codex's normal flow. Under the default mode, evaluation failure delegates and returns a fixed
`systemMessage`; it does not manufacture a deny.

While active, this adapter blocks visible lifecycle commands, mutations to
`hooks.json` or the global `config.toml` hook setting, and child launches using
an alternate `CODEX_HOME`, `--disable hooks`, or `-c` turning hooks off
(`codex_hooks` included). `--yolo` does not disable hooks and is not a
self-protection finding. The agent is told not to retry protected changes; an
operator can use `nah nap` from another terminal.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream documentation linked below,
inspect the loaded hook, and test it before relying on nah. See the
[Codex hooks documentation](https://learn.chatgpt.com/docs/hooks).
