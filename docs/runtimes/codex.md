# Codex

## Install

```sh
nah hook codex install
```

Open local Codex, run `/hooks`, and trust the new hook. Remove only nah's entry
with:

```sh
nah hook codex uninstall
```

The installer preserves unrelated `~/.codex/hooks.json` content and installs
the native `nah hook codex run` command without a copied script or interpreter.

## Behavior

Blocks stop definite policy violations. Everything else delegates and
continues through Codex's own sandbox and approval flow. Canonical
`apply_patch` input becomes per-file add, update, delete, and move effects, so
sensitive path guards and nah self-protection use the same policy as other file
tools. Malformed, future, and multi-environment patch forms delegate.

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
unknown MCP names as opaque and delegates unless an extension understands
them. Hosted tools such as web search, `write_stdin` continuations of an
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
into Codex's normal flow. Evaluation failure delegates and returns a fixed
`systemMessage`; it does not manufacture a deny.

While active, this adapter blocks visible lifecycle commands, mutations to
`hooks.json` or the global `config.toml` hook setting, and child launches using
an alternate `CODEX_HOME` or `--disable hooks`. `--yolo` does not disable
hooks and is not a self-protection finding. The agent is told not to retry
protected changes; an operator can use `nah nap` from another terminal.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream documentation linked below,
inspect the loaded hook, and test it before relying on nah. See the
[Codex hooks documentation](https://learn.chatgpt.com/docs/hooks).
