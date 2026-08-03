# Cline

## Install

```text
nah hook cline install
nah hook cline status
```

To deny explicit evaluation failures and bounded analysis refusals, install
with `--fail-closed`. Ordinary unknown or opaque calls still delegate.
`--fail-open` restores the default; flagless reinstall preserves a recognized
mode. The guarantee requires the loaded nah process to return a response;
missing hooks/binaries, runtime timeout, process termination, bypass, and
broken output pipes remain outside it.

Reload the IDE and confirm **Hooks** is enabled. CLI hooks load automatically;
verify them with `cline config hooks --json`. Remove nah's hook with:

```text
nah hook cline uninstall
```

## What nah installs

nah writes `PreToolUse` to the IDE's `Documents/Cline/Hooks/` directory and the
CLI's `~/.cline/hooks/` directory. Cline accepts one script per event in each
directory, so installation refuses to replace an existing unowned script.

The adapter covers legacy Cline shell, read, write, replace, search, and list
tools plus current `run_commands`, single-file `read_files`, `editor`,
`apply_patch`, and single-query `search_codebase` tools. Multi-file reads,
multi-query searches, and `editor` insert operations remain opaque because one
nah call cannot represent them. Blocks return `cancel: true` with branded
feedback; delegated calls return `cancel: false`, preserving Cline permissions.

IDE events use `hookName: PreToolUse` and may name the tool with
`preToolUse.tool`; CLI 3.0.48 uses `hookName: tool_call` and
`preToolUse.toolName`. Both supply arguments in `preToolUse.parameters`.
Stale or conflicting wiring requires reinstall. Unknown tools stay opaque and
delegate. By default, malformed known shapes and evaluation failures return
`cancel: false`; with `--fail-closed`, incomplete known shapes are denied.

## Boundaries

- This covers the local IDE extension and CLI, not remote Cline services. CLI
  and IDE auto-approval are separate from hooks: nah can still block while
  delegated calls may be approved.
- Cline defaults the global Hooks setting to enabled, but a user or runtime
  update can disable it. Hook loading, workspace trust, and the setting remain
  runtime-owned.
- On Unix the Cline UI enables and disables individual hooks through executable
  permissions. `nah hook cline status` reports a disabled owned script as
  `reinstall required`.
- The IDE runs global and workspace hooks concurrently. If a sibling errors or
  times out, the IDE currently fails open for that call and may discard nah's
  cancellation. CLI 3.0.48 instead runs blocking hooks sequentially and keeps a
  valid cancellation when another hook fails.
- CLI also discovers workspace `.clinerules/hooks` and `.cline/hooks`. Project
  and SDK plugin hooks remain user-owned and are not installed or protected.
- CLI `--config` and `CLINE_DIR` redirect its config hook root. Nah blocks
  visible non-default launches because the remaining Documents root is not
  guaranteed to match the platform-resolved IDE path. `--hooks-dir` is an
  additional user-owned hook directory and does not replace nah's roots.
While active, this adapter blocks visible lifecycle commands and direct
mutations to its dedicated nah-owned hook. The agent is told not to retry; an
operator can use `nah nap` from another terminal. Other runtime settings remain
user-owned and delegate.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream documentation linked below,
inspect the loaded hook, and test it before relying on nah. See Cline's [IDE hook
schema](https://github.com/cline/cline/blob/main/apps/vscode/proto/cline/hooks.proto),
[IDE hook
templates](https://github.com/cline/cline/blob/main/apps/vscode/src/core/hooks/templates.ts),
[hooks documentation](https://docs.cline.bot/customization/hooks),
[SDK plugin documentation](https://docs.cline.bot/sdk/plugins),
[configuration paths](https://docs.cline.bot/getting-started/config), and
[CLI reference](https://docs.cline.bot/cli/cli-reference).
