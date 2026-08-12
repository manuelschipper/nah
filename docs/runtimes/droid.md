# Factory Droid

## Install

```sh
nah hook droid install
```

Use `--fail-closed` to deny explicit failures/refusals. `--fail-open` restores
the default; flagless reinstall preserves a recognized mode.

Restart Droid and inspect `/hooks`. Remove only nah's hook group with:

```sh
nah hook droid uninstall
```

The installer atomically updates `~/.factory/hooks.json`, preserves unrelated
hooks, and is idempotent. Standalone event names such as `PreToolUse` live at
the top level. Installation migrates nah's old nested shape and removes
nah-owned copies from `~/.factory/settings.json` and the legacy
`~/.factory/hooks/hooks.json`.

## Behavior

Execute, Read, Create, Edit, ApplyPatch, Grep, literal-relative Glob, and LS
tools use the shared policy. Wildcard or multiple globs delegate.
Definite blocks and fail-closed failures/refusals exit 2. By default, malformed
and other unblocked calls delegate. If nah is missing or exits unexpectedly,
the installed wrapper exits 0 with fixed feedback on standard output.

## Boundaries

nah protects the execution host, not the interface. It must be installed for
the OS user running Droid, with this hook loaded from that user's Factory
configuration. Local `droid exec` is live-tested with Droid 0.186.0.
Interactive Droid and editor terminals use the same local CLI. JetBrains and
Zed ACP launch local `droid exec` and should load the same user hook, but have
not been live-tested with nah.

The same rule applies to CI containers, Missions, Droid Computers, Factory App
or Slack sessions targeting a Droid Computer, and automations: the execution
target is covered only when nah and its hook are installed for its runtime
user. Factory says Mission lifecycle hooks fire, but nah has not been
dogfooded on those remote paths. A laptop install does not propagate to a
remote computer or worker. Factory-hosted targets where users cannot install
nah are outside this integration.

Organization policy can require managed hooks only, excluding this user hook.
Droid snapshots hooks at startup; edits require review in `/hooks` before the
running session applies them. The `hooksDisabled` setting, also available from
`/hooks` and `/settings`, disables all hooks without removing their
configuration.

The current local CLI may still invoke hooks with
`--skip-permissions-unsafe`; Factory does not promise that as a stable security
contract. If invoked, a nah block still applies, while a delegate has no native
prompt behind it. Exit 2 blocks; other hook errors are non-blocking. The
installed wrapper preserves that runtime behavior. Alternate settings or
Factory homes without the installed hook, direct trusted hook or plugin
actions, and execution targets without nah remain outside the integration.

While active, this adapter blocks visible lifecycle commands, explicit native
removal commands naming nah, mutations to current or supported fallback hook
files, and child launches with alternate `--settings`. Permission-skip modes
do not disable hooks and are not self-protection findings. The agent is told
not to retry protected changes; an operator can use `nah nap` from another
terminal.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream documentation linked below,
inspect the loaded hook, and test it before relying on nah. See Factory's
[hook reference](https://docs.factory.ai/harness/hooks),
[settings reference](https://docs.factory.ai/cli/configuration/settings), and
[`droid exec` documentation](https://docs.factory.ai/droid-exec/overview).
Factory also documents [IDE integrations](https://docs.factory.ai/ide-integrations),
[Missions](https://docs.factory.ai/missions/reference),
[Droid Computers](https://docs.factory.ai/droid-computers/overview), and
[automation execution targets](https://docs.factory.ai/software-factory/automations).
