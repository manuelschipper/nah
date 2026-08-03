# Devin

## Install

```sh
nah hook devin install
```

To deny explicit evaluation failures and bounded analysis refusals, install
with `--fail-closed`. Ordinary unknown or opaque calls still delegate.
`--fail-open` restores the default; flagless reinstall preserves a recognized
mode. The guarantee requires the loaded nah process to return a response;
missing hooks/binaries, runtime timeout, process termination, bypass, and
broken output pipes remain outside it.

Restart Devin and inspect `/hooks`. Remove only nah's handlers with:

```sh
nah hook devin uninstall
```

The installer updates standard `~/.config/devin/config.json`, preserves
unrelated configuration, and replaces stale nah 0.x handlers.

## Behavior

The local harness shared by Devin CLI and Devin Local in Devin Desktop sends
exec, read, write, edit, grep, and glob calls through nah. Definite findings
block. Malformed and every other unblocked call delegate to Devin's permission
flow.

## Boundaries

This does not cover cloud Devin, handoff sessions, legacy Cascade, non-agent
Desktop features, third-party ACP agents, or direct human actions. Alternate
configuration files supplied with `--config` avoid the standard hook.

Devin's Bypass mode (`/yolo`) auto-approves normal tools, while Autonomous mode
auto-approves shell and fetch tools. Devin does not document either mode as
disabling `PreToolUse`, so a loaded nah hook can still block; delegated calls
may execute without a prompt. Exit 2 blocks, while other nonzero hook exits are
logged and continue. The nah adapter deliberately uses exit 2 when its own
guard blocks. Under the default mode, evaluation failure exits 0 with fixed
diagnostic feedback.

Devin imports Claude hooks by default, so installing both integrations can
check a call twice. The adapter uses `DEVIN_PROJECT_DIR`; a persistent shell's
changed cwd is not present in the documented payload. Devin also discovers
project hooks from `.devin/hooks.v1.json`, `.devin/config.json`,
`.devin/config.local.json`, `.claude/settings.json`, and
`.claude/settings.local.json` from the working directory through the repository
root. Those hooks can run alongside nah. Other hook sources, loading, future
tool shapes, and runtime failures remain outside nah.

While active, this adapter blocks visible lifecycle commands, mutations to its
standard user config, and child launches using `--config` to avoid it. Bypass
and Autonomous permission modes do not disable hooks and are not
self-protection findings. The agent is told not to retry protected changes; an
operator can use `nah nap` from another terminal.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream documentation linked below,
inspect the loaded hook, and test it before relying on nah. See Devin's
[hook documentation](https://docs.devin.ai/cli/extensibility/hooks/overview),
[permission modes](https://docs.devin.ai/cli/reference/permissions), and
[Devin Local documentation](https://docs.devin.ai/desktop/devin-local).
