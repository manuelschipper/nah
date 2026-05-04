# Codex

Codex protection is session-scoped. Use `nah run codex` for local interactive
Codex sessions that should route Bash and MCP permission requests through nah.

```bash
nah codex doctor
nah run codex
nah run codex --flow
nah run codex --no-sandbox
nah run codex --no-sandbox --auto-edits
```

There is no global `nah install codex` path. Codex must be launched through
`nah run codex` so nah can inject session-scoped native `PermissionRequest`
hooks and owned approval settings.

## What nah Sets

`nah run codex` launches Codex with nah-owned overrides for the guarded session:

- Codex hooks enabled
- native `PermissionRequest` hook pointing at nah
- `approval_policy="on-request"`
- `sandbox_mode="workspace-write"` by default
- human approval review
- dynamic MCP dependency installs disabled

Those settings are owned by nah for the protected session. User-supplied flags
or `-c` overrides for the same keys are rejected, except for nah's sandbox
mode flags described below.

## Sandbox Controls

By default, `nah run codex` keeps Codex in `workspace-write` sandbox mode. If
you want nah protection without Codex filesystem sandboxing, use
`--no-sandbox`:

```bash
nah run codex --no-sandbox
```

This sets `sandbox_mode="danger-full-access"` for the Codex process. It does
not disable nah, Codex approvals, or the `PermissionRequest` hook:
`approval_policy` becomes `untrusted`, so trusted commands can still run while
untrusted commands route through Codex's native approval UI and nah. It does
not auto-accept edits.

You can also choose an explicit Codex sandbox mode:

```bash
nah run codex --sandbox read-only
nah run codex --sandbox workspace-write
nah run codex --sandbox danger-full-access
nah run codex -s danger-full-access
```

Direct `-c sandbox_mode=...` overrides are still rejected so nah can keep a
single owner for the guarded session's approval and sandbox settings.

## Modes

| Command | Codex sandbox | Safe edits |
| --- | --- | --- |
| `nah run codex` | `workspace-write` | ask |
| `nah run codex --no-sandbox` | none | ask |
| `nah run codex --auto-edits` | `workspace-write` | auto-allow |
| `nah run codex --flow` | none | auto-allow |

## Edit Auto-Allow

By default, Codex `apply_patch` edits are guarded but still fall through to
Codex's native approval UI when they are otherwise safe. nah inspects the patch
first for path boundaries, protected files, and dangerous added content; asks
and blocks still win.

To let ordinary safe project-local add/update patches flow without a second
prompt, opt in for that session:

```bash
nah run codex --auto-edits
```

This is a nah-owned wrapper flag, not a native Codex flag. It is not equivalent
to `codex -a never`, which disables approval prompts and is rejected under
`nah run codex`. It is also not the same as `codex apply`, which applies a
previously produced diff after the interactive agent turn.

## Flow Mode

For the faster guarded mode, use `--flow`:

```bash
nah run codex --flow
```

This starts Codex without its filesystem sandbox and lets nah auto-allow safe
project-local `apply_patch` edits. Risky commands, risky paths, delete/move
patches, dangerous content, and unclear edits still ask or block.

It is equivalent to `nah run codex --no-sandbox --auto-edits`. Native Codex
`--yolo` is different and remains rejected because it bypasses approvals and
sandboxing entirely.

## Preflight

Codex can remember approval decisions. A remembered allow can skip the hook path
before nah sees a future command, so `nah run codex` scans Codex approval memory
and MCP approval modes before launch.

Inspect without changing files:

```bash
nah codex doctor
```

Repair supported findings:

```bash
nah codex repair
```

`repair` creates backups, removes supported remembered allow rules, and pins
supported MCP approval settings to `prompt`. If preflight blocks startup, run
`nah codex doctor` first so you can see the exact files and rules involved.

## Test It

For a live edit-flow test:

```bash
nah run codex --flow --no-alt-screen
```

Inside Codex, ask it to append a harmless test line to `README.md`. A safe
project-local add/update patch should apply without Codex showing its native
edit approval prompt. Confirm the nah decision:

```bash
nah log --tool apply_patch -n 1
```

The latest entry should be `allow` with reason `safe apply_patch edit`.

To compare the independent sandbox control:

```bash
nah run codex --no-sandbox --no-alt-screen
```

Ask for the same README edit. This session has no Codex filesystem sandbox, but
it should still show Codex's native edit prompt because `--no-sandbox` does not
imply edit auto-allow.

For a live command-approval test:

```bash
nah run codex --no-alt-screen
```

`--no-alt-screen` is a Codex UI flag that keeps the TUI in normal terminal
scrollback, which makes it easier to inspect test output. Inside Codex, ask it
to run:

```bash
curl -I https://nah.build
```

Codex should show its native approval UI for the command. If you approve, nah
receives the `PermissionRequest`, classifies the command, and can allow, ask,
or block according to policy.

Dry-run equivalent:

```bash
nah test --tool Bash -- "curl -I https://nah.build"
```

## Unsupported Modes

nah rejects Codex modes that can bypass the protected approval path, including:

- `--yolo`
- `--dangerously-bypass-approvals-and-sandbox`
- user overrides for nah-owned approval, hook, and MCP feature keys
- direct `-c sandbox_mode=...` overrides
- `codex exec`
- `codex apply`
- `codex review`
- remote/cloud Codex runs

Run `codex ...` directly only when you intentionally want an unguarded Codex
session.

## Coverage

`nah run codex` guards local interactive Codex Bash, MCP, and `apply_patch`
`PermissionRequest` payloads. It does not guard remote/cloud Codex sessions,
non-interactive `codex exec`, or Codex surfaces that do not emit the local
interactive approval hook.
