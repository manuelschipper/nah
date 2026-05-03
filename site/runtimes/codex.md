# Codex

Codex protection is session-scoped. Use `nah run codex` for local interactive
Codex sessions that should route Bash and MCP permission requests through nah.

```bash
nah codex doctor
nah run codex
nah run codex --no-sandbox
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
Codex sandboxing is not available in your environment, you can launch a guarded
session without the Codex sandbox:

```bash
nah run codex --no-sandbox
nah run codex --ns
```

Both flags set `sandbox_mode="danger-full-access"` for the Codex process.
They do not disable nah, Codex approvals, or the `PermissionRequest` hook:
`approval_policy` remains `on-request`.

You can also choose an explicit Codex sandbox mode:

```bash
nah run codex --sandbox read-only
nah run codex --sandbox workspace-write
nah run codex --sandbox danger-full-access
nah run codex -s danger-full-access
```

Direct `-c sandbox_mode=...` overrides are still rejected so nah can keep a
single owner for the guarded session's approval and sandbox settings.

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

For a live local test:

```bash
nah run codex --no-alt-screen
```

`--no-alt-screen` is a Codex UI flag that keeps the TUI in normal terminal
scrollback, which makes it easier to inspect test output. Inside Codex, ask it
to run:

```bash
curl -I https://schipper.ai
```

Codex should show its native approval UI for the command. If you approve, nah
receives the `PermissionRequest`, classifies the command, and can allow, ask,
or block according to policy.

Dry-run equivalent:

```bash
nah test --tool Bash -- "curl -I https://schipper.ai"
```

## Unsupported Modes

nah rejects Codex modes that can bypass the protected approval path, including:

- `--yolo`
- `--dangerously-bypass-approvals-and-sandbox`
- user overrides for nah-owned approval, hook, and MCP feature keys
- direct `-c sandbox_mode=...` overrides
- `codex exec`
- `codex review`
- remote/cloud Codex runs

Run `codex ...` directly only when you intentionally want an unguarded Codex
session.

## Coverage

`nah run codex` guards local interactive Codex Bash and MCP
`PermissionRequest` payloads. It does not guard remote/cloud Codex sessions,
non-interactive `codex exec`, or Codex surfaces that do not emit the local
interactive approval hook.
