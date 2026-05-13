# Codex

Codex protection is session-scoped. Use `nah run codex` for local interactive
Codex sessions that should route Bash, MCP, and `apply_patch` hooks through
nah.

```bash
nah codex doctor
nah run codex
```

There is no global `nah install codex` path. Codex must be launched through
`nah run codex` so nah can inject native hooks and session-scoped safety
settings.

## What nah Sets

`nah run codex` starts Codex with one guarded preset:

- Codex hooks enabled
- native `PreToolUse`, `PermissionRequest`, and `PostToolUse` hooks pointing
  at nah
- `sandbox_mode="workspace-write"`
- `approval_policy="on-request"`
- human approval review
- dynamic MCP dependency installs disabled

`workspace-write` lets ordinary project edits flow inside Codex's filesystem
sandbox. Commands that need extra permission, network access, MCP approvals,
or edits outside the workspace go through Codex's native approval path, where
nah can classify the `PermissionRequest`.

The `PreToolUse` and `PostToolUse` hooks are observation-only. They let nah
track configured [taint state](../configuration/taint-tracking.md) and
execution outcomes without changing Codex's native approval UI.

nah owns those safety settings for the protected session. Attempts to override
Codex sandbox, approval, hook, or dynamic MCP feature settings are rejected.
Normal Codex UI and session flags still pass through.

## Hook Review

Codex may require hook review before newly installed hook commands become
active. `nah run codex` injects the session hooks, but Codex stores per-hook
review state in its own config. If a hook is new or its command changed, Codex
can show it as needing review.

Open the hooks panel inside Codex:

```text
/hooks
```

Review and enable the nah `PreToolUse`, `PermissionRequest`, and `PostToolUse`
hooks. This is especially important after nah upgrades that add a new hook
event. For example, if `PostToolUse` and `PermissionRequest` log entries appear
but there is no `PreToolUse` entry, the `PreToolUse` hook is probably still
pending review.

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

For a live session test:

```bash
nah run codex
```

Inside Codex, run `/hooks` first and make sure the nah hooks are active. If
Codex reports hooks needing review, accept the nah hooks before testing.

Inside Codex, ask it to edit a project file such as `README.md`. A normal
project-local edit should use Codex `workspace-write` and not require a nah
edit mode.

Then ask Codex to run:

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
- `--sandbox` / `-s`
- `--ask-for-approval` / `-a`
- user overrides for nah-owned approval, hook, sandbox, and MCP feature keys
- `codex exec`
- `codex apply`
- `codex review`
- remote/cloud Codex runs

Run `codex ...` directly only when you intentionally want an unguarded Codex
session.

## Coverage

`nah run codex` guards local interactive Codex Bash, MCP, and `apply_patch`
hook payloads. It does not guard remote/cloud Codex sessions, non-interactive
`codex exec`, or Codex surfaces that do not emit local interactive hooks.
