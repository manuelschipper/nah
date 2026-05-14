# Codex

Codex protection is session-scoped. Use `nah run codex` for local interactive
Codex sessions that should route Bash, MCP, and `apply_patch` hooks through
nah.

```bash
nah codex setup
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
- `approval_policy="untrusted"`
- nah-managed Codex exec-policy prompt rules for Codex known-safe command
  prefixes
- human approval review
- dynamic MCP dependency installs disabled

`workspace-write` lets ordinary project edits flow inside Codex's filesystem
sandbox. `untrusted` routes commands that are not already trusted by Codex
through Codex's native approval path. nah also installs a managed rules file at
`$CODEX_HOME/rules/nah-authority.rules` so Codex-known-safe command prefixes,
such as `cat`, `git`, `ls`, `rg`, and `sed`, are still prompted first and nah
can apply path-sensitive policy before execution.

The `PreToolUse` and `PostToolUse` hooks are observation-only. They let nah
track configured [taint state](../configuration/taint-tracking.md) and
execution outcomes without changing Codex's native approval UI.

Safe project-local `apply_patch` add/update edits are allowed by default after
nah checks patch paths and added content. If you want Codex to ask before those
safe edits too, launch with:

```bash
nah run codex --confirm-edits
```

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

Codex can remember approval decisions and load exec-policy rules. A remembered
allow, conflicting `forbidden` rule, or `host_executable` entry for a
Codex-known-safe command can skip nah before nah sees a future command. Before
launch, `nah run codex` installs or refreshes nah's managed authority rules,
then scans Codex approval memory, exec-policy rules, and MCP approval modes.

Inspect without changing files:

```bash
nah codex doctor
```

Create or refresh only nah's managed Codex setup files:

```bash
nah codex setup
```

`setup` installs or refreshes `$CODEX_HOME/rules/nah-authority.rules`, then
reports any remaining Codex state that can bypass nah. It does not remove
remembered allows or rewrite MCP approval settings.

Repair supported findings:

```bash
nah codex repair
```

`repair` installs or refreshes nah's managed authority rules, creates backups,
removes supported remembered allow rules, and pins supported MCP approval
settings to `prompt`. If preflight blocks startup, run `nah codex doctor` first
so you can see the exact files and rules involved.

Remove only nah's managed Codex authority rules:

```bash
nah codex remove-setup
```

`remove-setup` refuses to remove an unmanaged file at the same path.

## Test It

For a live session test:

```bash
nah run codex
```

Inside Codex, run `/hooks` first and make sure the nah hooks are active. If
Codex reports hooks needing review, accept the nah hooks before testing.

Inside Codex, ask it to edit a project file such as `README.md`. A normal
project-local edit should use Codex `workspace-write` and not require a nah
edit prompt. Use `nah run codex --confirm-edits` when you want even safe
project-local edits to ask through Codex's native approval UI.

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
- user overrides for nah-owned approval, hook, sandbox, rules, and MCP feature
  keys
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
