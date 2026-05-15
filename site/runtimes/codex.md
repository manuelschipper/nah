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

`nah run codex` starts Codex with a guarded preset:

- Codex hooks enabled
- native `PreToolUse`, `PermissionRequest`, and `PostToolUse` hooks pointing
  at nah
- `sandbox_mode="danger-full-access"` by default
- `approval_policy="untrusted"`
- nah-managed Codex exec-policy prompt rules for Codex known-safe command
  prefixes
- human approval review
- dynamic MCP dependency installs disabled

`danger-full-access` gives the Codex process normal host access while nah
remains the permission authority through Codex's approval hooks. `untrusted`
normally asks before commands outside Codex's trusted command set. nah also
installs a managed rules file at
`$CODEX_HOME/rules/nah-authority.rules` so Codex-known-safe command prefixes,
such as `cat`, `git`, `ls`, `rg`, and `sed`, are prompted too and nah can apply
path-sensitive policy before execution.

Use nah's launcher flag when you want Codex's own sandbox too:

```bash
nah run codex --sandbox workspace-write
nah run codex --sandbox workspace-write --network
nah run codex --sandbox read-only
```

`--network` enables Codex workspace network access only with
`--sandbox workspace-write`. With the default `danger-full-access` sandbox,
network is already host-controlled and the flag is redundant. `workspace-write`
keeps Codex's filesystem sandbox, which can be useful when you want an
additional sandbox boundary but can also restrict host-level resources.

The `PreToolUse` and `PostToolUse` hooks are observation-only. They let nah
track configured [taint state](../configuration/taint-tracking.md) and
execution outcomes without changing Codex's native approval UI.

Safe project-local `apply_patch` add/update edits are allowed by nah after it
checks patch paths and added content. If you want Codex to ask before those
safe edits too, launch with:

```bash
nah run codex --confirm-edits
```

nah owns the safety settings for the protected session. Use nah's `--sandbox`
launcher flag to select the Codex sandbox. Attempts to override approval,
hooks, rules, dynamic MCP installs, or nah-owned Codex config with raw Codex
config are rejected. Normal Codex UI and session flags still pass through.

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

## Codex Setup and Checks

Codex can remember approval decisions and load exec-policy rules. A remembered
allow, conflicting `forbidden` rule, or `host_executable` entry for a
Codex-known-safe command can skip nah before nah sees a future command. Before
launch, `nah run codex` installs or refreshes nah's managed authority rules,
then scans Codex approval memory, exec-policy rules, and MCP approval modes.

Inspect without changing files:

```bash
nah codex doctor
```

Install, refresh, or fix nah's Codex integration:

```bash
nah codex setup
```

`setup` has three jobs:

- install or refresh `$CODEX_HOME/rules/nah-authority.rules`
- check Codex approval-memory rules and MCP approval modes
- back up and fix supported drift, including remembered allow rules and
  supported MCP approval settings that should be `prompt`

Clean setup output is intentionally short:

```text
$ nah codex setup
setup: /home/me/.codex/rules/nah-authority.rules
checked: Codex approval memory and MCP approval modes
nah codex: ready
```

When setup fixes supported drift, it creates timestamped local backups before
editing:

```text
$ nah codex setup
setup: /home/me/.codex/rules/nah-authority.rules
backup: /home/me/.codex/rules/default.rules.nah-bak-20260515103412
updated: /home/me/.codex/rules/default.rules
checked: Codex approval memory and MCP approval modes
nah codex: ready
```

If unsupported blockers remain, setup leaves them untouched and prints exact
file, rule, or config instructions:

```text
nah codex: still blocked:
- /home/me/.codex/rules/default.rules:1
  Codex prefix_rule forbidden for `git` can deny before nah decides
  Remove this rule or change its decision to `prompt`.
```

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
project-local edit should be allowed by nah after path and content checks. Use
`nah run codex --confirm-edits` when you want even safe project-local edits to
ask through Codex's native approval UI.

If you want to verify Codex workspace sandboxing specifically, launch with:

```bash
nah run codex --sandbox workspace-write
```

The default `nah run codex` session is host-capable, so normal host tools can
work when the current user has permission. nah still decides whether
permission-relevant commands are allowed, asked, or blocked.

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
- `--ask-for-approval` / `-a`
- user overrides for nah-owned approval, hook, sandbox, rules, and MCP feature
  keys through raw Codex config
- `codex exec`
- `codex apply`
- `codex review`
- remote/cloud Codex runs

`--sandbox` / `-s` is supported as a nah launcher flag for
`danger-full-access`, `workspace-write`, and `read-only`. Raw Codex config
overrides such as `-c sandbox_mode=...` are rejected.

Run `codex ...` directly only when you intentionally want an unguarded Codex
session.

## Coverage

`nah run codex` guards local interactive Codex Bash, MCP, and `apply_patch`
hook payloads. It does not guard remote/cloud Codex sessions, non-interactive
`codex exec`, or Codex surfaces that do not emit local interactive hooks.
