# Codex

Use `nah run codex` for local interactive Codex sessions that should route
Bash, MCP, and `apply_patch` hooks through nah. `nah setup codex` also adds a
persistent Codex rules file, so read [Running Codex Without nah](#running-codex-without-nah)
if you sometimes start Codex directly.

```bash
nah setup codex
nah status codex
nah run codex
nah run codex --preset work
nah run codex exec "run: git status"
```

There is no global `nah install codex` path. Codex must be launched through
`nah run codex` so nah can inject native hooks and session-scoped safety
settings. The rules file created by `nah setup codex` is the one persistent
Codex change.

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

Use `--preset <name>` to apply one named global config preset to the protected
session. The launcher strips the flag before starting Codex and exports
`NAH_PRESET` so all injected hooks use the same effective config.

`--network` enables Codex workspace network access only with
`--sandbox workspace-write`. With the default `danger-full-access` sandbox,
network is already host-controlled and the flag is redundant. `workspace-write`
keeps Codex's filesystem sandbox, which can be useful when you want an
additional sandbox boundary but can also restrict host-level resources.

For interactive Codex, the `PreToolUse` and `PostToolUse` hooks are
observation-only. `PostToolUse` lets nah log execution outcomes without
changing Codex's native approval UI. The interactive enforcement decision
happens in `PermissionRequest`. Setting `targets.codex.ask_fallback: native`
makes the default interactive behavior explicit: an unresolved ask returns to
Codex's native approval reviewer.

When global `llm.mode: on` is configured, interactive Codex uses the same single
LLM job as Claude Code: classify a deterministically unknown Bash command into a
built-in action type and re-check surfaced targets through the deterministic
floor. Known asks, inline code, writes, and blocks do not call the LLM.

For `codex exec`, Codex does not have the same interactive approval loop. In
that headless mode, nah makes `PreToolUse` authoritative and never emits an
unsupported ask decision. A deterministic allow continues with empty hook
output. A deterministic block returns a Codex PreToolUse deny. An unresolved
ask blocks by default.

Safe project-local `apply_patch` add/update edits are allowed by nah after it
checks the patch's target paths and project boundary. Deletes follow the
`filesystem_delete` policy, so project-local deletes are also allowed by
default. Moves and empty replacement patches still ask. If you want Codex to
ask before safe edits and deletes too, launch with:

```bash
nah run codex --confirm-edits
```

nah owns the safety settings for the protected session. Use nah's `--sandbox`
launcher flag to select the Codex sandbox. Attempts to override approval,
hooks, rules, dynamic MCP installs, or nah-owned Codex config with raw Codex
config are rejected. Normal Codex UI and session flags still pass through.

## Headless Exec

Use `nah run codex exec` when you want an unattended local Codex run guarded by
nah:

```bash
nah run codex exec "run: git status"
nah run codex --preset sandboxed-build-agent exec "run the test suite"
nah run codex --sandbox workspace-write --network exec "run npm test"
```

Headless exec uses deterministic PreToolUse enforcement. If nah can allow or
block the action, that decision is applied before execution. If nah would
normally ask, headless mode converts the ask through `targets.codex.ask_fallback`.
The default fallback is `block`.

A blocked PreToolUse decision blocks that tool call, not the whole `codex exec`
run. Codex sees the denial and can continue with another safe tool call or
fallback path when the task allows it.

Unresolved asks are handled by `targets.codex.ask_fallback`. With the default
fallback, unresolved asks fail closed as blocks.

The accepted values are `block`, `allow`, and `native`. In headless mode,
`native` resolves to `block` because there is no interactive approval prompt.
The decision log records both the configured `native` mode and the effective
`block` fallback.

Trusted global config or a trusted preset can opt into unattended fallback
allow:

```yaml
targets:
  codex:
    ask_fallback: allow
```

That only changes unresolved asks. Deterministic blocks remain blocks.

For guarded headless v1, nah disables Codex unified exec, Code Mode, and Code
Mode Only. It also rejects user flags or raw config that re-enable those
surfaces, because they can expose tool paths that are not enforceable through
the current PreToolUse contract.

The launcher also ignores Codex exec-policy rule files for the headless run.
Those rule files are useful for interactive Codex because they force known-safe
commands into `PermissionRequest`; in headless exec there is no approval prompt,
so nah uses authoritative `PreToolUse` instead.

Headless exec also records Codex hook trust for the session-scoped nah hooks
that the launcher injects. Interactive `nah run codex` still uses Codex's hook
review UI; headless cannot safely depend on a prompt that never appears.

The default headless sandbox is still `danger-full-access`. That keeps local
developer workflows working while nah remains the hook-visible policy gate. Use
`--sandbox workspace-write --network` when you want Codex's filesystem sandbox
as an additional boundary.

## Hook Review

Codex may require hook review before newly installed hook commands become
active. `nah run codex` injects the session hooks, but Codex stores per-hook
review state in its own config. If a hook is new or its command changed, Codex
can show it as needing review.

Because nah hook commands call the installed `nah` executable, package-manager
upgrades can change the executable path that Codex sees. Reopen `/hooks` after
upgrades when Codex reports newly changed nah hooks.

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
nah status codex
```

Install, refresh, or fix nah's Codex integration:

```bash
nah setup codex
```

`setup` has three jobs:

- install or refresh `$CODEX_HOME/rules/nah-authority.rules`
- check Codex approval-memory rules and MCP approval modes
- back up and fix supported drift, including remembered allow rules and
  supported MCP approval settings that should be `prompt`

The rules file lives in your Codex config, not only in the current terminal.
Codex reads it in plain `codex` sessions too.

Clean setup output is intentionally short:

```text
$ nah setup codex
setup: /home/me/.codex/rules/nah-authority.rules
checked: Codex approval memory and MCP approval modes
codex: ready
```

When setup fixes supported drift, it creates timestamped local backups before
editing:

```text
$ nah setup codex
setup: /home/me/.codex/rules/nah-authority.rules
backup: /home/me/.codex/rules/default.rules.nah-bak-20260515103412
updated: /home/me/.codex/rules/default.rules
checked: Codex approval memory and MCP approval modes
codex: ready
```

If unsupported blockers remain, setup leaves them untouched and prints exact
file, rule, or config instructions:

```text
codex: still blocked:
- /home/me/.codex/rules/default.rules:1
  Codex prefix_rule forbidden for `git` can deny before nah decides
  Remove this rule or change its decision to `prompt`.
```

Remove only nah's managed Codex authority rules:

```bash
nah uninstall codex
```

`nah uninstall codex` refuses to remove an unmanaged file at the same path, and
does not roll back approval-memory or MCP prompt-mode changes a prior
`nah setup codex` may have made.

## Running Codex Without nah

`nah setup codex` adds a Codex rules file so commands like `bash`, `cat`,
`git`, `pwd`, and `true` are routed through nah.

Codex reads that file even when you start Codex directly. That means raw bypass
modes such as `codex --yolo` can fail after setup: Codex sees a rule that asks
for permission, but bypass mode does not allow asking, so the command is
rejected.

To run Codex completely without nah, remove nah's Codex rules first:

```bash
nah uninstall codex
```

You can set them up again later:

```bash
nah setup codex
```

If `nah setup codex` printed `backup:` and `updated:` lines, it also changed an
existing Codex rules or config file after making a backup. Use the exact backup
path printed by setup if you want to restore Codex's previous behavior:

```bash
cp ~/.codex/rules/default.rules.nah-bak-YYYYMMDDHHMMSS ~/.codex/rules/default.rules
cp ~/.codex/config.toml.nah-bak-YYYYMMDDHHMMSS ~/.codex/config.toml
```

Restoring those backups can bring back Codex remembered allows or MCP approval
settings that skip nah. Do it only when you intentionally want Codex back in
its previous state.

## Test It

For a live session test:

```bash
nah run codex
```

Inside Codex, run `/hooks` first and make sure the nah hooks are active. If
Codex reports hooks needing review, accept the nah hooks before testing.

Inside Codex, ask it to edit a project file such as `README.md`. A normal
project-local edit should be allowed by nah after path and project-boundary
checks. Use `nah run codex --confirm-edits` when you want even safe project-local
edits to ask through Codex's native approval UI.

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
- `codex apply`
- `codex review`
- remote/cloud Codex runs

`--sandbox` / `-s` is supported as a nah launcher flag for
`danger-full-access`, `workspace-write`, and `read-only`. Raw Codex config
overrides such as `-c sandbox_mode=...` are rejected.

Raw `codex --yolo` can still be affected by the rules file created by
`nah setup codex`. See [Running Codex Without nah](#running-codex-without-nah)
for how to remove that setup first.

## Coverage

`nah run codex` guards local interactive Codex Bash, MCP, and `apply_patch`
hook payloads through `PermissionRequest`. `nah run codex exec` guards local
headless Codex Bash, MCP, and `apply_patch` hook payloads through
authoritative `PreToolUse`.

nah does not guard remote/cloud Codex sessions or Codex surfaces that do not
emit local hooks.
