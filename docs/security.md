# Security boundaries

See `nah docs threat-model` for the adversary and trust assumptions.

nah evaluates calls reaching a loaded adapter and blocks definite findings and
protected-state changes outside maintenance.

## Enforced

- nah returns only block or delegate; no guard can authorize a call.
- Project custom guards require trust and activation, which pins bundle bytes.
- Analyzer/custom-guard failure adds no finding by default; other evidence
  decides. `--fail-closed` blocks failures/refusals. Live failures enter the
  redacted audit log when writable.
- Understood attempts to mutate nah state, its executable, or
  authority-changing commands block.
- Active adapters protect reviewed hook/loading paths, lifecycle/removal, and
  launches that skip them.
- The 8 MiB log retains up to 200 recent blocks when compacting. `nah test
  --json` and custom guards may expose modeled input and inline code.
- Guards block modeled access to protected credential paths and visible flows
  from sensitive sources or network content into dangerous sinks.
- `git-remote-delete` defaults on for GitHub/GitLab CLI/REST repo deletion.
- `registry-unpublish` defaults on for npm unpublish, RubyGems yank, and
  published-name owner changes.
- `registry-publish` defaults off for reviewed package publication; supported
  dry runs delegate.
- Filesystem guards cover reviewed auth/identity, shell-profile, and startup
  paths plus static systemd units, persistent launchctl, and crontab changes;
  shell-profile and startup-management default off.
- Infrastructure defaults: Podman reset on; broad volume prune and whole-stack
  IaC off. Narrow/dry-run container and targeted or saved-plan IaC delegates.

## Not enforced

- Runtime hook/trust, UI, approvals, permissions, deadlines, and configuration
  outside intercepted calls.
- Unhooked, remote, or human tool calls; runtime bugs, trusted plugins, opaque
  programs, and unobservable effects or filesystems.
- Secret content under unclassified names; guards inspect paths and modeled
  effects, not arbitrary contents.
- Custom guards are trusted executables; nah does not sandbox them.
- Other remote deletion tools/routes, unresolved targets, branches, tags,
  archives, renames, and transfers.
- Registry exclusions: reversible yanks/deprecations, listing/admin commands,
  target-ambiguous tools, web/REST-only changes, and unmodeled ecosystems.
Unknown or opaque input delegates. Fail-closed denies malformed/no-decision
input only when loaded; missing hooks/binaries, runtime failure/bypass, and
broken pipes remain outside.

## Delegate is not approval

`delegate` means no guard blocked. The runtime applies its sandbox or approval;
some execute delegated calls by default. Read `nah docs runtimes`.
`nah log` and the TUI summarize failures retained in the audit log;
`nah why <id>` shows the typed failures attached to one decision.

## Credential and network flow

Credential guards classify modeled paths and effects, not contents. They
protect credential paths, auth stores, keychains, and caches. Cloud CLI use
alone does not imply file access. `secrets-env` blocks `.env` reads, including
copies, but not creation or replacement.

Network guards follow visible data and code through modeled shell pipes,
redirects, archives, links, and transfers. Opaque behavior and prior provenance
remain boundaries. Unresolved or bounded analysis is partial; uncertainty alone
does not block. Recognized danger still reaches guards. See `nah docs guards`.

PowerShell and cmd lower reviewed operations and exact argv into typed effects;
unproven behavior stays partial. `powershell` and `pwsh` differ; ambiguous
`curl`/`wget` aliases never invent writes.

## Trust and configuration

nah blocks understood agent attempts to trust or untrust projects, change guard
state or runtime wiring, open `nah tui`, start a nap, or edit protected state.
Agents may edit inert user or project `.nah/guards/` proposals and give the
human an exact out-of-band command. Before trust, `.nah/project.toml` may only
enable built-ins; an explicit global disable overrides it.

Path guards exclude reads. Gaps include Windows Run keys, `schtasks`,
runtime/offline/editor `systemctl`, `launchctl` bootstrap/bootout, dynamic input,
arbitrary executables, and scripted editors without a proven classified write.

## Operator maintenance

`nah nap` pauses self-protection user-wide for 10 minutes; guards keep running.
`nah nap --all` pauses all non-permanent enforcement and does not run custom
guards. `nah wake` ends either nap.

Starting or extending a nap needs an operator terminal. Invalid or expired
authenticated state fails awake; direct mutation of its state, key, or lock
always blocks. A nap is user-global, and its changes persist.

Self-protection blocks understood mutation of nah, active wiring, executable
aliases, and ancestors. Windows drive/UNC paths normalize; device/reparse paths
fail. `%USERPROFILE%\.nah` has an inheritable user/SYSTEM/Administrators
DACL; nap keys allow only their owner. Opaque or unhooked work remains the
user's responsibility.
