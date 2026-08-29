# Security boundaries

See `nah docs threat-model` for the adversary and trust assumptions.

nah evaluates only tool calls reaching a loaded adapter. It blocks definite
guard findings and understood protected-state changes outside maintenance.

## Enforced

- nah returns only block or delegate; no guard can authorize a call.
- Project custom guards require trust and activation, which pins bundle bytes.
- Analyzer or custom-guard failure adds no finding by default; other evidence
  still decides. `--fail-closed` blocks explicit failures and bounded refusals.
  Completed live failures enter the redacted audit log when writable.
- Understood attempts to mutate nah state, its executable, or
  authority-changing commands block.
- Active adapters also protect understood changes to standard hook and loading
  files, lifecycle/removal commands, and launches that skip them.
- On compaction, the 8 MiB redacted log prioritizes up to 200 recent
  blocks when space allows. `nah test --json` and custom guards may
  expose unredacted modeled input and inline code.
- Guards block modeled access to protected credential paths and visible flows
  from sensitive sources or network content into dangerous sinks.
- Default-on `git-remote-delete` blocks exact GitHub/GitLab whole-repository
  deletion through CLI and REST forms.
- The default-on `fs-auth-identity` guard blocks visible writes and deletes of
  reviewed login-authority, identity, PAM, sudoers, and sshd paths. The
  default-off `fs-shell-profile` guard applies the same mutation-only policy to
  reviewed user shell profiles when enabled. The default-on
  `fs-startup-persistence` guard protects reviewed service, schedule, login,
  autostart, and loader startup paths.
- Default-off `fs-startup-management` covers static Linux
  `systemctl` unit-file changes, macOS `launchctl` enable/disable or legacy
  `load`/`unload -w`, and `crontab` install/removal.

## Not enforced

- Runtime hook loading or trust, UI actions, approval or permission behavior,
  hook deadlines, and configuration outside intercepted calls.
- Unhooked, remote, or human tool calls; runtime bugs, trusted plugins, opaque
  programs, and unobservable effects or filesystems.
- Secret content under unclassified names; guards inspect paths and modeled
  effects, not arbitrary contents.
- Custom guards are trusted executables; nah does not sandbox them.
- Other remote deletion tools/routes, unresolved targets, and branch, tag,
  archive, rename, or transfer operations.

Unknown or opaque input delegates. Fail-closed uses native denial for malformed
or no-decision input, but requires loaded nah to respond; missing hooks/binaries,
runtime failure or bypass, and broken pipes remain outside.

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
human an exact out-of-band command. Before trust, `.nah/project.toml` may enable
additional built-in guards but cannot disable them.
An explicit global operator disable takes precedence over that project
enablement.

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
aliases, and ancestors. Windows drive and UNC paths
normalize; device or reparse paths fail. `%USERPROFILE%\.nah` has an inheritable
DACL for the user, SYSTEM, and Administrators; nap keys allow only their owner.
Opaque or unhooked work remains user
responsibility.
