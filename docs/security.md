# Security boundaries

See `nah docs threat-model` for adversary/trust assumptions.

nah evaluates calls reaching a loaded adapter and blocks definite findings and
protected-state changes outside maintenance.

## Enforced

- 36 guards span execution, secrets, filesystem, Git, infrastructure/storage/
  backup, and registries; 26 default on.
- nah only blocks/delegates; guards never authorize.
- Project guards need trust/activation and pin bundle bytes.
- Analyzer/custom-guard failure adds no finding by default; other evidence
  decides. `--fail-closed` blocks explicit failures/bounded refusals. Completed
  live failures enter the redacted log when writable.
- Understood nah-state/executable mutation or authority change blocks.
- Active adapters protect reviewed hook/loading paths, lifecycle/removal, and
  bypass launches.
- When space allows, the 8 MiB redacted log prioritizes up to 200 recent blocks
  on compaction. `nah test --json`/custom guards may expose unredacted
  modeled input and inline code.
- Guards block modeled protected-credential access and visible
  sensitive/network-content flows to dangerous sinks.
- `git-remote-repo-delete` defaults on for GitHub/GitLab CLI/REST repo deletion.
- `registry-unpublish` defaults on for npm unpublish, RubyGems yank, and
  published-name owner changes.
- `registry-publish` defaults off for reviewed publishing; supported dry runs
  delegate.
- Filesystem guards cover auth/identity, shell profiles, startup paths/commands,
  and recursive deletion outside the project; `fs-outside-workspace-delete`,
  shell-profile, and startup-management default off.
- `infra-container-reset` (on) blocks Podman reset; `infra-container-volume-delete`
  (off), broad volume prune and Compose `down`/`rm` volume removal;
  `infra-iac-destroy` (off), whole-stack IaC. Compose files are not inspected,
  and Compose excludes external volumes from `down -v`. Narrow/dry-run and named
  container or volume removal, plus targeted/saved/ambient/other IaC, delegates.
- `infra-k8s-delete` defaults off and blocks static namespace deletion,
  reviewed cluster-resource deletion, and bulk reviewed namespaced-resource
  deletion through `kubectl`. Named application resources and client/server
  dry runs delegate; manifest, kustomize, stdin, raw, dynamic, and unknown-kind
  selections are partial and do not reach the guard.
- `storage-backup-destroy` is on for whole Borg repos or all Restic/Velero backups.
- `storage-recursive-delete` is off: deletion/sync is routine; argv hides purpose.
- `storage-snapshot-delete` is off: backup rotation routinely deletes snapshots.

## Not enforced

- Runtime hook/trust, UI, approvals/permissions, deadlines, and configuration
  outside interception.
- Unhooked/remote/human calls; runtime bugs/trusted plugins/opaque programs;
  unobservable effects/filesystems.
- Secret content under unclassified names; guards inspect paths and modeled
  effects, not arbitrary contents.
- Custom guards are trusted, unsandboxed executables.
- Unmodeled remote deletion routes, unresolved targets, branches, tags,
  renames, and transfers.
- Registry excludes reversible yanks/deprecations, listing/admin, ambiguous
  targets, web/REST-only changes, and unmodeled ecosystems.
Unknown/opaque input delegates. Fail-closed denies malformed/no-decision input
only when loaded; missing hooks/binaries, runtime failure/bypass, and
broken pipes remain outside.

## Delegate is not approval

`delegate` means no guard blocked. The runtime applies its sandbox or approval;
some execute delegated calls by default. Read `nah docs runtimes`.
`nah log` and the TUI summarize failures retained in the audit log;
`nah why <id>` shows the typed failures attached to one decision.

## Credential and network flow

Credential guards classify modeled paths and effects, not arbitrary contents.
`secrets-credentials` protects credential paths, auth stores, keychains, and
caches. Cloud CLI use alone does not imply file access. `secrets-env` blocks
`.env` reads, including copies, and direct output of catalogued credential
environment variables, but not environment presence checks, `.env` creation,
or replacement.

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
