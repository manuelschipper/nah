# Security boundaries

See `nah docs threat-model` for adversary/trust assumptions.

nah evaluates calls reaching a loaded adapter and blocks definite findings and
protected-state changes outside maintenance.

## Enforced

- Eight guards of 40 rules, each off, core (default) or strict, plus `self`.
- nah only blocks/delegates; guards never authorize.
- Nesting refusals block by default. Failures block suspected guarded deletes
  or credential-file reads; else warn and delegate. `--fail-closed` blocks
  failures/refusals. Live failures enter the redacted log when writable.
- Understood nah-state/executable/authority changes and host power block;
  `machine/system-halt` covers service and stop-all container shutdown at strict.
- Active adapters protect reviewed hook/loading paths, lifecycle/removal, and
  bypass launches.
- When space allows, the 8 MiB redacted log prioritizes up to 200 recent blocks
  on compaction. `nah test --json` may expose unredacted modeled input.
- Credential and network-flow guards block modeled access to dangerous sinks.
  `secrets/vault-secrets-read` is core; it feeds `exfiltration/secret-upload`
  even when disabled.
- `remote-code/repo-delete` blocks whole repo deletion at core and pushes
  that delete refs at strict. `remote-code/hosted-resource-delete` blocks
  deletion of hosted resources at strict.
- `remote-code/package-unpublish`: npm unpublish, RubyGems yank and owner
  changes at core; reviewed publishing at strict; dry runs delegate.
- Filesystem rules cover auth/identity, profiles, startup, outside-project
  recursive deletion, and provable world-write or setuid/setgid `chmod`;
  profile, startup-command, and permission parts apply at strict.
- `infrastructure/container-prune` blocks Podman reset at core and broad volume
  prune and Compose `down`/`rm` volume removal at strict;
  `infrastructure/cloud-resources-destroy` (strict), whole-stack IaC and
  reviewed cloud deletes. Compose
  files are not inspected, and Compose excludes external volumes from `down -v`.
  Narrow/dry-run, named container/volume removal, and
  targeted/saved/ambient/other IaC delegate.
- `infrastructure/cluster-delete` (strict) blocks static namespace deletion,
  reviewed cluster-resource deletion, and bulk reviewed namespaced-resource
  deletion through `kubectl`. Named application resources and client/server
  dry runs delegate; manifest, kustomize, stdin, dynamic, and unknown-kind
  selections are partial and do not reach the guard.
- `infrastructure/cloud-storage-delete` blocks whole Borg repos or all
  Restic/Velero backups at core and bulk remote deletes and syncs that delete
  at strict. `infrastructure/snapshot-delete` blocks snapshot deletion and
  retention runs at strict.

## Not enforced

- Runtime hook/trust, UI, approvals/permissions, deadlines, and configuration
  outside interception.
- Unhooked/remote/human calls; runtime bugs/trusted plugins/opaque programs;
  unobservable effects/filesystems.
- Secret content under unclassified names: guards inspect paths/effects, not contents.
- Secret-store gaps: KMS/access removal, REST, dynamic/unreviewed syntax.
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

`secrets/key-files-access` covers paths, not CLIs; `secrets/env-files-read` covers `.env`
reads/copies and credential-variable output, not presence or writes.
`secrets/vault-secrets-read` covers value reads except run/inject and concealed
listings. `infrastructure/vault-secret-delete` covers permanent destruction at core and
other reviewed deletes at strict, excluding archive/non-executing forms.

Network guards follow visible data/code through modeled shell flows. Opaque and
prior provenance remain boundaries. Unresolved/bounded analysis is partial;
uncertainty doesn't block; recognized danger still reaches guards.
See `nah docs guards`.

PowerShell and cmd lower reviewed operations and exact argv into typed effects;
unproven behavior stays partial. `powershell` and `pwsh` differ; ambiguous
`curl`/`wget` aliases never invent writes.

## Configuration

nah blocks understood agent attempts to change guard state or runtime wiring,
open `nah tui`, start a nap, or edit protected state. Settings are per user:
no file in a repository changes what nah enforces.

Path guards exclude reads. Gaps include Windows Run keys, `schtasks`,
runtime/offline/editor `systemctl`, `launchctl` bootstrap/bootout, dynamic input,
arbitrary executables, and scripted editors without a proven classified write.

## Operator maintenance

`nah nap` pauses self-protection user-wide for 10 minutes; guards keep running.
`nah nap all` pauses all non-permanent enforcement;
`nah nap <guard|rule>...` pauses only those. `nah wake` ends it.

Starting or extending a nap needs an operator terminal. Invalid or expired
authenticated state fails awake; direct mutation of its state, key, or lock
always blocks. Proven removal, rename, or recursive mutation of the home `.nah`
container also stays protected during any nap; an agent doing that maintenance
requires operator action. Whole-home/root operations retain their existing tiers.
A nap is user-global, and its changes persist.

Recognizable executable Nah protected commands delivered through supported Herdr
pane input or tmux key input are restricted even without Enter. This also interrupts
sending executable examples into an editor: delivery does not prove receiver execution.
Nap commands remain blocked in both nap modes; Critical Nah maintenance commands
are permitted during naps. Ordinary agent prompts, quoted printing, help, and
`nah wake` add no self-protection block.

This restriction does not reconstruct split input, Enter-only calls, hidden buffers,
or earlier terminal state. Receiver shell, home, environment, cwd, and host are
unknown; sending filesystem command text does not identify local protected files.
Payload commands outside the bounded Nah/wrapper decoder retain incomplete coverage.
Unsupported carrier options, key encodings, remote execution, Screen raw input,
generic PTY and GUI automation remain outside this coverage. OpenClaw process input
carries unknown content; it does not yet receive command-content matching.

Tmux launches retain modeled repository deletion, environment disclosure, forkbomb,
registry, secret-store, backup, power, filesystem and execution-flow effects.
Compound statements retain commands; absolute redirects and patterns retain
lexical intent without receiver alias or selection proof. Receiver variables, function
calls, substitutions, descriptor state (including `/dev/tcp` input redirects), generated
code, relative paths and home resources remain unresolved. Root-pattern moves such as
`mv /* /tmp` need receiver destination-directory proof; forced Git clean needs
project-root selection proof. Neither can use sender observations. Unknown recursive
reads do not prove credential disclosure; explicit sensitive paths and recognized
credential-search intent retain protection.

Self-protection blocks understood mutation of nah, active wiring, executable
aliases, and ancestors. Windows drive/UNC paths normalize; device/reparse paths
fail. `%USERPROFILE%\.nah` has an inheritable user/SYSTEM/Administrators
DACL; nap keys allow only their owner. Opaque or unhooked work remains the
user's responsibility.
