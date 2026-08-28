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
- The default-on `fs-auth-identity` guard blocks visible writes and deletes of
  reviewed login-authority, identity, PAM, sudoers, and sshd paths. The
  default-off `fs-shell-profile` guard applies the same mutation-only policy to
  reviewed user shell profiles when enabled. The default-on
  `fs-startup-persistence` guard protects reviewed service, schedule, login,
  autostart, and loader startup paths.

## Not enforced

- Runtime hook loading or trust, UI actions, approval or permission behavior,
  hook deadlines, and configuration outside intercepted calls.
- Unhooked, remote, or human tool calls; runtime bugs, trusted plugins, opaque
  programs, and unobservable effects or filesystems.
- Secret content under unclassified names; guards inspect paths and modeled
  effects, not arbitrary contents.
- Custom guards are trusted executables; nah does not sandbox them.

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

## Trust and configuration

nah blocks understood agent attempts to trust or untrust projects, change guard
state or runtime wiring, open `nah tui`, start a nap, or edit protected state.
Agents may edit inert user or project `.nah/guards/` proposals and give the
human an exact out-of-band command. Before trust, `.nah/project.toml` may enable
additional built-in guards but cannot disable them.
An explicit global operator disable takes precedence over that project
enablement.

The host-integrity guards classify visible filesystem paths, not intent or file
contents. Reads stay outside these rules, and command-level mechanisms such
as `systemctl enable`, `launchctl`, registry Run keys, and `schtasks` are not
covered unless the call also exposes a classified filesystem mutation.

## Operator maintenance

`nah nap` pauses self-protection user-wide for 10 minutes; guards keep running.
`nah nap --all` pauses all non-permanent enforcement and does not run custom
guards. `nah wake` ends either nap.

Starting or extending a nap needs an operator terminal. Invalid or expired
authenticated state fails awake; direct mutation of its state, key, or lock
always blocks. A nap is user-global, and its changes persist.

Self-protection is a prompt-injection guardrail, not a same-user boundary. It
blocks understood direct, wrapped, package-manager, or bounded-inline attempts
to mutate nah or active wiring, replace its installed binary, skip hooks, add
hard-link aliases, or change access on wiring or executable ancestors. Setup,
hardening, opaque or unhooked paths, pre-existing aliases, and out-of-session
work remain user responsibilities.
