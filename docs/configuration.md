# Configuration

nah keeps global guard state, trust, activations, records, caches, and user
guard proposals under `~/.nah/`. Commands own its protected state; the
`~/.nah/guards/` subtree is an inert proposal area agents may edit.

Run `nah tui` in an interactive terminal for the same protected configuration
surface. It has these screens:

- **Guards** groups built-ins by semantic family and `DEFAULT ON` or `DEFAULT
  OFF`, with custom user and project subsections, and stages changes into one
  batch until Enter. Custom activation shows a bounded preview of covered
  files and pins the displayed path, scope, and full bundle hash; changed bytes
  are refused until reviewed again. Press `f` to compose family,
  factory-default, and source filters; filtering never drops staged changes.
- **Projects** trusts the current directory or revokes a selected trusted root.
- **Runtimes** installs, refreshes, or removes nah-owned integration wiring.
- **Log** keeps separate 200-row views for decisions and blocks. Rows name the
  runtime; runtime, verdict, and `/` text filters compose. Details summarize
  retained failures.

The TUI links to each runtime's `runtime-*` topic. `nah tui` is protected from
invocation through agent tool calls.

## Built-in guards

Every built-in has its own factory default. `fs-shell-profile` and
`fs-startup-management` ship off because routine tooling uses the files and
commands they cover. All other current built-ins ship on. The documentation
view shows live and factory status plus three examples:

```sh
nah guards
nah docs guards
```

A human can change one built-in or custom guard:

```sh
nah guard disable git-hard-reset
nah guard enable corp-api --user
```

Disabling a guard removes only that rule; another guard may still block, and
anything no guard blocks delegates to the runtime. Structural self-protection
has no persistent disable switch. If custom guards share a name across scopes,
select one with `--user` or `--project <root>`; built-ins are global.

Global built-in choices are stored in `~/.nah/built-ins.json`. State v2 keeps
sorted explicit overrides; missing names use their compiled factory defaults.
Nah reads the previous v1 disabled-name file without rewriting it and writes v2
on the next guard change. `D` in the TUI resets built-ins to their factory
posture and disables custom guards.

Configuration can only add or remove blocks; it cannot authorize a tool call.

## Tighten a project before trust

A repository may add `.nah/project.toml`:

```toml
enable-guards = ["secrets-env", "git-hard-reset"]
```

This file can only enable named built-in guards. It cannot disable guards or
define executable code. Unknown names warn on every affected decision. A
malformed or unreadable file adds no project guards; the globally enabled
guards still run. An explicit global operator disable wins over a project
enablement. A default-off guard with no explicit global override may still be
enabled by the project.

## Trust project guards

Project guards under `.nah/guards/` remain inert until a human runs the
matching command:

```sh
nah trust /absolute/project/root
nah guard enable <name> --project /absolute/project/root
```

The home directory itself cannot be a project root because its
`~/.nah/guards/` path belongs to user guards.

Trust must be an out-of-band human action. nah blocks visible agent attempts
to invoke `nah trust`, `nah untrust`, or mutate the trust database through
guarded tools. Revoke a root and all enabled project guards tied to it with:

```sh
nah untrust /absolute/project/root
```

Activation pins the manifest, executable, and declared data. Changed bytes
require re-enabling. An unreadable activation database, or an activated bundle
that is missing, changed, untrusted, or cannot be cataloged, adds an evaluation
failure. The decision still completes and delegates unless another guard or
self-protection blocks. Malformed inactive proposals only warn. `nah nap --all`
skips custom guards with the rest of non-permanent enforcement.

User guards live under `~/.nah/guards/<name>` and do not require project
trust, but they still require activation. See `nah docs extending`. Use
`nah guards` to inspect discovered and activated custom guard state without
changing it.

## Temporary operator maintenance

Run `nah nap` in a separate interactive terminal when you intentionally want
an agent to change protected nah configuration. It pauses self-protection
globally for 10 minutes while guards remain active. Use
`nah nap --all` only when every non-permanent intercepted call should delegate
to the runtime, and use `nah wake` to resume immediately.

The window applies to every project and concurrent session using the same
`~/.nah/`. Persistent changes are not rolled back at expiry. Invalid or
tampered nap state fails awake; see `nah docs security` for the protection
boundary.

While a nap is active, `nah tui` banners every screen with which enforcement is
paused and how long is left, and `w` there confirms the same wake. The TUI
cannot start or extend a nap.

## Runtime configuration

`nah hook <runtime> install` changes only nah-owned integration entries and
preserves unrelated runtime configuration. Each runtime has loading, trust,
and coverage limitations that nah cannot repair. Read `nah docs runtimes` and
the selected `runtime-*` topic before relying on the hook.

`--fail-closed` blocks explicit failures/refusals; `--fail-open` restores the
default. Flagless reinstall preserves a recognized mode, otherwise delegate is
used. In the TUI runtime screen, `f` switches the selected integration's mode;
`i` installs or refreshes it without changing a recognized mode.

While a hook is active, nah blocks visible install/uninstall commands,
mutations to its active wiring and standard enablement files, native removal
commands naming nah, and recognized child launches that skip the hook or
select alternate configuration. It tells the agent not to retry. Users still
own runtime hardening outside intercepted calls. Operators can run protected
commands directly there, or use `nah nap` when a tool must make the change.

Inspect managed files without changing them:

```sh
nah hook <runtime> status
```

Status reports `wiring current`, `not configured`, or `reinstall required`,
the detected failure policy, then the relevant install or documentation
command. Current wiring does
not prove that the runtime loaded or trusted it.
