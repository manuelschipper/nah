# Configuration

nah keeps global guard state, nap state, records, and snapshots under `~/.nah/`.
Commands own that protected state.

Run `nah tui` in an interactive terminal for the same protected configuration
surface. It has these screens:

- **Guards** lists each guard with its setting; Right shows a guard's rules.
  Space cycles a guard's setting or overrides a rule; Enter applies.
- **Runtimes** installs, refreshes, or removes nah-owned integration wiring.
- **Log** keeps separate 200-row views for decisions and blocks. Rows name the
  runtime and deciding rule; runtime, outcome, and `/` text filters compose. A
  saved discard's details give its `nah undo` command. `s` summarizes every
  call the log holds: how many ran as usual, were blocked and by which
  guards, were saved first, or were not fully checked.

The TUI links to each runtime's `runtime-*` topic. `nah tui` is protected from
invocation through agent tool calls.

## Built-in guards

Each guard is off, core (the default), or strict; `self` is always on. Strict
adds the rules, and parts of rules, whose danger depends on context nah cannot
see. `nah guards` shows live state and `nah docs guards` adds examples:

```sh
nah guards
nah docs guards
```

A human can set a guard or override a rule:

```sh
nah guard set work strict
nah rule disable work/changes-discard
```

A rule override wins over its guard until `nah rule reset`: `enable` runs
every part of the rule. Disabling removes only that rule; another may still
block. Built-in settings are per user: nothing in a repository changes what
nah enforces.

Global choices live in `~/.nah/built-ins.json`. V3 stores settings other than
core and rule overrides. Unknown saved rules are ignored with a warning, and
commands reject unknown names. If the file cannot be read, is malformed or
conflicting, has an unsupported version, or a 1.x file cannot be converted,
built-ins run at factory defaults and self-protection stays active. Saved
opt-in choices are suspended until the file is repaired. Each call reports an
evaluation failure to the runtime and records the filename and error code;
`--fail-closed` blocks calls that would otherwise delegate. `nah guards` and
guard changes reject invalid state. Repair the file to recover saved choices,
or delete it and reapply your choices. TUI `D` restores built-in defaults.

Configuration can only add or remove blocks, never authorize a call.

## Upgrade from nah 1.x

The first 2.0 process to load nah's settings converts a 1.x
`~/.nah/built-ins.json` and an active nap once, keeping `built-ins.json.1x`.
Each choice becomes the rule states that block what it blocked. `nah guards`
lists every choice that does not carry exactly, with its notice:

- Two 1.x guards in one rule set differently take the least protective state
  still blocking all both blocked.
- A choice that blocked discards 2.0 saves at core, such as `git-path-discard`
  (`work/changes-discard`) or `git-ref-delete` (`work/branch-delete` and
  `work/stash-drop`) turned on, enables each rule it maps to, which then
  blocks those discards instead of saving them. The notice gives the command
  that lets the rule save again.
- With `fs-outside-workspace-delete` on, a recursive delete inside a working
  directory no Git repository holds no longer blocks: that directory is now
  the project.

Commands given a 1.x guard name reject it and name the rules it became.

nah 2.0 reads no `.nah/project.toml`. In a project that has one, the first
hook reply that carries nah's notes, or the first `nah hook <runtime> status`,
says once that it is not read. Turn on the rules it enabled for your user with
`nah rule enable <guard/rule>`.

Rerun `nah hook <runtime> install`: `status` reports `reinstall required`
until a runtime has 2.0's post-call hooks. In
Codex, trust the new hooks in `/hooks`.

Nah 2.0 runs no custom guards, so a guard nah 1.x ran blocks nothing after the
upgrade. While `~/.nah/activations.json` lists one, `nah guards`, the TUI's
Guards tab and every `nah hook <runtime> install` name it and where its files
are. Move what it protected into your agent runtime's own permission rules or
another tool, then delete `~/.nah/activations.json` to clear the notice. nah
never runs, changes or deletes those files.

## Temporary operator maintenance

Run `nah nap` in a separate interactive terminal when you intentionally want
an agent to change protected nah configuration. It pauses self-protection
globally for 10 minutes while guards remain active. Use
`nah nap <guard|guard/rule>...` to pause only those while
self-protection and everything else stay active, and `nah nap all` only when
every non-permanent intercepted call should delegate to the runtime. Use `nah wake` to resume
immediately.

The window applies to every project and concurrent session using the same
`~/.nah/`. Persistent changes are not rolled back at expiry. Invalid or
tampered nap state fails awake; see `nah docs security` for the protection
boundary.

While a nap is active, `nah tui` banners every screen with which enforcement or
guards are paused and how long is left, marks each paused rule `[z]`, and `w`
there confirms the same wake. The TUI cannot start or extend a nap.

## Runtime configuration

`nah hook <runtime> install` changes only nah-owned integration entries and
preserves unrelated runtime configuration. Each runtime has loading, trust,
and coverage limitations that nah cannot repair. Read `nah docs runtimes` and
the selected `runtime-*` topic before relying on the hook.

Nesting-limit refusals block by default. `--fail-closed` also blocks other
explicit failures/refusals; `--fail-open` restores the
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
