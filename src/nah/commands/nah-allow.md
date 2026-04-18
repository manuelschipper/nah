# /nah-allow — Allow an Action Type or Command

Allow an action type globally, teach nah a specific command, or trust a network host or path.

## CRITICAL EXECUTION RULES

**Always show current classification before making changes.**
**Always confirm with `nah status` or `nah test` after.**

______________________________________________________________________

## Phase 0: Determine Intent

Check `$ARGUMENTS`:

- If provided, treat as the command or action type to allow and skip asking.
- If empty, ask:

> What do you want to allow?
>
> - **An action type** (e.g. `filesystem_delete`, `lang_exec`) — affects all commands of that type globally
> - **A specific command** (e.g. `cargo clean`) — more surgical, teaches nah this one command
> - **A network host or path** (e.g. `api.example.com`, `~/Obsidian Vault/context`) — use `nah trust`

Wait for user input.

______________________________________________________________________

## Phase 1: Allow an Action Type

1. Run `nah types` via Bash. Show the full output so the user can see current policies.
1. Confirm which type to allow.
1. Run:

```bash
nah allow <action_type>
```

4. Confirm with `nah status`.

______________________________________________________________________

## Phase 2: Allow a Specific Command

1. Run `nah test "<command>"` via Bash. Show current classification — action type, policy, reason.
1. Ask: allow this specific command (b), or allow the whole action type (a)?
1. If **(b)** — teach the command:

```bash
nah classify "<command>" <action_type>
```

4. Verify:

```bash
nah test "<command>"
```

Confirm the decision is now `ALLOW`.

______________________________________________________________________

## Phase 3: Trust a Host or Path

For network hosts:

```bash
nah trust <hostname>
```

For filesystem paths (e.g. vault subfolders, dotfiles subdirectories):

```bash
nah trust <path>
```

Confirm with `nah status`.

______________________________________________________________________

## Notes

- `nah allow <type>` is **global** — applies across all projects and sessions.
- `nah trust <path>` exempts a path from sensitive-path checks.
- Project `.nah.yaml` can only tighten policies, never relax them — global config is the only place to grant permissions.
- To undo any change: `nah forget <action_type>`.
