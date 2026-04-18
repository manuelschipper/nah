# Claude Code Slash Commands

Manage nah rules without leaving your Claude Code session.

## Install

```bash
pip install nah
nah install --skills
```

This symlinks four slash commands into `~/.claude/commands/`. They're available
globally in every Claude Code session.

!!! note "Already have nah installed?"
`bash     nah install --skills     `
Safe to run on an existing install — already-linked commands are skipped.
Use `--force` to overwrite.

## Commands

### `/nah-classify`

Review recent `nah?` prompts and promote them to permanent rules.

```
/nah-classify
```

Fetches your recent ask decisions, groups repeated commands, and walks you
through each one: allow the action type globally, teach nah this specific
command, deny it, or skip.

Run this after a session where nah has been interrupting you repeatedly.

### `/nah-allow`

Allow an action type, classify a specific command, or trust a host or path.

```
/nah-allow
/nah-allow cargo clean
/nah-allow filesystem_delete
```

With no argument, asks whether you want to allow an action type, a specific
command, or a host/path. With an argument, goes straight to classification.
Always shows current state before making changes.

### `/nah-status`

Show current nah configuration — custom rules, all action type policies, and
config file locations.

```
/nah-status
```

Equivalent to running `nah status`, `nah types`, `nah config show`, and
`nah config path` in sequence, formatted for readability.

### `/nah-log`

Audit recent hook decisions filtered by type or tool.

```
/nah-log
/nah-log asks
/nah-log blocks
/nah-log bash
```

Default (no argument) shows recent `nah?` prompts and hard blocks. Pass a
filter to narrow: `asks`, `blocks`, or a tool name (`bash`, `read`, `write`).
Repeated prompts surface a suggestion to run `/nah-classify`.

## The friction loop this closes

Without the commands:

```
nah? fires mid-session
  → open new terminal
  → nah log --asks
  → figure out action type
  → nah allow / nah classify
  → back to Claude Code
```

With `/nah-classify`:

```
nah? fires mid-session
  → /nah-classify
  → pick from list
  → done
```

## Uninstall

The commands are symlinks — removing them leaves no trace:

```bash
rm ~/.claude/commands/nah-classify.md
rm ~/.claude/commands/nah-allow.md
rm ~/.claude/commands/nah-status.md
rm ~/.claude/commands/nah-log.md
```

Or uninstall nah entirely:

```bash
nah uninstall
pip uninstall nah
```

!!! note
`nah uninstall` removes the PreToolUse hook but does not remove skill
symlinks. Remove those manually if needed.

## Next steps

- [Getting started](getting-started.md) — install nah and run the security demo
- [Action types](../configuration/actions.md) — all 23 types and their defaults
- [Configuration overview](../configuration/index.md) — global vs project config
