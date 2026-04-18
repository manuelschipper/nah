# /nah-classify — Review Recent Prompts

Review recent `nah?` decisions and promote them to permanent rules without leaving Claude Code.

## CRITICAL EXECUTION RULES

**Present decisions one at a time. Wait for user input before acting.**

For each candidate:

1. Show the tool, command/path, assigned action type, and hit count
1. Ask the user: allow-type / classify-command / deny / skip
1. Execute the chosen action
1. Confirm with output before moving to the next

**NEVER batch-run `nah allow` or `nah classify` without per-item user confirmation.**

______________________________________________________________________

## Phase 0: Setup

Run `nah config show` via Bash. Note any custom action overrides — they affect what "allow" means for a given type.

If `$ARGUMENTS` contains a tool filter (e.g. `Bash`, `Read`, `Write`), pass it as `--tool $ARGUMENTS` in Phase 1.

______________________________________________________________________

## Phase 1: Fetch Recent Asks

Run:

```bash
nah log --asks -n 30 --json
```

Parse the output. Group entries by `(tool, action_type)` pair and count occurrences. Sort by count descending.

If no asks are found, print:

```
No recent nah? decisions found. Your config may already cover these cases,
or nah hasn't been active long enough to accumulate a log.
```

And stop.

______________________________________________________________________

## Phase 2: Per-Item Review

For each grouped candidate, print:

```
### [N/total] tool: `input_summary`
Action type: action_type (policy: current_policy)
Seen: N times

Options:
  a) Always allow this action type  →  nah allow action_type
  b) Teach nah this command         →  nah classify "command" action_type
  c) Always block this action type  →  nah deny action_type
  d) Skip (leave as ask)
```

Wait for user input. Then:

- **(a)** — Run `nah allow <action_type>`. Confirm with `nah status`.
- **(b)** — Run `nah test "command"` first to show current classification. Then run `nah classify "<command>" <action_type>`. Confirm with `nah test "command"` again.
- **(c)** — Run `nah deny <action_type>`. Confirm with `nah status`.
- **(d)** — Print `Skipped.` and advance.

**Prefer (b) over (a)** when the user only wants to allow specific commands, not the whole category. Say so if they seem unsure.

______________________________________________________________________

## Phase 3: Summary

After all candidates:

```
## Summary

Allowed types:    action_type_1, action_type_2
Classified:       "command1" → type, "command2" → type
Denied types:     action_type_3
Skipped:          N

Run `nah status` to review all active rules.
```

Run `nah status` via Bash and print the output.
