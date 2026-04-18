# /nah-log — Show Recent Hook Decisions

Audit recent nah decisions — allows, asks, and blocks.

______________________________________________________________________

## Phase 0: Determine Filter

Check `$ARGUMENTS`:

| Argument | Command |
|----------|---------|
| `asks` | `nah log --asks -n 30` |
| `blocks` | `nah log --blocks -n 30` |
| `bash` | `nah log --tool Bash -n 30` |
| `read` | `nah log --tool Read -n 30` |
| `write` | `nah log --tool Write -n 30` |
| *(empty)* | `nah log --asks -n 20` then `nah log --blocks -n 5` |

If no argument, run both defaults and present combined.

______________________________________________________________________

## Phase 1: Fetch and Present

Run the appropriate command(s) via Bash.

Present output as:

```
## nah log

### nah? (prompted you)
  3×  Bash: `git push --force`         [git_history_rewrite]
  2×  Bash: `cargo clean`              [filesystem_delete]
  1×  Read: `~/.config/starship.toml`  [sensitive_path]

### nah. (hard blocked)
  1×  Bash: `base64 -d | bash`         [obfuscated]

### ✓ allowed
  47 silent passes (use `nah log -n 50` to see all)
```

Group repeated entries by `(tool, command/path)`. Show counts. Sort by count descending within each group.

______________________________________________________________________

## Phase 2: Prompt for Follow-up

If there are repeated `nah?` entries (count ≥ 2), print:

```
→ Repeated prompts detected. Run /nah-classify to promote these to permanent rules.
```

If the log is empty:

```
No recent decisions found. Confirm nah is installed and active:
  nah install      # installs the PreToolUse hook
  nah config show  # verify config is loaded
```
