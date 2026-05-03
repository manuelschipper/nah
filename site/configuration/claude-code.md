# Claude Code Configuration

Claude Code uses nah through PreToolUse hooks. These settings only affect
Claude Code hook behavior; Codex and shell guards do not use them.

## active_allow

When nah classifies a Claude Code tool call as safe, it can emit an explicit
`"allow"` response so Claude skips its own permission prompt. This is active
allow: nah takes over the safe-path permission decision for that tool call.

Sometimes you want nah's protection but still want Claude Code to prompt before
writes or edits. Set `active_allow` to a list of tool names to control which
tools nah actively allows:

```yaml
# ~/.config/nah/config.yaml

# nah handles Bash/Read/Glob/Grep; write-like tools fall back to Claude Code prompts
active_allow: [Bash, Read, Glob, Grep]
```

nah still classifies all guarded Claude Code tool calls. It will still block or
ask for dangerous operations on Write/Edit/MultiEdit/NotebookEdit and matching
MCP tools. The only difference is that safe calls for tools outside the list do
not get an automatic allow from nah, so Claude Code shows its normal permission
prompt.

| Value | Behavior |
|-------|----------|
| `true` (default) | Actively allow all guarded Claude Code tools |
| `false` | Never actively allow; nah only blocks and asks |
| list of tool names | Actively allow only the listed tools |

Valid tool names: `Bash`, `Read`, `Write`, `Edit`, `MultiEdit`,
`NotebookEdit`, `Glob`, `Grep`, and exact `mcp__...` tool names.
