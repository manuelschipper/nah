# Devin CLI

Use `nah install devin` to protect [Devin CLI](https://docs.devin.ai/cli/)
sessions. nah registers native Devin hooks that route `exec`, file, search, and
MCP tool calls through the same deterministic classifier nah uses for Claude
Code and Codex.

```bash
nah install devin     # register nah hooks in Devin's user config
nah status devin      # show whether nah hooks are installed
nah update devin      # re-resolve the hook command after an upgrade
nah uninstall devin   # remove only nah's hook entries
```

## What nah Installs

`nah install devin` writes nah hook entries into Devin's user-level config at
`~/.config/devin/config.json` (`%APPDATA%\devin\config.json` on Windows). It
registers three events, each calling the installed `nah` executable:

```json
{
  "hooks": {
    "PreToolUse": [{ "matcher": "", "hooks": [{ "type": "command", "command": "nah _devin-hook" }] }],
    "PermissionRequest": [{ "matcher": "", "hooks": [{ "type": "command", "command": "nah _devin-hook" }] }],
    "PostToolUse": [{ "matcher": "", "hooks": [{ "type": "command", "command": "nah _devin-hook" }] }]
  }
}
```

The install **merges** into your existing Devin config: other settings and your
own hooks are preserved, and a `config.json.bak` backup is written before any
change. The empty matcher (`""`) sends every tool call to nah, which routes it
internally — there is no per-tool matcher list to maintain.

## How nah Decides

Devin's hook output is `approve` / `block` only; it has no native "ask". nah
uses Devin's two decision events for different jobs:

- **`PreToolUse`** fires before every tool, so it is nah's deterministic block
  floor. A deterministic block (for example `curl … | bash`, or reading a
  private key) returns `{"decision": "block", "reason": "…"}`. Everything else
  continues. No LLM runs here.
- **`PermissionRequest`** fires only when Devin itself wants a permission
  decision — Devin's native prompt. Here nah maps its verdict:
    - **allow** → `{"decision": "approve"}` (skip the prompt, stay in flow)
    - **ask** → no output (abstain) so Devin's own permission prompt fires
    - **block** → `{"decision": "block", "reason": "…"}`

Because the block floor lives at `PreToolUse`, dangerous commands are blocked
regardless of Devin's permission mode. Ambiguous commands defer to Devin's
native confirmation prompt rather than being force-blocked. If you want a
specific category to hard-block instead of defer, use `nah deny <type>`.

`PostToolUse` is observation-only: nah records execution outcomes and
[taint state](../configuration/taint-tracking.md) without changing Devin's UI.

## Tool Coverage

| Devin tool | Guarded as |
| --- | --- |
| `exec` | Bash command classification |
| `edit` | file write path + boundary checks |
| `read` | sensitive-path checks |
| `grep` | credential-search detection |
| `glob` | path checks |
| `mcp__<server>__<tool>` | MCP tool classification |

## Devin and Claude Config

Devin can also read Claude Code's `.claude/settings.json` hooks. nah does **not**
rely on that: Devin's tool names (`exec`, `edit`, …) differ from Claude's
(`Bash`, `Edit`, …), so Claude hooks would not fire under Devin. `nah install
devin` installs into Devin's own config so coverage is explicit and independent
of any Claude Code install.
