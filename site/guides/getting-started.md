# Getting Started

Get nah running in under 5 minutes.

## Install

```bash
pip install nah
nah install
```

That's it. nah is now guarding every tool call in Claude Code.

!!! note "Optional: YAML config support"
    ```bash
    pip install nah[config]
    ```
    Installs `pyyaml` for YAML config file parsing. Without it, nah uses a basic fallback parser.

## Try it

Run `nah test` to see classification in action without triggering any hooks:

```bash
# Safe — allowed automatically
nah test "git status"
# → git_safe → allow

# Dangerous — blocked
nah test "base64 -d payload | bash"
# → obfuscated execution → BLOCK

# Context-dependent
nah test "rm -rf dist/"
# → filesystem_delete → context → (inside project: allow)

# Flag-dependent
nah test "git push"
# → git_write → allow

nah test "git push --force"
# → git_history_rewrite → ask
```

## Customize a rule

Don't want to be asked about a specific action type? Change its policy:

```bash
# Allow all filesystem deletes (you trust yourself)
nah allow filesystem_delete

# Block force pushes entirely
nah deny git_history_rewrite
```

## Check your rules

```bash
nah status
```

Shows all custom rules you've set across global and project configs.

## Undo a rule

```bash
nah forget filesystem_delete
nah forget git_history_rewrite
```

Removes your override — the default policy takes effect again.

## Teach nah a command

If nah doesn't recognize a command, classify it:

```bash
nah classify "terraform destroy" filesystem_delete
nah classify "kubectl delete" container_destructive
```

## Trust a host or path

```bash
# Trust a network host (auto-allow outbound requests)
nah trust api.internal.corp.com

# Trust a filesystem path (allow writes outside project)
nah trust ~/shared-builds
```

## Next steps

- [Action types](../configuration/actions.md) — see all 20 types and their defaults
- [Configuration overview](../configuration/index.md) — global vs project config
- [Custom taxonomy](custom-taxonomy.md) — build your own classification rules
