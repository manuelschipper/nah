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
    Installs `pyyaml` for YAML config file parsing. Without it, config files are ignored (stderr warning).

## See it in action

Clone the repo and run the security demo inside Claude Code to see nah intercepting real tool calls:

```bash
git clone https://github.com/manuelschipper/nah.git
cd nah
# inside Claude Code:
/nah-demo
```

25 live cases across 8 threat categories. Takes ~5 minutes.

## Try it

Run `nah test` to see classification in action without triggering any hooks:

```
$ nah test "git status"
Command:  git status
Stages:
  [1] git status → git_safe → allow → allow (git_safe → allow)
Decision:    ALLOW
Reason:      git_safe → allow

$ nah test "base64 -d payload | bash"
Command:  base64 -d payload | bash
Stages:
  [1] base64 -d payload → unknown → ask → ask (unknown → ask)
  [2] bash → unknown → ask → ask (unknown → ask)
Composition: decode | exec → BLOCK
Decision:    BLOCK
Reason:      obfuscated execution: bash receives decoded input

$ nah test "rm -rf dist/"
Command:  rm -rf dist/
Stages:
  [1] rm -rf dist/ → filesystem_delete → context → allow (inside project)
Decision:    ALLOW
Reason:      inside project

$ nah test "git push --force"
Command:  git push --force
Stages:
  [1] git push --force → git_history_rewrite → ask → ask (git_history_rewrite → ask)
Decision:    ASK
Reason:      git_history_rewrite → ask
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
