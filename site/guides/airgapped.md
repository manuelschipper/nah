# Airgapped Environments

Running nah in restricted environments where there's no internet access, no public registries, and no LLM providers.

## Start with profile: none

The blank-slate profile clears all built-in assumptions:

```yaml
# ~/.config/nah/config.yaml
profile: none
```

This disables:

- All built-in classify tables
- All flag classifiers
- All safety lists (known registries, exec sinks, etc.)
- Built-in sensitive paths and basenames
- Built-in content patterns
- Project boundary checks

Everything falls to `unknown` → `ask` unless you explicitly classify it.

## Build your own rules

Add only the commands and policies relevant to your environment:

```yaml
profile: none

# Classify the commands your team uses
classify:
  filesystem_delete:
    - "rm -rf"
    - "rm -r"
  git_history_rewrite:
    - "git push --force"
    - "git push -f"
  filesystem_read:
    - cat
    - ls
    - head
    - tail

# Set policies
actions:
  filesystem_delete: ask
  git_history_rewrite: block
  filesystem_read: allow
```

## Internal registries

If you have internal package mirrors, add them as known registries:

```yaml
known_registries:
  - nexus.internal.corp.com
  - artifactory.mycompany.io
  - registry.internal.corp.com
```

Without this, all network commands to these hosts will trigger `ask`.

## Internal tool directories

If your tools live outside the project directory and you're using `profile: full` or `minimal`, add them as trusted paths:

```yaml
trusted_paths:
  - /opt/internal-tools
  - ~/corp-scripts
```

Without this, Write/Edit operations to these paths trigger `ask` (project boundary check).

!!! note
    `profile: none` disables the project boundary check entirely, so `trusted_paths` is unnecessary in that case. It only matters when using `full` or `minimal` profiles.

## No LLM

With no LLM configured, all ambiguous `ask` decisions go straight to the user for confirmation. This is the default behavior — you don't need to disable anything.

If you previously had LLM configured and want to explicitly disable it:

```yaml
llm:
  enabled: false
```

## Full example

```yaml
# ~/.config/nah/config.yaml — airgapped environment
profile: none

classify:
  filesystem_delete:
    - "rm -rf"
    - "rm -r"
    - "shutil.rmtree"
  git_history_rewrite:
    - "git push --force"
    - "git push -f"
    - "git rebase"
  filesystem_read:
    - cat
    - ls
    - head
    - tail
    - grep
    - find
  git_safe:
    - "git status"
    - "git log"
    - "git diff"

actions:
  filesystem_delete: ask
  git_history_rewrite: block
  unknown: ask

known_registries:
  - nexus.internal.corp.com

trusted_paths:
  - /opt/internal-tools

sensitive_paths:
  ~/.ssh: block
  ~/.aws: block
```
