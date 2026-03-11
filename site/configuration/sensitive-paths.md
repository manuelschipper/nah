# Sensitive Paths

nah protects sensitive filesystem locations from accidental access. Both directory paths and filename patterns are checked.

## Built-in sensitive directories

| Path | Default policy |
|------|:--------------:|
| `~/.ssh` | block |
| `~/.gnupg` | block |
| `~/.git-credentials` | block |
| `~/.netrc` | block |
| `~/.aws` | ask |
| `~/.config/gcloud` | ask |

These are checked on every tool call that touches a file path (Bash, Read, Write, Edit, Glob, Grep).

## Built-in sensitive basenames

| Basename | Default policy |
|----------|:--------------:|
| `.env` | ask |
| `.env.local` | ask |
| `.env.production` | ask |
| `.npmrc` | ask |
| `.pypirc` | ask |

Basename matching triggers regardless of directory -- a file named `.env` anywhere will be flagged.

## Hook self-protection

`~/.claude/hooks/` is **always** protected. Write and Edit to this directory are blocked (not just asked). This is immutable -- no config can change it.

## Config options

### sensitive_paths

Override policies for existing paths or add new ones:

```yaml
# ~/.config/nah/config.yaml
sensitive_paths:
  ~/.kube: ask              # add new sensitive directory
  ~/Documents/taxes: block  # add new blocked directory
  ~/.aws: ask               # already default, but explicit
```

Valid policies: `ask`, `block`. Project config can only tighten (e.g., escalate `ask` to `block`).

### sensitive_paths_default

Set the default policy for all sensitive paths:

```yaml
sensitive_paths_default: block   # default is "ask"
```

### allow_paths

Exempt specific paths from sensitive path checks for a given project:

```yaml
# ~/.config/nah/config.yaml (global only)
allow_paths:
  ~/.aws/config:
    - /Users/me/infra-project
```

This allows `~/.aws/config` access only from `/Users/me/infra-project`. The exemption is scoped to the project root.

**CLI:** `nah allow-path ~/.aws/config`

### trusted_paths

Directories outside the project root where Write/Edit are allowed without asking:

```yaml
# ~/.config/nah/config.yaml (global only)
trusted_paths:
  - ~/builds
  - /tmp/staging
```

Without this, Write/Edit to paths outside the git project root triggers an `ask` decision (project boundary check).

**CLI:** `nah trust ~/builds`

!!! warning "Global config only"
    Both `allow_paths` and `trusted_paths` are only accepted in global config. Project `.nah.yaml` cannot modify them.

## profile: none

Setting `profile: none` clears all built-in sensitive directories and basenames. The hook self-protection (`~/.claude/hooks/`) remains active regardless.
