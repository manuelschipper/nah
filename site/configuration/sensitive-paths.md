# Sensitive Paths

nah protects sensitive filesystem locations from accidental access. Both directory paths and filename patterns are checked.

## Built-in sensitive paths

| Path | Default policy |
|------|:--------------:|
| `~/.ssh` | block |
| `~/.gnupg` | block |
| `~/.git-credentials` | block |
| `~/.netrc` | block |
| `~/.aws` | ask |
| `~/.azure` | ask |
| `~/.config/gcloud` | ask |
| `~/.config/gh` | ask |
| `~/.docker` | ask |
| `/etc/docker` | ask |
| `/var/run/docker.sock` | ask |
| `/run/podman/podman.sock` | ask |
| `~/.kube` | ask |
| `/etc/systemd` | ask |
| `~/.config/systemd/user` | ask |
| `/lib/systemd` | ask |
| `~/.config/az` | ask |
| `~/.config/heroku` | ask |
| `~/.terraform.d/credentials.tfrc.json` | ask |
| `~/.terraformrc` | ask |
| `~/.claude/settings.json` | ask |
| `~/.claude/settings.local.json` | ask |
| `~/.bashrc` | ask |
| `~/.bash_profile` | ask |
| `~/.bash_aliases` | ask |
| `~/.bash_login` | ask |
| `~/.bash_logout` | ask |
| `~/.profile` | ask |
| `~/.zshrc` | ask |
| `~/.zshenv` | ask |
| `~/.zprofile` | ask |
| `~/.zlogin` | ask |
| `~/.zlogout` | ask |
| `~/.bashrc.d` | ask |
| `~/.zshrc.d` | ask |
| `/etc/shadow` | block |

These are checked for guarded file-oriented tools: Bash, Read, Write, Edit, MultiEdit, NotebookEdit, Glob, and Grep.

## Built-in sensitive basenames

| Basename | Default policy |
|----------|:--------------:|
| `.env` | ask |
| `.env.local` | ask |
| `.env.production` | ask |
| `.npmrc` | ask |
| `.pypirc` | ask |
| `.pgpass` | ask |
| `.boto` | ask |
| `terraform.tfvars` | ask |

Basename matching triggers regardless of directory -- a file named `.env` anywhere will be flagged.

## Hook self-protection

`~/.claude/hooks/` is **always** protected. Write, Edit, MultiEdit, and NotebookEdit to this directory are blocked (not just asked). This is immutable -- no config can change it.

## Config options

### sensitive_paths

Override policies for existing paths or add new ones:

```yaml
# ~/.config/nah/config.yaml
sensitive_paths:
  ~/Secrets: ask            # add new sensitive directory
  ~/Documents/taxes: block  # add new blocked directory
  ~/.aws: ask               # already default, but explicit
```

Valid policies: `allow`, `ask`, `block`. `allow` removes that entry from the
sensitive-path list. Because that loosens policy, use it in global config or in
a project trusted with `nah trust-project`; untrusted project config can only
tighten entries, for example from `ask` to `block`.

### sensitive_paths_default

Escalate every built-in `ask` path and sensitive basename to `block` in one
setting:

```yaml
sensitive_paths_default: block   # default is "ask"
```

The normal `ask` default preserves the built-in hard blocks listed above.
Explicit `sensitive_paths` and `sensitive_basenames` entries take precedence
over this blanket default.

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

Directories outside the project root where Write/Edit/MultiEdit/NotebookEdit are allowed without asking:

```yaml
# ~/.config/nah/config.yaml (global only)
trusted_paths:
  - ~/builds
```

`/tmp` and `/private/tmp` are always built-in trusted scratch directories, so
they do not need to be listed and cannot be removed through `trusted_paths`.
Trust applies beneath these directories; deleting a trusted directory root
itself still blocks.
This only bypasses the project-boundary prompt; sensitive-path and
self-protection checks still apply. Other Write/Edit/MultiEdit/NotebookEdit
targets outside the project root trigger an `ask` unless configured here.

**CLI:** `nah trust ~/builds`

!!! warning "Global config only"
    Both `allow_paths` and `trusted_paths` are only accepted in global config. Project `.nah.yaml` cannot modify them.

Use [presets](index.md#presets) when you want different sensitive-path policy
bundles for different workflows. Legacy `profile` keys are ignored and do not
disable built-in sensitive path checks.
