# Action Types

Every command nah classifies maps to one of 20 **action types**. Each type has a default **policy** that determines the decision.

## Policy levels

| Level | Meaning | Strictness |
|-------|---------|:----------:|
| `allow` | Always permit | 0 |
| `context` | Check path/host/project context, then decide | 1 |
| `ask` | Prompt the user for confirmation | 2 |
| `block` | Always reject | 3 |

Policies are ordered by strictness. When merging configs, nah always keeps the stricter policy (tighten-only).

## All action types

| Type | Default | Description |
|------|:-------:|-------------|
| `filesystem_read` | allow | Read files or list directories |
| `filesystem_write` | context | Create or modify files |
| `filesystem_delete` | context | Delete files or directories |
| `git_safe` | allow | Read-only git operations (status, log, diff) |
| `git_write` | allow | Git operations that modify the working tree or index |
| `git_discard` | ask | Discard uncommitted changes (reset --hard, checkout .) |
| `git_history_rewrite` | ask | Rewrite published history (force push, rebase -i) |
| `network_outbound` | context | Outbound network requests (curl, wget, ssh) |
| `network_write` | context | Data-sending network requests (POST/PUT/DELETE/PATCH) |
| `network_diagnostic` | allow | Read-only network probes (ping, dig, traceroute) |
| `package_install` | allow | Install packages (npm install, pip install) |
| `package_run` | allow | Run package scripts (npm run, npx, just) |
| `package_uninstall` | ask | Remove packages (npm uninstall, pip uninstall) |
| `lang_exec` | context | Execute code via language runtimes (python, node) |
| `process_signal` | ask | Send signals to processes (kill, pkill) |
| `container_destructive` | ask | Destructive container operations (docker rm, docker system prune) |
| `db_read` | allow | Read-only database operations (SELECT, introspection) |
| `db_write` | ask | Write operations on databases (INSERT, UPDATE, DELETE, DROP, ALTER) |
| `obfuscated` | block | Obfuscated or encoded commands (base64 \| bash) |
| `unknown` | ask | Unrecognized command or tool -- not in any classify table |

## Overriding policies

Override any action type's default policy in your config:

```yaml
# ~/.config/nah/config.yaml
actions:
  filesystem_delete: ask         # always confirm deletes
  git_history_rewrite: block     # never allow force push
  lang_exec: allow               # trust inline scripts
```

Project `.nah.yaml` can only **tighten** policies (raise strictness), never relax them. For example, a project config can escalate `git_write` from `allow` to `ask`, but cannot lower `git_discard` from `ask` to `allow`.

### The `unknown` type

Commands not in any classify table get type `unknown` (default: `ask`). You can change this:

```yaml
actions:
  unknown: block    # strict: block all unrecognized commands
  unknown: allow    # sandbox: trust everything (not recommended)
```

### Context policies

Types with `context` as their default policy delegate to a **context resolver**:

- **Filesystem types** (`filesystem_write`, `filesystem_delete`) -- check if the target path is inside the project, in a trusted path, or targets a sensitive location.
- **Network types** (`network_outbound`, `network_write`) -- check if the target host is localhost, a known registry, or an unknown host. `network_write` always asks (known hosts only trusted for reads).

## CLI

```bash
nah types                         # list all types with default policies
nah allow filesystem_delete       # set a type to allow
nah deny network_outbound         # set a type to block
nah forget filesystem_delete      # remove your override
```
