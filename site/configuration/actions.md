# Action Types

Every command nah classifies maps to one of 43 **action types**. Each type has a default **policy** that determines the decision.

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
| `git_remote_write` | ask | Remote git mutations (gh pr merge, gh issue create, git push) |
| `git_discard` | ask | Discard uncommitted changes (reset --hard, checkout .) |
| `git_history_rewrite` | ask | Rewrite published history (force push, rebase -i) |
| `network_outbound` | context | Outbound network requests (curl, wget, ssh) |
| `network_write` | context | Data-sending network requests (POST/PUT/DELETE/PATCH) |
| `network_diagnostic` | allow | Read-only network probes (ping, dig, traceroute) |
| `package_install` | allow | Install packages (npm install, pip install) |
| `package_run` | allow | Run package scripts (npm run, npx, just) |
| `package_uninstall` | ask | Remove packages (npm uninstall, pip uninstall) |
| `lang_exec` | context | Execute code via language runtimes or shell-sourced scripts (python, node, source) |
| `process_signal` | ask | Send signals to processes (kill, pkill) |
| `container_read` | allow | Read-only container and image inspection (logs, inspect, stats, ps) |
| `container_lifecycle` | context | Named container lifecycle changes gated by trusted_containers |
| `container_build` | allow | Container image builds and infrastructure setup (build, tag, create, compose build) |
| `container_exec` | ask | Execute or copy data in containers (exec, run, attach, cp) |
| `container_destructive` | ask | Destructive container operations (docker rm, docker system prune) |
| `service_inspect` | allow | Read-only inspection of local service/daemon state (systemctl status, journalctl, launchctl list) |
| `service_read` | context | Read state from a remote service or API (curl GET, gRPC read, GraphQL query) |
| `service_write` | ask | Change local service or remote API state (restart, enable, daemon-reload) |
| `service_destructive` | ask | Remove, reset, or disrupt local service or remote API state (reboot, poweroff, isolate) |
| `env_read` | ask | Expose environment variables or secret/credential values (printenv, vault kv get, kubectl get secret) |
| `browser_read` | allow | Read-only browser inspection (snapshots, screenshots, console, network, assertions) |
| `browser_interact` | allow | In-page browser interactions (click, type, resize, mouse, navigation controls) |
| `browser_state` | allow | Browser state mutations (cookies, storage, routes, console/network state) |
| `browser_navigate` | context | Navigate a browser page to a new URL |
| `browser_exec` | ask | Execute arbitrary code in the browser page context |
| `browser_file` | context | Browser actions that read from or write to the host filesystem |
| `db_safe` | allow | Database tools that structurally cannot run caller-supplied SQL |
| `db_exec` | context | Database tools that can run caller-supplied SQL |
| `agent_read` | allow | Read-only agent CLI metadata, status, help, or generated output |
| `agent_write` | ask | Agent CLI state mutations without launching a coding run |
| `agent_exec_read` | ask | Launch a local agent run intended for inspection or review |
| `agent_exec_write` | ask | Launch a local agent run that can edit workspace state |
| `agent_exec_remote` | ask | Submit or continue an agentic run in a remote agent service |
| `agent_server` | ask | Start an agent protocol server or app server |
| `agent_exec_bypass` | ask | Launch an agent run while explicitly bypassing approvals or sandboxing |
| `obfuscated` | block | Obfuscated or encoded commands (base64 \| bash) |
| `unknown` | ask | Unrecognized command or tool — not in any classify table |

## Overriding policies

Override any action type's default policy in your config:

```yaml
# ~/.config/nah/config.yaml
actions:
  filesystem_delete: ask         # always confirm deletes
  git_history_rewrite: block     # never allow force push
  lang_exec: allow               # trust inline scripts
  container_build: block         # useful for unattended agents
```

Project `.nah.yaml` can only **tighten** policies by default. For example, a
project config can escalate `git_write` from `allow` to `ask`, but lowering
`git_discard` from `ask` to `allow` requires `nah trust-project` for that exact
project root.

### The `unknown` type

Commands not in any classify table get type `unknown` (default: `ask`). You can change this:

```yaml
actions:
  unknown: block    # strict: block all unrecognized commands
  unknown: allow    # sandbox: trust everything (not recommended)
```

### Context policies

Types with `context` as their default policy delegate to a **context resolver**:

- **Filesystem types** (`filesystem_write`, `filesystem_delete`) -- check if the target path is inside the project, in a trusted path, or targets a sensitive location. Catastrophic targets are subject to the invariant safety floor below.
- **Network types** (`network_outbound`, `network_write`) -- check if the target host is localhost, a known registry, or an unknown host. `network_write` always asks (known hosts only trusted for reads).
- **Remote service reads** (`service_read`) -- apply host checks to the remote API target: a known host (or implicit `gh api`/`glab api` host) allows, an unknown host asks. Local daemon inspection is a separate `allow`-policy type (`service_inspect`) and is not host-checked.
- **Container lifecycle** (`container_lifecycle`) -- check flag-free named container operands against `trusted_containers`; every extracted container must be trusted. Flags, dynamic identities, compose lifecycle commands, missing tokens, and untrusted names fail closed to `ask`.
- **Language execution** (`lang_exec`) -- allow existing file-backed scripts inside the project or trusted paths based on location. Inline code and heredoc-fed interpreters ask for approval; script bodies are not inspected.
- **Database execution** (`db_exec`) -- check extracted database/schema targets against `db_targets`; unknown SQL-capable targets still ask. nah does not parse SQL intent.
- **Browser context types** (`browser_navigate`, `browser_file`) -- currently fail closed to `ask` with an extraction-pending reason because URL/path extraction from structured browser-tool input is not implemented yet.

`container_build` is intentionally not cwd-gated: image, build, tag, create,
network, volume, and compose build/config commands default to `allow`.
Unattended presets should tighten it explicitly when Dockerfile `RUN` steps or
container infrastructure changes should not proceed without a human.

### Invariant safety floor

Some structurally explicit operations block regardless of action-policy
overrides:

- Deletes selecting the filesystem root, current home, critical operating-system
  trees, a trusted directory root, or core Git history metadata.
- Raw disk, partition table, logical volume, and storage-pool erasure.
- Recursive permission or ownership changes selecting the filesystem root,
  current home, critical system trees, or a trusted directory root.
- Canonical fork bombs and writes to Linux's `/proc/sysrq-trigger` crash
  interface.

Deleting the current project root or non-core `.git` metadata asks for approval.
Deleting a child beneath a trusted path remains governed by normal context
policy; trusting `/tmp` does not authorize deleting `/tmp` itself.

### Legacy `container_write`

`container_write` was split into `container_lifecycle` and `container_build`.
For migration, `actions:` entries fan out to both new types:

```yaml
actions:
  container_write: block
```

is treated as:

```yaml
actions:
  container_lifecycle: block
  container_build: block
```

`classify:` entries using `container_write` map to the conservative
`container_lifecycle` successor. Interactive CLI writes such as
`nah deny container_write` and `nah classify "x" container_write` ask you to
choose one of the new action types instead of guessing.

## CLI

```bash
nah types                         # list all types with default policies
nah allow filesystem_delete       # set a type to allow
nah deny network_outbound         # set a type to block
nah forget filesystem_delete      # remove your override
```
