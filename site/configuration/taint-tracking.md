# Taint Tracking

Taint tracking is a session-level flow layer. Normal nah policy still controls
the immediate tool call. When taint is enabled, nah can also remember that a
session successfully read a sensitive source and then flag later side effects
that might activate or move that data.

The goal is not full program analysis. It is a deterministic guardrail for
read -> write -> execute/network/remote chains that are hard to judge one tool
call at a time.

## Mental Model

| Term | Meaning |
|------|---------|
| **Source** | A configured sensitive path, or an inherited sensitive path, was read successfully. |
| **Label** | A user-defined name attached to a source, such as `secret`, `customer_data`, or `prod_config`. |
| **Propagation** | Tainted state was written into a trackable target, so that target inherits the label. |
| **Activation** | Code or agent execution after taint exists in the session. |
| **Boundary** | A network, database, service, container, browser, git-remote/history, or remote-agent action after taint exists. |
| **Unknown** | An unrecognized action after taint exists. In v1 this remains at least `ask`. |

A blocked source access does not taint the session. nah only tracks sources
that were allowed and, for runtimes with post-tool hooks, confirmed as executed.

## Runtime Scope

| Runtime | Taint behavior |
|---------|----------------|
| Claude Code | Uses PreToolUse and post-tool hooks for source tracking, execution confirmation, and enforcement. |
| Codex | Uses PreToolUse/PostToolUse for observation and PermissionRequest for enforceable decisions. Review hooks in `/hooks` after install or upgrade. |
| Terminal Guard | Audit-only in v1. It can log taint findings, but taint policy does not change terminal decisions. |

## Enable Audit Mode

Start with audit mode. It records what nah would have asked or blocked without
changing the runtime decision.

```yaml
# ~/.config/nah/config.yaml
taint:
  mode: audit
```

Then inspect decisions:

```bash
nah log --json
```

Example log metadata:

```json
{
  "taint": {
    "mode": "audit",
    "labels": ["secret"],
    "chain": "Read ~/.aws/credentials secret -> Bash curl -I https://example.com",
    "category": "boundary",
    "policy": "secret + boundary = ask",
    "policy_decision": "ask",
    "would_decision": "ask",
    "enforced": false
  }
}
```

## Enforce Mode

When the audit output matches the workflow you want, switch to enforce mode.
Only policies stricter than the original decision can change the outcome.

```yaml
taint:
  mode: enforce
```

For example, if a command would normally be allowed but follows a sensitive read
and matches a `boundary: ask` policy, nah can escalate it to `ask`. If the
normal classifier already asked, nah records taint context rather than making
the decision weaker.

## Sources

By default, when taint tracking is enabled, nah inherits effective sensitive
paths as taint sources:

```yaml
taint:
  mode: audit
  inherit_sensitive_paths: true
```

Inherited sensitive paths use the `secret` label when their effective
sensitive-path policy is `ask` or `block`. If you desensitize a path so it no
longer has an ask/block policy, it is not inherited as a taint source.

Add explicit sources with your own labels:

```yaml
taint:
  mode: audit
  sources:
    - paths:
        - ".env*"
        - "config/prod/**"
      labels: [secret, prod_config]
    - paths:
        - "customers/**/*.csv"
      labels: [customer_data]
```

Source patterns are matched against the raw path, resolved path, friendly path,
and basename.

## Propagation

Propagation means a tainted session wrote data into another target. nah then
treats that target as tainted for later actions.

Supported v1 propagation targets:

| Action type | Default | What becomes tainted |
|-------------|:-------:|----------------------|
| `filesystem_write` | on | The written file path |
| `git_write` | on | The current repository |
| `browser_file` | on | The browser file target |

Configure propagation with booleans:

```yaml
taint:
  mode: audit
  propagation:
    filesystem_write: true
    git_write: true
    browser_file: true
```

Custom action types cannot be propagation targets in v1. They can be marked as
activation or boundary sinks.

## Activation and Boundary Sinks

Built-in activation sinks are action types that execute code or agent/tool
behavior inside the current controlled environment:

- `lang_exec`
- `package_run`
- `agent_exec_read`
- `agent_exec_write`
- `agent_exec_bypass`

Built-in boundary sinks are action types where data, code, or effects leave the
current controlled environment:

- `network_outbound`
- `network_write`
- `network_diagnostic`
- `git_remote_write`
- `git_history_rewrite`
- `db_safe`
- `db_exec`
- `service_read`
- `service_write`
- `service_destructive`
- `container_read`
- `container_lifecycle`
- `container_build`
- `container_exec`
- `container_destructive`
- `browser_interact`
- `browser_state`
- `browser_navigate`
- `browser_exec`
- `browser_file`
- `agent_exec_remote`
- `agent_server`

If an action could be read as both execution and boundary crossing, boundary
wins. For example, `container_exec`, `browser_exec`, `agent_exec_remote`, and
`agent_server` are execution-shaped, but their permission category is boundary
because they expose behavior outside the local controlled execution path.

Add or remove action types from the sink categories:

```yaml
taint:
  mode: audit
  categories:
    activation:
      add: [mytool_run]
      remove: []
    boundary:
      add: [mytool_upload]
      remove: [container_exec, browser_interact]
```

Use this for custom action types that you classify with `nah classify` or
`classify:` config. Do not use it for unknown command names; unknown actions
remain a separate taint category and default to `ask`.

## Policies

Policies are per label. A policy key can be a specific action type, or one of
the category keys `activation`, `boundary`, or `unknown`.

```yaml
taint:
  mode: enforce
  policies:
    default:
      activation: audit
      boundary: ask
      unknown: ask
    secret:
      activation: audit
      boundary: ask
      git_remote_write: block
    customer_data:
      activation: ask
      boundary: block
      unknown: ask
```

Valid policies are `allow`, `audit`, `ask`, and `block`.

Specific action-type policies win before category policies. In the example
above, `secret + git_remote_write = block` is stricter than
`secret + boundary = ask`, so a remote git write after secret access blocks.

In v1, `unknown` cannot be loosened below `ask`.

## Project Config Trust

Global config can set the full taint shape. Project `.nah.yaml` files are more
restricted:

- `taint.mode` and `taint.inherit_sensitive_paths` are global-only.
- Trusted projects can add sources, categories, propagation settings, and
  policies.
- Untrusted projects can only tighten policies.

Trust a project root only when you want that project to define richer taint
metadata for itself:

```bash
nah trust-project
```

## Local State

Taint state is local session state under:

```text
~/.config/nah/taint/sessions/
```

State contains labels, compact target identities, and chain metadata. It does
not store command output or file contents.

## Limitations

- Taint tracking is action/category based, not byte-level dataflow analysis.
- It does not inspect process memory.
- Generic build commands can activate code after taint exists; use audit mode
  before enforcing strict activation policies.
- Codex enforcement depends on the local interactive hook surface. If Codex
  runs a tool without a `PermissionRequest`, PreToolUse/PostToolUse can still
  record audit metadata but cannot force Codex's native approval UI.
- Terminal Guard taint is audit-only in v1.
