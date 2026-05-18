# Session Provenance

Session provenance tracks files and repo state written during the current
guarded run. Later, when the runtime tries to execute or externalize that
session-written state, nah can pause, block, or ask an LLM to review the
session delta.

This is different from [taint tracking](taint-tracking.md):

| Feature | Tracks | Later checks |
| --- | --- | --- |
| Taint tracking | Successful reads from configured sensitive sources | Whether that data flows into activation or boundary actions |
| Session provenance | Successful writes from the current guarded run | Whether those written files or repo changes are activated or cross a boundary |

The goal is narrow. nah does not prove that an arbitrary program is safe. It
remembers what the guarded runtime wrote and applies policy before later action
types run, move, or externalize those changes.

## Enable

```yaml
provenance:
  mode: audit   # off | audit | enforce
```

Modes:

| Mode | Behavior |
| --- | --- |
| `off` | No provenance state is recorded. |
| `audit` | Record state and log what would have happened, without changing decisions. |
| `enforce` | Apply provenance policy before activation or boundary actions run. |

`nah run claude` and `nah run codex` set `NAH_PROVENANCE_RUN_ID` for the
guarded process. Child processes and subagents that inherit the environment
share the same provenance run.

## What Gets Recorded

nah records successful writes only. A blocked write, denied ask, failed tool
call, or missing post-tool success event does not become active provenance
state.

Recorded write sources include:

- Claude Code `Write`, `Edit`, `MultiEdit`, and `NotebookEdit`
- Codex `apply_patch`
- Bash file writes and redirects when nah can identify the target
- Local git write state, such as commits or index mutations

For runtimes with post-tool hooks, nah records a pending write before execution
and finalizes it only after successful `PostToolUse`. If a target cannot be
identified, nah records incomplete repo-scoped state and fails safe at later
context review.

Write stamps are evidence only:

| Stamp | Meaning |
| --- | --- |
| `indexed` | A write candidate was recorded. |
| `clean_local` | The finalized write had no local deterministic flags. |
| `flagged` | Local deterministic metadata found a risky path/content signal. |
| `incomplete` | nah could not identify or reconstruct the changed target. |

`clean_local` does not mean the file is safe forever. Cross-file chains are
reviewed when a later activation or boundary action happens.

## Activation and Boundary

Session provenance uses the same category definitions as taint tracking:

- `activation`: action types that execute code or agent/tool behavior inside
  the current controlled environment.
- `boundary`: action types where data, code, or effects leave the current
  controlled environment.

Built-in activation action types:

- `lang_exec`
- `package_run`
- `agent_exec_read`
- `agent_exec_write`
- `agent_exec_bypass`

Built-in boundary action types:

- `network_outbound`
- `network_write`
- `network_diagnostic`
- `git_remote_write`
- `git_history_rewrite`
- `db_read`
- `db_write`
- `service_read`
- `service_write`
- `service_destructive`
- `container_read`
- `container_write`
- `container_exec`
- `container_destructive`
- `browser_interact`
- `browser_state`
- `browser_navigate`
- `browser_exec`
- `browser_file`
- `agent_exec_remote`
- `agent_server`

Boundary wins when an action could be read as both execution and boundary
crossing. For example, `container_exec`, `browser_exec`, `agent_exec_remote`,
and `agent_server` are boundary by default.

Tune category membership with action types, not raw command names:

```yaml
provenance:
  mode: enforce
  categories:
    activation:
      add: [mytool_run]
      remove: []
    boundary:
      add: [mytool_upload]
      remove: [container_exec]
```

For custom commands, first map the command to an action type with
`nah classify` or `classify:` config, then add that action type to a category
if needed.

## Policies

Policy keys are either category names or existing action types:

```yaml
provenance:
  mode: enforce
  policies:
    activation: context
    boundary: ask
    lang_exec: context
    package_run: context
    git_remote_write: context
    git_history_rewrite: block
    network_write: block
    service_write: block
    db_write: block
```

Valid provenance policies are:

| Policy | Meaning |
| --- | --- |
| `allow` | Provenance adds no extra friction beyond normal nah policy. |
| `context` | Build a session-delta packet and ask the configured LLM reviewer. |
| `ask` | Pause for human review. |
| `block` | Deny. |

`audit` is a mode, not a per-action provenance policy.

Specific action-type policies win over category policies. If no provenance
policy applies, the normal nah decision stands.

## Context Review

`context` does not mean automatic allow. It means nah needs extra evidence.

When a `context` provenance policy applies, nah builds a bounded packet with:

- the exact activation or boundary action;
- directly targeted session-written files;
- relevant manifests/scripts such as `package.json`, `Makefile`, `justfile`,
  `pyproject.toml`, or lockfiles when present in the session delta;
- session-written source files, prioritized by relevance and recency;
- omitted-file metadata when limits are reached.

Default limits:

```yaml
provenance:
  review:
    max_files: 50
    max_bytes_per_file: 16384
    max_bytes_total: 131072
```

Only a complete, well-formed LLM `allow` can allow a `context` decision. An
uncertain answer, provider error, timeout, missing provider, malformed output,
redaction failure, or incomplete packet becomes `ask`.

Each provenance LLM review logs a `provenance.review.prompt_hash` value so the
review input can be correlated later without storing code content. To also log
the exact prompt sent to the audit LLM, enable global prompt logging:

```yaml
log:
  llm_prompt: true
```

With that setting, the exact prompt appears under `provenance.review.prompt` in
the nah log. Keep this off unless you explicitly want audit logs to contain the
session-written file contents sent for review.

In `nah run codex exec`, provenance `context` review runs during authoritative
headless `PreToolUse`. That means a headless run can write a file, attempt to
execute it, and continue only if the session-delta reviewer returns `allow`.
If the reviewer is unavailable or uncertain, the unresolved ask is converted by
`targets.codex.ask_fallback`; the default is `block`.

For unattended agents, combine this with target ask fallback:

```yaml
targets:
  codex:
    ask_fallback: block
  claude:
    ask_fallback: block
```

That gives the runtime a productive path for clear allows while preventing it
from getting stuck on a prompt it cannot answer.

## Project Config Trust

Global config and selected global presets can set the full provenance shape.
Project `.nah.yaml` files are restricted until the project root is trusted:

- `provenance.mode`, review limits, and category removals are global/trusted
  only.
- Untrusted project config can tighten policies using
  `allow < context < ask < block`.
- Untrusted project config can add stricter category membership, but cannot
  remove built-in boundary coverage such as `container_exec`.

This keeps a malicious repo from disabling the provenance guard that would
review its own generated code.
