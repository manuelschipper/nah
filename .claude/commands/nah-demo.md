# nah demo

Run a concise Claude Code demo of nah's safety decisions.

The demo is intentionally small: 25 curated cases from
`src/nah/data/nah_demo.json`. It is a product demo, not the regression suite.
The regression suite is pytest.

## Execution Rules

Execute one case at a time. Do not batch cases into shell scripts, loops, or
helper programs. The narration between cases is part of the demo.

Never put comments inside Bash tool calls. Put all narration in your assistant
text, then run the command or dry-run classification as a separate tool call.

## Pacing

Default: run straight through.

If `$ARGUMENTS` is exactly `pause`, pause after each case and wait for the user
to say `next` or `continue`.

Ignore old mode arguments such as `full` or `story:...`. This demo always runs
the same 25 curated cases.

## Introduction

Start with a short introduction in your own words:

> nah classifies Claude Code tool calls before they run. Safe everyday work can
> proceed, ambiguous actions ask for confirmation, and clearly dangerous actions
> are blocked. This demo walks through 25 curated examples across safe work,
> destructive operations, remote execution, sensitive paths, credentials, and
> network context.

Then run `nah config show`. If the user has custom nah config, explain briefly
that live cases use their active config, while dry-run cases use packaged
defaults through `nah test --defaults`.

## Setup

1. Read `src/nah/data/nah_demo.json`.
2. Confirm it contains 25 cases.
3. Group cases by `story` in this order:

| Story key | Header |
| --- | --- |
| `safe_operations` | Safe Operations |
| `remote_code_execution` | Remote Code Execution |
| `data_exfiltration` | Data Exfiltration |
| `obfuscated_execution` | Obfuscated Execution |
| `path_boundary_protection` | Path and Boundary Protection |
| `destructive_operations` | Destructive Operations |
| `credential_secret_detection` | Credential and Secret Detection |
| `network_context` | Network Context |

Print:

```text
## nah demo - 25 curated cases
```

## Case Format

For each case, print:

```text
### [N/25] `input summary`

Threat: narration from JSON
```

Derive `input summary` from the case input, for example `input.command`,
`input.file_path`, `input.pattern`, or `input.tool_name`.

Then execute the case using the mechanics below.

After the tool call, print:

```text
Result: decision [checkmark or mismatch]
Why: description from JSON

---
```

If the actual decision differs from `expected`, print:

```text
Result: actual mismatch (expected: expected)
```

Track totals by decision and by story.

## Execution Mechanics

### Live cases

Live cases use the real Claude Code tool. The demo data should only mark stable,
safe allow cases as live.

- `Bash`: run `input.command`.
- `Read`: read `input.file_path`.
- `Glob`: search with `input.pattern` and optional `input.path`.
- `Grep`: search with `input.pattern` and optional `input.path`.
- `Write` and `Edit`: do not run live unless the JSON explicitly marks a case
  live and the content/path are clearly safe.

Decision mapping:

- Tool succeeds normally: `allow`
- Tool is denied with a reason beginning `nah.`: `block`
- Tool asks with a reason beginning `nah?`: `ask`

If a live allow command exits non-zero for an environmental reason, still treat
the nah decision as `allow` when the tool was permitted to run. Mention the
command failure separately.

### Dry-run cases

Dry-run cases must not call the original tool. Use `nah test --defaults` and
parse the `Decision:` line. Map `ALLOW` to `allow`, `ASK` to `ask`, and `BLOCK`
to `block`.

Use the case's `tool` and `input` fields to build the dry-run command:

- Bash: `nah test --defaults "..."`
- Read: `nah test --defaults --tool Read <path>`
- Glob: `nah test --defaults --tool Glob --path <path> --pattern <pattern>`
- Grep: `nah test --defaults --tool Grep --path <path> --pattern <pattern>`
- Write: `nah test --defaults --tool Write --path <path> --content <content>`
- Edit: `nah test --defaults --tool Edit --path <path> --content <content>`
- MCP: `nah test --defaults --tool <tool_name>`

Quote arguments safely. Do not write temporary config files.

## Summary

After all cases, print:

```text
## Demo Complete

| Story | Cases | Passed |
| --- | ---: | ---: |
| Safe Operations | N | N |
| Remote Code Execution | N | N |
| Data Exfiltration | N | N |
| Obfuscated Execution | N | N |
| Path and Boundary Protection | N | N |
| Destructive Operations | N | N |
| Credential and Secret Detection | N | N |
| Network Context | N | N |

Passed: N/25
Allow: N | Ask: N | Block: N
```

If there were mismatches, list each mismatch by case ID, expected decision,
actual decision, and the relevant tool output.
