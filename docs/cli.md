# CLI guide

## Learn and inspect

| Command | Purpose |
| --- | --- |
| `nah --help` | See the bounded command overview |
| `nah <command> --help`, `nah help [command]` | See exact syntax for one command |
| `nah --version` | Print the installed CLI version |
| `nah docs [topic]` | List or read built-in documentation |
| `nah test [--json] <command>` | Evaluate without executing; `--tool` and `--source` take tool calls and code; JSON adds the engine plan |
| `nah guards` | List the guards with their live status |
| `nah docs guards` | Render built-in behavior and examples, plus the live guard catalog |
| `nah docs guards <guard\|guard/rule>` | Print one guard or rule in full |
| `nah log [--blocked] [--json] [-n count]` | List recent decisions or only recent blocks; JSON Lines use `nah/audit/v1` |
| `nah why <id>` | Explain one redacted decision |
| `nah snapshots [prune]`, `nah undo <id> [--into DIR]` | List the project's saved snapshots, prune them (operator only), or restore one; `--into` takes file snapshots only |
| `nah session [id]` | Print one session's memory ledger, or the latest without an id |

`nah why` is redaction-honest: it explains recorded effects and metadata, and
never reconstructs or reveals the raw command.

## Replay a session

`nah test --session FILE` replays a recorded session (`nah/session/v2`):
prompts, tool calls with the state before each, and results with output.
Each call is decided as its hook would, session memory included, and
each result settles its call. Nothing runs or reads the host's disk; a
save is only reported. It prints deterministic `nah/session-facts/v2`
JSON: each call's decision, rules, plan, annotations, session memory's
facts and ledger, where each name it uses was first seen (and links out
of a folder it archives), the lines its writes change, the deletes `rm`
asks about first (or would via a profile alias, never read live), what
the state left unanswered (never guessed), and which of it each verdict
rested on (see `nah test --help`).

## Configure

| Command | Purpose |
| --- | --- |
| `nah tui` | Configure guards and runtime integrations, and browse recent decisions interactively |
| `nah guard set <guard> off\|core\|strict`, `nah guard reset <guard>` | Set a built-in guard |
| `nah rule enable\|disable\|reset <guard/rule>` | Override a rule |
| `nah hook <runtime> install\|uninstall` | Change one supported runtime integration |
| `nah hook <runtime> status` | Report `not configured`, `wiring current`, or `reinstall required` |
| `nah nap` | Pause self-protection globally for 10 minutes; guards continue |
| `nah nap all` | Pause all non-permanent enforcement globally for 10 minutes |
| `nah nap <guard\|guard/rule>...` | Pause only those globally for 10 minutes; self-protection and the rest continue |
| `nah wake` | End the active nap immediately |

Use `nah hook --help` for runtime names and `nah docs runtimes` before
installation.

Nesting-limit refusals block by default. `--fail-closed` also blocks other
explicit failures/refusals; `--fail-open` restores the
default. Flagless reinstall preserves a recognized mode, and `status` reports it.
In the TUI, `f` changes runtime mode and `?` opens contextual help.

Starting or extending a nap requires a separate interactive operator terminal
and confirmation; intercepted agents cannot invoke it. Naps are user-global,
expire after 10 minutes, and do not roll back changes. Guard names are those
`nah guards` lists. Starting a nap replaces the active one and restarts the
timer. `nah wake` ends one sooner. Permanent nap-state protection remains active. See `nah docs security`
for the boundary.

## Machine entry point

Runtime adapters call `nah decide`. It reads one JSON object from standard
input through EOF:

```json
{"v":1,"tool":"Bash","input":{"command":"git status"},"cwd":"/repo"}
```

`cwd` must be the absolute call-site directory. Output contains the version,
verdict, reason, policy attributions, decision id, coverage, and duration. Its
schema is `nah/decide/v1`. Exit codes mirror the verdict: 1 block and 2
delegate. Integrations should use the JSON contract and exit code, not parse
human `nah test` output.

Observation or built-in evaluation failure produces `delegate`. Live audit
recording is best effort; when a record persists, `nah why` shows its redacted
failure metadata. `nah test --json` includes a `failures` array.

Exit code 3 means failure before a valid decision exists, such as invalid
outer tool-call JSON or a dispatcher failure. Shipped adapters return control
through their documented runtime fallback and use fixed, non-secret feedback
where supported.

Exit code 4 means an invalid CLI invocation for every command. `nah test` is a
human dry run: it exits 0 after printing any completed verdict, including a
block or delegate, and its JSON schema is `nah/test/v3`.
