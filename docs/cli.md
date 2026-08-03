# CLI guide

## Learn and inspect

| Command | Purpose |
| --- | --- |
| `nah --help` | See the bounded command overview |
| `nah <command> --help` | See exact syntax for one command |
| `nah --version` | Print the installed CLI version |
| `nah docs [topic]` | List or read built-in documentation |
| `nah test [--json] <command>` | Evaluate without executing the command; JSON includes the exact `exec/v1` custom-guard request |
| `nah guards` | List built-in and custom guards with their live status |
| `nah docs guards` | Render built-in behavior and examples, plus the live guard catalog |
| `nah log [--blocked] [--json] [-n count]` | List recent decisions or only recent blocks; JSON Lines use `nah/audit/v1` |
| `nah why <id>` | Explain one redacted decision |

`nah why` is redaction-honest: it explains recorded effects and metadata, and
never reconstructs or reveals the raw command.

## Configure

| Command | Purpose |
| --- | --- |
| `nah tui` | Configure guards, trusted projects, and runtime integrations, and browse recent decisions interactively |
| `nah guard enable\|disable <name> [--user\|--project root]` | Change a built-in or exact custom guard |
| `nah trust [root]` | Trust a project root; defaults to the current directory |
| `nah untrust [root]` | Revoke a trusted root and its enabled project guards |
| `nah hook <runtime> install\|uninstall` | Change one supported runtime integration |
| `nah hook <runtime> status` | Report `not configured`, `wiring current`, or `reinstall required` |
| `nah nap` | Pause self-protection globally for 10 minutes; guards continue |
| `nah nap --all` | Pause all non-permanent enforcement globally for 10 minutes |
| `nah wake` | End either nap immediately |

Use `nah hook --help` for runtime names and `nah docs runtimes` before
installation.

`--fail-closed` blocks explicit failures/refusals; `--fail-open` restores the
default. Flagless reinstall preserves a recognized mode, and `status` reports it.

Starting or extending a nap requires a separate interactive operator terminal
and confirmation; intercepted agents cannot invoke it. Naps are user-global,
expire after 10 minutes, and do not roll back changes. `nah wake` ends one
sooner. Permanent nap-state protection remains active. See `nah docs security`
for the boundary.

## Extend

| Command | Purpose |
| --- | --- |
| `nah guard new <name> [--project root]` | Create a user or project guard template |

Custom guards are unsandboxed programs. Even though `nah test` does not run the
tested command, matching active custom guards still execute. See `nah docs
extending` for the manifest, activation states, and `exec/v1` contract.

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

Observation or built-in evaluation failure produces `delegate`. A failed custom
guard contributes no finding, so another guard can still block. Live audit
recording is best effort; when a record persists, `nah why` shows its redacted
failure metadata. `nah test --json` includes a `failures` array.

Exit code 3 is reserved for failure before a valid decision can be produced,
such as invalid outer tool-call JSON or an outer dispatcher failure. It has no
valid decision body. Shipped adapters return control through their documented
runtime fallback and use fixed, non-secret feedback where supported.

Exit code 4 means the CLI invocation itself was invalid. `nah test` is a human
dry run: it exits 0 after printing any completed verdict, including a block or
delegate, and its JSON schema is `nah/test/v1`.
