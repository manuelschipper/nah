# Extending

A custom guard is a trusted, one-shot executable supported on macOS, Linux, and
Windows through the unsigned x86-64 release.
It can add a block and nothing else. Keep its data, documentation, and tests
together.

## Human boundary

A coding agent may inspect this topic, dry-run commands, scaffold a guard, and
edit the inert proposal. `nah test` never executes the tested command, but it
does execute matching active custom guards. Trust and activation are protected
changes: ordinarily the human runs `nah trust`, `nah untrust`, and `nah guard
enable|disable` outside the session. During a suitable operator-started nap the
agent may help, but any guard not paused by that mode still decides.

User guard loop:

```sh
nah guard new corp-api
# Agent edits the generated guard files under ~/.nah/guards/corp-api/.
nah guards
# Human reviews and enables the exact bytes:
nah guard enable corp-api
nah test --json "corp-api status"
```

`nah guard new` creates:

```text
~/.nah/guards/corp-api/
  policy.toml
  run
  README.md
```

On Windows it instead creates `run.cmd` and `run.py`; `run.cmd` invokes
`py -3` with the adjacent Python file. The generated template therefore
requires the Python Launcher with Python 3 installed.

Project guards live under `<project>/.nah/guards/<name>`. Create one with
`nah guard new corp-api --project /repo`; after `nah trust /repo`, enable it
with the same `--project /repo`. Untrusting the root revokes its activations.
Scope flags disambiguate the same name in multiple scopes.

Changing covered bytes makes an activation `needs-reapproval`; review and
enable it again. For `missing`, restore the bundle or disable its activation.
`nah guards` also reports `inactive` and `active`.

Malformed, reserved, or colliding proposals are skipped; `nah test` warns
without hiding healthy siblings.
Once an activation exists, a missing, changed, untrusted, or unreadable
activated bundle contributes an evaluation failure. The call delegates unless
another guard or self-protection blocks. `nah nap all` is the intentional
exception: it skips custom guards with the rest of non-permanent enforcement.

## Manifest

```toml
name = "corp-api"
match = ["corp-api", "curl"]
protocol = "exec/v2"
provenance = "agent"       # "user" or "agent"; informational only
data = ["rules.json"]      # optional
```

Unknown manifest fields are rejected. A bundle with another `protocol`, such as
an `exec/v1` guard from nah 1.5.0, is skipped with `unsupported-policy-protocol`
until its manifest and program are updated for `exec/v2`. A guard name is 1–64 ASCII bytes,
starts and ends with a lowercase letter or digit, and otherwise contains only
lowercase letters, digits, `-`, `_`, or `.`. Built-in guard names are reserved.
Each `match` entry is an exact lexical program token, not a glob, command line,
or regular expression. Entries must be unique and nonempty; control characters
and `*`, `?`, `[`, or `]` are rejected.
An explicit path selector matches only that path. A bare selector such as
`aws` also matches the same name in a standard executable directory such as
`/bin`, `/usr/bin`, `/usr/local/bin`, or macOS Homebrew's `/opt/homebrew/bin`
and its coreutils and findutils `libexec/gnubin`. Filesystem guards trust the
same list for `/`-spelled program paths.
It does not match `./aws`, `/tmp/aws`, or a project-local lookalike; name one of
those paths explicitly when intended.

Selection and `exec/v2` use the same public evidence. Public calls are the
tool call itself and, for shell input, the exact child commands it launches
with fully literal arguments and a bound working directory, such as `corp-api`
under `sudo corp-api`. A child with an unresolved expansion or directory, and
interpreter source, including `bash -c` and script launches, stay private to
built-in guards. Any public call with a known identity may select a guard. A
user guard is eligible everywhere. A project guard also requires the matching
call's known `cwd` to be its trusted root or a descendant. Re-check each call
rather than treating unrelated or out-of-root facts as in scope.

Use explicit parent and dataflow references; array adjacency does not
establish nesting or execution.

Every `data` path must be unique, relative, nonempty, and made only of normal
path components. `policy.toml`, `run`, `run.exe`, `run.cmd`, and `run.bat`
cannot be data entries. Manifest, entrypoints, and data entries must be regular
files, not symlinks.

macOS and Linux require an executable `run`. Windows requires exactly one of
`run.exe`, `run.cmd`, or `run.bat`; a missing or ambiguous Windows entrypoint
leaves the bundle inactive. A cross-platform bundle may contain `run` and one
Windows entrypoint. Every recognized entrypoint present in the bundle, plus
every declared data file, is covered by the activation hash on every platform.
The Windows template declares `run.py` as data so its interpreter source is
also covered.

## Exact exec/v2 request

For every selected uncached request, nah starts the selected entrypoint with the
guard directory as its working directory. The unsandboxed process inherits nah's
environment. nah writes one compact UTF-8 JSON object plus a newline to standard
input, closes it, and captures stdout and stderr. Inherited variables may
contain credentials.

Request for `corp-api delete --all`, with `resources`, `facts`, `occurrences`,
and `relations` omitted:

```json
{
  "v": 2,
  "evidence": {
    "coverage": "partial",
    "complete": true,
    "calls": [{
      "id": 0,
      "parent": null,
      "kind": "Shell",
      "identity": {"Known": "Bash"},
      "arguments": "Unknown",
      "cwd": {"Known": "/repo"},
      "payload_group": {"Known": 0},
      "visibility_ordinal": {"Known": 0},
      "coverage": "partial"
    }, {
      "id": 1,
      "parent": 0,
      "kind": "Argv",
      "identity": {"Known": "corp-api"},
      "arguments": {"Known": ["corp-api", "delete", "--all"]},
      "cwd": {"Known": "/repo"},
      "payload_group": {"Known": 0},
      "visibility_ordinal": {"Known": 1},
      "coverage": "partial"
    }],
    "conditions": [],
    "gaps": [{"id": 0, "call": 0, "phase": "Analysis", "category": "Unmodeled",
      "code": "unmodeled-command", "domain": null}]
  },
  "observation": {
    "cwd": {"status": "ok", "value": "/repo"},
    "roots": {
      "status": "ok",
      "value": [{"kind": "project", "path": "/repo"}]
    }
  }
}
```

`coverage` is `full` or `partial`; partial evidence cannot prove that an
unrepresented operation is absent. `complete: false` means the public projection
omitted evidence, for example private interpreter source. IDs are
request-local integers; resolve references by ID rather than array position.
The public subset closes call parents and fact, resource, occurrence, relation,
and condition references without exposing private calls.

Calls have a `kind` of `Shell`, `Argv`, `VisibleCode`, or `Native`. A known
identity can select a guard even when the call's arguments are unknown.
Knowledge fields use `{"Known": value}` or the string `"Unknown"`. Unknown is not an empty value or a negative finding.

`arguments`, when known, contains exact visible command arguments including
element zero, empty arguments, repeated flags, `--`, and `--key=value` spelling.
Compare the array directly rather than joining it into a string. Shell and
other source-bearing calls have unknown arguments. Raw tool input, shell
source, inline code, and process-resource argv are excluded. Native calls
expose modeled facts rather than their raw input objects.

Facts carry `call`, `realm`, `certainty`, `modality`, optional `condition` and
occurrence bounds, and a tagged `payload`. For example,
`{"EnvironmentAccess": {...}}` represents environment access,
`{"FilesystemSearch": {...}}` a search, and `{"FilesystemAccess": {...}}`
a filesystem operation. Filesystem operations include `Read`, `Write`, `Delete`,
and `Move`; their `target` and optional `destination` reference resources.
Their `purpose` is what the modeled command or the plan's data flow shows the
access does with the contents, not a policy judgment about disclosure.
Resource `labels`, when available, carry path scope, sensitivity, protection,
and host-integrity evidence. These are knowledge fields, so a missing label
must not be treated as a safe target.

Occurrences identify a call's semantic or concrete ports. Relations connect
occurrence IDs and describe the modeled flow, with their own certainty and
optional condition. Do not infer a flow merely because a source and sink both
appear. Conditions preserve boolean expressions and exclusive alternatives;
conditional evidence does not establish unconditional execution. Gaps identify
incomplete interpretation using stable phase, category, and code fields.

Visible arguments and modeled resource values can still contain secrets. nah
does not copy raw evidence into records, diagnostics, or feedback, but a guard's
`reason` is memoized and sent to the runtime. Never put secrets or raw input in
a reason.

Observed `cwd` and `roots` either have `{"status":"ok","value":...}` or
`{"status":"error","error":"..."}`. Error values are `invalid-path`,
`not-found`, `permission-denied`, `timeout`, `unavailable`, and `non-unicode`.
Root kinds are `project` and `worktree-main`. Consume the JSON structurally;
do not depend on object-key spacing or ordering. Inspect the exact request
without execution or audit recording with `nah test --json <command>`, or
`nah test --json --runtime <runtime> --tool <name> --args-json <json>` for a
tool call as that runtime's hook receives it (default runtime: `claude`).

## Exact responses

A guard blocks with exactly:

```json
{"block":true,"reason":"delete --all blocked; use the staged cleanup"}
```

Otherwise it declines to act:

```json
{"abstain":true}
```

Only `block`, `abstain`, and `reason` are accepted. Block with `block: true`
and a nonempty reason of at most 1024 UTF-8 bytes. Reasons may contain tab or
newline but no other control characters. Abstain with exactly `abstain: true`
and no reason; it contributes nothing. No response approves a call. Make
reasons actionable. Reserve prompt-injection warnings for unexpected secret,
exfiltration, or hidden-code requests.

Match a dangerous shape positively and abstain from everything else:

```python
import json
import sys

request = json.load(sys.stdin)
response = {"abstain": True}
for call in request["evidence"]["calls"]:
    identity = call["identity"]
    if not isinstance(identity, dict) or identity.get("Known") != "corp-api":
        continue
    arguments = call["arguments"]
    argv = arguments.get("Known") if isinstance(arguments, dict) else None
    if argv == ["corp-api", "delete", "--all"]:
        response = {
            "block": True,
            "reason": "corp-api delete --all requires review",
        }
        break
print(json.dumps(response))
```

Write one compact JSON object to stdout, optionally followed by one newline.
Leading whitespace, trailing whitespace other than that newline, carriage
returns, invalid UTF-8, multiple JSON values, and unknown fields are rejected.
Stdout is capped at 64 KiB. Stderr is capped at 8 KiB and is diagnostic only.
Execution has 750 ms on Unix and 1.5 s on Windows. Timeout or teardown kills its
Unix process group or Windows Job Object, including descendants. A nonzero exit
is a crash.
A successful exit with empty stdout is silence. A spawn, crash, silence,
timeout, transport rejection, or semantically invalid response produces a typed
failure and no finding. Other guards still run; any definite finding blocks,
otherwise the call delegates. Live non-dry-run dispatch attempts to persist the
failure redacted. A valid abstention contributes nothing.

`--fail-closed` converts that delegate to a structural block. Only validated
responses enter the memo cache, so failures execute again.

Selected custom guards execute sequentially, so their elapsed time accumulates
within the agent runtime's hook deadline. Runtime limits and behavior vary.

`nah test --json` puts process outcomes under `consultations`: `response`,
`silence`, `crash`, `timeout`, `spawn-failure`, or `rejected-transport`.
Transport rejection codes are `oversize`, `invalid-utf8`, `invalid-json`,
`multiple-values`, `invalid-framing`, and `invalid-response-fields`. Top-level
`failures` carries semantic codes including `ambiguous-response`,
`missing-outcome`, `block-must-be-true`, `abstain-must-be-true`,
`abstain-has-reason`, `missing-reason`, `reason-too-long`, and
`invalid-reason-control`.

## Purity and memoization

The response must be a pure function of the request and activated bundle: do
not use cross-call memory, clocks, or changing network reads. nah memoizes a
validated response under a digest covering the exact serialized exec/v2 request,
activation, and trusted project root. The activation includes the bundle hash.
Private source and omitted evidence do not affect this key; changes to visible
arguments, facts, working directories, or observations do. Raw evidence is not
stored in the key. Identical hot calls
can avoid a process spawn. No manifest option disables memoization.
