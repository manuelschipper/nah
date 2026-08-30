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
another guard or self-protection blocks. `nah nap --all` is the intentional
exception: it skips custom guards with the rest of non-permanent enforcement.

## Manifest

```toml
name = "corp-api"
match = ["corp-api", "curl"]
protocol = "exec/v1"
provenance = "agent"       # "user" or "agent"; informational only
data = ["rules.json"]      # optional
```

Unknown manifest fields are rejected. A guard name is 1–64 ASCII bytes,
starts and ends with a lowercase letter or digit, and otherwise contains only
lowercase letters, digits, `-`, `_`, or `.`. Built-in guard names are reserved.
Each `match` entry is an exact lexical program token, not a glob, command line,
or regular expression. Entries must be unique and nonempty; control characters
and `*`, `?`, `[`, or `]` are rejected.
An explicit path selector matches only that path. A bare selector such as
`aws` also matches the same name in a standard executable directory such as
`/bin`, `/usr/bin`, `/usr/local/bin`, or macOS Homebrew's `/opt/homebrew/bin`.
It does not match `./aws`, `/tmp/aws`, or a project-local lookalike; name one of
those paths explicitly when intended.

Selection and `exec/v1` use the public ActionStream: at most 64 modeled calls per
interpreted source. Saturation makes coverage partial; later calls are
language-safety only. Any visible known, opaque, or code-execution invocation
may select a guard. A user guard is eligible
everywhere. A project guard also requires the invocation's visible `cwd` to be
its trusted root or a descendant. Re-check each invocation rather than treating
unrelated or out-of-root effects as in scope.

Exact child commands found in visible interpreter code may appear as additional
stages beside the original `code-execution` invocation. They use the ordinary
effect schema; a flow to the parent exists only when the child API is proven to
inherit stdout. Do not infer nesting or execution from stage adjacency.

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

## Exact exec/v1 request

For every selected uncached request, nah starts the selected entrypoint with the
guard directory as its working directory. The unsandboxed process inherits nah's
environment. nah writes one compact UTF-8 JSON object plus a newline to standard
input, closes it, and captures stdout and stderr. Inherited variables may
contain credentials.

Representative request:

```json
{
  "v": 1,
  "action_stream": {
    "v": 1,
    "coverage": "full",
    "effects": [
      {
        "id": "e0",
        "stage": "s0",
        "kind": {
          "kind": "invocation",
          "invocation": {
            "kind": "known",
            "program": "curl",
            "operation": "network-transfer",
            "input": {
              "kind": "shell",
              "words": ["curl", "https://example.test"],
              "argv": ["curl", "https://example.test"]
            },
            "cwd": "/repo"
          }
        }
      },
      {
        "id": "e1",
        "stage": "s0",
        "kind": {
          "kind": "network",
          "direction": "outbound"
        }
      }
    ],
    "flows": []
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

`coverage` describes preserved visible input, not whether nah understands an
opaque program; see `nah docs concepts`. Effects are ordered and have stable
request-local ids `e0`, `e1`, and so on. Each stage has one invocation and its
associated effects. `flows` contains `{ "from_stage": "s0", "to_stage": "s1" }`
edges when data flows between stages.

An effect `kind` is one of:

- `invocation`, whose `invocation.kind` is `known` (`program`, `operation`),
  `opaque` (`program`), or `code-execution` (`program`, optional
  `interpreter`, `source`, and optional exact `code`);
- `filesystem` (`operation`, `target`, `scope`, `sensitivity`, optional
  `protection`, optional `host_integrity`, `selects_root`, `selects_home`,
  `recursive`, `pattern`);
- `filesystem-unresolved` (`operation`, `recursive`) when a visible operand
  cannot be bounded to one filesystem root; the invocation keeps its input;
- `git` (`operation`);
- `network` (`direction`, optional `host`);
- `system-state` (`operation`).

Filesystem operation values are `read`, `write`, or `delete`. Scope is tagged
by `kind`: `project` also has `root`; the other values are `home`, `system`,
and `outside-project`. Sensitivity is `none`, `environment-secret`,
`credential-secret`, or `other-sensitive`. Protection, when present, is
`critical`, `permanent`, or `proposal`. `host_integrity`, when present, is
`shell-profile`, `startup-persistence`, or `auth-identity`; it classifies a
reviewed requested or effective target independently of sensitivity. Built-in
policy uses it only for writes and deletes, so extensions should still inspect
`operation`. `pattern` is true when the shell expands the target: the effect
covers paths starting with the literal text before the first `*`, `?`, `[`,
`{`, `@(`, `+(`, or `!(`, and coverage is `partial`. The optional field retains
ActionStream v1.

Every invocation also has an `input`. Shell input is
`{"kind":"shell","words":[...],"argv":[...]}`. `words` preserves the visible
shell tokens; `argv`, when present, is the exact statically determined argument
array including element zero, empty arguments, repeated flags, `--`, and
`--key=value` spelling. If expansion, substitution, or globbing prevents nah
from proving the final arguments, `argv` is absent and coverage is partial.
Compare the array directly rather than joining it into a string.

`environment-disclosure` and `credential-search` are extension-visible `known`
operations. ActionStream stays v1.

Each invocation includes `cwd` when nah can bind the visible requested working
directory at that stage; it is absent when that directory is unresolved. When
an earlier `cd` may have failed, coverage is partial even though the requested
directory remains visible.

Native input is `{"kind":"native","value":{...},"complete":true}`.
Adapters preserve it for custom guards while normalizing documented tools for
built-in policy. Unknown native tools remain opaque. An unrecognized field
makes coverage partial but remains visible. Input and inline code can contain
secrets and are provided only to activated custom guards and `nah test --json`.
nah does not copy raw evidence into records, diagnostics, or feedback, but a
guard's `reason` is memoized and sent to the runtime. Never put secrets or raw
input in a reason.
Invocation evidence over 1 MiB is omitted and marked incomplete rather than
being sent to a guard.

Observed `cwd` and `roots` either have `{"status":"ok","value":...}` or
`{"status":"error","error":"..."}`. Error values are `invalid-path`,
`not-found`, `permission-denied`, `timeout`, `unavailable`, and `non-unicode`.
Root kinds are `project` and `worktree-main`. Consume the JSON structurally;
do not depend on object-key spacing or ordering. For Bash, inspect the exact
request without execution or audit recording with `nah test --json <command>`.
Native input shapes arrive through runtime adapters; `nah test` does not
synthesize them.

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
for effect in request["action_stream"]["effects"]:
    invocation = effect["kind"].get("invocation")
    if not invocation or invocation.get("program") != "corp-api":
        continue
    input = invocation["input"]
    if input.get("kind") == "shell" and input.get("argv") == [
        "corp-api", "delete", "--all"
    ]:
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
validated response under a digest covering the represented arguments, code,
native input, working directories, observations, guard context, and bundle
identity. Raw evidence is not stored in the key. Identical hot calls
can avoid a process spawn. No manifest option disables memoization.
