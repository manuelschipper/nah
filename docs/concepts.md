# Core concepts

## Effects and coverage

nah does not decide from a command name alone. It lowers a visible tool call
into typed invocation, filesystem, Git, network, and system-state effects.
Observation resolves requested working directories, project roots, paths, and
environment values before guards evaluate them.

Coverage is `full` when nah preserves every visible input needed by guards.
It does not mean nah understands an opaque program. Unknown semantics may be
fully represented;
unresolved arguments, code, or native fields remain `partial`.

For Bash, nah parses visible pipelines, branches, loops, subshells, and
redirects, then unions their possible effects into stages and data-flow edges.
Unresolved shell state or expansion makes the stream partial.

Visible inline source in Python, JavaScript, Ruby, Perl, PHP, Lua, R, Julia,
Swift, PowerShell, or cmd stays a `code-execution` effect. Python first lowers
through a maintained grammar into an owned HIR, then evaluates a bounded
subset without running the code. Unknown values and unsupported constructs
stay local to the state they can affect. Other languages currently use bounded
signature passes. Proven child shell source or argv re-enters the Bash planner
and publishes its effects to all guards.
Child stdout connects only for APIs that inherit it; cwd and environment stay
unknown unless proven. Unsupported or ambiguous code adds no finding;
malformed or bounded-out code adds a refusal. The interpreter remains visible.

## Verdicts and failures

- `block` — an active guard or structural self-protection found definite danger.
- `delegate` — nothing blocked; the runtime keeps control.

Evaluation failure is diagnostic, not a third verdict. By default it contributes
no finding and delegates if policy cannot reduce. An installed `--fail-closed`
hook blocks explicit failures/refusals, not ordinary uncertainty; no valid
decision uses runtime-native denial. See `nah docs security`.

nah never approves a call. Delegation returns control to the runtime's normal
permission or execution behavior. nah is a guard layer, not an approval UI or
sandbox.

## Guards

A guard blocks a narrow dangerous behavior such as remote content flowing into
execution, a destructive Git operation, or access to a sensitive path. Guards
compose by union: any one of them can block a call, and none of them can
approve one.

An activated custom guard is a one-shot executable that answers `block` or
`abstain`. Abstain means no finding, not approval. Failure or an invalid response
contributes a typed failure but no finding.

Coverage does not gate guards: definite evidence may block even when the stream
is partial; uncertainty alone never blocks.

Run `nah docs guards` for the installed catalog and three tested,
non-exhaustive examples per built-in guard.

## Trust and activation

User custom guards require activation. Project custom guards require both
project trust and separate activation; nah does not read their manifests before
trust. Activation pins the manifest, executable, and declared data. Changed or
missing activated bytes do not run and add an evaluation failure.

Before trust, `.nah/project.toml` may enable additional built-in guards but
cannot disable guards or execute repository code. Agents may edit inert guard
proposals; a human performs trust and activation out of band. nah blocks
understood intercepted attempts to cross that boundary or disable active
runtime wiring.

`nah nap` gives the operator a fixed 10-minute, user-global maintenance window:
plain nap pauses self-protection while guards continue; `--all` pauses every
non-permanent layer. Permanent nap-state protection remains. See `nah docs
configuration` and `nah docs security`.

## Audit records

Completed live non-dry-run decisions attempt a redacted audit append; recording
failure never changes the verdict. Stored records name the deciding runtime
(`unknown` for plain `nah decide`). `nah why <id>` explains one, `nah log` lists
recent decisions, and `nah log --blocked` lists blocks independently of
intervening delegates. `nah log --json` emits JSON Lines. Human log and TUI
views summarize retained evaluation failures without changing JSON output.
