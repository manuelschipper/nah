# Core concepts

## Effects and coverage

nah does not decide from a command name alone. It lowers a visible tool call
into typed invocation, filesystem, Git, network, and system-state effects.
Observation resolves working directories, roots, paths, and environment before
guards evaluate.

Coverage is `full` when nah preserves every visible input needed by guards; it
does not mean nah understands an opaque program. Unresolved arguments, code, or
native fields remain `partial`.

For Bash, nah parses visible pipelines, control flow, subshells, and redirects,
then unions possible effects into stages and data-flow edges.
Unresolved shell state or expansion makes the stream partial.

Visible source remains a `code-execution` effect. Python and
JavaScript/TypeScript/TSX use maintained grammars, owned HIRs, and bounded
interpretation; IPython preprocesses magics. Nah recovers
constants and effects without running code. Unknowns widen only affected state.

Profiles own only proven Node, Deno, Bun, OpenClaw QuickJS, or Prime current-cell
APIs. Rebinding or visible mutation removes ownership; hidden state stays
unknown. Generic JavaScript owns none.

Exact child argv and cwd are nested. Observed aliases canonicalize; missing or
non-directory cwd prevents the child.
Unawaited JavaScript applies state only through its first `await`;
`Deno.Command` reads options and cwd when consumed.

Only proven Bash enters full Bash lowering. `sh` gets a reviewed portable
subset; dialect-sensitive state, `echo`, redirects, Windows or custom shells,
Bun's `$`, and `bun exec` stay partial. Accessors or custom coercion make
calls partial. Sinks vanish only when proven to throw first. Code
execution remains visible.

## Verdicts and failures

- `block` — an active guard or structural self-protection found definite danger.
- `delegate` — nothing blocked; the runtime keeps control.

Evaluation failure is diagnostic, not a third verdict. By default it contributes
no finding. `--fail-closed` blocks explicit failures/refusals, not ordinary
uncertainty. See `nah docs security`.

nah never approves a call. Delegation returns control to the runtime's normal
permission or execution behavior. nah is a guard layer, not an approval UI or
sandbox.

## Guards

A guard blocks a narrow dangerous behavior such as remote content flowing into
execution, a destructive Git operation, or access to a sensitive path. Guards
compose by union: any one of them can block a call, and none of them can
approve one.

An activated custom guard answers `block` or `abstain`. Abstain is no finding,
not approval. Failure or an invalid response adds a typed failure only.

Coverage does not gate guards: definite evidence may block even when the stream
is partial; uncertainty alone never blocks.

Run `nah docs guards` for the catalog and tested examples.

## Trust and activation

User guards require activation. Project guards require trust plus activation;
nah does not read manifests before trust. Activation pins the manifest,
executable, and data. Changed or missing bytes do not run and add an evaluation
failure.

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

Live decisions attempt a redacted audit append; failure never changes the
verdict. Records name the runtime (`unknown` for plain `nah decide`). `nah why
<id>` explains one, `nah log` lists recent decisions, and `nah log --blocked`
lists blocks independently of intervening delegates. `nah log --json` emits
JSON Lines. Human views summarize failures without changing JSON output.
