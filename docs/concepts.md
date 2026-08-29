# Core concepts

## Effects and coverage

nah lowers visible tool calls into typed invocation, filesystem, Git, network,
and system-state effects. Observation resolves cwd, roots, paths, and environment.

Coverage is `full` when every guard-relevant visible input is preserved; it does
not mean nah understands an opaque program. Unresolved arguments, code, or
fields are `partial`.

For Bash, nah parses pipelines, control flow, subshells, and redirects into
stages and data-flow edges. Unresolved shell state makes the stream partial.

Visible source stays a `code-execution` effect. Python and JavaScript/TypeScript
grammars lower to owned HIRs; bounded interpreters follow runtime semantics
without execution. PowerShell and cmd have separate static tokenizers. IPython
handles magics. TypeScript and TSX ignore reviewed type-only syntax for
JavaScript runtime semantics; nah does not type-check or run the full
TypeScript compiler. Other languages use narrow detectors.

Profiles own only proven Node, Deno, Bun, OpenClaw QuickJS, or Prime current-cell
APIs. Rebinding or visible mutation removes ownership; hidden state is unknown.
Generic JavaScript owns none.

Exact child argv and cwd are nested; missing or non-directory cwd prevents the
child. Unawaited JavaScript applies state only through its first `await`.
`Deno.Command` reads options and cwd when consumed.

Only proven Bash has full lowering. `sh` is a portable subset;
dialect-sensitive state and redirects stay partial. `powershell`, `pwsh`, and
`cmd` share reviewed typed effects. Other syntax, custom shells, Bun's `$`,
and `bun exec` stay partial; sinks vanish only after a proven throw.

From each interpreted source, at most 64 modeled language calls enter the public
ActionStream for custom guards, dry-run JSON, and records. Saturation makes
coverage partial. Built-ins continue on a per-source language-safety projection
capped at 256 calls and 4,096 flows, so later modeled danger can still block.
Fail-closed records these bounds as `language-call-limit` or
`language-safety-limit` analysis refusals.

## Verdicts and failures

- `block` — an active guard or structural self-protection found definite danger.
- `delegate` — nothing blocked; the runtime keeps control.

Evaluation failure is diagnostic, not a third verdict. By default it adds no
finding. `--fail-closed` blocks explicit failures/refusals, not ordinary
uncertainty. See `nah docs security`.

nah never approves. Delegation returns control to the runtime's permission or
execution behavior; nah is neither an approval UI nor a sandbox.

## Guards

A guard blocks a narrow danger such as remote content flowing into execution,
destructive Git, or sensitive-path access. Guards compose by union: any may
block, and none may approve.

An activated custom guard answers `block` or `abstain`. Abstain is no finding,
not approval. Failure or invalid output adds a typed failure only.

Definite evidence may block a partial stream; uncertainty alone never blocks.

Run `nah docs guards` for the catalog and tested examples.

## Trust and activation

User guards require activation. Project guards require trust plus activation;
nah does not read manifests before trust. Activation pins the manifest,
executable, and data. Changed or missing bytes do not run and add a failure.

Before trust, `.nah/project.toml` may enable built-ins but cannot disable guards
or execute code. Agents may edit inert proposals; a human performs trust and
activation out of band. nah blocks understood intercepted attempts to cross
that boundary or disable active wiring.

`nah nap` starts a 10-minute, user-global maintenance window: plain nap pauses
self-protection; `--all` pauses every non-permanent layer. Nap-state protection
remains. See `nah docs configuration` and `nah docs security`.

## Audit records

Live decisions attempt a redacted audit append; failure does not change the
verdict. Records name the runtime (`unknown` for `nah decide`). `nah why <id>`
explains one; `nah log` lists recent decisions, `--blocked` lists blocks, and
`--json` emits JSON Lines.
