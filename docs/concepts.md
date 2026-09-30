# Core concepts

## Effects and coverage

nah lowers calls into typed invocation, filesystem, Git, network, and
system-state effects. Observation resolves cwd, roots, paths, and environment.

Coverage reports only what the analyzer established. `full` means every
reported domain was fully modeled with no boundary left open. Unmodeled
programs, unresolved arguments, code, or fields, and environment-run code such
as Git hooks or package scripts make it `partial`.

Bash pipelines, control flow, subshells, and redirects become stages and
data-flow edges. Unresolved shell state makes coverage partial.

The engine analyzes visible shell, PowerShell, cmd, and language source without
running it. Exact child commands in source become nested calls. Unmodeled
dialects or language APIs and engine limits leave coverage partial rather than
inventing effects.

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
self-protection; `nah nap all` pauses every non-permanent layer; `nah nap
<guard>...` pauses only the named guards. Nap-state protection remains. See `nah docs configuration` and `nah docs security`.

## Audit records

Live decisions attempt a redacted audit append; failure does not change the
verdict. Records name the runtime (`unknown` for `nah decide`). `nah why <id>`
explains one; `nah log` lists recent decisions, `--blocked` lists blocks, and
`--json` emits JSON Lines.
