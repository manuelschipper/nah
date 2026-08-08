# Changelog

## Unreleased

- **Environment and credential-search exfiltration sources** — `exfil-pipe`
  now blocks reviewed Bash environment dumps and scoped credential-indicator
  searches when their output reaches an outbound transfer, including a strict
  one-recipient mail form.
- **Prime Agent adapter** — `nah hook prime-agent install` wires a direct global
  tool-call extension and routes exact built-in `ipython` cells through
  persistent-state Python analysis. Prior bindings, imported modules, builtins,
  relative kernel paths, and pre-rewrite shell syntax stay explicitly partial
  instead of being guessed; additional tool fields cannot hide the visible code
  string. Custom, SDK, and future tools share an opaque identity so native-looking
  names cannot impersonate unrelated tool schemas.
- **Exact code launcher intake** — Node, Deno, Bun, tsx, and IPython now
  classify only verified inline, stdin, and file forms. Non-executing check
  modes, package scripts without explicit paths, remote modules, and unknown
  flags stay opaque. Exact Deno subcommands and `--ext` values select distinct
  eval/run and JavaScript, TypeScript, or TSX profiles; Bun shell forms stay
  partial rather than entering Bash lowering.
- **Python effect frontend** — inline Python now uses a maintained grammar,
  owned HIR, and bounded interpreter for constants, f-strings, aliases,
  branches, finite loops, simple functions, decoded values, and exact child
  execution. Unsupported behavior stays local, while malformed required suites
  use the existing structural-mismatch refusal. Raised or non-returning local
  calls and terminated branch state no longer leak effects into unreachable
  code, while binders, deletion, and shared module or environment mutations no
  longer retain stale library ownership or home paths. Recognized mutation or
  escape of `sys.modules` removes later import ownership, while reviewed
  read-only registry operations retain it. Definitely invalid integer and
  file-descriptor arguments stop before filesystem effects instead of blocking
  calls that Python rejects first. Typed exception handlers retain possible
  caught paths instead of terminating later analysis.
- **Canonical Python API effects** — proven Python filesystem, subprocess, and
  reviewed HTTP calls now publish ordinary ActionStream stages, path
  observations, sensitivity, and data-flow edges for built-in and custom
  guards. Unresolved values make coverage partial; unowned calls add no effect,
  possible working-directory changes no longer misresolve relative paths, and
  self-protection now follows the same owned calls instead of a separate source
  scanner. Rename, hardlink, and access-control effects retain protected path
  identity; unreachable, rebound, and unresolved `which()` targets do not
  block.
- **Canonical JavaScript and TypeScript effects** — inline JavaScript,
  TypeScript, and TSX now lower into owned HIR and bounded effect
  interpretation. Node owns reviewed filesystem and child-process APIs; Deno
  eval owns reviewed Deno filesystem and command APIs while checked eval and
  `deno run` remain unowned; Bun owns reviewed Bun APIs plus Node builtins; and
  OpenClaw QuickJS owns only provenance-tracked tool-bridge calls. Rebinding,
  unsupported behavior, and unresolved values remain partial or unowned instead
  of fabricating effects. Mutation, invocation, or escape of the reviewed Node
  loader hooks `Module._load`, `Module.createRequire`, and
  `Module.prototype.require` (including CommonJS aliases) removes later built-in
  ownership; cached export mutations do not restore it, while
  `Module.isBuiltin` and unrelated module properties retain it. Exact strict
  writes, deletes, property-descriptor failures, and uncaught augmented writes
  stop unreachable tails.
  JavaScript-family native evidence uses v2 so object and `undefined` values do
  not silently extend the frozen Python v1 domain.
- **Lexical JavaScript helpers** — inline helper functions now resolve captured
  bindings instead of caller-local shadows, preventing both fabricated and
  missed effects when a call occurs inside a nested block.
- **JavaScript accessor barriers** — recognized object-literal accessors and
  descriptor mutations make affected analysis partial instead of being treated
  as exact property values.
- **Node filesystem overloads** — JavaScript analysis now distinguishes valid
  modes, file descriptors, stream options, callback effects, accessor barriers,
  and result truthiness so reviewed calls cannot disappear or claim a path that
  Node ignores.
- **Node promise filesystem effects** — `node:fs/promises`, `fs/promises`, and
  `require('fs').promises` now share owned filesystem effects and rebinding
  invalidation with the callback and synchronous APIs.
- **Node child-process overloads** — JavaScript analysis now preserves valid
  options and callbacks, joins `shell` argv with Node semantics, analyzes local
  callback effects conditionally, and keeps invalid call shapes inert.
- **Nested shell dialect boundary** — only explicitly proven Bash payloads enter
  the Bash lowerer; default `sh`, Windows, custom-shell, and malformed payloads
  retain partial coverage without fabricated Bash effects.
- **Python subprocess context** — `cwd`, `env`, `executable`, and unresolved
  command inputs now suppress speculative nested execution and keep coverage
  partial instead of resolving a child under the parent process context.
- **Mobile theme toggle alignment** — the homepage theme control now shares
  the navigation links' text baseline on small screens.

## nah 1.2.0 — Aug 4, 2026

- **Generated web guard reference** — the homepage build now renders
  `/docs/guards/` directly from the compiled CLI catalog under shipped-default
  state, preventing a second hand-maintained guard list from drifting.
- **Destructive Git worktree guards** — two new default-on guards block forced
  project-root cleans, project-wide checkout/restore, and statically proven
  forced branch changes while named targets and ambiguous checkout forms still
  delegate.

## nah 1.1.0 — Aug 3, 2026

- **Opt-in fail-closed runtime hooks** — `nah hook <runtime> install
  --fail-closed` now blocks otherwise-delegated explicit evaluation failures
  and bounded analysis refusals, with fixed recovery guidance and native denial
  when no valid decision exists. Default installs remain delegate-on-failure;
  `--fail-open` downgrades and flagless reinstall preserves recognized mode.
- **Inline language disaster signatures** — built-in guards now recognize
  selected exact visible Python, JavaScript, Ruby, Perl, PHP, Lua, R, Julia,
  Swift, PowerShell, and cmd forms for supported filesystem and execution
  disasters. Exact child shell and argv calls reuse normal Bash effects and
  proven stdout flows; ambiguous child calls or unsupported code add nothing.
- **Stable inline extension input** — visible interpreter code remains an
  `code-execution` invocation with source `interpreter-inline` for custom
  guards, alongside any proven child effects; private built-in findings do not
  rewrite its source classification.

## nah 1.0.0 — Aug 1, 2026

First release. One static Rust binary that hooks into a coding agent,
blocks catastrophic tool calls before they run, and delegates everything
else to the runtime.

- **17 built-in guards, all on by default** — execution hijacks, secret
  theft, filesystem destruction, and Git disasters, decided
  deterministically in microseconds with no LLM.
- **Block or delegate, never approve** — any guard can block a call;
  nothing can widen the runtime's own permissions. Partial understanding
  can block, never allow.
- **14 runtime adapters** — one install command each for claude code,
  codex, cursor, cline, copilot, antigravity, kiro, amp, devin, droid,
  opencode, openclaw, hermes, and pi. Every adapter hooks the native path.
- **Custom guards in any language** — `nah guard new`, effects on stdin,
  block or abstain on stdout. Extensions can only make nah stricter, and
  project guards stay inert until a human trusts the repository.
- **Structural self-protection** — an agent cannot disable guards, trust
  a project, or unhook the runtime through a tool call. Operators get a
  supervised ten-minute window with `nah nap` / `nah wake`.
- **On the record** — every decision is stored redacted and explained by
  `nah why`; structure only, never command text.
- **Self-teaching CLI** — embedded `nah docs` topics shared verbatim by
  the binary, the repository, and nahguard.ai.
- **Policy version 1** — guards-only decision semantics: every decision
  is `block` or `delegate`; custom guards answer `block` or `abstain`.
