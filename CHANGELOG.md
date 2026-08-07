# Changelog

## Unreleased

- **Prime Agent adapter** — `nah hook prime-agent install` wires the global
  tool-call extension and routes exact `ipython` cells through persistent-state
  Python effect analysis. Proven absolute effects reach normal guards, while
  prior kernel state, relative kernel paths, and pre-rewrite shell syntax stay
  explicitly partial instead of being guessed.
- **Exact code launcher intake** — Node, Deno, Bun, tsx, and IPython now
  classify only verified inline, stdin, and file forms. Syntax-check modes,
  invisible package scripts, remote modules, and unknown flags stay opaque;
  exact Deno `--ext` values select the matching JavaScript, TypeScript, or TSX
  frontend.
- **Python effect frontend** — inline Python now uses a maintained grammar,
  owned HIR, and bounded interpreter for constants, f-strings, aliases,
  branches, finite loops, simple functions, decoded values, and exact child
  execution. Unsupported behavior stays local, while malformed required suites
  use the existing structural-mismatch refusal. Raised or non-returning local
  calls and terminated branch state no longer leak effects into unreachable
  code, while binders, deletion, and shared module or environment mutations no
  longer retain stale library ownership or home paths.
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
  TypeScript, and TSX now lower into owned HIR and a bounded interpreter for
  constants, scopes, helpers, branches, loops, exact eval, and reviewed Node
  filesystem and child-process calls. Proven calls publish ordinary
  ActionStream effects; unowned Deno, Bun, and direct-tool profiles do not
  inherit Node APIs, while rebinding and unsupported behavior stay explicit
  instead of fabricating effects.
- **Lexical JavaScript helpers** — inline helper functions now resolve captured
  bindings instead of caller-local shadows, preventing both fabricated and
  missed effects when a call occurs inside a nested block.
- **JavaScript accessor barriers** — accessed object-literal getters and
  descriptor mutations now make coverage partial instead of silently treating
  potentially effectful property access as inert.
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
