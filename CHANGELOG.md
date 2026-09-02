# Changelog

## Unreleased

- **Guard rename compatibility** — `fs-storage-destroy` is now
  `fs-volume-destroy`, and `git-remote-delete` is now `git-remote-repo-delete`;
  saved choices and guard commands still accept the old names as hidden
  compatibility aliases, while unknown saved names warn without resetting
  unrelated overrides.
- **Windows support** — Releases now ship a tested, checksummed Windows x86-64
  archive and PowerShell installer. Claude Code, Codex, Cursor, GitHub Copilot,
  Cline, and Kiro support native Windows hooks, backed by typed PowerShell and
  cmd analysis plus Windows-safe custom guards and host state.
- **Infrastructure destruction guards** — New guards cover Kubernetes deletion
  (`infra-k8s-delete`, optional), whole-stack Terraform, OpenTofu, and Pulumi
  teardown (`infra-iac-destroy`, optional), broad Docker and Podman pruning
  (`infra-container-prune`, optional), and Podman runtime reset
  (`infra-container-reset`, enabled by default).
- **Storage destruction guards** — `storage-backup-destroy` blocks broad backup
  repository destruction by default. Optional guards cover recursive cloud
  storage deletion and snapshot deletion, while `fs-volume-destroy` now also
  covers live ZFS datasets.
- **Package registry guards** — `registry-unpublish` blocks package unpublishing
  and published-name ownership changes by default; optional `registry-publish`
  covers publication across npm-compatible registries, Cargo, RubyGems, Python,
  and NuGet.
- **Remote repository deletion guard** — Default-on `git-remote-delete` blocks
  exact whole-repository deletion through GitHub and GitLab CLI commands and
  REST routes while leaving branches, tags, archives, renames, and transfers
  outside its scope.
- **Host and project guards** — New default-on guards protect project roots,
  authentication and identity files, and startup-persistence paths. Optional
  guards cover shell profiles and persistent startup-management commands.
- **Resilient decisions and logs** — Runtime wiring failures no longer suppress
  independent guard decisions, and `nah log` plus the TUI recover readable
  history from a damaged audit log instead of leaving browsing unavailable.
- **Mixed built-in defaults** — Guard state now preserves each guard's factory
  default and explicit global overrides, with operator disables taking
  precedence over project enablement.
- **Focused guard browsing** — The TUI now cycles directly between Type,
  applied State, and current Project views; `nah guards` reports only applied
  state instead of mixing in factory labels.
- **Simpler shipped guard attribution** — `nah/decide/v1` and `nah/audit/v1`
  now identify shipped guards with only their kind and guard name.

## nah 1.3.1 — Aug 13, 2026

- **Portable installer checksums** — The installer now verifies one-shot
  SHA-256 output directly, so non-GNU `sha256sum` implementations do not need
  GNU check mode, and reports when no supported checksum tool is installed.
- **Node overload effects** — JavaScript filesystem and child-process calls now
  retain protected paths and nested commands across reviewed Node overloads,
  ignored surplus arguments, uncertain spreads, option accessors, and runtime
  coercions. Recognized invalid overloads stop unreachable following effects.

## nah 1.3.0 — Aug 11, 2026

- **Clear `secrets-env` explanation** — block messages now say that the guard
  blocks reading environment credential files, matching its read-only policy.
- **Reliable audit writes during child startup** — audit writes now unlock
  explicitly, preventing a concurrently started child from briefly retaining
  a completed write's lock.
- **Portable Kiro hook updates** — reinstalling or changing Kiro's failure
  policy now works on Linux filesystems without rename-exchange support.
- **Bounded language safety projection** — Each Python and JavaScript
  interpretation keeps public output at 64 calls while shipped guards inspect
  up to 256 calls and 4,096 data-flow edges. A later dangerous call can block
  without expanding audit or extension payloads; public-output and
  language-safety saturation now produce distinct typed refusals for
  fail-closed runtimes.
- **Policy contract v2** — shipped policy now considers the bounded internal
  language safety projection, so an exact dangerous effect after the public
  output limit can change a delegate verdict to block.
- **Audit symlink protection** — audit reads and writes now verify opened Unix
  files and parent directories against their paths, protecting symlink targets
  even on kernels that do not enforce `O_NOFOLLOW` for directories.
- **Working README menu** — the install, extend, and runtime shortcuts now
  target their current sections instead of obsolete heading anchors.
- **Contextual TUI help** — `?` opens help for the active screen with its
  security concepts and key map, including project trust, runtime
  failure modes, guard review, and decision verdicts.
- **Runtime failure modes in the TUI** — CLI and TUI status call the default
  mode fail-open, and the runtime screen can switch the selected integration
  between fail-open and fail-closed without repeating generic mode guidance.
- **Current homepage star count** — nahguard.ai now hides the GitHub star count
  until GitHub returns a live value instead of baking a stale cached number.
- **Concise README overview** — the README now lists Prime Agent among
  supported runtime hook targets without carrying detailed Bash model
  boundaries in the product overview.
- **Guard names match their scope** — `fs-system-tree` replaces `fs-root`,
  and `secrets-exfil` replaces `exfil-pipe`, so configuration and block
  attribution name the protected system trees and sensitive network flow.
- **Network-shell documentation** — `exec-network-shell` now documents shell
  redirection alongside netcat and socat attachments.
- **Nested child working directories** — exact `os.chdir`, `process.chdir`, and
  Python, Node, Deno, or Bun child-process `cwd` values now carry into nested
  command effects. Explicit child directories are observed and canonicalized;
  a missing or non-directory cwd produces no child effect.
- **JavaScript execution timing** — unawaited async helpers now preserve their
  synchronous pre-`await` state without applying deferred cwd changes early.
  `Deno.Command` reads mutable options and relative cwd at consumption time.
- **Portable `sh` lowering** — default Unix `sh` executions lower a reviewed
  POSIX subset. Bash-only state, implementation-sensitive `echo`, and divergent
  redirects remain partial instead of publishing Bash-specific effects.
- **Prime Agent IPython operations** — explicit `%%bash` and `%%sh` cells,
  timing and output-capturing wrappers, and exact current-cell `!` and `!!`
  interpolation now retain their visible shell effects without trusting the
  persistent kernel's mutable `get_ipython` binding or exposing output captured
  by IPython. Bare escapes use the observed normal shell; unsupported or
  visibly mutated shell selection remains partial.
- **Deterministic `printf` shell output** — Bash-correct bounded hex, octal,
  and ASCII-only Unicode escapes now feed exact ASCII bytes through existing
  shell-content guards; unsupported, non-ASCII, and non-executed output remains
  delegated.
- **Proven root-entry relocation** — `fs-system-tree` now blocks the exact active
  `mv /*` forms when their observed destination is a non-root directory,
  including trusted executable identities, while named, home, project,
  quoted-pattern, and non-directory moves remain delegated.
- **Environment and credential-search exfiltration sources** — `secrets-exfil`
  now blocks reviewed Bash environment dumps and scoped credential-indicator
  searches when their output reaches an outbound transfer, including a strict
  one-recipient mail form.
- **Prime Agent adapter** — `nah hook prime-agent install` wires a direct global
  tool-call extension and routes exact built-in `ipython` cells through
  persistent-state Python analysis. Reviewed imports and builtins used in the
  current cell now publish effects, while inherited names,
  relative kernel paths, and pre-rewrite shell syntax stay explicitly partial;
  additional tool fields cannot hide the visible code string. Custom, SDK, and
  future tools share an opaque identity so native-looking names cannot
  impersonate unrelated tool schemas.
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
