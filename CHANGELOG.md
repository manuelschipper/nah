# Changelog

## Unreleased

- **Windows release and installer** — Releases now include a checksummed,
  pre-publication-tested x86-64 MSVC ZIP and an unsigned PowerShell installer
  that preserves expandable user PATH entries and replaces upgrades safely.
- **Qualified Windows runtime integrations** — Claude Code, Codex, Cursor,
  GitHub Copilot, Cline, and Kiro now support native hook lifecycle and typed
  tools on Windows while ambiguous shell payloads stay partial. Amp, Factory
  Droid, Hermes, and OpenCode now fail installation before writes and report
  not configured.
- **Windows custom guards** — exec/v1 guards now use one deterministic Windows
  entrypoint, generate a `py -3` template, and terminate full descendant trees
  after each consultation.
- **Windows host-state protection** — Windows path observations now normalize
  extended drive and UNC results, unsafe reparse paths fail closed, and
  `%USERPROFILE%\.nah` uses a private inheritable DACL. The release-installed
  `nah.exe` path is also self-protected, and nap keys inherited under that
  boundary remain usable.
- **Unreadable decision log recovery** — `nah log` and the TUI archive an
  unreadable `~/.nah/audit.jsonl` under `~/.nah/old_logs`, retain its latest
  readable records, and warn instead of leaving decision browsing unavailable.
- **Optional startup-management guard** — New default-off
  `fs-startup-management` blocks reviewed persistent `systemctl` on Linux,
  `launchctl` on macOS, and `crontab` mutations on either when enabled without
  changing startup-path defaults. Its documentation examples follow the host.
- **`crontab -u` payload inspection** — Visible stdin installed for another
  user now receives the same nested-command and self-protection analysis as
  `crontab -`.
- **PowerShell and cmd effects** — Top-level and nested Windows shell source now
  lowers reviewed static filesystem, network, redirection, and exact child argv
  through the existing typed effects. Dynamic and multi-target forms stay
  partial; escaped non-ASCII paths remain exact and `~` resolves to the declared
  home. Unknown `-WhatIf` values, lookalike variables, platform-specific aliases,
  path globs, and cmd directory semantics avoid resolved effects they cannot prove.
  Comment markers inside bare words stay literal, and `del /s` retains its recursive
  file scope. Quoted segments no longer make a following variable exact, unambiguous
  parameter prefixes such as `-Rec` bind like their full names, and `del` on an
  observed directory reports an unresolved deletion instead of dropping the effect.
  PowerShell redirects remain visible when `>` is attached to the preceding word.
  Line continuations stay partial without fabricated effects, and parameter prefixes
  must remain unambiguous against PowerShell's common parameters. `cmd` numeric output
  streams retain their static redirection writes. Executable-suffixed cmd names stay
  external, and PowerShell alias removal invalidates later alias resolution through
  every supported `Remove-Item` spelling and Alias-provider root path. `Set-Item`
  provider rebinding also invalidates later alias resolution. Surplus positional
  `Remove-Item` and `Move-Item` bindings stay partial. Conflicting `-Path` and
  `-LiteralPath` bindings stay partial without fabricated filesystem effects.
  `-WhatIf` provider mutations and selector values leave later alias resolution
  unchanged.
- **Remote repository deletion guard** — New default-on `git-remote-delete`
  blocks exact whole-repository deletion through GitHub and GitLab CLI commands
  and REST routes, including valid confirmation values, false-valued help flags,
  GitHub and GitLab API fragments, and documented GitLab composite placeholders,
  single-label GitHub Enterprise hosts, attached and separated GitHub API
  short-option forms, disabled GitHub API pagination, percent-encoded GitHub
  repository routes, and percent-encoded GitLab project paths, numeric IDs, and
  group placeholders, plus GitHub's
  `--allow-escape-sequences` output option and repeated or inherited boolean
  flags whose final value restores destructive execution and port-qualified
  GitHub Enterprise hosts. Parent-command help flags, GitHub field placeholders,
  GitLab user placeholders, and API preflight flags now follow the providers'
  effective behavior. GitHub's short `-h` remains a help request even when
  assigned false. Glab short-option clusters remain guarded, while
  conflicting API body modes delegate. GitHub include-prefixed short options
  remain guarded, while invalid Glab output formats delegate. Empty or superseded
  GitHub output filters now follow the provider's effective preflight behavior.
  Invalid API hostnames, malformed GitHub API field, header, cache, and template
  values, malformed Glab headers, and Glab fields that cannot be encoded as DELETE
  query values delegate before the guard, as do duplicate form stdin sources and
  pagination/input conflicts. Literal closing braces in valid GitHub templates,
  normalized standard-system executable paths, including root-clamped parent
  traversal, and trailing-dot or bracketed IPv6 GitHub Enterprise hosts, including
  zone identifiers with percent-encoded bytes, remain guarded. GitHub template rune
  literals, two-variable ranges, and the current `replace` helper remain guarded, as
  does Glab's static `-R`/`--repo` selection,
  including reviewed short-option clusters.
  Static GitHub API IDN hosts and digit-separated Go template numbers remain
  guarded, as do IPv4-mapped IPv6 and precomposed or canonically decomposed IDN
  GitHub repository hosts with numeric ports, including IDNs with combining marks
  across scripts,
  while invalid GitHub header names delegate before the guard. GitLab API IDN hosts
  and current GitHub template literals remain guarded, while duplicate GitHub API
  scalar fields and invalid GitLab headers delegate.
  Parent traversal after arbitrary absolute path prefixes also delegates instead of
  acquiring standard-system executable identity.
  Dynamic API option values, incompatible GitHub output options, branches, tags,
  archives, renames, and transfers remain outside its scope.
- **Project root filesystem guard** — New default-on `fs-project-root` blocks
  recursive deletion and known recursive permission changes selecting the exact
  project root or one of its three root-wide patterns.
- **Inbound `scp` and `rsync` destinations** — Remote downloads with an
  unresolved local destination no longer look like sensitive uploads.
- **Authentication and identity guard** — New default-on `fs-auth-identity`
  blocks visible writes and deletes of reviewed login authority, identity,
  privilege, PAM, sudoers, sshd, and Windows identity-database paths.
- **Optional shell-profile guard** — New default-off `fs-shell-profile` blocks
  mutations to reviewed user shell profiles when enabled without interrupting
  routine shell installers and dotfile tooling at factory posture.
- **Startup-persistence guard** — Default-on `fs-startup-persistence` blocks
  mutations to reviewed service, schedule, login, autostart, and loader startup
  paths while excluding routine user shell profiles.
- **Mixed built-in defaults** — Guard state now preserves per-guard factory
  defaults and explicit global overrides, with operator disables taking
  precedence over project enablement.
- **Focused guard browsing** — The TUI now cycles between Type, applied State,
  and current Project views without a filter modal, and `nah guards` omits
  factory labels from its live-state listing.
- **Simpler shipped guard attribution** — `nah/decide/v1` and `nah/audit/v1`
  shipped attributions now contain only the kind discriminator and guard name.
  Extension memo entries miss once and are replaced through normal cache use.

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
