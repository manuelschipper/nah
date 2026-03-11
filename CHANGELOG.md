# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
- Dead Cursor/Kiro multi-agent code removed — ~200 lines across agents.py, cli.py, hook.py, config.py and tests; only Claude and Cortex remain as active agents (FD-040)

### Changed

- Unified decision dict key from mixed `reason`/`message` to single `"reason"` key, extracted DRY helpers (`_build_llm_meta`, `_resolve_cwd_context`, `_obfuscated_result`), converted `LLMResult` to `@dataclass`, added stderr trace to log error path (FD-026)

- LLM config key renamed from `backends:` to `providers:` — old key accepted as deprecated alias for one version cycle. Log fields `llm_backend` → `llm_provider`, cascade entries `backend` → `provider` (FD-036)
- Error default changed from `allow` to `ask` — crashes no longer silently bypass security (FD-014)
- Hook output uses Claude Code `hookSpecificOutput` protocol with required `hookEventName` field (FD-014)
- Extracted shared helpers: `check_path_basic()`, `_check_write_content()`, `_extract_positional_host()`, `_apply_policy()`, `_unwrap_shell()`, `_merge_dict_tighten()`, `_merge_list_union()` (FD-014)
