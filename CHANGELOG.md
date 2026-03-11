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

### Fixed

- Unknown/unhandled tools now default to ask instead of silent allow — added `write_to_file → Write` TOOL_MAP entry for Cursor (FD-037)
- Unknown tool policy (`actions.unknown`) in user config is now respected — previously hardcoded to `ask` regardless of config (FD-045)
- `nah config show` no longer crashes — updated to use renamed `classify_global`/`classify_project` fields and display `profile`, `llm_max_decision`, `ask_fallback` (FD-044)
- Sensitive path config overrides now applied — `build_merged_sensitive_paths()` wired into path checking via lazy `_ensure_sensitive_paths_merged()`, existing entries can be overridden (FD-025)
- Ask decisions no longer shown as "hook error" — `detect_agent()` misidentified Claude Code as Kiro via `hook_event_name` payload field, triggering `sys.exit(2)` (FD-029)

- Allow decisions no longer bypass Claude Code's permission system — silent passthrough (empty stdout) lets acceptEdits and other permission modes work correctly (FD-028)

### Removed

- Claude Code deny list (`permissions.deny` in settings.json) — all 82 patterns superseded by nah's taxonomy-based classification (FD-013)

### Changed

- LLM config key renamed from `backends:` to `providers:` — old key accepted as deprecated alias for one version cycle. Log fields `llm_backend` → `llm_provider`, cascade entries `backend` → `provider` (FD-036)
- Error default changed from `allow` to `ask` — crashes no longer silently bypass security (FD-014)
- Hook output uses Claude Code `hookSpecificOutput` protocol with required `hookEventName` field (FD-014)
- Extracted shared helpers: `check_path_basic()`, `_check_write_content()`, `_extract_positional_host()`, `_apply_policy()`, `_unwrap_shell()`, `_merge_dict_tighten()`, `_merge_list_union()` (FD-014)
