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
