# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- PreToolUse hook skeleton with 6 tool handlers (Bash, Read, Write, Edit, Glob, Grep), sensitive path protection, hook self-protection, install/uninstall CLI (FD-004)
- Bash command classification with action taxonomy, pipe composition rules, shell unwrapping, context resolution for filesystem and network actions (FD-005)
