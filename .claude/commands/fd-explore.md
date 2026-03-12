---
description: Explore any FD-enabled project - overview, FD history, recent activity
allowed-tools: Task, Read, Glob, Grep
---

# Explore Project

General-purpose exploration command for any project using the FD system. Uses parallel subagents to quickly build context.

## Step 1: Launch Parallel Subagents

Launch these THREE subagents IN PARALLEL (single message with multiple Task tool calls):

### Agent 1: Project Overview

Explore the project root to understand what this project is and how it works:

1. **Read key docs** — `CLAUDE.md`, `README.md`, any top-level docs
2. **Directory structure** — Glob for top-level files and key subdirectories
3. **Tech stack** — Identify languages, frameworks, build tools from config files (`package.json`, `pyproject.toml`, `Cargo.toml`, `go.mod`, `Makefile`, etc.)
4. **Gotchas** — Note any warnings, constraints, or non-obvious conventions from CLAUDE.md

Return: project name, purpose, tech stack, directory layout, key gotchas.

### Agent 2: FD History

Explore the feature design system to understand what's been built and what's planned:

1. **Read index** — `docs/features/FEATURE_INDEX.md`
2. **Active FDs** — Read each active FD file (non-Complete status)
3. **Archived FDs** — List files in `docs/features/archive/` to understand completed work
4. **Recent FD commits** — Search git log for commits matching `FD-` pattern (last 20)

Return: active FDs table, count of archived FDs, recent FD commit summary.

### Agent 3: Recent Activity

Explore recent development activity to understand current momentum:

1. **Recent commits** — Last 15 commits with messages
2. **Modified files** — Files changed in the last 5 commits
3. **Branch context** — Current branch name and how far ahead of main
4. **Uncommitted work** — Check git status for staged/unstaged changes

Return: recent commit summary, files in flux, branch status, open work.

## Step 2: Synthesize Results

Combine all agent outputs into a single briefing:

### Project Overview
- Name, purpose, tech stack (from Agent 1)
- Key gotchas or constraints

### FD Status
- Active features table (from Agent 2)
- Archived count and notable completions

### Recent Activity
- What's been happening (from Agent 3)
- Current branch and open work

### Quick Reference

| Item | Value |
|------|-------|
| **Project** | {name} |
| **Branch** | {current branch} |
| **Active FDs** | {count} |
| **Recent focus** | {summary of last few commits} |

## Working Directory

Use the current working directory as the project root.
