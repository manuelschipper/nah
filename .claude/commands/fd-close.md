# Close / Complete a Feature Design

Close an FD by marking it complete (or closed/deferred), archiving the file, and updating the index.

## Argument

The argument should contain:
- **FD number** (required-ish): e.g. `1` or `FD-001`
- **Disposition** (optional): `complete` (default), `closed`, or `deferred`
- **Notes** (optional): any additional context

Examples:
- `/fd-close 1` — mark FD-001 as Complete
- `/fd-close 2 deferred blocked on X` — mark FD-002 as Deferred
- `/fd-close 3 closed superseded by FD-005` — mark FD-003 as Closed
- `/fd-close` (no args) — infer from conversation context

Parse the argument: $ARGUMENTS

## Inferring the FD

If no FD number provided, infer from conversation context:
- Look at which FD was most recently discussed or worked on
- If exactly one FD is obvious, use it and state which one
- If ambiguous, ask the user

## Steps

### 1. Find and read the FD file

- Glob for `docs/features/FD-{number}_*.md`
- Read to get title, current status
- If already archived or not found, report and stop

### 2. Update the FD file

- Set `**Status:**` to `Complete`, `Closed`, or `Deferred`
- For Complete: add `**Completed:** {today YYYY-MM-DD}` after Status
- For Closed/Deferred: add `**Closed:** {today}` if not present

### 3. Update FEATURE_INDEX.md

- Read `docs/features/FEATURE_INDEX.md`
- Remove FD's row from **Active Features** table
- Add to appropriate section:
  - **Complete** → add to top of `## Completed` table with date and notes
  - **Closed/Deferred** → add to top of `## Deferred / Closed` table with status and notes

### 4. Update CHANGELOG.md (Complete only)

- Only for `complete` disposition (skip for closed/deferred)
- Read `CHANGELOG.md`
- Add an entry under `## [Unreleased]` in the appropriate subsection:
  - If the FD adds new functionality → `### Added`
  - If the FD changes existing behavior → `### Changed`
  - If the FD fixes a bug → `### Fixed`
  - If the FD removes something → `### Removed`
- Write a concise changelog entry with the FD number reference in parentheses at the end, e.g.: `- Add widget caching for faster load times (FD-003)`
- If the subsection doesn't exist yet under `[Unreleased]`, create it
- If `CHANGELOG.md` doesn't exist, skip this step

### 5. Archive the file

- Move FD file to `docs/features/archive/`

### 6. Commit

Commit all changes related to this FD in a single atomic commit:
- Check `git status` for uncommitted changes related to the FD implementation (code files modified during this session)
- Stage implementation files, the archived FD, deleted original FD path, `FEATURE_INDEX.md`, and `CHANGELOG.md` (if updated)
- Commit with message: `FD-{number}: {title}`

### 7. Summary

Report:
- FD number and title
- Disposition (Complete / Closed / Deferred)
- Status updated in FD file
- Moved from Active to the appropriate section in index
- Changelog updated (if complete disposition)
- Archived to `docs/features/archive/`
- Committed: {short hash}
