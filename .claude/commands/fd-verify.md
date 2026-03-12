# Verify Implementation

Post-implementation workflow: commit, proofread, fix, then propose a verification plan.

## Argument

Optional context about what was implemented. If empty, infer from recent conversation and git diff.

Parse the argument: $ARGUMENTS

## Phase 1: Commit (no approval needed)

1. Run `git status` and `git diff` to see uncommitted changes
2. If there are uncommitted changes related to the implementation:
   - Stage the relevant files
   - Commit with a concise message
3. If nothing to commit, note this and continue

## Phase 2: Proofread (no approval needed)

Review ALL code changes from this implementation session. Use `git diff` against the base commit.

For each modified file, check for:

**Correctness:**
- Logic errors, wrong variable names
- Missing edge cases (None/empty checks)
- Injection or escaping issues
- Parameter substitution bugs

**Consistency:**
- Naming conventions match codebase
- Patterns match existing code (error handling, logging)

**Completeness:**
- All code paths covered
- Config/schema changes documented

**Cleanliness:**
- No debug prints or TODOs left
- No unnecessary changes outside scope
- Imports are clean

If issues found:
- Fix them immediately
- Commit fixes separately with a descriptive message (e.g., `FD-XXX: Proofread fixes` if working on an FD, otherwise a plain descriptive message). Infer the FD number from the branch name or recent commits if available.

If clean, state the code looks good.

## Phase 3: Verification Plan (requires user approval)

Based on the implementation, propose a concrete verification plan:

**Think about:**
- What can be tested locally (unit tests, linting, compilation)
- What needs manual or integration testing
- What edge cases to cover
- What signals confirm success

**Format as numbered steps**, e.g.:
1. Run unit tests to verify logic
2. Check output matches expected format
3. Test edge case: empty input
4. Verify no regressions in related code

Present plan and **wait for approval** before executing.

## Phase 4: Execute (after approval)

Execute the verification plan step by step, reporting results.
