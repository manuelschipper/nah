# Feature Design Status

Generate an up-to-date summary of active feature design items.

## Fast Path vs Full Grooming

**Decide which path to take based on conversation context:**

### Fast Path (just print the table)
Use this when you are **confident the index is up to date** — for example:
- You've been working on FDs in this session (closing, creating, updating)
- You just ran a full grooming pass recently
- The user just asked you to "print the status"

Simply read `docs/features/FEATURE_INDEX.md` and each active FD file, then output the table.

### Full Grooming (first invocation or uncertain state)
Use this when you have **no context about the current state**:
- Start of a new conversation
- You haven't touched any FDs yet
- The user explicitly asks for a grooming check

Perform these housekeeping checks:

#### 1. Status Sync Check
- Read each active FD file and compare its `**Status:**` line to the index
- If discrepancy, update the index to match the file (file is source of truth)
- Report any discrepancies found and fixed

#### 2. Archive Check
- Look for FD files in `docs/features/` (not in `archive/`) with status: Complete, Deferred, or Closed
- For each such FD not yet archived:
  - Move to `docs/features/archive/`
  - Ensure it's in the appropriate section of the index
- Report any files archived

#### 3. Orphan Check
- Check if any FDs in the index don't have corresponding files
- Check if any FD files exist that aren't in the index
- Report any orphans found

## Output

Format the output as a markdown table:

    ## Active Feature Designs

    | FD | Title | Status | Effort | Description |
    |----|-------|--------|--------|-------------|
    | FD-XXX | Title here | Status | Effort | Brief description |

    **Total:** X active items (Y design, Z open, W in progress)

If full grooming was performed and changes were made, prepend a grooming report.

## Notes

- Keep descriptions concise (< 60 chars if possible)
- Include a count summary at the bottom
