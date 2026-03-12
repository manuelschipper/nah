# Create New Feature Design

Create a new FD file and add it to the index.

## Argument

Title or description of the feature: $ARGUMENTS

## Steps

### 1. Determine the next FD number

- Read `docs/features/FEATURE_INDEX.md`
- Find the highest FD number across Active, Completed, Deferred, and Backlog sections
- Next number = highest + 1 (start at 1 if no FDs exist)
- Pad to 3 digits: FD-001, FD-002, etc.

### 2. Parse the argument

- Extract a title from $ARGUMENTS
- If no argument provided, ask the user for a title and brief description
- Generate a filename-safe slug from the title (UPPER_SNAKE_CASE)

### 3. Create the FD file

- Copy structure from `docs/features/TEMPLATE.md`
- File: `docs/features/FD-{number}_{SLUG}.md`
- Fill in: FD number, title, Status: Open
- If the user provided enough context, fill in Problem and Solution sections
- Otherwise leave them as placeholders for the user to fill

### 4. Update FEATURE_INDEX.md

- Add a row to the **Active Features** table
- Include: FD number, title, status (Open), effort (if known), priority (if known)

### 5. Report

Print the created FD with its number, file path, and what sections need filling in.
Do NOT commit — the user will fill in details first.
