# nah test-live — Security Demo

Demonstrate nah's protection by running curated test cases through the live classification pipeline. The user watches nah intercept tool calls in real-time.

## CRITICAL EXECUTION RULES

**Execute ONE case at a time. This is non-negotiable.**

For each case:
1. Print the story context and narration (the threat being demonstrated)
2. Execute the case (live tool call or dry-run classification)
3. Print the result with match indicator and technical explanation
4. Print a `---` separator before the next case

**NEVER batch cases into shell scripts or for-loops.** Each case gets its own individual tool call with narration. If you find yourself writing a loop or a script that runs multiple cases, STOP — you are violating the execution rules. The narration between cases IS the demo.

**NEVER include comments in Bash tool calls.** No `# description` lines before commands. Comments become the first token and change nah's classification. Put all narration in your text output, not in the command string.

## Phase 0: Introduction & Mode Selection

### Introduce the demo

Print this introduction (adapt the tone, don't copy verbatim):

> nah is a safety guard that intercepts every tool call Claude makes — Bash commands, file reads, writes, edits, searches — and classifies them in milliseconds with zero tokens. It blocks dangerous patterns (like remote code execution), asks for confirmation on risky operations (like force-pushing), and stays invisible for safe everyday work.
>
> This demo runs curated test cases through the live pipeline. For safe cases and blocked cases, you'll see nah's real interception in your terminal. For dangerous commands that shouldn't actually execute, we use dry-run classification.

### Permission setup check

Before proceeding, remind the user about the recommended permission setup (adapt the tone, don't copy verbatim):

> **Quick setup note:** For the best experience with nah, avoid using `--dangerously-skip-permissions` — in bypass mode, hooks fire asynchronously, so commands can execute before nah blocks them.
>
> Instead, allow-list **Bash**, **Read**, **Glob**, and **Grep** in Claude Code's permissions and let nah be the guard. For **Write** and **Edit**, it's your call — nah inspects their content either way.
>
> This way, nah's live blocks and asks will show up properly during the demo.

### Config check

Run `nah config show` via Bash and inspect the output. If the user has any custom configuration (action overrides, classify entries, custom sensitive paths, content pattern changes, etc.), warn them:

> **Heads up:** You have a custom nah config. The expected results in this demo assume default settings (full profile, no overrides). Your custom config may change some decisions — I'll note any mismatches as we go, but they might be intentional on your part rather than bugs.

If the config is default/empty, say so briefly and move on.

### Understanding config vs defaults

This is important context for interpreting results during the demo:

- The **test battery expected values assume default config** (full profile, no overrides).
- **Both live tool calls AND `nah test` use the active config.** There is no way to test "default" behavior while a custom config is active — `nah test` is not a defaults-only mode.
- If a user's config changes a policy (e.g., adds `~/.ssh` to allowed paths, or relaxes `network_outbound` to allow), the live result will differ from the test battery's expected value. **This is the config working correctly, not a bug in the test battery.**
- When you encounter a mismatch and the config check found custom settings, attribute it to the config — don't try to "verify" default behavior by running `nah test`, since it will show the same config-influenced result.
- Only flag a mismatch as a real issue if the user has default config and the result still doesn't match.

### Select mode

Check `$ARGUMENTS`:

- If argument is **`full`**: use full mode (90 base + 21 config variants)
- If argument is **`story:NAME`**: use story mode for that story
- If **no argument**: ask the user which mode they want:

> **Which mode would you like?**
> - **Demo** (recommended) — 25 curated cases across 8 security stories. Takes ~5 minutes. Covers all the highlights.
> - **Full** — All 90 base cases + 21 config variants + log verification. Comprehensive regression suite.
> - **Single story** — Deep-dive into one threat category. Stories: `safe_operations`, `remote_code_execution`, `data_exfiltration`, `obfuscated_execution`, `path_boundary_protection`, `destructive_operations`, `credential_secret_detection`, `network_context`.

Wait for the user's answer before proceeding.

### Select pacing

After the user picks a mode, ask:

> **Pacing?**
> - **Pause between cases** — I'll stop after each case so you can inspect the result. Say "next" or "continue" to advance.
> - **Run straight through** — I'll run all cases back-to-back without stopping.

Wait for the user's answer. If they choose to pause, after printing each case's result, wait for the user to respond before continuing to the next case.

---

## Phase 1: Setup

1. Read `src/nah/data/test_battery.json`
2. Filter cases based on selected mode:
   - **demo**: base cases with `quick: true` (25 cases)
   - **full**: all base cases (90) + all variants (21)
   - **story:NAME**: base cases where `story` field matches NAME
3. Print header:

```
## nah test-live — N cases (demo|full|story:NAME)
```

---

## Phase 2: Story-Based Execution

Group selected base cases by their `story` field. Process stories in this order:

| Story key | Header |
|-----------|--------|
| `safe_operations` | Safe Operations — nah stays out of your way |
| `remote_code_execution` | Remote Code Execution — download-and-execute pipelines |
| `data_exfiltration` | Data Exfiltration — stealing sensitive data |
| `obfuscated_execution` | Obfuscated Execution — hiding malicious intent |
| `path_boundary_protection` | Path & Boundary Protection — sensitive files and directories |
| `destructive_operations` | Destructive Operations — irreversible changes |
| `credential_secret_detection` | Credential & Secret Detection — scanning for secrets |
| `network_context` | Network Context — who are you talking to? |

For each story group, print a story header:

```
## [Story Header]
```

Then for each case in the story, print:

```
### [N/total] `input_summary`

**Threat:** [narration field from JSON]
```

Execute the case (see Execution Mechanics below), then print:

```
**Result:** decision ✓
**Why:** [description field from JSON]

---
```

If mismatch: `**Result:** actual ✗ (expected: expected)`

---

## Execution Mechanics

### Live cases (`mode: "live"`)

Actually invoke the real tool. The user sees nah's real decision in their terminal.

**Bash**: Use the Bash tool with `input.command`.
**Read**: Use the Read tool with `input.file_path`.
**Write**: Use the Write tool with `input.file_path` and `input.content`. nah intercepts at the tool-call level, so blocked writes never need a prior Read.
**Glob**: Use the Glob tool with `input.pattern` and `input.path` (if present).
**Grep**: Use the Grep tool with `input.pattern` and `input.path` (if present).

Detection:
- Tool denied with reason starting with `nah.` → record as **block**
- Tool denied with reason starting with `nah?` → record as **ask**
- Tool executed normally → record as **allow**

### Dry-run cases (`mode: "dry_run"`)

Never execute the real tool. Use `nah test` via the Bash tool for all dry-run cases. Parse the `Decision:` line from output. Map: `ALLOW` → allow, `ASK` → ask, `BLOCK` → block.

**Bash**:
```bash
nah test "the command here"
```

**Write** (with content inspection):
```bash
nah test --tool Write --path ./config.py --content "AWS_SECRET_ACCESS_KEY=AKIA1234567890ABCDEF"
```

**Edit** (with content inspection):
```bash
nah test --tool Edit --path ./app.py --content "api_secret = \"hunter2hunter2\""
```

**Read/Glob** (path-only):
```bash
nah test --tool Read ~/.ssh/id_rsa
nah test --tool Glob ~/.ssh
```

**Grep** (with search pattern for credential detection):
```bash
nah test --tool Grep --path /tmp --pattern "password\s*="
```

**MCP tools**:
```bash
nah test --tool mcp__example__tool
```

---

## Phase 3: Summary

After all cases, print a summary.

**Demo mode:**
```
## Demo Complete

| Story | Cases | Passed |
|-------|-------|--------|
| Safe Operations | N/N | ✓ |
| Remote Code Execution | N/N | ✓ |
| ... | | |

**Passed:** N/N | **Allow:** N | **Ask:** N | **Block:** N
```

If any mismatches, list them with case ID, expected, and actual.

**Full mode:** Same summary, plus note the report file path.

---

## Full Mode: Additional Phases

These phases run only in `full` mode, after the base battery.

### Config Variants

Run each variant using `nah test --config` with the variant's `config` object as inline JSON. This applies a temporary config override for that single invocation — no file writes, no backup/restore needed.

For each variant, announce it:
```
### [V#] Config variant (feature): `input_summary`
Config: config_description
Expected: expected (default: default_expected)
```

Then execute using `nah test --config '<JSON>' ...` — convert the variant's `config` object to a JSON string and pass it via the `--config` flag. Construct the rest of the command from the variant's `tool` and `input` fields.

Examples:
```bash
# Bash variant with classify override
nah test --config '{"classify": {"git_safe": ["git push --force"]}}' "git push --force"

# Bash variant with profile: none
nah test --config '{"profile": "none"}' "git status"

# Write variant with content pattern suppression
nah test --tool Write --path ./config.py --content "secret=abc" --config '{"content_patterns": {"suppress": ["private key"]}}'
```

### Log Cross-Check

1. Run `nah log -n 50 --json` via Bash
2. For each base case that resulted in block or ask, check for a matching log entry
3. Report: `Log verified: ✓` or list missing entries

### Report File

Create `command_test_runs/` directory if it doesn't exist, then write a markdown report to `command_test_runs/YYYY-MM-DD_HHMMSS.md`:

```markdown
# nah test report

**Date:** YYYY-MM-DD HH:MM:SS
**Mode:** full
**Cases:** N total (X base + Y variants)

## Results

| # | Story | Tool | Input | Expected | Actual | Mode | Match |
|---|-------|------|-------|----------|--------|------|-------|

## Config Variants

| V# | Feature | Config | Input | Expected | Actual | Match |
|----|---------|--------|-------|----------|--------|-------|

## Summary

- **Passed:** N/N (X%)
- **Live/Dry-run:** N/N
- **Log verification:** ✓ or N missing

## Mismatches

(only if any — include case ID, tool, input, expected vs actual, full output)
```
