# Novita Bash Friction Benchmark

Date: 2026-05-07

This benchmark measures permission-review friction for `nah` on Bash tool calls
from the public Novita agent trace:

```text
novita/agentic_code_dataset_22
https://huggingface.co/datasets/novita/agentic_code_dataset_22
```

It is a `nah` benchmark only. It does not compare against Claude Code auto mode
and it does not execute the original commands. It replays recorded Bash
permission decisions through the current local `nah` classifier.

## Headline

Recommended headline with the custom project CLI excluded:

> Across 101,194 extracted Bash tool calls from the public Novita Claude Code
> trace, excluding the dataset-specific `reminder` app CLI, `nah` asked on 4.2%
> and resolved 95.8% deterministically.

Unfiltered baseline:

> Across 101,775 extracted Bash tool calls from the public Novita Claude Code
> trace, `nah` asked on 4.8% and resolved 95.2% deterministically.

Use "extracted Bash tool calls" rather than "all Bash strings" or "eligible Bash
calls".

## What Is Counted

The denominator is structured assistant tool calls where:

```text
function.name == "Bash"
```

This does not count tool schema definitions, documentation text, or raw mentions
of the word `Bash` in the trace.

The full unfiltered extraction found:

```text
101,775 structured Bash tool calls
22 sessions
1,559,733,861 byte local JSON export
```

## Reproduction

From the `nah` repo root:

```bash
python3 benchmarks/novita_bash_friction.py \
  --dataset /home/dev/datasets/novita_e22/e22_sessions_openai.json \
  --out-json benchmarks/reports/novita_bash_friction.json \
  --out-md benchmarks/reports/novita_bash_friction.md
```

Publication-grade run with input hashing:

```bash
python3 benchmarks/novita_bash_friction.py \
  --dataset /home/dev/datasets/novita_e22/e22_sessions_openai.json \
  --hash-input
```

Custom-project-CLI-excluded run:

```bash
python3 benchmarks/novita_bash_friction.py \
  --dataset /home/dev/datasets/novita_e22/e22_sessions_openai.json \
  --exclude-custom-cli reminder \
  --out-json benchmarks/reports/novita_bash_friction.no-reminder.json \
  --out-md benchmarks/reports/novita_bash_friction.no-reminder.md
```

Quick checks:

```bash
python3 -m py_compile benchmarks/novita_bash_friction.py
python3 benchmarks/novita_bash_friction.py --smoke
```

## Views

The benchmark reports two views.

`raw` classifies commands exactly as captured, from the current machine/repo
context.

`replay_normalized` infers Yanghu's original project root from paths like:

```text
/Users/yanghu/Documents/develop/claude_seeds/English/<project>/
```

Then it classifies each command as if the command were evaluated inside that
original project. This removes benchmark replay artifacts caused by evaluating
another machine's absolute paths from this repo's current working directory.

Replay normalization mostly removes false outside-project asks. It does not
remove unknown CLIs, process kills, sensitive paths, database ambiguity,
dangerous actions, or missing-script replay artifacts.

## Current Full Results

These numbers were generated with:

```text
nah version: 0.8.3
nah commit: 743ac7a
config: packaged defaults via nah.config.use_defaults()
generated_at: 2026-05-07T00:38:48.401312+00:00
```

### Unfiltered

Replay-normalized results:

| Metric | Count | Rate |
| --- | ---: | ---: |
| Extracted Bash tool calls | 101,775 | 100.00% |
| Allow | 96,779 | 95.09% |
| Ask | 4,870 | 4.79% |
| Block | 126 | 0.12% |
| Deterministic resolution | 96,905 | 95.21% |

`unknown_cli` asks:

```text
1,656 calls
1.63% of all Bash calls
34.00% of remaining asks
```

### Excluding `reminder`

`reminder` is a dataset-specific custom app CLI in the Novita corpus. It is
reasonable to exclude it from a general Bash-friction benchmark, as long as the
exclusion is explicit and generic developer tools remain in scope.

The exclusion is narrow:

```text
first executable token == "reminder"
```

It does not exclude normal file operations inside a project directory named
`reminder`.

Excluded:

```text
581 Bash calls
```

Replay-normalized results after excluding `reminder`:

| Metric | Count | Rate |
| --- | ---: | ---: |
| Extracted Bash tool calls | 101,194 | 100.00% |
| Allow | 96,779 | 95.64% |
| Ask | 4,289 | 4.24% |
| Block | 126 | 0.12% |
| Deterministic resolution | 96,905 | 95.76% |

`unknown_cli` asks after excluding `reminder`:

```text
1,075 calls
1.06% of all included Bash calls
25.06% of remaining asks
```

The custom CLI exclusion removed:

```text
581 calls
581 asks
unknown_cli: 1,656 -> 1,075
ask rate: 4.79% -> 4.24%
deterministic resolution: 95.21% -> 95.76%
```

Do not exclude generic developer tools. These remain in scope:

```text
npm, sleep, curl, node, python, git, sqlite
```

## Read-Only and Local-Safe Coverage

With `reminder` excluded, `nah` recognized `78,729` Bash calls as read-only or
local-safe.

| Metric | Count | Rate |
| --- | ---: | ---: |
| Recognized read-only/local-safe calls | 78,729 | 100.00% |
| Allowed | 78,686 | 99.945% |
| Asked | 43 | 0.055% |
| Deterministic resolution | 78,686 | 99.945% |

This is the key evidence that remaining friction is not mostly missed obvious
read-only work.

Defensible phrase:

> On recognized read-only/local-safe Bash calls, `nah` resolved 99.945%
> deterministically.

## Remaining Asks

With `reminder` excluded, the replay-normalized ask buckets were:

| Bucket | Count | Share of asks | Share of all included Bash calls |
| --- | ---: | ---: | ---: |
| `replay_artifact_script_not_found` | 1,708 | 39.82% | 1.69% |
| `unknown_cli` | 1,075 | 25.06% | 1.06% |
| `process_signal` | 821 | 19.14% | 0.81% |
| `unknown_db_target` | 247 | 5.76% | 0.24% |
| `mutating_or_destructive` | 230 | 5.36% | 0.23% |
| `replay_artifact_outside_project` | 71 | 1.66% | 0.07% |
| `sensitive_path` | 60 | 1.40% | 0.06% |
| `replay_artifact_redirect_outside_project` | 45 | 1.05% | 0.04% |
| `other` | 32 | 0.75% | 0.03% |

Interpretation:

- `process_signal`, `sensitive_path`, and `mutating_or_destructive` are mostly
  legitimate asks.
- `replay_artifact_script_not_found` and residual outside-project buckets are
  replay artifacts, not normal user friction.
- `unknown_cli` is the main real residual. After excluding `reminder`, it is
  mostly generic compound workflow shapes rather than one custom app CLI.
- `unknown_db_target` is a reasonable ambiguity bucket until database read/write
  target semantics are stronger.

## Top Remaining Unknown CLI Shapes

After excluding `reminder`, top replay-normalized `unknown_cli` shapes were:

| Count | Shape |
| ---: | --- |
| 72 | `npm run build &&` |
| 67 | `npm run dev:backend >` |
| 65 | `sleep 3 && curl` |
| 44 | `npm run start >` |
| 42 | `sleep 2 && curl` |
| 39 | `npm run dev:server &` |
| 38 | `npm unlink -g reminder-cli` |
| 32 | `npm start & sleep` |
| 30 | `# Test registration echo` |
| 29 | `mv $NOVITA_ROOT/im/src/server/middleware/auth.test.ts $NOVITA_ROOT/im/tests/ &&` |
| 28 | `cd $NOVITA_ROOT/inlove/frontend && npm` |
| 28 | `wait` |

These are not all safe read-only calls. Many are server starts, background
process orchestration, global package unlinking, command compounds, or commands
whose safety depends on local project semantics.

## Improvement Candidates

The benchmark suggests several classifier improvements that would be general
enough to consider:

- SQLite read-only query classification, including `.schema` and `SELECT`.
- More precise `npm run build/test` handling when the script can be resolved
  locally and does not start a long-running service.
- Healthcheck compounds such as `npm run dev & sleep N && curl localhost...`,
  if the server process and network target are local and scoped.
- Better distinction between replay-host missing artifacts and actual unknown
  script execution.

The benchmark does not justify globally allowing arbitrary unknown project CLIs.
Those should remain asks unless `nah` learns local semantics through project
configuration or a specific deterministic classifier.

## What This Proves

The benchmark supports these claims:

- `nah` keeps Bash permission-review friction low on a public coding-agent trace.
- Replay-normalized friction is about 4.2% with a dataset-specific custom CLI
  excluded.
- `nah` deterministically resolves 95.8% of included Bash calls.
- `nah` deterministically resolves 99.945% of recognized read-only/local-safe
  Bash calls.
- The remaining friction is mostly legitimate ambiguity or replay artifacts, not
  missed obvious read-only work.

The benchmark does not prove:

- That every remaining ask is unsafe.
- That `nah` should allow all unknown CLIs.
- That the original commands would have succeeded on the replay machine.
- Any cost comparison against another agent's permission system.
