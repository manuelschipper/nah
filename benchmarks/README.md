# Benchmarks

This directory contains reproducible public benchmark runners for `nah`.

Generated reports go under `benchmarks/reports/` and are gitignored. Benchmark
scripts are intended for local/public reporting, not CI, because the datasets can
be large and externally stored.

## Novita Bash Friction

`novita_bash_friction.py` replays Bash permission decisions from the public
Novita agent trace:

```text
novita/agentic_code_dataset_22
https://huggingface.co/datasets/novita/agentic_code_dataset_22
```

Detailed methodology and current full-run numbers are documented in
[`docs/benchmarks/novita-bash-friction.md`](../docs/benchmarks/novita-bash-friction.md).

Run from the repo root:

```bash
python3 benchmarks/novita_bash_friction.py \
  --dataset /home/dev/datasets/novita_e22/e22_sessions_openai.json \
  --out-json benchmarks/reports/novita_bash_friction.json \
  --out-md benchmarks/reports/novita_bash_friction.md
```

Optional publication-grade run with input hashing:

```bash
python3 benchmarks/novita_bash_friction.py \
  --dataset /home/dev/datasets/novita_e22/e22_sessions_openai.json \
  --hash-input
```

Optional run excluding a dataset-specific custom app CLI:

```bash
python3 benchmarks/novita_bash_friction.py \
  --dataset /home/dev/datasets/novita_e22/e22_sessions_openai.json \
  --exclude-custom-cli reminder
```

Only use `--exclude-custom-cli` for project-specific app commands that are part
of the benchmark subject's implementation, not generic developer tools. For
example, `reminder` is a custom app CLI in the Novita corpus. `npm`, `sleep`,
`curl`, `node`, `python`, `git`, and `sqlite` should stay in scope.

Quick checks:

```bash
python3 -m py_compile benchmarks/novita_bash_friction.py
python3 benchmarks/novita_bash_friction.py --smoke
python3 benchmarks/novita_bash_friction.py \
  --dataset /home/dev/datasets/novita_e22/e22_sessions_openai.json \
  --max-bash-calls 200 \
  --out-json /tmp/novita_bash_friction_200.json \
  --out-md /tmp/novita_bash_friction_200.md
```

### What Is Counted

The denominator is structured assistant tool calls where:

```text
function.name == "Bash"
```

It does not count tool schema definitions, documentation text, or raw mentions
of the word `Bash` in the trace.

### Views

The report includes two views:

- `raw`: classifies commands as captured, from the current machine/repo context.
- `replay_normalized`: infers Yanghu's original project root from paths like
  `/Users/yanghu/Documents/develop/claude_seeds/English/<project>/` and
  classifies as if the command were evaluated inside that original project.

Replay normalization is meant to remove benchmark replay artifacts, mostly
false outside-project asks caused by replaying absolute paths from another
machine. It does not remove unknown CLIs, process kills, sensitive paths,
database ambiguity, dangerous actions, or missing-script replay artifacts.

### Defensible Claim Shape

For the latest full run, phrase the result as:

> Across 101,775 extracted Bash tool calls from the public Novita Claude Code
> trace, current `nah` asked on 4.8% and resolved 95.2% deterministically.

Use "extracted Bash tool calls" rather than "all Bash strings" or "eligible Bash
calls".
