#!/usr/bin/env python3
"""Replay Novita Bash tool calls through nah and measure review friction.

This benchmark is intentionally Bash-only because Bash is the most portable
permission surface across Claude Code, Codex, and other coding agents.

The runner emits aggregate reports by default. Raw command samples are opt-in
with --include-samples.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator


DEFAULT_NOVITA_PATH = os.environ.get(
    "NOVITA_E22_PATH",
    "/home/dev/datasets/novita_e22/e22_sessions_openai.json",
)
DEFAULT_REPORT_JSON = "benchmarks/reports/novita_bash_friction.json"
DEFAULT_REPORT_MD = "benchmarks/reports/novita_bash_friction.md"
RUNNER_NAME = "novita_bash_friction"
RUNNER_VERSION = "1"
SCHEMA_VERSION = "nah_bash_friction.v1"
NOVITA_DATASET_ID = "novita/agentic_code_dataset_22"
NOVITA_DATASET_URL = "https://huggingface.co/datasets/novita/agentic_code_dataset_22"
YANGHU_PREFIX = "/Users/yanghu/Documents/develop/claude_seeds/English/"
PROJECT_RE = re.compile(
    re.escape(YANGHU_PREFIX) + r"([A-Za-z0-9._-]+)(?=$|[/'\"`\s])"
)

READ_ONLY_TYPES = {
    "filesystem_read",
    "git_safe",
    "network_diagnostic",
    "db_read",
    "service_read",
    "container_read",
    "browser_read",
    "agent_read",
}
LOCAL_SAFE_TYPES = {"package_run"}
MUTATING_OR_DESTRUCTIVE_TYPES = {
    "filesystem_write",
    "filesystem_delete",
    "git_write",
    "git_remote_write",
    "git_discard",
    "git_history_rewrite",
    "network_write",
    "package_install",
    "package_uninstall",
    "process_signal",
    "container_write",
    "container_exec",
    "container_destructive",
    "service_write",
    "service_destructive",
    "db_write",
    "browser_write",
    "browser_exec",
    "browser_file",
    "agent_write",
    "agent_exec_read",
    "agent_exec_write",
    "agent_exec_remote",
    "agent_server",
    "agent_exec_bypass",
}


@dataclass
class NahRuntime:
    bash: Any
    config: Any
    paths: Any
    version: str
    source_path: str
    git_commit: str


@dataclass
class ViewStats:
    name: str
    total: int = 0
    decisions: Counter = field(default_factory=Counter)
    ask_buckets: Counter = field(default_factory=Counter)
    ask_action_types: Counter = field(default_factory=Counter)
    ask_known_vs_novel: Counter = field(default_factory=Counter)
    readonly: Counter = field(default_factory=Counter)
    local_safe: Counter = field(default_factory=Counter)
    bucket_shapes: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    normalization: Counter = field(default_factory=Counter)
    samples: dict[str, list[dict[str, str]]] = field(default_factory=lambda: defaultdict(list))

    def add(
        self,
        *,
        session_id: str,
        command: str,
        result: Any,
        shape: str,
        seen_shape: bool,
        normalization_status: str = "",
        include_samples: bool = False,
    ) -> None:
        self.total += 1
        decision = result.final_decision
        self.decisions[decision] += 1
        if normalization_status:
            self.normalization[normalization_status] += 1

        stage_types = [stage.action_type for stage in result.stages]
        if stage_types and all(action in READ_ONLY_TYPES for action in stage_types):
            self.readonly[decision] += 1
        if stage_types and all(action in READ_ONLY_TYPES | LOCAL_SAFE_TYPES for action in stage_types):
            self.local_safe[decision] += 1

        if decision != "ask":
            return

        bucket = reason_bucket(result.reason or "", stage_types)
        action_type = "compound" if len(result.stages) > 1 else (
            result.stages[0].action_type if result.stages else "unknown"
        )
        self.ask_buckets[bucket] += 1
        self.ask_action_types[action_type] += 1
        self.ask_known_vs_novel["known" if seen_shape else "novel"] += 1
        self.bucket_shapes[bucket][shape] += 1

        if include_samples and len(self.samples[bucket]) < 10:
            self.samples[bucket].append({
                "session_id": session_id,
                "shape": shape,
                "command": sanitize_command(command),
                "reason": result.reason or "",
                "action_type": action_type,
            })

    def to_json(self, *, top_shapes: int, include_samples: bool) -> dict[str, Any]:
        deterministic = self.decisions.get("allow", 0) + self.decisions.get("block", 0)
        asks = self.decisions.get("ask", 0)
        data: dict[str, Any] = {
            "total": self.total,
            "decisions": dict(sorted(self.decisions.items())),
            "deterministic_resolution_rate": ratio(deterministic, self.total),
            "review_friction_rate": ratio(asks, self.total),
            "recognized_readonly": counter_summary(self.readonly),
            "recognized_readonly_or_local_safe": counter_summary(self.local_safe),
            "ask_buckets": dict(self.ask_buckets.most_common()),
            "ask_action_types": dict(self.ask_action_types.most_common()),
            "ask_known_vs_novel": dict(self.ask_known_vs_novel.most_common()),
            "top_shapes_by_bucket": {
                bucket: [
                    {"shape": shape, "count": count}
                    for shape, count in shapes.most_common(top_shapes)
                ]
                for bucket, shapes in sorted(self.bucket_shapes.items())
            },
        }
        if self.normalization:
            data["normalization"] = dict(self.normalization.most_common())
        if include_samples:
            data["samples"] = dict(self.samples)
        return data


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input",
        nargs="?",
        help="Novita OpenAI-format JSON export. Defaults to --dataset or NOVITA_E22_PATH.",
    )
    parser.add_argument("--dataset", dest="dataset", default="")
    parser.add_argument("--nah-src", default=os.environ.get("NAH_SRC", ""))
    parser.add_argument("--out-json", default=DEFAULT_REPORT_JSON)
    parser.add_argument("--out-md", default=DEFAULT_REPORT_MD)
    parser.add_argument("--max-bash-calls", type=int, default=0)
    parser.add_argument("--top-shapes", type=int, default=12)
    parser.add_argument("--include-samples", action="store_true")
    parser.add_argument(
        "--exclude-custom-cli",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "exclude Bash calls whose first command token is NAME; repeatable. "
            "Use only for dataset-specific app CLIs, not generic tools."
        ),
    )
    parser.add_argument(
        "--hash-input",
        action="store_true",
        help="include a chunked SHA-256 of the input file in the report",
    )
    parser.add_argument("--smoke", action="store_true", help="run built-in smoke checks and exit")
    args = parser.parse_args(argv)
    args.input = args.input or args.dataset or DEFAULT_NOVITA_PATH
    return args


def load_nah(nah_src: str) -> NahRuntime:
    source = resolve_nah_src(nah_src)
    if source:
        sys.path.insert(0, source)

    from nah import __version__  # type: ignore
    from nah import bash, config, paths  # type: ignore

    config.use_defaults()
    return NahRuntime(
        bash=bash,
        config=config,
        paths=paths,
        version=__version__,
        source_path=source or str(Path(bash.__file__).resolve().parents[1]),
        git_commit=git_commit_for_source(source),
    )


def resolve_nah_src(explicit: str) -> str:
    candidates = []
    if explicit:
        candidates.append(explicit)
    repo_root = Path(__file__).resolve().parents[1]
    candidates.append(str(repo_root / "src"))
    for candidate in candidates:
        path = Path(candidate)
        if candidate and (path / "nah").is_dir():
            return str(path.resolve())
    return ""


def git_commit_for_source(source: str) -> str:
    if not source:
        return ""
    repo = Path(source).resolve().parent
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def iter_sessions(path: str) -> Iterator[dict[str, Any]]:
    """Yield Novita session objects without loading the whole 1.5 GB file."""
    decoder = json.JSONDecoder()
    with open(path, "r", encoding="utf-8") as handle:
        buffer = ""
        in_sessions = False
        eof = False

        while not in_sessions:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                raise ValueError("sessions array not found")
            buffer += chunk
            key_idx = buffer.find('"sessions"')
            if key_idx < 0:
                buffer = buffer[-32:]
                continue
            array_idx = buffer.find("[", key_idx)
            if array_idx < 0:
                continue
            buffer = buffer[array_idx + 1:]
            in_sessions = True

        while True:
            buffer = buffer.lstrip()
            if buffer.startswith(","):
                buffer = buffer[1:].lstrip()
            if buffer.startswith("]"):
                return

            while True:
                try:
                    item, end = decoder.raw_decode(buffer)
                except json.JSONDecodeError:
                    if eof:
                        raise
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        eof = True
                    buffer += chunk
                    continue
                yield item
                buffer = buffer[end:]
                break


def iter_bash_calls(session: dict[str, Any]) -> Iterator[tuple[int, str]]:
    for turn in session.get("turns", []):
        turn_number = int(turn.get("turn_number", -1))
        for message in turn.get("messages", []):
            if message.get("role") != "assistant":
                continue
            for tool_call in message.get("tool_calls") or []:
                function = tool_call.get("function") or {}
                if function.get("name") != "Bash":
                    continue
                raw_args = function.get("arguments", "{}")
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                except json.JSONDecodeError:
                    args = {}
                command = str((args or {}).get("command") or "")
                yield turn_number, command


def first_command_token(command: str) -> str:
    """Return the first executable token after leading env assignments/wrappers."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    while tokens and is_env_assignment(tokens[0]):
        tokens.pop(0)
    while tokens and tokens[0] in {"command", "builtin", "env"}:
        tokens.pop(0)
    return tokens[0] if tokens else ""


def is_env_assignment(token: str) -> bool:
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token))


def should_exclude_command(command: str, custom_clis: set[str]) -> bool:
    return first_command_token(command) in custom_clis


def extract_projects(text: str) -> Counter:
    return Counter(PROJECT_RE.findall(text or ""))


def session_dominant_project(commands: list[str]) -> str:
    counts = Counter()
    for command in commands:
        counts.update(extract_projects(command))
    if not counts:
        return ""
    most_common = counts.most_common(2)
    project, count = most_common[0]
    second = most_common[1][1] if len(most_common) > 1 else 0
    total = sum(counts.values())
    if count >= 3 and count / total >= 0.8 and (second == 0 or count >= second * 3):
        return project
    return ""


def infer_replay_root(command: str, dominant_project: str) -> tuple[str, str]:
    projects = set(extract_projects(command))
    if len(projects) == 1:
        return YANGHU_PREFIX + next(iter(projects)), "command_project"
    if len(projects) > 1:
        return "", "ambiguous_project"
    if dominant_project:
        return YANGHU_PREFIX + dominant_project, "session_project"
    return "", "no_project"


@contextlib.contextmanager
def replay_context(runtime: NahRuntime, project_root: str) -> Iterator[None]:
    """Set a synthetic project root and cwd for one replay classification."""
    if not project_root:
        runtime.paths.reset_project_root()
        yield
        runtime.paths.reset_project_root()
        return

    original_getcwd = os.getcwd
    original_resolve_path = runtime.paths.resolve_path

    def replay_getcwd() -> str:
        return project_root

    def replay_resolve_path(raw: str) -> str:
        if not raw:
            return ""
        expanded = os.path.expanduser(os.path.expandvars(raw))
        if not os.path.isabs(expanded):
            expanded = os.path.join(project_root, expanded)
        return os.path.realpath(expanded)

    try:
        os.getcwd = replay_getcwd  # type: ignore[assignment]
        runtime.paths.resolve_path = replay_resolve_path
        runtime.paths.set_project_root(project_root)
        yield
    finally:
        os.getcwd = original_getcwd  # type: ignore[assignment]
        runtime.paths.resolve_path = original_resolve_path
        runtime.paths.reset_project_root()


def classify(runtime: NahRuntime, command: str, project_root: str = "") -> Any:
    with replay_context(runtime, project_root):
        return runtime.bash.classify_command(command)


def command_shape(command: str) -> str:
    sanitized = sanitize_command(command)
    try:
        tokens = shlex.split(sanitized)
    except ValueError:
        tokens = sanitized.split()
    if not tokens:
        return "<empty>"
    return " ".join(tokens[:4])


def sanitize_command(command: str) -> str:
    return (command or "").replace(YANGHU_PREFIX, "$NOVITA_ROOT/")


def reason_bucket(reason: str, action_types: list[str]) -> str:
    lowered = reason.lower()
    actions = set(action_types)
    if "redirect target: outside project" in lowered:
        return "replay_artifact_redirect_outside_project"
    if "script not found" in lowered:
        return "replay_artifact_script_not_found"
    if "outside project" in lowered:
        return "replay_artifact_outside_project"
    if "sensitive path" in lowered or "shell init" in lowered:
        return "sensitive_path"
    if (
        "remote code execution" in lowered
        or "obfuscated" in lowered
        or "decode" in lowered
        or "data exfiltration" in lowered
    ):
        return "dangerous_dataflow_or_obfuscation"
    if "unknown database target" in lowered:
        return "unknown_db_target"
    if "process_signal" in lowered or "process_signal" in actions:
        return "process_signal"
    if "unknown" in lowered or "unknown" in actions:
        return "unknown_cli"
    if actions & MUTATING_OR_DESTRUCTIVE_TYPES:
        return "mutating_or_destructive"
    return "other"


def run_benchmark(args: argparse.Namespace, runtime: NahRuntime) -> dict[str, Any]:
    raw = ViewStats("raw")
    normalized = ViewStats("replay_normalized")
    raw_seen: dict[str, set[str]] = defaultdict(set)
    normalized_seen: dict[str, set[str]] = defaultdict(set)
    bash_total = 0
    excluded = Counter()
    custom_clis = set(args.exclude_custom_cli or [])
    session_count = 0

    for session in iter_sessions(args.input):
        session_count += 1
        session_id = str(session.get("session_id") or f"session_{session_count}")
        commands = [command for _turn, command in iter_bash_calls(session)]
        dominant_project = session_dominant_project(commands)

        for command in commands:
            token = first_command_token(command)
            if token in custom_clis:
                excluded[token] += 1
                continue
            if args.max_bash_calls and bash_total >= args.max_bash_calls:
                return build_report(
                    args,
                    runtime,
                    raw,
                    normalized,
                    session_count,
                    excluded=excluded,
                    stopped_early=True,
                )
            bash_total += 1
            if bash_total % 10000 == 0:
                print(f"processed {bash_total} Bash calls", file=sys.stderr)

            shape = command_shape(command)
            raw_seen_before = shape in raw_seen[session_id]
            raw_seen[session_id].add(shape)
            raw_result = classify(runtime, command)
            raw.add(
                session_id=session_id,
                command=command,
                result=raw_result,
                shape=shape,
                seen_shape=raw_seen_before,
                include_samples=args.include_samples,
            )

            project_root, norm_status = infer_replay_root(command, dominant_project)
            normalized_seen_before = shape in normalized_seen[session_id]
            normalized_seen[session_id].add(shape)
            norm_result = classify(
                runtime,
                command,
                project_root if norm_status != "ambiguous_project" else "",
            )
            normalized.add(
                session_id=session_id,
                command=command,
                result=norm_result,
                shape=shape,
                seen_shape=normalized_seen_before,
                normalization_status=norm_status,
                include_samples=args.include_samples,
            )

    return build_report(
        args,
        runtime,
        raw,
        normalized,
        session_count,
        excluded=excluded,
        stopped_early=False,
    )


def build_report(
    args: argparse.Namespace,
    runtime: NahRuntime,
    raw: ViewStats,
    normalized: ViewStats,
    session_count: int,
    *,
    excluded: Counter,
    stopped_early: bool,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now_iso(),
        "runner": {
            "name": RUNNER_NAME,
            "title": "Novita Bash Friction Benchmark",
            "version": RUNNER_VERSION,
            "script_path": str(Path(__file__).resolve()),
            "options": {
                "max_bash_calls": args.max_bash_calls,
                "top_shapes": args.top_shapes,
                "include_samples": args.include_samples,
                "hash_input": args.hash_input,
                "exclude_custom_cli": list(args.exclude_custom_cli or []),
            },
        },
        "dataset": {
            "id": NOVITA_DATASET_ID,
            "name": NOVITA_DATASET_ID,
            "kind": "public_trace",
            "source_url": NOVITA_DATASET_URL,
            **input_file_metadata(args.input, hash_input=args.hash_input),
            "sessions_seen": session_count,
            "stopped_early": stopped_early,
        },
        "nah": {
            "version": runtime.version,
            "source_path": runtime.source_path,
            "git_commit": runtime.git_commit,
            "config": "packaged defaults via nah.config.use_defaults()",
        },
        "redaction": {
            "raw_samples_included": args.include_samples,
            "command_samples": "excluded by default; included only with --include-samples",
            "shape_policy": "Yanghu Novita root is replaced with $NOVITA_ROOT/",
            "private_path_policy": "aggregate reports only by default",
        },
        "exclusions": {
            "custom_cli": dict(excluded.most_common()),
            "total_excluded": sum(excluded.values()),
            "policy": (
                "Only dataset-specific app CLIs should be excluded. Generic tools "
                "such as npm, sleep, curl, node, python, git, and sqlite remain in scope."
            ),
        },
        "views": {
            raw.name: raw.to_json(
                top_shapes=args.top_shapes,
                include_samples=args.include_samples,
            ),
            normalized.name: normalized.to_json(
                top_shapes=args.top_shapes,
                include_samples=args.include_samples,
            ),
        },
    }


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def counter_summary(counter: Counter) -> dict[str, Any]:
    total = sum(counter.values())
    deterministic = counter.get("allow", 0) + counter.get("block", 0)
    return {
        "total": total,
        "decisions": dict(sorted(counter.items())),
        "deterministic_resolution_rate": ratio(deterministic, total),
        "review_friction_rate": ratio(counter.get("ask", 0), total),
    }


def input_file_metadata(path: str, *, hash_input: bool) -> dict[str, Any]:
    input_path = Path(path)
    stat = input_path.stat()
    data: dict[str, Any] = {
        "input_path": str(input_path),
        "input_size_bytes": stat.st_size,
        "input_mtime": dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc).isoformat(),
        "input_sha256": None,
    }
    if hash_input:
        data["input_sha256"] = sha256_file(input_path)
    return data


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def write_reports(report: dict[str, Any], json_path: str, md_path: str) -> None:
    Path(json_path).parent.mkdir(parents=True, exist_ok=True)
    Path(md_path).parent.mkdir(parents=True, exist_ok=True)
    Path(json_path).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    Path(md_path).write_text(markdown_report(report), encoding="utf-8")


def markdown_report(report: dict[str, Any]) -> str:
    title = report.get("runner", {}).get("title") or "nah Bash Friction Benchmark"
    dataset = report.get("dataset", {})
    nah = report.get("nah", {})
    redaction = report.get("redaction", {})
    runner = report.get("runner", {})
    lines = [
        f"# {title}",
        "",
        f"- Schema: `{report.get('schema_version', '')}`",
        f"- Generated: `{report.get('generated_at', '')}`",
        f"- Runner: `{runner.get('name', '')}` version `{runner.get('version', '')}`",
        f"- Dataset: `{dataset.get('id') or dataset.get('name', '')}`",
        f"- Dataset kind: `{dataset.get('kind', '')}`",
        f"- Source URL: `{dataset.get('source_url', '')}`",
        f"- Input: `{dataset.get('input_path', '')}`",
        f"- Input size: `{dataset.get('input_size_bytes', '')}` bytes",
        f"- Input SHA-256: `{dataset.get('input_sha256') or 'not requested'}`",
        f"- Sessions seen: `{dataset.get('sessions_seen', '')}`",
        f"- Stopped early: `{dataset.get('stopped_early', False)}`",
        f"- nah: `{nah.get('version', '')}` commit `{nah.get('git_commit', '')}`",
        f"- Config: `{nah.get('config', '')}`",
        f"- Raw samples included: `{redaction.get('raw_samples_included', False)}`",
        f"- Exclusions: `{report.get('exclusions', {})}`",
        "",
    ]

    for view_name, view in report.get("views", {}).items():
        lines.extend(view_markdown(view_name, view))
    return "\n".join(lines).rstrip() + "\n"


def view_markdown(view_name: str, view: dict[str, Any]) -> list[str]:
    lines = [
        f"## {view_name}",
        "",
        f"- Bash calls: `{view.get('total', 0)}`",
        f"- Decisions: `{view.get('decisions', {})}`",
        f"- Deterministic resolution: `{view.get('deterministic_resolution_rate', 0.0):.4%}`",
        f"- Review friction: `{view.get('review_friction_rate', 0.0):.4%}`",
        f"- Recognized read-only: `{view.get('recognized_readonly', {})}`",
        f"- Recognized read-only/local-safe: `{view.get('recognized_readonly_or_local_safe', {})}`",
        "",
        "### Ask Buckets",
        "",
    ]
    ask_buckets = view.get("ask_buckets", {})
    if ask_buckets:
        for bucket, count in ask_buckets.items():
            lines.append(f"- `{bucket}`: `{count}`")
    else:
        lines.append("- None")

    if view.get("ask_action_types"):
        lines.extend(["", "### Ask Action Types", ""])
        for action_type, count in view["ask_action_types"].items():
            lines.append(f"- `{action_type}`: `{count}`")

    if view.get("normalization"):
        lines.extend(["", "### Normalization", ""])
        for status, count in view["normalization"].items():
            lines.append(f"- `{status}`: `{count}`")

    if view.get("samples"):
        lines.extend(["", "### Samples", ""])
        for bucket, samples in view["samples"].items():
            lines.append(f"- `{bucket}`: `{len(samples)}` sample(s)")
    lines.append("")
    return lines


def run_smoke(runtime: NahRuntime) -> None:
    cases = [
        {
            "name": "npm script args with transparent tail is measured",
            "command": 'npm run test:e2e -- --project=chromium -g "adds" 2>&1 | tail -60',
            "root": "",
            "allowed_decisions": {"allow", "ask"},
        },
        {
            "name": "Yanghu absolute write normalizes inside project",
            "command": f"mkdir -p {YANGHU_PREFIX}video/logs",
            "root": f"{YANGHU_PREFIX}video",
            "expected_decision": "allow",
        },
        {
            "name": "Yanghu redirect target normalizes inside project",
            "command": f"cat > {YANGHU_PREFIX}video/PATCHES/wu-001.diff << 'EOF'\nhello\nEOF",
            "root": f"{YANGHU_PREFIX}video",
            "expected_decision": "allow",
        },
        {
            "name": "sensitive path remains sensitive",
            "command": f"git add {YANGHU_PREFIX}video/.env.local",
            "root": f"{YANGHU_PREFIX}video",
            "expected_decision": "ask",
            "expected_bucket": "sensitive_path",
        },
        {
            "name": "remote code execution remains blocked",
            "command": 'curl -s "http://localhost:3001/api" | python3 -c "import sys; print(sys.stdin.read())"',
            "root": "",
            "expected_decision": "block",
        },
    ]
    failures = []
    for case in cases:
        result = classify(runtime, case["command"], case["root"])
        allowed_decisions = case.get("allowed_decisions") or {case["expected_decision"]}
        if result.final_decision not in allowed_decisions:
            failures.append(
                f"{case['name']}: expected one of {sorted(allowed_decisions)}, "
                f"got {result.final_decision}: {result.reason}"
            )
            continue
        expected_bucket = case.get("expected_bucket")
        if expected_bucket:
            bucket = reason_bucket(result.reason or "", [stage.action_type for stage in result.stages])
            if bucket != expected_bucket:
                failures.append(f"{case['name']}: expected bucket {expected_bucket}, got {bucket}: {result.reason}")

    ambiguous_cmd = f"cp {YANGHU_PREFIX}video/a.txt {YANGHU_PREFIX}music/a.txt"
    root, status = infer_replay_root(ambiguous_cmd, "")
    if root or status != "ambiguous_project":
        failures.append(f"ambiguous project inference failed: root={root!r}, status={status!r}")

    if failures:
        raise SystemExit("\n".join(failures))
    print("smoke: pass")


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv or sys.argv[1:])
    runtime = load_nah(args.nah_src)
    if args.smoke:
        run_smoke(runtime)
        return
    report = run_benchmark(args, runtime)
    write_reports(report, args.out_json, args.out_md)
    raw = report["views"]["raw"]
    normalized = report["views"]["replay_normalized"]
    print(
        "raw: "
        f"{raw['total']} Bash calls, "
        f"{raw['decisions']}, "
        f"friction={raw['review_friction_rate']:.2%}"
    )
    print(
        "replay_normalized: "
        f"{normalized['total']} Bash calls, "
        f"{normalized['decisions']}, "
        f"friction={normalized['review_friction_rate']:.2%}"
    )
    print(f"wrote {args.out_json}")
    print(f"wrote {args.out_md}")


if __name__ == "__main__":
    main()
