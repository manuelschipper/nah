"""Decision logging — JSONL log with redaction and rotation."""

import json
import os
import re
import sys
from datetime import datetime, timezone

_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "nah")
LOG_PATH = os.path.join(_CONFIG_DIR, "nah.log")
_LOG_BACKUP = os.path.join(_CONFIG_DIR, "nah.log.1")

_DEFAULT_VERBOSITY = "all"
_DEFAULT_MAX_SIZE = 5_000_000  # 5 MB

_ENV_VALUE_RE = re.compile(r"(export\s+\w+=)(\S+)")


def log_decision(entry: dict, log_config: dict | None = None) -> None:
    """Write a JSONL log entry. Never raises."""
    try:
        cfg = log_config or {}
        verbosity = cfg.get("verbosity", _DEFAULT_VERBOSITY)
        decision = entry.get("decision", "allow")

        if verbosity == "blocks_only" and decision != "block":
            return
        if verbosity == "decisions" and decision == "allow":
            return

        if "ts" not in entry:
            entry["ts"] = datetime.now(timezone.utc).isoformat(timespec="milliseconds")

        line = json.dumps(entry, separators=(",", ":")) + "\n"

        os.makedirs(_CONFIG_DIR, exist_ok=True)

        max_size = cfg.get("max_size_bytes", _DEFAULT_MAX_SIZE)
        try:
            if os.path.getsize(LOG_PATH) > max_size:
                _rotate()
        except OSError:
            pass

        with open(LOG_PATH, "a") as f:
            f.write(line)
    except Exception as exc:
        try:
            sys.stderr.write(f"nah: log: {exc}\n")
        except Exception:
            pass


def _rotate() -> None:
    """Rotate log: current -> .1, start fresh."""
    try:
        if not os.path.exists(LOG_PATH) or os.path.getsize(LOG_PATH) == 0:
            return
        if os.path.exists(_LOG_BACKUP):
            os.unlink(_LOG_BACKUP)
        os.rename(LOG_PATH, _LOG_BACKUP)
    except OSError as exc:
        sys.stderr.write(f"nah: log: rotation: {exc}\n")
        try:
            with open(LOG_PATH, "w") as f:
                f.write("")
        except OSError as exc2:
            sys.stderr.write(f"nah: log: rotation reset: {exc2}\n")


def build_entry(
    tool: str, input_summary: str, decision: str, reason: str,
    agent: str, hook_version: str, total_ms: int,
    meta: dict, transcript_path: str = "",
) -> dict:
    """Build a structured log entry with core + detail fields."""
    from nah.paths import get_project_root  # lazy import to avoid circular

    entry: dict = {
        "id": os.urandom(8).hex(),
        "user": os.environ.get("USER", ""),
        "agent": agent,
        "hook_version": hook_version,
        "tool": tool,
        "input": input_summary,
        "project": get_project_root() or "",
        "session": os.path.basename(transcript_path) if transcript_path else "",
        "decision": decision,
        "reason": reason,
        "action_type": _extract_action_type(meta),
        "ms": total_ms,
    }

    # Detail: classify
    stages = meta.get("stages")
    if stages:
        classify: dict = {"stages": stages}
        comp = meta.get("composition_rule")
        if comp:
            classify["composition"] = comp
        redir = meta.get("redirect_target", "")
        if redir:
            classify["redirect_target"] = redir
        entry["classify"] = classify

    # Detail: llm — log whenever LLM was attempted (provider set or cascade exists)
    llm_provider = meta.get("llm_provider", "")
    llm_cascade = meta.get("llm_cascade")
    if llm_provider or llm_cascade:
        llm: dict = {
            "provider": llm_provider or "(none)",
            "model": meta.get("llm_model", ""),
            "ms": meta.get("llm_latency_ms", 0),
            "decision": meta.get("llm_decision", ""),
            "reasoning": meta.get("llm_reasoning", ""),
        }
        if llm_cascade:
            llm["cascade"] = llm_cascade
        prompt = meta.get("llm_prompt")
        if prompt:
            llm["prompt"] = prompt
        entry["llm"] = llm

    # Detail: hint, content_match, warning
    hint = meta.get("hint")
    if hint:
        entry["hint"] = hint
    content = meta.get("content_match")
    if content:
        entry["content_match"] = content
    warning = meta.get("warning")
    if warning:
        entry["warning"] = warning

    return entry


def _extract_action_type(meta: dict) -> str:
    """Extract primary action_type: first ask/block stage, else first stage."""
    stages = meta.get("stages", [])
    for s in stages:
        if s.get("decision") in ("ask", "block"):
            return s.get("action_type", "")
    return stages[0].get("action_type", "") if stages else ""


def redact_input(tool: str, tool_input: dict) -> str:
    """Build a redacted input summary string."""
    if tool == "Bash":
        cmd = tool_input.get("command", "")[:200]
        return _ENV_VALUE_RE.sub(r"\1***", cmd)

    if tool in ("Read", "Glob"):
        return tool_input.get("file_path", "") or tool_input.get("path", "") or tool_input.get("pattern", "")

    if tool == "Grep":
        path = tool_input.get("path", "")
        pattern = tool_input.get("pattern", "")
        return f"pattern={pattern} path={path}" if path else f"pattern={pattern}"

    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        return tool_input.get("file_path", "") or tool_input.get("notebook_path", "")

    if tool.startswith("mcp__"):
        for key, val in tool_input.items():
            return f"{key}={str(val)[:100]}"
        return ""

    return ""


def read_log(filters: dict | None = None, limit: int = 50) -> list[dict]:
    """Read recent log entries, newest first. For CLI display."""
    filters = filters or {}
    if not os.path.isfile(LOG_PATH):
        return []

    entries = []
    try:
        with open(LOG_PATH) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if "decision" in filters and entry.get("decision") != filters["decision"]:
                    continue
                if "tool" in filters and entry.get("tool") != filters["tool"]:
                    continue

                entries.append(entry)
    except OSError:
        return []

    entries.reverse()
    return entries[:limit]
