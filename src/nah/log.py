"""Decision logging — JSONL log with redaction and rotation."""

import getpass
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

from nah.platform_paths import nah_config_dir

_CONFIG_DIR = nah_config_dir()
LOG_PATH = os.path.join(_CONFIG_DIR, "nah.log")
_LOG_BACKUP = os.path.join(_CONFIG_DIR, "nah.log.1")

_DEFAULT_VERBOSITY = "all"
_DEFAULT_MAX_SIZE = 5_000_000  # 5 MB

_ENV_VALUE_RE = re.compile(r"(export\s+\w+=)(\S+)")


def _current_user() -> str:
    """Return a best-effort local username for structured log entries."""
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or os.environ.get("USERNAME")
    if user:
        return user
    try:
        return getpass.getuser()
    except Exception:
        return ""


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
        "user": _current_user(),
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
    preset = meta.get("selected_preset") or meta.get("preset")
    if not preset:
        try:
            from nah.config import get_config

            preset = get_config().selected_preset
        except Exception:
            preset = ""
    if preset:
        entry["selected_preset"] = str(preset)

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
            "reasoning_long": meta.get("llm_reasoning_long", ""),
        }
        if llm_cascade:
            llm["cascade"] = llm_cascade
        review = meta.get("llm_review")
        if review:
            llm["review"] = review
        prompt = meta.get("llm_prompt")
        if prompt:
            llm["prompt"] = prompt
        entry["llm"] = llm

    # Detail: hint, content_match, warning
    human = meta.get("human_reason")
    if human:
        entry["human_reason"] = human
    hint = meta.get("hint")
    if hint:
        entry["hint"] = hint
    content = meta.get("content_match")
    if content:
        entry["content_match"] = content
    warning = meta.get("warning")
    if warning:
        entry["warning"] = warning

    runtime = _copy_log_object(meta.get("runtime"))
    if runtime:
        runtime.setdefault("input_hash", redacted_input_hash(input_summary))
        entry["runtime"] = runtime

    execution = _copy_log_object(meta.get("execution"))
    if execution:
        entry["execution"] = execution

    ask_fallback = _copy_log_object(meta.get("ask_fallback"))
    if ask_fallback:
        entry["ask_fallback"] = ask_fallback

    taint = _copy_log_object(meta.get("taint"))
    if taint:
        entry["taint"] = taint

    provenance = _copy_log_object(meta.get("provenance"))
    if provenance:
        entry["provenance"] = provenance

    for key in (
        "target",
        "source",
        "terminal_event",
        "terminal_confirmed",
        "terminal_bypass",
        "terminal_error",
    ):
        if key in meta:
            entry[key] = meta[key]

    return entry


def redacted_input_hash(input_summary: str) -> str:
    """Return a stable hash of the already-redacted input summary."""
    digest = hashlib.sha256((input_summary or "").encode("utf-8", "replace")).hexdigest()
    return f"sha256:{digest}"


def _copy_log_object(value) -> dict | None:
    """Copy a nested log object while dropping empty optional values."""
    if not isinstance(value, dict):
        return None
    result = {}
    for key, item in value.items():
        if item is None or item == "":
            continue
        result[str(key)] = item
    return result or None


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

    if tool == "apply_patch":
        summary = str(tool_input.get("_nah_patch_summary", ""))[:200]
        paths = tool_input.get("_nah_patch_paths", [])
        if summary:
            return summary
        if isinstance(paths, list):
            return ", ".join(str(p) for p in paths)[:200]
        return ""

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
                if filters.get("llm") and "llm" not in entry:
                    continue

                entries.append(entry)
    except OSError:
        return []

    entries.reverse()
    return entries[:limit]
