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
    """Rotate log: current -> .1, start fresh.

    Only performs rotation if the current log file exists and has content.
    This avoids creating unnecessary empty log files.
    """
    try:
        # Only rotate if the current log file exists and is non-empty
        if not os.path.exists(LOG_PATH):
            return
        if os.path.getsize(LOG_PATH) == 0:
            return

        if os.path.exists(_LOG_BACKUP):
            os.unlink(_LOG_BACKUP)
        os.rename(LOG_PATH, _LOG_BACKUP)
    except OSError as exc:
        sys.stderr.write(f"nah: log: rotation: {exc}\n")
        # Only create/reset log file if rotation failed due to rename issue
        # This ensures we always have a writable log file
        try:
            with open(LOG_PATH, "w") as f:
                f.write("")
        except OSError as exc2:
            sys.stderr.write(f"nah: log: rotation reset: {exc2}\n")


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

    if tool in ("Write", "Edit"):
        return tool_input.get("file_path", "")

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
