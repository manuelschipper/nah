#!/usr/bin/env python3
"""Run bundled nah from a Claude Code plugin artifact."""

import io
import json
import os
import sys

_REAL_STDOUT = sys.stdout
_ASK = (
    '{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
    '"permissionDecision":"ask",'
    '"permissionDecisionReason":"nah plugin: error, requesting confirmation"}}\n'
)
_LOG_MAX = 1_000_000


def _nah_config_dir():
    appdata = os.environ.get("APPDATA") if sys.platform == "win32" else ""
    if appdata:
        return os.path.join(appdata, "nah")
    return os.path.join(os.path.expanduser("~"), ".config", "nah")


_LOG_PATH = os.path.join(_nah_config_dir(), "hook-errors.log")


def _plugin_root():
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if root:
        return root
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _log_error(tool_name, error):
    """Append a crash entry to the nah hook log without affecting hook output."""
    try:
        from datetime import datetime

        ts = datetime.now().isoformat(timespec="seconds")
        etype = type(error).__name__
        msg = str(error)[:200]
        line = f"{ts} {tool_name or 'unknown'} {etype}: {msg}\n"
        os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)
        try:
            size = os.path.getsize(_LOG_PATH)
        except OSError:
            size = 0
        mode = "w" if size > _LOG_MAX else "a"
        with open(_LOG_PATH, mode, encoding="utf-8") as f:
            f.write(line)
    except Exception as exc:
        # Logging is diagnostic-only; if the log path is unavailable, the
        # safer behavior is still to return a valid ask response to Claude.
        try:
            sys.stderr.write(f"nah plugin: log failed: {exc}\n")
        except Exception:
            # Nothing else is safer to do during hook error handling.
            pass


def _safe_write(data):
    """Write to real stdout, tolerating a closed Claude hook pipe."""
    try:
        _REAL_STDOUT.write(data)
        _REAL_STDOUT.flush()
    except BrokenPipeError:
        pass


def _extract_tool_name(payload):
    try:
        data = json.loads(payload or "{}")
    except json.JSONDecodeError:
        return ""
    if isinstance(data, dict):
        return str(data.get("tool_name") or "")
    return ""


def _run_hook(payload):
    root = _plugin_root()
    lib_dir = os.path.join(root, "lib")
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)

    old_stdin = sys.stdin
    old_stdout = sys.stdout
    buf = io.StringIO()
    try:
        sys.stdin = io.StringIO(payload)
        sys.stdout = buf
        from nah.hook import main as hook_main

        hook_main()
    finally:
        sys.stdin = old_stdin
        sys.stdout = old_stdout
    return buf.getvalue()


def main():
    tool_name = ""
    try:
        if sys.version_info < (3, 10):
            _safe_write(_ASK)
            return

        payload = sys.stdin.read()
        tool_name = _extract_tool_name(payload)
        output = _run_hook(payload)

        # Empty output means nah active_allow is disabled for this allow
        # decision, so Claude Code's own permission system should decide.
        if not output.strip():
            return

        try:
            json.loads(output)
        except (json.JSONDecodeError, ValueError) as exc:
            _log_error(tool_name, ValueError(f"invalid JSON from main: {output[:200]}"))
            _safe_write(_ASK)
            return

        _safe_write(output)
    except BaseException as exc:
        sys.stdout = _REAL_STDOUT
        _log_error(tool_name, exc)
        _safe_write(_ASK)


if __name__ == "__main__":
    try:
        main()
    finally:
        os._exit(0)
