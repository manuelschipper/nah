"""Hidden Claude Code direct-hook runner used by ``nah _claude-hook``."""

from __future__ import annotations

import io
import json
import os
import sys
from datetime import datetime
from typing import TextIO

_ASK = (
    '{"hookSpecificOutput": {"hookEventName": "PreToolUse", '
    '"permissionDecision": "ask", '
    '"permissionDecisionReason": "nah: error, requesting confirmation"}}\n'
)
_POST_TOOL_EVENTS = {"PostToolUse", "PostToolUseFailure"}
_LOG_MAX = 1_000_000


def _config_dir() -> str:
    appdata = os.environ.get("APPDATA") if sys.platform == "win32" else ""
    if appdata:
        return os.path.join(appdata, "nah")
    return os.path.join(os.path.expanduser("~"), ".config", "nah")


def _log_path() -> str:
    return os.path.join(_config_dir(), "hook-errors.log")


def _log_error(tool_name: str, error: BaseException) -> None:
    """Append a hook failure entry without interrupting Claude hook handling."""
    try:
        etype = type(error).__name__
        msg = str(error)[:200]
        line = (
            f"{datetime.now().isoformat(timespec='seconds')} "
            f"{tool_name or 'unknown'} {etype}: {msg}\n"
        )
        path = _log_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        mode = "w" if size > _LOG_MAX else "a"
        with open(path, mode, encoding="utf-8") as f:
            f.write(line)
    except Exception as exc:
        # Hook error logging is best-effort. The hook decision fallback below is
        # more important than making an advisory diagnostic fatal.
        sys.stderr.write(f"nah: hook error log: {exc}\n")


def _safe_write(stdout: TextIO, data: str) -> None:
    try:
        stdout.write(data)
        stdout.flush()
    except BrokenPipeError:
        # Claude already closed the hook pipe; exiting zero is safer than
        # turning a completed decision into a Python shutdown error.
        pass


def _payload_dict(payload: str) -> dict:
    try:
        data = json.loads(payload or "{}")
    except json.JSONDecodeError:
        # Malformed hook payloads cannot be classified. The caller falls back
        # to the conservative PreToolUse ask response.
        return {}
    return data if isinstance(data, dict) else {}


def _extract_tool_name(payload: str) -> str:
    return str(_payload_dict(payload).get("tool_name") or "")


def _extract_hook_event(payload: str) -> str:
    data = _payload_dict(payload)
    return str(data.get("hook_event_name") or data.get("hookEventName") or "PreToolUse")


def _fallback_output(event_name: str) -> str:
    if event_name in _POST_TOOL_EVENTS:
        return ""
    return _ASK


def main(stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    """Run the installed nah Claude hook with stdout capture and safe fallback."""
    hook_stdin = sys.stdin if stdin is None else stdin
    hook_stdout = sys.stdout if stdout is None else stdout
    payload = ""
    tool_name = ""
    event_name = ""
    real_stdin = sys.stdin
    real_stdout = sys.stdout
    try:
        payload = hook_stdin.read()
        tool_name = _extract_tool_name(payload)
        event_name = _extract_hook_event(payload)

        captured = io.StringIO()
        sys.stdin = io.StringIO(payload)
        sys.stdout = captured
        try:
            from nah.hook import main as hook_main

            hook_main()
        finally:
            sys.stdin = real_stdin
            sys.stdout = real_stdout

        output = captured.getvalue()
        if not output.strip():
            return 0
        try:
            json.loads(output)
        except (json.JSONDecodeError, ValueError) as exc:
            _log_error(tool_name, ValueError(f"invalid JSON from main: {output[:200]}"))
            _safe_write(hook_stdout, _fallback_output(event_name))
            return 0
        _safe_write(hook_stdout, output)
        return 0
    except BaseException as exc:
        sys.stdin = real_stdin
        sys.stdout = real_stdout
        _log_error(tool_name, exc)
        _safe_write(hook_stdout, _fallback_output(event_name))
        return 0
