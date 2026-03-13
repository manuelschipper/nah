"""Robustness tests — crash recovery, stdout buffering, debug logging."""

import json
import os
import subprocess
import sys
import textwrap

import pytest

PYTHON = sys.executable

_SHIM_BODY = """\
import sys, json, os, io

_REAL_STDOUT = sys.stdout
_ASK = '{{"hookSpecificOutput": {{"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": "nah: error, requesting confirmation"}}}}\\n'
_LOG_PATH = {log_path!r}
_LOG_MAX = 1_000_000

def _log_error(tool_name, error):
    try:
        from datetime import datetime
        ts = datetime.now().isoformat(timespec="seconds")
        etype = type(error).__name__
        msg = str(error)[:200]
        line = f"{{ts}} {{tool_name or 'unknown'}} {{etype}}: {{msg}}\\n"
        os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)
        try:
            size = os.path.getsize(_LOG_PATH)
        except OSError:
            size = 0
        if size > _LOG_MAX:
            with open(_LOG_PATH, "w") as f:
                f.write(line)
        else:
            with open(_LOG_PATH, "a") as f:
                f.write(line)
    except Exception:
        pass

def _safe_write(data):
    try:
        _REAL_STDOUT.write(data)
        _REAL_STDOUT.flush()
    except BrokenPipeError:
        pass

def main():
{main_body}

tool_name = ""
try:
    buf = io.StringIO()
    sys.stdout = buf
    main()
    sys.stdout = _REAL_STDOUT
    output = buf.getvalue()
    if not output.strip():
        pass  # allow — write nothing to stdout
    else:
        try:
            json.loads(output)
            _safe_write(output)
        except (json.JSONDecodeError, ValueError):
            _log_error(tool_name, ValueError(f"invalid JSON from main: {{output[:200]}}"))
            _safe_write(_ASK)
except BaseException as e:
    sys.stdout = _REAL_STDOUT
    _log_error(tool_name, e)
    _safe_write(_ASK)

os._exit(0)
"""


def _get_shim_path():
    """Return the installed nah_guard.py shim path."""
    return os.path.join(os.path.expanduser("~"), ".claude", "hooks", "nah_guard.py")


def _make_shim_script(tmp_path, main_body, *, log_path=None, name="test_shim.py"):
    """Generate a self-contained shim script with a custom main() and optional log path."""
    if log_path is None:
        log_path = os.path.join(
            os.path.expanduser("~"), ".config", "nah", "hook-errors.log"
        )
    indented = textwrap.indent(textwrap.dedent(main_body).strip(), "    ")
    content = _SHIM_BODY.format(log_path=log_path, main_body=indented)
    script = tmp_path / name
    script.write_text(content)
    return script


class TestBrokenPipe:
    def test_broken_pipe_exit_zero(self):
        """Shim exits 0 when stdout pipe is closed early."""
        shim = _get_shim_path()
        if not os.path.exists(shim):
            pytest.skip("nah not installed (no shim)")
        p = subprocess.Popen(
            [PYTHON, shim],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        p.stdin.write(b'{"tool_name":"Bash","tool_input":{"command":"ls"}}')
        p.stdin.close()
        p.stdout.close()
        p.wait()
        assert p.returncode == 0


class TestStdoutBuffering:
    """Fix 5: shim captures main() stdout and validates JSON."""

    def test_partial_stdout_recovery(self, tmp_path):
        """main() writes partial JSON then crashes → shim returns valid ask."""
        script = _make_shim_script(tmp_path, """\
            sys.stdout.write('{"decision":')
            raise RuntimeError("mid-write crash")
        """)
        result = subprocess.run(
            [PYTHON, str(script)], input="", capture_output=True, text=True,
        )
        assert result.returncode == 0
        out = json.loads(result.stdout)
        assert out["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_base_exception_recovery(self, tmp_path):
        """main() raises SystemExit(1) → shim returns ask."""
        script = _make_shim_script(tmp_path, "raise SystemExit(1)")
        result = subprocess.run(
            [PYTHON, str(script)], input="", capture_output=True, text=True,
        )
        assert result.returncode == 0
        out = json.loads(result.stdout)
        assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


class TestCrashLog:
    """Fix 4: debug log on errors only."""

    def test_crash_log_written(self, tmp_path):
        """Error triggers log entry in hook-errors.log."""
        log_file = str(tmp_path / "logs" / "hook-errors.log")
        script = _make_shim_script(
            tmp_path, 'raise RuntimeError("test crash")', log_path=log_file,
        )
        result = subprocess.run(
            [PYTHON, str(script)], input="", capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert os.path.exists(log_file)
        content = open(log_file).read()
        assert "RuntimeError" in content
        assert "test crash" in content

    def test_happy_path_no_log(self, tmp_path):
        """Normal operation creates no crash log. Allow emits active allow JSON (FD-094)."""
        log_file = str(tmp_path / "logs" / "hook-errors.log")
        # Run the real hook with valid input — should not crash-log
        result = subprocess.run(
            [PYTHON, "-m", "nah.hook"],
            input='{"tool_name":"Bash","tool_input":{"command":"ls"}}',
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        # FD-094: active_allow defaults to True, so ALLOW emits JSON
        import json
        output = json.loads(result.stdout)
        assert output["hookSpecificOutput"]["permissionDecision"] == "allow"
        assert not os.path.exists(log_file)

    def test_log_rotation(self, tmp_path):
        """Log file exceeding 1MB gets truncated on next error."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = str(log_dir / "hook-errors.log")
        with open(log_file, "w") as f:
            f.write("x" * 1_100_000)
        assert os.path.getsize(log_file) > 1_000_000

        script = _make_shim_script(
            tmp_path, 'raise RuntimeError("test crash")', log_path=log_file,
        )
        result = subprocess.run(
            [PYTHON, str(script)], input="", capture_output=True, text=True,
        )
        assert result.returncode == 0
        size = os.path.getsize(log_file)
        assert size < 1_000
        content = open(log_file).read()
        assert "RuntimeError" in content
