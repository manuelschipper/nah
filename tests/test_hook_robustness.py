"""Robustness tests for Claude direct hook stdout capture and fallback."""

import io
import json
import os
import sys

from nah import claude_hooks


def _run(monkeypatch, payload, hook_main):
    monkeypatch.setattr("nah.hook.main", hook_main)
    stdout = io.StringIO()
    rc = claude_hooks.main(stdin=io.StringIO(json.dumps(payload)), stdout=stdout)
    return rc, stdout.getvalue()


class TestBrokenPipe:
    def test_broken_pipe_exit_zero(self, monkeypatch):
        class BrokenPipeStdout(io.StringIO):
            def write(self, _data):
                raise BrokenPipeError()

        def hook_main():
            sys.stdout.write(
                '{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
                '"permissionDecision":"allow"}}\n'
            )

        monkeypatch.setattr("nah.hook.main", hook_main)

        rc = claude_hooks.main(
            stdin=io.StringIO('{"tool_name":"Bash","tool_input":{"command":"ls"}}'),
            stdout=BrokenPipeStdout(),
        )

        assert rc == 0


class TestStdoutBuffering:
    def test_partial_stdout_recovery(self, monkeypatch):
        def hook_main():
            sys.stdout.write('{"decision":')
            raise RuntimeError("mid-write crash")

        rc, output = _run(
            monkeypatch,
            {"hook_event_name": "PreToolUse", "tool_name": "Bash"},
            hook_main,
        )

        assert rc == 0
        out = json.loads(output)
        assert out["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_base_exception_recovery(self, monkeypatch):
        def hook_main():
            raise SystemExit(1)

        rc, output = _run(
            monkeypatch,
            {"hook_event_name": "PreToolUse", "tool_name": "Bash"},
            hook_main,
        )

        assert rc == 0
        out = json.loads(output)
        assert out["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_post_tool_failure_falls_through(self, monkeypatch):
        def hook_main():
            raise RuntimeError("post crash")

        rc, output = _run(
            monkeypatch,
            {"hook_event_name": "PostToolUse", "tool_name": "Bash"},
            hook_main,
        )

        assert rc == 0
        assert output == ""

    def test_empty_output_falls_through(self, monkeypatch):
        rc, output = _run(
            monkeypatch,
            {"hook_event_name": "PreToolUse", "tool_name": "Bash"},
            lambda: None,
        )

        assert rc == 0
        assert output == ""

    def test_valid_json_passes_through(self, monkeypatch):
        expected = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
            }
        }

        def hook_main():
            json.dump(expected, sys.stdout)
            sys.stdout.write("\n")

        rc, output = _run(
            monkeypatch,
            {"hook_event_name": "PreToolUse", "tool_name": "Bash"},
            hook_main,
        )

        assert rc == 0
        assert json.loads(output) == expected


class TestCrashLog:
    def test_crash_log_written(self, tmp_path, monkeypatch):
        log_file = tmp_path / "logs" / "hook-errors.log"
        monkeypatch.setattr(claude_hooks, "_log_path", lambda: str(log_file))

        def hook_main():
            raise RuntimeError("test crash")

        rc, output = _run(
            monkeypatch,
            {"hook_event_name": "PreToolUse", "tool_name": "Bash"},
            hook_main,
        )

        assert rc == 0
        assert json.loads(output)["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert log_file.exists()
        content = log_file.read_text(encoding="utf-8")
        assert "RuntimeError" in content
        assert "test crash" in content

    def test_happy_path_no_log(self, tmp_path, monkeypatch):
        log_file = tmp_path / "logs" / "hook-errors.log"
        monkeypatch.setattr(claude_hooks, "_log_path", lambda: str(log_file))

        def hook_main():
            json.dump(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                    }
                },
                sys.stdout,
            )
            sys.stdout.write("\n")

        rc, output = _run(
            monkeypatch,
            {"hook_event_name": "PreToolUse", "tool_name": "Bash"},
            hook_main,
        )

        assert rc == 0
        assert json.loads(output)["hookSpecificOutput"]["permissionDecision"] == "allow"
        assert not log_file.exists()

    def test_log_rotation(self, tmp_path, monkeypatch):
        log_file = tmp_path / "logs" / "hook-errors.log"
        log_file.parent.mkdir(parents=True)
        log_file.write_text("x" * 1_100_000, encoding="utf-8")
        monkeypatch.setattr(claude_hooks, "_log_path", lambda: str(log_file))

        def hook_main():
            raise RuntimeError("test crash")

        rc, output = _run(
            monkeypatch,
            {"hook_event_name": "PreToolUse", "tool_name": "Bash"},
            hook_main,
        )

        assert rc == 0
        assert json.loads(output)["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert os.path.getsize(log_file) < 1_000
        assert "RuntimeError" in log_file.read_text(encoding="utf-8")
