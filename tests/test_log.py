"""Unit tests for the decision logging module."""

import json
import os

import pytest

from nah import log


@pytest.fixture(autouse=True)
def _use_tmp_log(tmp_path, monkeypatch):
    """Redirect log to tmp_path for all tests."""
    log_path = str(tmp_path / "nah.log")
    backup_path = str(tmp_path / "nah.log.1")
    monkeypatch.setattr(log, "LOG_PATH", log_path)
    monkeypatch.setattr(log, "_LOG_BACKUP", backup_path)
    monkeypatch.setattr(log, "_CONFIG_DIR", str(tmp_path))


# -- redact_input --


class TestRedactInput:
    def test_bash_command(self):
        result = log.redact_input("Bash", {"command": "git status"})
        assert result == "git status"

    def test_bash_truncated_at_200(self):
        long_cmd = "x" * 300
        result = log.redact_input("Bash", {"command": long_cmd})
        assert len(result) == 200

    def test_bash_env_redacted(self):
        result = log.redact_input("Bash", {"command": "export SECRET_KEY=abc123"})
        assert "abc123" not in result
        assert "export SECRET_KEY=***" in result

    def test_bash_multiple_exports(self):
        result = log.redact_input("Bash", {"command": "export A=1 && export B=2"})
        assert "export A=***" in result
        assert "export B=***" in result

    def test_read_file_path(self):
        result = log.redact_input("Read", {"file_path": "/tmp/foo.py"})
        assert result == "/tmp/foo.py"

    def test_glob_pattern(self):
        result = log.redact_input("Glob", {"pattern": "**/*.py"})
        assert result == "**/*.py"

    def test_grep_with_path(self):
        result = log.redact_input("Grep", {"pattern": "TODO", "path": "src/"})
        assert result == "pattern=TODO path=src/"

    def test_grep_without_path(self):
        result = log.redact_input("Grep", {"pattern": "TODO"})
        assert result == "pattern=TODO"

    def test_write_path_only(self):
        result = log.redact_input("Write", {"file_path": "/tmp/x.py", "content": "SECRET=abc"})
        assert result == "/tmp/x.py"
        assert "SECRET" not in result

    def test_edit_path_only(self):
        result = log.redact_input("Edit", {"file_path": "/tmp/x.py", "new_string": "password=abc"})
        assert result == "/tmp/x.py"
        assert "password" not in result

    def test_mcp_tool(self):
        result = log.redact_input("mcp__postgres__query", {"query": "SELECT * FROM users"})
        assert "query=" in result
        assert "SELECT" in result

    def test_mcp_tool_empty_input(self):
        result = log.redact_input("mcp__foo__bar", {})
        assert result == ""

    def test_unknown_tool(self):
        result = log.redact_input("Agent", {"foo": "bar"})
        assert result == ""


# -- log_decision --


class TestLogDecision:
    def test_writes_jsonl(self, tmp_path):
        log.log_decision({"decision": "allow", "tool": "Bash"})
        path = str(tmp_path / "nah.log")
        with open(path) as f:
            lines = f.readlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["decision"] == "allow"
        assert entry["tool"] == "Bash"
        assert "ts" in entry

    def test_appends_multiple(self, tmp_path):
        log.log_decision({"decision": "allow"})
        log.log_decision({"decision": "block"})
        path = str(tmp_path / "nah.log")
        with open(path) as f:
            lines = [l for l in f.readlines() if l.strip()]
        assert len(lines) == 2

    def test_preserves_existing_ts(self):
        log.log_decision({"decision": "allow", "ts": "2026-01-01T00:00:00"})
        # Didn't crash, ts preserved

    def test_llm_fields_preserved(self, tmp_path):
        log.log_decision({
            "decision": "allow",
            "tool": "Bash",
            "llm_provider": "openrouter",
            "llm_model": "gemini-flash",
            "llm_latency_ms": 500,
            "llm_reasoning": "safe operation",
            "llm_cascade": [{"provider": "openrouter", "status": "success", "latency_ms": 500}],
        })
        entries = log.read_log()
        assert len(entries) == 1
        assert entries[0]["llm_provider"] == "openrouter"
        assert entries[0]["llm_model"] == "gemini-flash"
        assert entries[0]["llm_cascade"][0]["status"] == "success"

    def test_never_raises_on_bad_path(self, monkeypatch):
        monkeypatch.setattr(log, "LOG_PATH", "/nonexistent/dir/nah.log")
        monkeypatch.setattr(log, "_CONFIG_DIR", "/nonexistent/dir")
        # Should not raise
        log.log_decision({"decision": "allow"})


# -- verbosity --


class TestVerbosityFiltering:
    def test_blocks_only_skips_allow(self, tmp_path):
        log.log_decision({"decision": "allow"}, {"verbosity": "blocks_only"})
        path = str(tmp_path / "nah.log")
        assert not os.path.exists(path) or os.path.getsize(path) == 0

    def test_blocks_only_skips_ask(self, tmp_path):
        log.log_decision({"decision": "ask"}, {"verbosity": "blocks_only"})
        path = str(tmp_path / "nah.log")
        assert not os.path.exists(path) or os.path.getsize(path) == 0

    def test_blocks_only_writes_block(self, tmp_path):
        log.log_decision({"decision": "block"}, {"verbosity": "blocks_only"})
        path = str(tmp_path / "nah.log")
        assert os.path.getsize(path) > 0

    def test_decisions_skips_allow(self, tmp_path):
        log.log_decision({"decision": "allow"}, {"verbosity": "decisions"})
        path = str(tmp_path / "nah.log")
        assert not os.path.exists(path) or os.path.getsize(path) == 0

    def test_decisions_writes_ask(self, tmp_path):
        log.log_decision({"decision": "ask"}, {"verbosity": "decisions"})
        path = str(tmp_path / "nah.log")
        assert os.path.getsize(path) > 0

    def test_decisions_writes_block(self, tmp_path):
        log.log_decision({"decision": "block"}, {"verbosity": "decisions"})
        path = str(tmp_path / "nah.log")
        assert os.path.getsize(path) > 0

    def test_all_writes_everything(self, tmp_path):
        for d in ("allow", "ask", "block"):
            log.log_decision({"decision": d}, {"verbosity": "all"})
        path = str(tmp_path / "nah.log")
        with open(path) as f:
            lines = [l for l in f.readlines() if l.strip()]
        assert len(lines) == 3


# -- rotation --


class TestRotation:
    def test_rotates_on_size(self, tmp_path):
        log_path = str(tmp_path / "nah.log")
        # Write enough to exceed a tiny max_size
        for i in range(100):
            log.log_decision({"decision": "allow", "data": "x" * 100}, {"max_size_bytes": 500})
        # Backup should exist
        backup = str(tmp_path / "nah.log.1")
        assert os.path.exists(backup)
        # Main log should be smaller than total written
        assert os.path.getsize(log_path) < 100 * 200

    def test_no_rotation_on_empty_log(self, tmp_path):
        """FD-084: empty log file is not rotated."""
        log_path = tmp_path / "nah.log"
        log_path.touch()  # empty file
        log._rotate()
        assert not os.path.exists(str(tmp_path / "nah.log.1"))


# -- read_log --


class TestReadLog:
    def test_empty_log(self, tmp_path):
        entries = log.read_log()
        assert entries == []

    def test_returns_newest_first(self, tmp_path):
        log.log_decision({"decision": "allow", "tool": "Bash", "ts": "2026-01-01T00:00:01"})
        log.log_decision({"decision": "block", "tool": "Read", "ts": "2026-01-01T00:00:02"})
        entries = log.read_log()
        assert len(entries) == 2
        assert entries[0]["ts"] == "2026-01-01T00:00:02"
        assert entries[1]["ts"] == "2026-01-01T00:00:01"

    def test_filter_by_decision(self, tmp_path):
        log.log_decision({"decision": "allow"})
        log.log_decision({"decision": "block"})
        entries = log.read_log(filters={"decision": "block"})
        assert len(entries) == 1
        assert entries[0]["decision"] == "block"

    def test_filter_by_tool(self, tmp_path):
        log.log_decision({"decision": "allow", "tool": "Bash"})
        log.log_decision({"decision": "allow", "tool": "Read"})
        entries = log.read_log(filters={"tool": "Bash"})
        assert len(entries) == 1
        assert entries[0]["tool"] == "Bash"

    def test_limit(self, tmp_path):
        for i in range(20):
            log.log_decision({"decision": "allow", "i": i})
        entries = log.read_log(limit=5)
        assert len(entries) == 5

    def test_handles_corrupt_lines(self, tmp_path):
        log_path = str(tmp_path / "nah.log")
        with open(log_path, "w") as f:
            f.write('{"decision": "allow"}\n')
            f.write('not json\n')
            f.write('{"decision": "block"}\n')
        entries = log.read_log()
        assert len(entries) == 2
