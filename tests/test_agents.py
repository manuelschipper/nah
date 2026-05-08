"""Tests for multi-agent support — tool mapping, detection, output formatting."""

from nah import agents, config
from nah.config import NahConfig


# --- Tool mapping ---


class TestNormalizeTool:
    def test_claude_tools_identity(self):
        for tool in ("Bash", "Read", "Write", "Edit", "Glob", "Grep"):
            assert agents.normalize_tool(tool) == tool

    def test_unknown_passthrough(self):
        assert agents.normalize_tool("UnknownTool") == "UnknownTool"
        assert agents.normalize_tool("SomeOtherThing") == "SomeOtherThing"


# --- Agent detection ---


class TestDetectAgent:
    """Agent detection defaults to claude for all inputs."""

    def test_claude_tools_bare(self):
        """Bare Claude tool names → claude."""
        for tool in ("Bash", "Read", "Write", "Edit", "Glob", "Grep"):
            assert agents.detect_agent(tool) == "claude"

    def test_claude_payload(self):
        """Claude payload (no special fields) → claude."""
        assert agents.detect_agent({"tool_name": "Bash"}) == "claude"
        assert agents.detect_agent({"tool_name": "Read"}) == "claude"

    def test_unknown_defaults_claude(self):
        assert agents.detect_agent("UnknownTool") == "claude"
        assert agents.detect_agent("") == "claude"
        assert agents.detect_agent({"tool_name": "UnknownTool"}) == "claude"

    def test_shared_tool_without_payload_is_claude(self):
        """Read/Write/Grep without payload markers → claude (safe default)."""
        assert agents.detect_agent("Read") == "claude"
        assert agents.detect_agent("Write") == "claude"
        assert agents.detect_agent("Grep") == "claude"

    def test_claude_payload_with_hook_event_name(self):
        """FD-029: Claude Code sends hook_event_name — still detected as claude."""
        data = {"tool_name": "Bash", "hook_event_name": "PreToolUse",
                "session_id": "abc123", "cwd": "/tmp"}
        assert agents.detect_agent(data) == "claude"
        for tool in ("Bash", "Read", "Write", "Edit", "Glob", "Grep"):
            assert agents.detect_agent({"tool_name": tool, "hook_event_name": "PreToolUse"}) == "claude"


# --- Output formatting ---


class TestFormatBlock:
    def test_claude_format(self):
        result = agents.format_block("dangerous command", "claude")
        hso = result["hookSpecificOutput"]
        assert hso["permissionDecision"] == "deny"
        assert hso["permissionDecisionReason"] == "nah blocked: dangerous command."
        assert hso["hookEventName"] == "PreToolUse"

    def test_claude_empty_reason(self):
        result = agents.format_block("", "claude")
        hso = result["hookSpecificOutput"]
        assert hso["permissionDecision"] == "deny"
        assert hso["permissionDecisionReason"] == "nah blocked: this was blocked before it could run."

    def test_claude_color_when_enabled(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        config._cached_config = NahConfig(ui_color="always")

        result = agents.format_block("dangerous command", "claude")

        hso = result["hookSpecificOutput"]
        assert hso["permissionDecisionReason"] == "\033[31mnah blocked: dangerous command.\033[0m"


class TestFormatAsk:
    def test_claude_format(self):
        result = agents.format_ask("needs confirmation", "claude")
        hso = result["hookSpecificOutput"]
        assert hso["permissionDecision"] == "ask"
        assert hso["permissionDecisionReason"] == "nah paused: needs confirmation."

    def test_empty_reason(self):
        result = agents.format_ask("", "claude")
        hso = result["hookSpecificOutput"]
        assert hso["permissionDecisionReason"] == "nah paused: this needs confirmation before it can run."

    def test_claude_color_when_enabled(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        config._cached_config = NahConfig(ui_color="always")

        result = agents.format_ask("needs confirmation", "claude")

        hso = result["hookSpecificOutput"]
        assert hso["permissionDecisionReason"] == "\033[33mnah paused: needs confirmation.\033[0m"

    def test_claude_color_respects_no_color(self):
        config._cached_config = NahConfig(ui_color="always")

        result = agents.format_ask("needs confirmation", "claude")

        hso = result["hookSpecificOutput"]
        assert hso["permissionDecisionReason"] == "nah paused: needs confirmation."


class TestFormatAllow:
    def test_claude_format(self):
        result = agents.format_allow("claude")
        hso = result["hookSpecificOutput"]
        assert hso["permissionDecision"] == "allow"


class TestFormatError:
    def test_claude_format(self):
        result = agents.format_error("oops", "claude")
        hso = result["hookSpecificOutput"]
        assert hso["permissionDecision"] == "deny"
        assert "oops" in hso["permissionDecisionReason"]
        assert "nah: internal error" in hso["permissionDecisionReason"]


# --- MCP matcher registration (FD-024) ---


class TestMcpMatchers:
    def test_mcp_matcher_registered(self):
        assert "mcp__.*" in agents.AGENT_TOOL_MATCHERS[agents.CLAUDE]
