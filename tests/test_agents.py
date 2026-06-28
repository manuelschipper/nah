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
        assert hso["permissionDecisionReason"] == "nah blocked - dangerous command."
        assert hso["hookEventName"] == "PreToolUse"

    def test_claude_empty_reason(self):
        result = agents.format_block("", "claude")
        hso = result["hookSpecificOutput"]
        assert hso["permissionDecision"] == "deny"
        assert hso["permissionDecisionReason"] == "nah blocked - this was blocked before it could run."

    def test_claude_color_when_enabled(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        config._cached_config = NahConfig(ui_color="always")

        result = agents.format_block("dangerous command", "claude")

        hso = result["hookSpecificOutput"]
        assert hso["permissionDecisionReason"] == "\033[31mnah blocked - dangerous command.\033[0m"


class TestFormatAsk:
    def test_claude_format(self):
        result = agents.format_ask("needs confirmation", "claude")
        hso = result["hookSpecificOutput"]
        assert hso["permissionDecision"] == "ask"
        assert hso["permissionDecisionReason"] == "nah paused - needs confirmation."

    def test_empty_reason(self):
        result = agents.format_ask("", "claude")
        hso = result["hookSpecificOutput"]
        assert hso["permissionDecisionReason"] == "nah paused - this needs confirmation before it can run."

    def test_claude_color_when_enabled(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        config._cached_config = NahConfig(ui_color="always")

        result = agents.format_ask("needs confirmation", "claude")

        hso = result["hookSpecificOutput"]
        assert hso["permissionDecisionReason"] == "\033[33mnah paused - needs confirmation.\033[0m"

    def test_claude_color_respects_no_color(self):
        config._cached_config = NahConfig(ui_color="always")

        result = agents.format_ask("needs confirmation", "claude")

        hso = result["hookSpecificOutput"]
        assert hso["permissionDecisionReason"] == "nah paused - needs confirmation."


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
        assert "nah blocked - internal error" in hso["permissionDecisionReason"]


# --- MCP matcher registration (FD-024) ---


class TestMcpMatchers:
    def test_mcp_matcher_registered(self):
        assert "mcp__.*" in agents.AGENT_TOOL_MATCHERS[agents.CLAUDE]


# --- Devin CLI agent wiring (nah-950) ---


class TestDevinAgent:
    def test_devin_constant(self):
        assert agents.DEVIN == "devin"

    def test_devin_tool_name_mapping(self):
        assert agents.normalize_tool("exec") == "Bash"
        assert agents.normalize_tool("edit") == "Edit"
        assert agents.normalize_tool("read") == "Read"
        assert agents.normalize_tool("grep") == "Grep"
        assert agents.normalize_tool("glob") == "Glob"

    def test_devin_names_do_not_shadow_claude_identity(self):
        # Claude/Codex send capitalized names; the lowercase Devin keys must
        # not disturb the identity mapping for the canonical Claude tools.
        for tool in ("Bash", "Read", "Write", "Edit", "Glob", "Grep"):
            assert agents.normalize_tool(tool) == tool

    def test_devin_installable_and_named(self):
        assert agents.DEVIN in agents.INSTALLABLE_AGENTS
        assert agents.AGENT_NAMES[agents.DEVIN] == "Devin CLI"

    def test_devin_matchers(self):
        matchers = agents.AGENT_TOOL_MATCHERS[agents.DEVIN]
        assert "exec" in matchers
        assert "mcp__.*" in matchers

    def test_devin_settings_user_level(self):
        path = agents.AGENT_SETTINGS[agents.DEVIN]
        # User-level Devin config (mirrors Claude's user-level settings.json).
        assert path.name == "config.json"
        assert "devin" in str(path)
