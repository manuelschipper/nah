"""Tests for multi-agent support — tool mapping, detection, output formatting."""

from nah import agents


# --- Tool mapping ---


class TestNormalizeTool:
    def test_claude_tools_identity(self):
        for tool in ("Bash", "Read", "Write", "Edit", "Glob", "Grep"):
            assert agents.normalize_tool(tool) == tool

    def test_cursor_tool(self):
        # Cursor's only unique hook tool name
        assert agents.normalize_tool("Shell") == "Bash"
        # Read/Write/Grep are same name as Claude (identity mapping)

    def test_kiro_tools(self):
        assert agents.normalize_tool("execute_bash") == "Bash"
        assert agents.normalize_tool("shell") == "Bash"
        assert agents.normalize_tool("fs_read") == "Read"
        assert agents.normalize_tool("fs_write") == "Write"
        assert agents.normalize_tool("glob") == "Glob"
        assert agents.normalize_tool("grep") == "Grep"

    def test_unknown_passthrough(self):
        assert agents.normalize_tool("UnknownTool") == "UnknownTool"
        assert agents.normalize_tool("SomeOtherThing") == "SomeOtherThing"


# --- Agent detection ---


class TestDetectAgent:
    """Agent detection uses payload fields first, tool names as fallback."""

    def test_claude_tools_bare(self):
        """Bare Claude tool names → claude."""
        for tool in ("Bash", "Read", "Write", "Edit", "Glob", "Grep"):
            assert agents.detect_agent(tool) == "claude"

    def test_claude_payload(self):
        """Claude payload (no special fields) → claude."""
        assert agents.detect_agent({"tool_name": "Bash"}) == "claude"
        assert agents.detect_agent({"tool_name": "Read"}) == "claude"

    def test_cursor_by_payload(self):
        """cursor_version in payload → cursor (even for shared tool names)."""
        assert agents.detect_agent({"tool_name": "Read", "cursor_version": "1.0"}) == "cursor"
        assert agents.detect_agent({"tool_name": "Write", "cursor_version": "1.0"}) == "cursor"
        assert agents.detect_agent({"tool_name": "Shell", "cursor_version": "1.0"}) == "cursor"

    def test_cursor_by_tool_fallback(self):
        """Shell (unique to Cursor) → cursor even without payload marker."""
        assert agents.detect_agent("Shell") == "cursor"
        assert agents.detect_agent({"tool_name": "Shell"}) == "cursor"

    def test_kiro_by_tool(self):
        """Kiro-specific snake_case tool names → kiro."""
        for tool in ("execute_bash", "shell", "fs_read", "fs_write", "glob", "grep"):
            assert agents.detect_agent(tool) == "kiro"
        # Also works with full payload dict
        assert agents.detect_agent({"tool_name": "execute_bash"}) == "kiro"
        assert agents.detect_agent({"tool_name": "fs_read"}) == "kiro"

    def test_unknown_defaults_claude(self):
        assert agents.detect_agent("UnknownTool") == "claude"
        assert agents.detect_agent("") == "claude"
        assert agents.detect_agent({"tool_name": "UnknownTool"}) == "claude"

    def test_cursor_beats_kiro_with_both_fields(self):
        """cursor_version takes priority over hook_event_name."""
        data = {"tool_name": "Shell", "cursor_version": "1.0", "hook_event_name": "preToolUse"}
        assert agents.detect_agent(data) == "cursor"

    def test_shared_tool_without_payload_is_claude(self):
        """Read/Write/Grep without payload markers → claude (safe default)."""
        assert agents.detect_agent("Read") == "claude"
        assert agents.detect_agent("Write") == "claude"
        assert agents.detect_agent("Grep") == "claude"

    def test_claude_payload_with_hook_event_name(self):
        """FD-029: Claude Code sends hook_event_name — must NOT be detected as Kiro."""
        data = {"tool_name": "Bash", "hook_event_name": "PreToolUse",
                "session_id": "abc123", "cwd": "/tmp"}
        assert agents.detect_agent(data) == "claude"
        # All PascalCase tools with hook_event_name → claude
        for tool in ("Bash", "Read", "Write", "Edit", "Glob", "Grep"):
            assert agents.detect_agent({"tool_name": tool, "hook_event_name": "PreToolUse"}) == "claude"


# --- Output formatting ---


class TestSupportsAsk:
    def test_claude_supports_ask(self):
        assert agents.supports_ask("claude") is True

    def test_cortex_supports_ask(self):
        assert agents.supports_ask("cortex") is True

    def test_cursor_no_ask(self):
        assert agents.supports_ask("cursor") is False

    def test_kiro_supports_ask(self):
        assert agents.supports_ask("kiro") is True

    def test_unknown_no_ask(self):
        assert agents.supports_ask("unknown") is False


class TestFormatBlock:
    def test_claude_format(self):
        result = agents.format_block("dangerous command", "claude")
        hso = result["hookSpecificOutput"]
        assert hso["permissionDecision"] == "deny"
        assert hso["permissionDecisionReason"] == "nah. dangerous command"
        assert hso["hookEventName"] == "PreToolUse"

    def test_claude_empty_reason(self):
        result = agents.format_block("", "claude")
        hso = result["hookSpecificOutput"]
        assert hso["permissionDecision"] == "deny"
        assert hso["permissionDecisionReason"] == "nah."

    def test_cursor_format(self):
        result = agents.format_block("dangerous command", "cursor")
        assert result["permission"] == "deny"
        assert result["user_message"] == "nah. dangerous command"
        assert result["agent_message"] == "nah. dangerous command"
        assert "hookSpecificOutput" not in result

    def test_kiro_uses_hook_format(self):
        result = agents.format_block("bad stuff", "kiro")
        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


class TestFormatAsk:
    def test_claude_format(self):
        result = agents.format_ask("needs confirmation", "claude")
        hso = result["hookSpecificOutput"]
        assert hso["permissionDecision"] == "ask"
        assert hso["permissionDecisionReason"] == "nah? needs confirmation"

    def test_cursor_format(self):
        result = agents.format_ask("needs confirmation", "cursor")
        assert result["permission"] == "ask"
        assert result["user_message"] == "nah? needs confirmation"

    def test_empty_reason(self):
        result = agents.format_ask("", "claude")
        hso = result["hookSpecificOutput"]
        assert hso["permissionDecisionReason"] == "nah?"


class TestFormatAllow:
    def test_claude_format(self):
        result = agents.format_allow("claude")
        hso = result["hookSpecificOutput"]
        assert hso["permissionDecision"] == "allow"

    def test_cursor_format(self):
        result = agents.format_allow("cursor")
        assert result == {"permission": "allow"}
        assert "hookSpecificOutput" not in result


class TestFormatError:
    def test_claude_format(self):
        result = agents.format_error("oops", "claude")
        hso = result["hookSpecificOutput"]
        assert hso["permissionDecision"] == "ask"
        assert "oops" in hso["permissionDecisionReason"]
        assert "nah: internal error" in hso["permissionDecisionReason"]

    def test_cursor_format(self):
        result = agents.format_error("oops", "cursor")
        assert result["permission"] == "ask"
        assert "oops" in result["user_message"]
