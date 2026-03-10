"""Tests for multi-agent support — tool mapping, detection, output formatting."""

from nah import agents


# --- Tool mapping ---


class TestNormalizeTool:
    def test_claude_tools_identity(self):
        for tool in ("Bash", "Read", "Write", "Edit", "Glob", "Grep"):
            assert agents.normalize_tool(tool) == tool

    def test_cursor_tools(self):
        assert agents.normalize_tool("Shell") == "Bash"
        assert agents.normalize_tool("read_file") == "Read"
        assert agents.normalize_tool("write_to_file") == "Write"
        assert agents.normalize_tool("edit_file") == "Edit"
        assert agents.normalize_tool("list_dir") == "Glob"
        assert agents.normalize_tool("grep") == "Grep"

    def test_kiro_tools(self):
        assert agents.normalize_tool("execute_bash") == "Bash"
        assert agents.normalize_tool("shell") == "Bash"
        assert agents.normalize_tool("fs_read") == "Read"
        assert agents.normalize_tool("fs_write") == "Write"
        assert agents.normalize_tool("fs_edit") == "Edit"

    def test_unknown_passthrough(self):
        assert agents.normalize_tool("UnknownTool") == "UnknownTool"
        assert agents.normalize_tool("SomeOtherThing") == "SomeOtherThing"


# --- Agent detection ---


class TestDetectAgent:
    def test_claude_tools(self):
        for tool in ("Bash", "Read", "Write", "Edit", "Glob", "Grep"):
            assert agents.detect_agent(tool) == "claude"

    def test_cursor_tools(self):
        for tool in ("Shell", "read_file", "write_to_file", "edit_file", "list_dir"):
            assert agents.detect_agent(tool) == "cursor"

    def test_kiro_tools(self):
        for tool in ("execute_bash", "fs_read", "fs_write", "fs_edit"):
            assert agents.detect_agent(tool) == "kiro"

    def test_unknown_defaults_claude(self):
        assert agents.detect_agent("UnknownTool") == "claude"
        assert agents.detect_agent("") == "claude"


# --- Output formatting ---


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
