"""Multi-agent support — tool name mapping, agent detection, output formatting.

Supports Claude Code, Cortex Code, Cursor, and Kiro CLI. The hook script
auto-detects the calling agent from the tool name and formats output accordingly.
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# Tool name → canonical handler name
# ---------------------------------------------------------------------------

TOOL_MAP: dict[str, str] = {
    # Claude Code / Cortex Code (canonical)
    "Bash": "Bash",
    "Read": "Read",
    "Write": "Write",
    "Edit": "Edit",
    "Glob": "Glob",
    "Grep": "Grep",
    # Cursor
    "Shell": "Bash",
    "read_file": "Read",
    "write_to_file": "Write",
    "edit_file": "Edit",
    "list_dir": "Glob",
    # Note: Cursor's "grep" (lowercase) vs Claude's "Grep" (PascalCase)
    "grep": "Grep",
    # Kiro CLI
    "execute_bash": "Bash",
    "shell": "Bash",
    "fs_read": "Read",
    "fs_write": "Write",
    "fs_edit": "Edit",
}


def normalize_tool(tool_name: str) -> str:
    """Map agent-specific tool name to canonical handler name."""
    return TOOL_MAP.get(tool_name, tool_name)


# ---------------------------------------------------------------------------
# Agent detection from tool name
# ---------------------------------------------------------------------------

_CURSOR_TOOLS = {"Shell", "read_file", "write_to_file", "edit_file", "list_dir"}
_KIRO_TOOLS = {"execute_bash", "fs_read", "fs_write", "fs_edit"}

# Agent type constants
CLAUDE = "claude"
CORTEX = "cortex"
CURSOR = "cursor"
KIRO = "kiro"


def detect_agent(tool_name: str) -> str:
    """Detect which agent is calling based on tool name.

    Claude and Cortex use the same tool names and output format, so both
    return 'claude'. Cursor and Kiro have distinct tool names.
    """
    if tool_name in _CURSOR_TOOLS:
        return CURSOR
    if tool_name in _KIRO_TOOLS:
        return KIRO
    # Claude and Cortex use identical tool names — treat the same.
    return CLAUDE


# ---------------------------------------------------------------------------
# Output formatting per agent
# ---------------------------------------------------------------------------

def format_block(reason: str, agent: str) -> dict:
    """Format a block/deny response for the given agent."""
    branded = f"nah. {reason}" if reason else "nah."
    if agent == CURSOR:
        return {"permission": "deny", "user_message": branded, "agent_message": branded}
    # Claude / Cortex / Kiro — hookSpecificOutput protocol
    result: dict = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"}}
    if branded:
        result["hookSpecificOutput"]["permissionDecisionReason"] = branded
    return result


def format_ask(reason: str, agent: str) -> dict:
    """Format an ask/confirm response for the given agent."""
    branded = f"nah? {reason}" if reason else "nah?"
    if agent == CURSOR:
        return {"permission": "ask", "user_message": branded, "agent_message": branded}
    result: dict = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask"}}
    if branded:
        result["hookSpecificOutput"]["permissionDecisionReason"] = branded
    return result


def format_allow(agent: str) -> dict:
    """Format an allow response for the given agent."""
    if agent == CURSOR:
        return {"permission": "allow"}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}


def format_error(error: str, agent: str) -> dict:
    """Format an error response (ask with error message)."""
    msg = f"nah: internal error: {error}"
    if agent == CURSOR:
        return {"permission": "ask", "user_message": msg, "agent_message": msg}
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask",
        "permissionDecisionReason": msg,
    }}


# ---------------------------------------------------------------------------
# Agent install configs
# ---------------------------------------------------------------------------

# Per-agent tool matchers for hook registration.
AGENT_TOOL_MATCHERS: dict[str, list[str]] = {
    CLAUDE: ["Bash", "Read", "Write", "Edit", "Glob", "Grep"],
    CORTEX: ["Bash", "Read", "Write", "Edit", "Glob", "Grep"],
    CURSOR: ["Shell", "read_file", "write_to_file", "edit_file", "list_dir", "grep"],
    KIRO: ["execute_bash", "shell", "fs_read", "fs_write", "fs_edit"],
}

# Settings file paths per agent.
AGENT_SETTINGS: dict[str, Path] = {
    CLAUDE: Path.home() / ".claude" / "settings.json",
    CORTEX: Path.home() / ".cortex" / "settings.json",
}

# Agents that use the same settings.json format as Claude Code.
# Cursor and Kiro have different config formats — not yet supported for auto-install.
INSTALLABLE_AGENTS = {CLAUDE, CORTEX}

AGENT_NAMES: dict[str, str] = {
    CLAUDE: "Claude Code",
    CORTEX: "Cortex Code",
    CURSOR: "Cursor",
    KIRO: "Kiro CLI",
}
