"""Multi-agent support — tool name mapping, agent detection, output formatting.

Supports Claude Code, Cortex Code, Cursor, and Kiro CLI. The hook script
auto-detects the calling agent from payload fields and formats output accordingly.
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# Tool name → canonical handler name
# ---------------------------------------------------------------------------

TOOL_MAP: dict[str, str] = {
    # Claude Code / Cortex Code (canonical — identity mapping)
    "Bash": "Bash",
    "Read": "Read",
    "Write": "Write",
    "Edit": "Edit",
    "Glob": "Glob",
    "Grep": "Grep",
    # Cursor (hook-facing names; Read/Write/Grep are same as Claude)
    "Shell": "Bash",
    "write_to_file": "Write",  # Cursor
    # Kiro CLI (snake_case names)
    "execute_bash": "Bash",
    "shell": "Bash",
    "fs_read": "Read",
    "fs_write": "Write",
    "glob": "Glob",
    "grep": "Grep",
}


def normalize_tool(tool_name: str) -> str:
    """Map agent-specific tool name to canonical handler name."""
    return TOOL_MAP.get(tool_name, tool_name)


# ---------------------------------------------------------------------------
# Agent detection
# ---------------------------------------------------------------------------

# Tool names unique to each agent (used as fallback when no payload markers).
_CURSOR_TOOLS = {"Shell"}
_KIRO_TOOLS = {"execute_bash", "shell", "fs_read", "fs_write", "glob", "grep"}

# Agent type constants
CLAUDE = "claude"
CORTEX = "cortex"
CURSOR = "cursor"
KIRO = "kiro"

_ASK_SUPPORT = {CLAUDE, CORTEX, KIRO}


def supports_ask(agent: str) -> bool:
    """Whether the agent's hook protocol supports ask (user confirmation)."""
    return agent in _ASK_SUPPORT


def detect_agent(data) -> str:
    """Detect which agent is calling.

    Accepts either a full payload dict or a bare tool name string.
    Uses payload fields for reliable detection (cursor_version),
    falls back to tool name heuristics for bare strings and unknown payloads.

    Note: hook_event_name is NOT a reliable Kiro detector — Claude Code also
    sends it in all hook payloads (FD-029).
    """
    if isinstance(data, str):
        data = {"tool_name": data}
    # Cursor sends cursor_version in every hook payload
    if "cursor_version" in data:
        return CURSOR
    # Detect from tool name — Kiro uses snake_case, Claude/Cortex use PascalCase
    tool_name = data.get("tool_name", "")
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
    CLAUDE: ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "mcp__.*"],
    CORTEX: ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "mcp__.*"],
    CURSOR: ["Shell", "Read", "Write", "Grep"],
}

# Settings/hooks file paths per agent.
AGENT_SETTINGS: dict[str, Path] = {
    CLAUDE: Path.home() / ".claude" / "settings.json",
    CORTEX: Path.home() / ".cortex" / "settings.json",
    CURSOR: Path.home() / ".cursor" / "hooks.json",
}

# Agents whose config format we can auto-install into.
# Claude/Cortex: settings.json with nested hooks format.
# Cursor: disabled — no ask support in hook protocol (FD-033). Code retained for future.
# Kiro: disabled — IDE uses .kiro.hook files, CLI uses agent JSON. Needs further work.
INSTALLABLE_AGENTS = {CLAUDE, CORTEX}

# Config format groups — determines how install reads/writes the config.
CURSOR_FORMAT_AGENTS = {CURSOR}

AGENT_NAMES: dict[str, str] = {
    CLAUDE: "Claude Code",
    CORTEX: "Cortex Code",
    CURSOR: "Cursor",
    KIRO: "Kiro",
}
