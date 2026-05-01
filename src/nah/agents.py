"""Agent support — tool name mapping, agent detection, output formatting.

Supports Claude Code. The hook script detects the calling agent from payload
fields and formats output accordingly.
"""

from pathlib import Path

from nah.messages import brand

# ---------------------------------------------------------------------------
# Tool name → canonical handler name
# ---------------------------------------------------------------------------

TOOL_MAP: dict[str, str] = {
    # Claude Code (canonical — identity mapping)
    "Bash": "Bash",
    "Read": "Read",
    "Write": "Write",
    "Edit": "Edit",
    "MultiEdit": "MultiEdit",
    "NotebookEdit": "NotebookEdit",
    "Glob": "Glob",
    "Grep": "Grep",
}


def normalize_tool(tool_name: str) -> str:
    """Map agent-specific tool name to canonical handler name."""
    return TOOL_MAP.get(tool_name, tool_name)


# ---------------------------------------------------------------------------
# Agent detection
# ---------------------------------------------------------------------------

# Agent type constants
CLAUDE = "claude"
CODEX = "codex"


def detect_agent(data) -> str:
    """Detect which agent is calling.

    Accepts either a full payload dict or a bare tool name string.
    """
    return CLAUDE


# ---------------------------------------------------------------------------
# Output formatting per agent
# ---------------------------------------------------------------------------

def format_block(reason: str, agent: str) -> dict:
    """Format a block/deny response for the given agent."""
    branded = brand("nah blocked", reason or "this was blocked before it could run")
    result: dict = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"}}
    if branded:
        result["hookSpecificOutput"]["permissionDecisionReason"] = branded
    return result


def format_ask(reason: str, agent: str, system_message: str = "") -> dict:
    """Format an ask/confirm response for the given agent."""
    branded = brand("nah paused", reason or "this needs confirmation before it can run")
    result: dict = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask"}}
    if branded:
        result["hookSpecificOutput"]["permissionDecisionReason"] = branded
    if system_message:
        result["systemMessage"] = system_message  # top-level, shown to user
    return result


def format_allow(agent: str) -> dict:
    """Format an allow response for the given agent."""
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}


def format_error(error: str, agent: str) -> dict:
    """Format an error response (deny with error message)."""
    msg = (
        f"nah: internal error — blocked for safety: {error}\n"
        "      To bypass: nah uninstall | To debug: nah log --tail"
    )
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": msg,
    }}


# ---------------------------------------------------------------------------
# Agent install configs
# ---------------------------------------------------------------------------

# Per-agent tool matchers for hook registration.
AGENT_TOOL_MATCHERS: dict[str, list[str]] = {
    CLAUDE: ["Bash", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Glob", "Grep", "mcp__.*"],
}

# Settings/hooks file paths per agent.
AGENT_SETTINGS: dict[str, Path] = {
    CLAUDE: Path.home() / ".claude" / "settings.json",
}

# Agents whose config format we can auto-install into.
INSTALLABLE_AGENTS = {CLAUDE}

AGENT_NAMES: dict[str, str] = {
    CLAUDE: "Claude Code",
    CODEX: "OpenAI Codex",
}
