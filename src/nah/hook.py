"""PreToolUse hook entry point — reads JSON from stdin, returns decision on stdout."""

import json
import re
import sys

from nah import paths

# Tools where hook-path access is hard-blocked (self-protection).
# Write/Edit are definitively modifying → block.
# Bash can't be distinguished (ls vs rm) in Phase 1a → ask.
# Read/Glob/Grep are read-only → ask.
_HOOK_BLOCK_TOOLS = {"Write", "Edit"}

# Regex to find path-like strings in Bash commands (Phase 1a — intentionally naive).
# Matches ~/.<something> and common absolute sensitive prefixes.
_BASH_PATH_RE = re.compile(r"~[/\w.\-]+")


def _check_path(tool_name: str, raw_path: str) -> dict | None:
    """Shared path-check logic. Returns a decision dict or None (= allow)."""
    if not raw_path:
        return None

    resolved = paths.resolve_path(raw_path)
    friendly = paths.friendly_path(resolved)

    # Hook self-protection (highest priority)
    if paths.is_hook_path(resolved):
        if tool_name in _HOOK_BLOCK_TOOLS:
            return {
                "decision": "block",
                "reason": f"{tool_name} targets hook directory: ~/.claude/hooks/ (self-modification blocked)",
            }
        return {
            "decision": "ask",
            "message": f"{tool_name} targets hook directory: ~/.claude/hooks/",
        }

    # Sensitive path check
    matched, pattern, policy = paths.is_sensitive(resolved)
    if matched:
        if policy == "block":
            return {
                "decision": "block",
                "reason": f"{tool_name} targets sensitive path: {pattern}",
            }
        return {
            "decision": "ask",
            "message": f"{tool_name} targets sensitive path: {pattern}",
        }

    return None


def handle_read(tool_input: dict) -> dict:
    return _check_path("Read", tool_input.get("file_path", "")) or {"decision": "allow"}


def handle_write(tool_input: dict) -> dict:
    return _check_path("Write", tool_input.get("file_path", "")) or {"decision": "allow"}


def handle_edit(tool_input: dict) -> dict:
    return _check_path("Edit", tool_input.get("file_path", "")) or {"decision": "allow"}


def handle_glob(tool_input: dict) -> dict:
    raw_path = tool_input.get("path", "")
    if not raw_path:
        return {"decision": "allow"}  # defaults to cwd
    return _check_path("Glob", raw_path) or {"decision": "allow"}


def handle_grep(tool_input: dict) -> dict:
    raw_path = tool_input.get("path", "")
    if not raw_path:
        return {"decision": "allow"}  # defaults to cwd
    return _check_path("Grep", raw_path) or {"decision": "allow"}


def handle_bash(tool_input: dict) -> dict:
    """Naive path extraction from Bash commands (Phase 1a).

    Scans for ~/ path patterns. Real parsing comes in FD-005.
    """
    command = tool_input.get("command", "")
    if not command:
        return {"decision": "allow"}

    # Extract path-like strings from the command
    found_paths = _BASH_PATH_RE.findall(command)
    if not found_paths:
        return {"decision": "allow"}

    # Check each extracted path — most restrictive wins
    block_result = None
    ask_result = None
    for raw_path in found_paths:
        result = _check_path("Bash", raw_path)
        if result is None:
            continue
        if result["decision"] == "block":
            block_result = result
        elif result["decision"] == "ask" and ask_result is None:
            ask_result = result

    return block_result or ask_result or {"decision": "allow"}


HANDLERS = {
    "Bash": handle_bash,
    "Read": handle_read,
    "Write": handle_write,
    "Edit": handle_edit,
    "Glob": handle_glob,
    "Grep": handle_grep,
}


def main():
    try:
        data = json.loads(sys.stdin.read())
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})

        handler = HANDLERS.get(tool_name)
        if handler is None:
            decision = {"decision": "allow"}
        else:
            decision = handler(tool_input)

        json.dump(decision, sys.stdout)
        sys.stdout.write("\n")
        sys.stdout.flush()
    except Exception as e:
        sys.stderr.write(f"nah: error: {e}\n")
        json.dump({"decision": "allow"}, sys.stdout)
        sys.stdout.write("\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
