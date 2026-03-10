"""PreToolUse hook entry point — reads JSON from stdin, returns decision on stdout."""

import json
import os
import sys

from nah import paths, taxonomy
from nah.bash import classify_command
from nah.content import scan_content, format_content_message, is_credential_search


def _check_write_content(tool_name: str, tool_input: dict, content_field: str) -> dict:
    """Shared handler for Write/Edit: path check + content inspection."""
    path_check = paths.check_path(tool_name, tool_input.get("file_path", ""))
    if path_check:
        return path_check
    content = tool_input.get(content_field, "")
    matches = scan_content(content)
    if matches:
        return {"decision": taxonomy.ASK, "message": format_content_message(tool_name, matches)}
    return {"decision": taxonomy.ALLOW}


def handle_read(tool_input: dict) -> dict:
    return paths.check_path("Read", tool_input.get("file_path", "")) or {"decision": taxonomy.ALLOW}


def handle_write(tool_input: dict) -> dict:
    return _check_write_content("Write", tool_input, "content")


def handle_edit(tool_input: dict) -> dict:
    return _check_write_content("Edit", tool_input, "new_string")


def handle_glob(tool_input: dict) -> dict:
    raw_path = tool_input.get("path", "")
    if not raw_path:
        return {"decision": taxonomy.ALLOW}  # defaults to cwd
    return paths.check_path("Glob", raw_path) or {"decision": taxonomy.ALLOW}


def handle_grep(tool_input: dict) -> dict:
    raw_path = tool_input.get("path", "")
    # Path check (if path provided)
    if raw_path:
        path_check = paths.check_path("Grep", raw_path)
        if path_check:
            return path_check

    # Credential search detection
    pattern = tool_input.get("pattern", "")
    if is_credential_search(pattern):
        # Check if searching outside project root
        project_root = paths.get_project_root()
        if project_root:
            resolved_path = paths.resolve_path(raw_path) if raw_path else ""
            real_root = paths.resolve_path(project_root)
            if resolved_path and not (resolved_path == real_root or resolved_path.startswith(real_root + os.sep)):
                return {
                    "decision": taxonomy.ASK,
                    "message": "Grep: credential search pattern outside project root",
                }
        else:
            # No project root — any credential search is suspicious
            if raw_path:
                return {
                    "decision": taxonomy.ASK,
                    "message": "Grep: credential search pattern (no project root)",
                }

    return {"decision": taxonomy.ALLOW}


def handle_bash(tool_input: dict) -> dict:
    """Classify bash commands via the full structural pipeline."""
    command = tool_input.get("command", "")
    if not command:
        return {"decision": taxonomy.ALLOW}

    result = classify_command(command)

    if result.final_decision == taxonomy.BLOCK:
        reason = result.reason
        if result.composition_rule:
            reason = f"[{result.composition_rule}] {reason}"
        return {"decision": taxonomy.BLOCK, "reason": f"Bash: {reason}"}

    if result.final_decision == taxonomy.ASK:
        reason = result.reason
        if result.composition_rule:
            reason = f"[{result.composition_rule}] {reason}"
        return {"decision": taxonomy.ASK, "message": f"Bash: {reason}"}

    return {"decision": taxonomy.ALLOW}


HANDLERS = {
    "Bash": handle_bash,
    "Read": handle_read,
    "Write": handle_write,
    "Edit": handle_edit,
    "Glob": handle_glob,
    "Grep": handle_grep,
}


def _to_hook_output(decision: dict) -> dict:
    """Convert internal decision to Claude Code hookSpecificOutput protocol."""
    d = decision.get("decision", taxonomy.ALLOW)
    reason = decision.get("reason", decision.get("message", ""))
    # Map internal → protocol: allow→allow, ask→ask, block→deny
    perm = "deny" if d == taxonomy.BLOCK else d
    # Brand the reason: "nah." for block, "nah?" for ask
    if reason:
        if d == taxonomy.BLOCK:
            branded = f"nah. {reason}"
        elif d == taxonomy.ASK:
            branded = f"nah? {reason}"
        else:
            branded = reason
    else:
        branded = ""
    result = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": perm}}
    if branded:
        result["hookSpecificOutput"]["permissionDecisionReason"] = branded
    return result


def main():
    try:
        data = json.loads(sys.stdin.read())
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})

        handler = HANDLERS.get(tool_name)
        if handler is None:
            decision = {"decision": taxonomy.ALLOW}
        else:
            decision = handler(tool_input)

        json.dump(_to_hook_output(decision), sys.stdout)
        sys.stdout.write("\n")
        sys.stdout.flush()
    except Exception as e:
        sys.stderr.write(f"nah: error: {e}\n")
        try:
            output = {"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": f"nah: internal error: {e}",
            }}
            json.dump(output, sys.stdout)
            sys.stdout.write("\n")
            sys.stdout.flush()
        except BrokenPipeError:
            pass


if __name__ == "__main__":
    main()
