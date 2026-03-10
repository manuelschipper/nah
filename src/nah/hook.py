"""PreToolUse hook entry point — reads JSON from stdin, returns decision on stdout."""

import json
import sys

from nah import paths
from nah.bash import classify_command
from nah.content import scan_content, format_content_message, is_credential_search


def handle_read(tool_input: dict) -> dict:
    return paths.check_path("Read", tool_input.get("file_path", "")) or {"decision": "allow"}


def handle_write(tool_input: dict) -> dict:
    path_check = paths.check_path("Write", tool_input.get("file_path", ""))
    if path_check:
        return path_check
    # Content inspection
    content = tool_input.get("content", "")
    matches = scan_content(content)
    if matches:
        return {"decision": "ask", "message": format_content_message("Write", matches)}
    return {"decision": "allow"}


def handle_edit(tool_input: dict) -> dict:
    path_check = paths.check_path("Edit", tool_input.get("file_path", ""))
    if path_check:
        return path_check
    # Content inspection
    new_string = tool_input.get("new_string", "")
    matches = scan_content(new_string)
    if matches:
        return {"decision": "ask", "message": format_content_message("Edit", matches)}
    return {"decision": "allow"}


def handle_glob(tool_input: dict) -> dict:
    raw_path = tool_input.get("path", "")
    if not raw_path:
        return {"decision": "allow"}  # defaults to cwd
    return paths.check_path("Glob", raw_path) or {"decision": "allow"}


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
            if resolved_path and not (resolved_path == real_root or resolved_path.startswith(real_root + "/")):
                return {
                    "decision": "ask",
                    "message": f"Grep: credential search pattern outside project root",
                }
        else:
            # No project root — any credential search is suspicious
            if raw_path:
                return {
                    "decision": "ask",
                    "message": f"Grep: credential search pattern (no project root)",
                }

    return {"decision": "allow"}


def handle_bash(tool_input: dict) -> dict:
    """Classify bash commands via the full structural pipeline."""
    command = tool_input.get("command", "")
    if not command:
        return {"decision": "allow"}

    result = classify_command(command)

    if result.final_decision == "block":
        reason = result.reason
        if result.composition_rule:
            reason = f"[{result.composition_rule}] {reason}"
        return {"decision": "block", "reason": f"Bash: {reason}"}

    if result.final_decision == "ask":
        reason = result.reason
        if result.composition_rule:
            reason = f"[{result.composition_rule}] {reason}"
        return {"decision": "ask", "message": f"Bash: {reason}"}

    return {"decision": "allow"}


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
        try:
            json.dump({"decision": "allow"}, sys.stdout)
            sys.stdout.write("\n")
            sys.stdout.flush()
        except BrokenPipeError:
            pass


if __name__ == "__main__":
    main()
