"""PreToolUse hook entry point — reads JSON from stdin, returns decision on stdout."""

import json
import os
import sys

from nah import agents, paths, taxonomy
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


def _format_bash_reason(result) -> str:
    """Build the human-readable reason string from a ClassifyResult."""
    reason = result.reason
    if result.composition_rule:
        reason = f"[{result.composition_rule}] {reason}"
    return f"Bash: {reason}"


def _is_llm_eligible(result) -> bool:
    """Check if an ask decision could benefit from LLM analysis."""
    if result.composition_rule:
        return False
    for sr in result.stages:
        if sr.decision != taxonomy.ASK:
            continue
        if sr.action_type == taxonomy.UNKNOWN:
            return True
        if sr.action_type == taxonomy.LANG_EXEC:
            return True
        if sr.default_policy == taxonomy.CONTEXT and "sensitive" not in sr.reason.lower():
            return True
    return False


def _try_llm(classify_result) -> dict | None:
    """Attempt LLM resolution for bash ClassifyResult. Returns decision dict or None."""
    try:
        from nah.config import get_config
        cfg = get_config()
        if not cfg.llm or not cfg.llm.get("enabled", False):
            return None
        from nah.llm import try_llm
        return try_llm(classify_result, cfg.llm)
    except Exception:
        return None


def handle_bash(tool_input: dict) -> dict:
    """Full Bash handler: structural classification -> LLM layer -> decision."""
    command = tool_input.get("command", "")
    if not command:
        return {"decision": taxonomy.ALLOW}

    result = classify_command(command)

    if result.final_decision == taxonomy.BLOCK:
        return {"decision": taxonomy.BLOCK, "reason": _format_bash_reason(result)}

    if result.final_decision == taxonomy.ASK:
        if _is_llm_eligible(result):
            llm_decision = _try_llm(result)
            if llm_decision is not None:
                return llm_decision
        return {"decision": taxonomy.ASK, "message": _format_bash_reason(result)}

    return {"decision": taxonomy.ALLOW}


HANDLERS = {
    "Bash": handle_bash,
    "Read": handle_read,
    "Write": handle_write,
    "Edit": handle_edit,
    "Glob": handle_glob,
    "Grep": handle_grep,
}


def _to_hook_output(decision: dict, agent: str) -> dict:
    """Convert internal decision to agent-appropriate output format."""
    d = decision.get("decision", taxonomy.ALLOW)
    reason = decision.get("reason", decision.get("message", ""))
    if d == taxonomy.BLOCK:
        return agents.format_block(reason, agent)
    if d == taxonomy.ASK:
        return agents.format_ask(reason, agent)
    return agents.format_allow(agent)


def _signal_kiro(decision: dict, agent: str) -> None:
    """For Kiro CLI, signal block/ask via exit code 2 + stderr."""
    if agent != agents.KIRO:
        return
    d = decision.get("decision", taxonomy.ALLOW)
    if d in (taxonomy.BLOCK, taxonomy.ASK):
        reason = decision.get("reason", decision.get("message", ""))
        if d == taxonomy.BLOCK:
            branded = f"nah. {reason}" if reason else "nah."
        else:
            branded = f"nah? {reason}" if reason else "nah?"
        sys.stderr.write(branded + "\n")
        sys.exit(2)


def main():
    agent = agents.CLAUDE  # default until we can detect
    try:
        data = json.loads(sys.stdin.read())
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})

        agent = agents.detect_agent(data)
        canonical = agents.normalize_tool(tool_name)

        handler = HANDLERS.get(canonical)
        if handler is None:
            decision = {"decision": taxonomy.ALLOW}
        else:
            decision = handler(tool_input)

        d = decision.get("decision", taxonomy.ALLOW)
        if d != taxonomy.ALLOW:
            json.dump(_to_hook_output(decision, agent), sys.stdout)
            sys.stdout.write("\n")
            sys.stdout.flush()
            # Kiro CLI: also signal via exit code 2 + stderr
            _signal_kiro(decision, agent)
    except Exception as e:
        sys.stderr.write(f"nah: error: {e}\n")
        try:
            json.dump(agents.format_error(str(e), agent), sys.stdout)
            sys.stdout.write("\n")
            sys.stdout.flush()
            _signal_kiro({"decision": taxonomy.ASK, "message": str(e)}, agent)
        except BrokenPipeError:
            pass


if __name__ == "__main__":
    main()
