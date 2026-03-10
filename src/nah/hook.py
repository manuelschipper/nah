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
        return {
            "decision": taxonomy.ASK,
            "message": format_content_message(tool_name, matches),
            "_meta": {"content_match": ", ".join(m.pattern_desc for m in matches)},
        }
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


def _try_llm(classify_result) -> tuple[dict | None, dict]:
    """Attempt LLM resolution for bash ClassifyResult. Returns (decision, llm_meta)."""
    try:
        from nah.config import get_config
        cfg = get_config()
        if not cfg.llm or not cfg.llm.get("enabled", False):
            return None, {}
        from nah.llm import try_llm
        llm_call = try_llm(classify_result, cfg.llm)
        llm_meta = {}
        if llm_call.cascade:
            llm_meta = {
                "llm_provider": llm_call.provider,
                "llm_model": llm_call.model,
                "llm_latency_ms": llm_call.latency_ms,
                "llm_reasoning": llm_call.reasoning,
                "llm_cascade": [
                    {"provider": a.provider, "status": a.status, "latency_ms": a.latency_ms}
                    for a in llm_call.cascade
                ],
            }
        return llm_call.decision, llm_meta
    except ImportError:
        return None, {}
    except Exception as exc:
        sys.stderr.write(f"nah: LLM error: {exc}\n")
        return None, {}


def _resolve_ask_for_agent(decision: dict, tool_name: str) -> tuple[dict, str, dict]:
    """Resolve ask→allow/deny for agents without ask support.

    Tries LLM if configured, otherwise falls back to ask_fallback config.
    Returns (decision, resolved_by, llm_meta).
    """
    from nah.config import get_config
    cfg = get_config()
    reason = decision.get("reason", decision.get("message", ""))

    if cfg.llm and cfg.llm.get("enabled", False):
        try:
            from nah.llm import try_llm_generic
            llm_call = try_llm_generic(tool_name, reason, cfg.llm)
            llm_meta = {}
            if llm_call.cascade:
                llm_meta = {
                    "llm_provider": llm_call.provider,
                    "llm_model": llm_call.model,
                    "llm_latency_ms": llm_call.latency_ms,
                    "llm_reasoning": llm_call.reasoning,
                    "llm_cascade": [
                        {"provider": a.provider, "status": a.status, "latency_ms": a.latency_ms}
                        for a in llm_call.cascade
                    ],
                }
            if llm_call.decision is not None:
                return llm_call.decision, "llm", llm_meta
        except ImportError:
            pass
        except Exception as exc:
            sys.stderr.write(f"nah: LLM escalation error: {exc}\n")

    if cfg.ask_fallback == "allow":
        return {"decision": taxonomy.ALLOW}, "ask_fallback", {}
    return {"decision": taxonomy.BLOCK, "reason": reason}, "ask_fallback", {}


def _classify_meta(result) -> dict:
    """Build classification metadata from ClassifyResult."""
    meta = {
        "stages": [
            {"action_type": sr.action_type, "decision": sr.decision,
             "policy": sr.default_policy, "reason": sr.reason}
            for sr in result.stages
        ],
    }
    if result.composition_rule:
        meta["composition_rule"] = result.composition_rule
    return meta


def handle_bash(tool_input: dict) -> dict:
    """Full Bash handler: structural classification -> LLM layer -> decision."""
    command = tool_input.get("command", "")
    if not command:
        return {"decision": taxonomy.ALLOW}

    result = classify_command(command)
    meta = _classify_meta(result)

    if result.final_decision == taxonomy.BLOCK:
        return {"decision": taxonomy.BLOCK, "reason": _format_bash_reason(result), "_meta": meta}

    if result.final_decision == taxonomy.ASK:
        if _is_llm_eligible(result):
            llm_decision, llm_meta = _try_llm(result)
            meta.update(llm_meta)
            if llm_decision is not None:
                llm_decision["_meta"] = meta
                return llm_decision
        return {"decision": taxonomy.ASK, "message": _format_bash_reason(result), "_meta": meta}

    return {"decision": taxonomy.ALLOW, "_meta": meta}


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


def _log_hook_decision(
    tool: str, tool_input: dict, decision: dict,
    agent: str, ask_resolved_by: str | None, llm_meta: dict, total_ms: int,
) -> None:
    """Build and write the log entry. Never raises."""
    try:
        from nah.log import log_decision, redact_input
        from nah import __version__

        meta = decision.pop("_meta", None) or {}

        entry: dict = {
            "tool": tool,
            "input_summary": redact_input(tool, tool_input),
            "decision": decision.get("decision", "allow"),
            "reason": decision.get("reason", decision.get("message", "")),
            "agent": agent,
            "hook_version": __version__,
            "total_ms": total_ms,
        }

        if ask_resolved_by:
            entry["ask_resolved_by"] = ask_resolved_by

        entry.update(meta)
        entry.update(llm_meta)

        log_config = None
        try:
            from nah.config import get_config
            log_config = get_config().log or None
        except Exception:
            pass

        log_decision(entry, log_config)
    except Exception:
        pass


def main():
    agent = agents.CLAUDE  # default until we can detect
    try:
        import time
        t0 = time.monotonic()

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
        ask_resolved_by = None
        llm_meta: dict = {}

        # Agents without ask support: resolve ask→allow/deny
        if d == taxonomy.ASK and not agents.supports_ask(agent):
            decision, ask_resolved_by, llm_meta = _resolve_ask_for_agent(decision, canonical)
            d = decision.get("decision", taxonomy.ALLOW)

        if d != taxonomy.ALLOW:
            json.dump(_to_hook_output(decision, agent), sys.stdout)
            sys.stdout.write("\n")
            sys.stdout.flush()
            # Kiro CLI: also signal via exit code 2 + stderr
            _signal_kiro(decision, agent)

        total_ms = int((time.monotonic() - t0) * 1000)
        _log_hook_decision(canonical, tool_input, decision, agent, ask_resolved_by, llm_meta, total_ms)

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
