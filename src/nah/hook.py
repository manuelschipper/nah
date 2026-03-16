"""PreToolUse hook entry point — reads JSON from stdin, returns decision on stdout."""

import json
import os
import sys

from nah import agents, context, paths, taxonomy
from nah.bash import classify_command
from nah.content import scan_content, format_content_message, is_credential_search

_transcript_path: str = ""  # set per-invocation by main()


def _check_write_content(tool_name: str, tool_input: dict, content_field: str) -> dict:
    """Shared handler for Write/Edit: path check + boundary check + content inspection."""
    file_path = tool_input.get("file_path", "")
    path_check = paths.check_path(tool_name, file_path)
    if path_check:
        return path_check
    boundary_check = paths.check_project_boundary(tool_name, file_path)
    if boundary_check:
        return boundary_check
    content = tool_input.get(content_field, "")
    matches = scan_content(content)
    if matches:
        decision = max(
            (m.policy for m in matches),
            key=lambda p: taxonomy.STRICTNESS.get(p, 2),
        )
        return {
            "decision": decision,
            "reason": format_content_message(tool_name, matches),
            "_meta": {"content_match": ", ".join(m.pattern_desc for m in matches)},
            "_hint": "(content varies per call — cannot be remembered)",
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
                    "reason": "Grep: credential search pattern outside project root",
                    "_hint": "(content varies per call — cannot be remembered)",
                }
        else:
            # No project root — any credential search is suspicious
            if raw_path:
                return {
                    "decision": taxonomy.ASK,
                    "reason": "Grep: credential search pattern (no project root)",
                    "_hint": "(content varies per call — cannot be remembered)",
                }

    return {"decision": taxonomy.ALLOW}


def _extract_target_from_tokens(tokens: list[str]) -> str | None:
    """Extract first path-like argument from tokens for hint generation."""
    for tok in tokens[1:]:  # skip command name
        if tok.startswith("-"):
            continue
        if "/" in tok or tok.startswith("~") or tok.startswith("."):
            return tok
    return None


def _format_bash_reason(result) -> str:
    """Build the human-readable reason string from a ClassifyResult."""
    reason = result.reason
    if result.composition_rule:
        reason = f"[{result.composition_rule}] {reason}"
    return f"Bash: {reason}"


def _is_llm_eligible(result) -> bool:
    """Check if an ask decision could benefit from LLM analysis."""
    try:
        from nah.config import get_config
        eligible = get_config().llm_eligible
    except Exception as exc:
        sys.stderr.write(f"nah: config: llm_eligible: {exc}\n")
        eligible = "default"

    if eligible == "all":
        return True

    if isinstance(eligible, list):
        # Structural gate: composition
        if result.composition_rule and "composition" not in eligible:
            return False
        for sr in result.stages:
            if sr.decision != taxonomy.ASK:
                continue
            # Sensitive exclusion (context-policy stages only)
            if sr.default_policy == taxonomy.CONTEXT and "sensitive" in sr.reason.lower():
                if "sensitive" not in eligible:
                    continue
            # Direct action type match
            if sr.action_type in eligible:
                return True
            # "context" keyword: any context-policy type
            if "context" in eligible and sr.default_policy == taxonomy.CONTEXT:
                return True
        return False

    # "default" — equivalent to [unknown, lang_exec, context]
    # Compositions are evaluated stage-by-stage like everything else —
    # if any ask stage qualifies, the whole command goes to the LLM.
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


def _build_llm_meta(llm_call, cfg) -> dict:
    """Build LLM metadata dict from an LLMCallResult."""
    llm_meta: dict = {}
    if llm_call.cascade:
        llm_meta = {
            "llm_provider": llm_call.provider,
            "llm_model": llm_call.model,
            "llm_latency_ms": llm_call.latency_ms,
            "llm_reasoning": llm_call.reasoning,
            "llm_cascade": [
                {"provider": a.provider, "status": a.status, "latency_ms": a.latency_ms,
                 **({"error": a.error} if a.error else {})}
                for a in llm_call.cascade
            ],
        }
    try:
        if cfg.log and cfg.log.get("llm_prompt", False):
            llm_meta["llm_prompt"] = llm_call.prompt
    except Exception as exc:
        sys.stderr.write(f"nah: config: log.llm_prompt: {exc}\n")
    return llm_meta


def _try_llm(classify_result) -> tuple[dict | None, dict]:
    """Attempt LLM resolution for bash ClassifyResult. Returns (decision, llm_meta)."""
    try:
        from nah.config import get_config
        cfg = get_config()
        if not cfg.llm or not cfg.llm.get("enabled", False):
            return None, {}
        from nah.llm import try_llm
        llm_call = try_llm(classify_result, cfg.llm, _transcript_path)
        return llm_call.decision, _build_llm_meta(llm_call, cfg)
    except ImportError:
        return None, {}
    except Exception as exc:
        sys.stderr.write(f"nah: LLM error: {exc}\n")
        return None, {}


def _cap_llm_decision(llm_decision: dict) -> dict:
    """Apply llm.max_decision cap. Downgrades but preserves reasoning."""
    try:
        from nah.config import get_config
        cap = get_config().llm_max_decision
    except Exception as exc:
        sys.stderr.write(f"nah: config: llm_max_decision: {exc}\n")
        return llm_decision
    if not cap:
        return llm_decision
    decision = llm_decision.get("decision", taxonomy.ASK)
    if taxonomy.STRICTNESS.get(decision, 2) > taxonomy.STRICTNESS.get(cap, 3):
        original_reason = llm_decision.get("reason", "")
        llm_decision["decision"] = cap
        llm_decision["reason"] = f"LLM suggested {decision}: {original_reason}"
    return llm_decision


def _build_bash_hint(result) -> str | None:
    """Build an actionable hint for bash ask decisions."""
    if result.composition_rule:
        return None
    for sr in result.stages:
        if sr.decision != taxonomy.ASK:
            continue
        if sr.action_type == taxonomy.UNKNOWN:
            cmd = sr.tokens[0] if sr.tokens else "command"
            return f"To classify: nah classify {cmd} <type>\n     See available types: nah types"
        if sr.action_type == taxonomy.NETWORK_WRITE:
            return f"To always allow: nah allow network_write"
        if "unknown host: " in sr.reason:
            # Extract host from reason like "network_outbound → ask (unknown host: example.com)"
            idx = sr.reason.index("unknown host: ") + len("unknown host: ")
            host = sr.reason[idx:].rstrip(")")
            return f"To trust this host: nah trust {host}"
        if "targets sensitive path:" in sr.reason:
            # Extract path from reason like "targets sensitive path: ~/.aws"
            idx = sr.reason.index("targets sensitive path:") + len("targets sensitive path: ")
            path = sr.reason[idx:].strip()
            return f"To always allow: nah allow-path {path}"
        if "outside project" in sr.reason:
            # Extract target from tokens and suggest trust dir
            target = _extract_target_from_tokens(sr.tokens)
            if target:
                dir_hint = paths._suggest_trust_dir(target)
                return f"To always allow: nah trust {dir_hint}"
        # Action policy ask
        return f"To always allow: nah allow {sr.action_type}"
    return None


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
        hint = _build_bash_hint(result)
        if hint:
            meta["hint"] = hint

        if _is_llm_eligible(result):
            llm_decision, llm_meta = _try_llm(result)
            meta.update(llm_meta)
            if llm_decision is not None:
                llm_decision = _cap_llm_decision(llm_decision)
                llm_decision["_meta"] = meta
                return llm_decision

        decision = {"decision": taxonomy.ASK, "reason": _format_bash_reason(result), "_meta": meta}
        if hint:
            decision["_hint"] = hint
        return decision

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
    reason = decision.get("reason", "")
    if d == taxonomy.BLOCK:
        return agents.format_block(reason, agent)
    if d == taxonomy.ASK:
        hint = decision.get("_hint")
        if hint:
            reason = f"{reason}\n     {hint}"
        return agents.format_ask(reason, agent)
    return agents.format_allow(agent)


def _log_hook_decision(
    tool: str, tool_input: dict, decision: dict,
    agent: str, total_ms: int,
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
            "reason": decision.get("reason", ""),
            "agent": agent,
            "hook_version": __version__,
            "total_ms": total_ms,
        }

        entry.update(meta)

        log_config = None
        try:
            from nah.config import get_config
            log_config = get_config().log or None
        except Exception as exc:
            sys.stderr.write(f"nah: config: log: {exc}\n")

        log_decision(entry, log_config)
    except Exception as exc:
        sys.stderr.write(f"nah: log error: {exc}\n")


def _classify_unknown_tool(canonical: str, tool_input: dict | None = None) -> dict:
    """Classify tools without a dedicated handler via the classify table.

    MCP tools (mcp__*) skip the project classify table — only global config
    can classify them. See FD-024 for rationale.
    """
    try:
        from nah.config import get_config
        cfg = get_config()

        global_table = taxonomy.build_user_table(cfg.classify_global) if cfg.classify_global else None
        builtin_table = taxonomy.get_builtin_table(cfg.profile)

        # MCP tools: project config cannot classify (untrusted, no builtin coverage)
        is_mcp = canonical.startswith("mcp__")
        project_table = None
        if not is_mcp and cfg.classify_project:
            project_table = taxonomy.build_user_table(cfg.classify_project)

        user_actions = cfg.actions or None
    except Exception:
        return {"decision": taxonomy.ASK, "reason": f"unrecognized tool: {canonical}"}

    action_type = taxonomy.classify_tokens([canonical], global_table, builtin_table, project_table,
                                           profile=cfg.profile,
                                           trust_project=cfg.trust_project_config)

    policy = taxonomy.get_policy(action_type, user_actions)
    if policy == taxonomy.ALLOW:
        return {"decision": taxonomy.ALLOW}
    if policy == taxonomy.BLOCK:
        reason = f"unrecognized tool: {canonical}" if action_type == taxonomy.UNKNOWN else f"{action_type} → {policy}"
        return {"decision": taxonomy.BLOCK, "reason": reason}
    if policy == taxonomy.CONTEXT:
        decision, reason = context.resolve_context(action_type, tool_input=tool_input)
        return {"decision": decision, "reason": reason}
    msg = f"unrecognized tool: {canonical}" if action_type == taxonomy.UNKNOWN else f"{action_type} → {policy}"
    return {"decision": taxonomy.ASK, "reason": msg}


def _is_active_allow(tool_name: str) -> bool:
    """Check if active allow emission is enabled for this tool."""
    try:
        from nah.config import get_config
        aa = get_config().active_allow
    except Exception:
        return True  # default: active allow on
    if isinstance(aa, bool):
        return aa
    if isinstance(aa, list):
        return tool_name in aa
    return True


def main():
    agent = agents.CLAUDE  # default until we can detect
    try:
        import time
        t0 = time.monotonic()

        global _transcript_path
        data = json.loads(sys.stdin.read())
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})
        _transcript_path = data.get("transcript_path", "")

        agent = agents.detect_agent(data)
        canonical = agents.normalize_tool(tool_name)

        handler = HANDLERS.get(canonical)
        if handler is None:
            decision = _classify_unknown_tool(canonical, tool_input)
        else:
            decision = handler(tool_input)

        d = decision.get("decision", taxonomy.ALLOW)

        if d != taxonomy.ALLOW or _is_active_allow(canonical):
            json.dump(_to_hook_output(decision, agent), sys.stdout)
            sys.stdout.write("\n")
            sys.stdout.flush()

        total_ms = int((time.monotonic() - t0) * 1000)
        _log_hook_decision(canonical, tool_input, decision, agent, total_ms)

    except Exception as e:
        sys.stderr.write(f"nah: error: {e}\n")
        try:
            json.dump(agents.format_error(str(e), agent), sys.stdout)
            sys.stdout.write("\n")
            sys.stdout.flush()
        except BrokenPipeError:
            pass


if __name__ == "__main__":
    main()
