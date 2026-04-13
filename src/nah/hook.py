"""PreToolUse hook entry point — reads JSON from stdin, returns decision on stdout."""

import json
import os
import sys

from nah import agents, context, paths, taxonomy
from nah.bash import classify_command
from nah.content import scan_content, format_content_message, is_credential_search

_transcript_path: str = ""  # set per-invocation by main()
_AUTO_STATE_DIR = os.path.join(os.path.expanduser("~"), ".config", "nah", "auto-state")

_LLM_ELIGIBLE_PRESETS = {
    "strict": (taxonomy.UNKNOWN, taxonomy.LANG_EXEC, taxonomy.CONTEXT),
    "default": (
        "strict",
        taxonomy.PACKAGE_UNINSTALL,
        taxonomy.CONTAINER_EXEC,
        taxonomy.BROWSER_EXEC,
        taxonomy.AGENT_EXEC_READ,
    ),
}


def _auto_state_path(transcript_path: str) -> str | None:
    """Return the session state file path for unified ask refinement."""
    if not transcript_path:
        return None
    session_id = os.path.basename(transcript_path)
    if not session_id:
        return None
    return os.path.join(_AUTO_STATE_DIR, session_id)


def _read_auto_state(transcript_path: str) -> tuple[int, bool]:
    """Read (deny_count, disabled) from session state, defaulting safely."""
    path = _auto_state_path(transcript_path)
    if not path:
        return 0, False
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return int(data.get("deny_count", 0)), bool(data.get("disabled", False))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return 0, False


def _write_auto_state(transcript_path: str, deny_count: int, disabled: bool) -> None:
    """Persist unified ask-refinement state across hook invocations."""
    path = _auto_state_path(transcript_path)
    if not path:
        return
    try:
        os.makedirs(_AUTO_STATE_DIR, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"deny_count": deny_count, "disabled": disabled}, f)
    except OSError as exc:
        sys.stderr.write(f"nah: auto-state write: {exc}\n")


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


def _should_llm_inspect_write() -> bool:
    """Check if LLM should review this write-like operation."""
    try:
        from nah.config import get_config
        cfg = get_config()
        if cfg.llm_mode != "on" or not cfg.llm:
            return False
    except Exception:
        return False
    # LLM inspects all writes when enabled — the value is catching
    # what deterministic misses, so we can't filter by decision.
    return True


def _try_llm_write(tool_name: str, tool_input: dict, decision: dict) -> tuple[dict | None, dict]:
    """LLM review gate for Write/Edit. Returns (decision, llm_meta).

    Fail-open: any exception → (None, {}) → structural decision stands.
    Uncertain → keep/escalate to ask (human should decide).
    """
    try:
        from nah.config import get_config
        cfg = get_config()
        if cfg.llm_mode != "on" or not cfg.llm:
            return None, {}
        from nah.llm import try_llm_write
        llm_call = try_llm_write(tool_name, tool_input, decision, cfg.llm, _transcript_path)
        if llm_call.decision is not None:
            return llm_call.decision, _build_llm_meta(llm_call, cfg)
        # All providers errored or none configured — fail-open to deterministic
        if llm_call.cascade:
            attempts = "; ".join(
                f"{a.provider}={a.status}({a.latency_ms}ms){' err=' + a.error if a.error else ''}"
                for a in llm_call.cascade
            )
            sys.stderr.write(f"nah: LLM write: all providers failed [{attempts}]\n")
            return None, _build_llm_meta(llm_call, cfg)
        return None, {}
    except ImportError:
        return None, {}
    except Exception as exc:
        sys.stderr.write(f"nah: LLM write error: {exc}\n")
        return None, {}


def _scan_and_decide(tool_name: str, content: str) -> dict:
    """Scan content and return deterministic decision dict."""
    if not content:
        return {"decision": taxonomy.ALLOW}
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


def _is_project_boundary_ask(tool_name: str, det_result: dict) -> bool:
    """Return True for the narrow project-boundary ask class the LLM can relax."""
    reason = det_result.get("reason", "")
    return (
        det_result.get("decision") == taxonomy.ASK
        and (
            reason.startswith(f"{tool_name} outside project:")
            or reason.startswith(f"{tool_name} outside project (no git root):")
        )
    )


def _is_write_llm_allow_eligible(tool_name: str, det_result: dict) -> bool:
    """Return True when a write-like LLM allow may become the final decision."""
    if det_result.get("decision") == taxonomy.ALLOW:
        return True
    return _is_project_boundary_ask(tool_name, det_result)


def _llm_write_review_gate(tool_name: str, tool_input: dict, det_result: dict) -> dict:
    """LLM review gate for write-like tools.

    The LLM can escalate deterministic allows to asks and can relax only
    explicit project-boundary asks to allow. Blocks remain deterministic-only.
    """
    if not _should_llm_inspect_write():
        return det_result
    llm_decision, llm_meta = _try_llm_write(tool_name, tool_input, det_result)

    # Always attach LLM metadata when LLM was called (even if it agrees)
    if llm_meta:
        det_result.setdefault("_meta", {}).update(llm_meta)

    if llm_decision is None:
        return det_result
    structural_d = det_result.get("decision", taxonomy.ALLOW)
    llm_d = llm_decision.get("decision")

    # Surface LLM warning to user via systemMessage (always, not just escalation)
    llm_reason = llm_decision.get("reason", "")
    if llm_reason and llm_d != taxonomy.ALLOW:
        # Strip wrapper prefixes to get clean LLM reasoning
        clean = llm_reason
        for prefix in (
            f"{tool_name} (LLM): ",
            "LLM: ",
        ):
            if clean.startswith(prefix):
                clean = clean[len(prefix):]
        clean = clean.strip()
        if clean:
            det_result["_llm_reason"] = clean
            det_result["_system_message"] = f"nah: {clean}"

    # Write review never returns a final block. Non-allow provider decisions
    # keep or escalate to ask for human review.
    if structural_d == taxonomy.ALLOW and llm_d != taxonomy.ALLOW:
        ask = {
            "decision": taxonomy.ASK,
            "reason": llm_reason or f"{tool_name} (LLM): human review needed",
            "_meta": dict(det_result.get("_meta", {})),
        }
        ask["_meta"]["llm_veto"] = True
        if det_result.get("_system_message"):
            ask["_system_message"] = det_result["_system_message"]
        if det_result.get("_llm_reason"):
            ask["_llm_reason"] = det_result["_llm_reason"]
        return ask

    if (
        structural_d == taxonomy.ASK
        and llm_d == taxonomy.ALLOW
        and _is_write_llm_allow_eligible(tool_name, det_result)
    ):
        allow = {
            "decision": taxonomy.ALLOW,
            "_meta": dict(det_result.get("_meta", {})),
        }
        allow["_meta"]["llm_review"] = "ask_to_allow"
        return allow

    return det_result


def _handle_write_with_llm(tool_name: str, tool_input: dict, content_field: str) -> dict:
    """Shared Write/Edit handler: deterministic check + LLM write review."""
    det_result = _check_write_content(tool_name, tool_input, content_field)
    if det_result.get("decision") == taxonomy.BLOCK:
        return det_result
    return _llm_write_review_gate(tool_name, tool_input, det_result)


def handle_write(tool_input: dict) -> dict:
    return _handle_write_with_llm("Write", tool_input, "content")


def handle_edit(tool_input: dict) -> dict:
    return _handle_write_with_llm("Edit", tool_input, "new_string")


def handle_multiedit(tool_input: dict) -> dict:
    """Guard MultiEdit: path + boundary + content check on each edit + LLM review."""
    file_path = tool_input.get("file_path", "")
    path_check = paths.check_path("MultiEdit", file_path)
    if path_check:
        if path_check.get("decision") == taxonomy.BLOCK:
            return path_check
        return _llm_write_review_gate("MultiEdit", tool_input, path_check)
    boundary_check = paths.check_project_boundary("MultiEdit", file_path)
    if boundary_check:
        return _llm_write_review_gate("MultiEdit", tool_input, boundary_check)
    edits = tool_input.get("edits", [])
    combined = "\n".join(str(e.get("new_string") or "") for e in edits if isinstance(e, dict))
    det_result = _scan_and_decide("MultiEdit", combined)
    if det_result.get("decision") == taxonomy.BLOCK:
        return det_result
    return _llm_write_review_gate("MultiEdit", tool_input, det_result)


def handle_notebookedit(tool_input: dict) -> dict:
    """Guard NotebookEdit: path + boundary + content check on cell source + LLM review."""
    file_path = tool_input.get("notebook_path", "")
    path_check = paths.check_path("NotebookEdit", file_path)
    if path_check:
        if path_check.get("decision") == taxonomy.BLOCK:
            return path_check
        return _llm_write_review_gate("NotebookEdit", tool_input, path_check)
    boundary_check = paths.check_project_boundary("NotebookEdit", file_path)
    if boundary_check:
        return _llm_write_review_gate("NotebookEdit", tool_input, boundary_check)
    action = tool_input.get("action", "")
    content = "" if action == "delete" else str(tool_input.get("new_source") or "")
    det_result = _scan_and_decide("NotebookEdit", content)
    if det_result.get("decision") == taxonomy.BLOCK:
        return det_result
    return _llm_write_review_gate("NotebookEdit", tool_input, det_result)


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
            if resolved_path and not paths.is_inside_project_boundary(resolved_path):
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


def _is_llm_eligible_stages(
    action_type: str,
    stages: list[dict],
    eligible,
    composition_rule: str = "",
) -> bool:
    """Check if an ask decision could benefit from unified LLM analysis."""
    all_eligible, expanded = _expand_llm_eligible(eligible)
    if all_eligible:
        return True

    if composition_rule and "composition" not in expanded:
        return False

    for sr in stages:
        if sr.get("decision") != taxonomy.ASK:
            continue
        stage_action_type = sr.get("action_type", "")
        reason = sr.get("reason", "")

        if sr.get("policy") == taxonomy.CONTEXT and "sensitive" in reason.lower():
            if "sensitive" not in expanded:
                continue

        if stage_action_type in expanded or action_type in expanded:
            return True
        if taxonomy.CONTEXT in expanded and sr.get("policy") == taxonomy.CONTEXT:
            return True
    return False


def _expand_llm_eligible(eligible) -> tuple[bool, set[str]]:
    """Expand llm.eligible presets and keywords into a membership set."""
    if eligible == "all":
        return True, set()

    raw_items = eligible if isinstance(eligible, list) else [eligible]
    expanded: set[str] = set()
    seen: set[str] = set()

    def add_item(item) -> bool:
        name = str(item)
        if name == "all":
            return True
        if name in _LLM_ELIGIBLE_PRESETS:
            if name in seen:
                return False
            seen.add(name)
            for preset_item in _LLM_ELIGIBLE_PRESETS[name]:
                if add_item(preset_item):
                    return True
            return False
        expanded.add(name)
        return False

    for item in raw_items:
        if add_item(item):
            return True, set()
    return False, expanded


def _is_llm_eligible(result) -> bool:
    """Check if a bash ask decision could benefit from LLM analysis."""
    try:
        from nah.config import get_config
        eligible = get_config().llm_eligible
    except Exception as exc:
        sys.stderr.write(f"nah: config: llm_eligible: {exc}\n")
        eligible = "default"

    stages = [
        {
            "action_type": sr.action_type,
            "decision": sr.decision,
            "policy": sr.default_policy,
            "reason": sr.reason,
        }
        for sr in result.stages
    ]
    action_type = ""
    for stage in stages:
        if stage["decision"] == taxonomy.ASK:
            action_type = stage["action_type"]
            break
    if not action_type and stages:
        action_type = stages[0]["action_type"]
    return _is_llm_eligible_stages(
        action_type, stages, eligible, result.composition_rule,
    )


def _build_llm_meta(llm_call, cfg) -> dict:
    """Build LLM metadata dict from an LLMCallResult."""
    llm_meta: dict = {}
    if llm_call.cascade:
        llm_meta = {
            "llm_provider": llm_call.provider,
            "llm_model": llm_call.model,
            "llm_latency_ms": llm_call.latency_ms,
            "llm_decision": (
                llm_call.decision.get("decision", "")
                if llm_call.decision is not None else ""
            ),
            "llm_reasoning": llm_call.reasoning,
            "llm_reasoning_long": getattr(llm_call, "reasoning_long", ""),
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


def _try_llm_script_veto(classify_result) -> tuple[dict | None, dict]:
    """Attempt content veto for clean lang_exec commands."""
    try:
        from nah.config import get_config
        cfg = get_config()
        if cfg.llm_mode != "on" or not cfg.llm:
            return None, {}
        from nah.llm import _try_llm_script_veto as run_script_veto

        llm_call = run_script_veto(classify_result, cfg.llm, _transcript_path)
        return llm_call.decision, _build_llm_meta(llm_call, cfg)
    except ImportError:
        return None, {}
    except Exception as exc:
        sys.stderr.write(f"nah: LLM script veto error: {exc}\n")
        return None, {}


def _build_bash_hint(result) -> str | None:
    """Build an actionable hint for bash ask decisions."""
    if result.composition_rule:
        return None
    for sr in result.stages:
        if sr.decision != taxonomy.ASK:
            continue
        if sr.action_type == taxonomy.UNKNOWN:
            cmd = sr.tokens[0] if sr.tokens else "command"
            if cmd.startswith(("(", "{")) or sr.reason == "subshell pipe pending":
                return None
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
            # Prefer redirect target over token extraction
            target = getattr(sr, "redirect_target", "") or _extract_target_from_tokens(sr.tokens)
            if target:
                dir_hint = paths._suggest_trust_dir(target)
                if dir_hint != "/":  # Never suggest trusting root
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
    """Full Bash handler: structural classification + content veto."""
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

        decision = {"decision": taxonomy.ASK, "reason": _format_bash_reason(result), "_meta": meta}
        if hint:
            decision["_hint"] = hint
        return decision

    # LLM veto gate for lang_exec scripts (FD-079): even when the deterministic
    # layer allows, the LLM inspects script content and can escalate to ask.
    if _has_lang_exec_script(result):
        llm_decision, llm_meta = _try_llm_script_veto(result)
        meta.update(llm_meta)
        if llm_decision is not None:
            llm_d = llm_decision.get("decision")
            if llm_d != taxonomy.ALLOW:
                meta["llm_veto"] = True
                return {
                    "decision": taxonomy.ASK,
                    "reason": llm_decision.get("reason", "Bash (LLM): human review needed"),
                    "_meta": meta,
                }
            # LLM says allow — keep structural allow

    return {"decision": taxonomy.ALLOW, "_meta": meta}


def _has_lang_exec_script(result) -> bool:
    """Check if result has a lang_exec stage where content was inspected.

    Returns True when the context resolver successfully scanned content —
    either a script file ('script clean:') or inline code ('inline clean').
    Returns False for nonexistent files and outside-project scripts.
    """
    for sr in result.stages:
        if sr.action_type == taxonomy.LANG_EXEC and (
            sr.reason.startswith("script clean:") or sr.reason == "lang_exec: inline clean"
        ):
            return True
    return False


HANDLERS = {
    "Bash": handle_bash,
    "Read": handle_read,
    "Write": handle_write,
    "Edit": handle_edit,
    "MultiEdit": handle_multiedit,
    "NotebookEdit": handle_notebookedit,
    "Glob": handle_glob,
    "Grep": handle_grep,
}

_WRITE_LIKE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}


def _to_hook_output(decision: dict, agent: str) -> dict:
    """Convert internal decision to agent-appropriate output format."""
    d = decision.get("decision", taxonomy.ALLOW)
    reason = decision.get("reason", "")
    if d == taxonomy.BLOCK:
        return agents.format_block(reason, agent)
    if d == taxonomy.ASK:
        llm_reason = decision.get("_llm_reason", "")
        if llm_reason:
            reason = f"{reason}\n     LLM: {llm_reason}"
        hint = decision.get("_hint")
        if hint:
            reason = f"{reason}\n     {hint}"
        system_message = decision.get("_system_message", "")
        return agents.format_ask(reason, agent, system_message=system_message)
    return agents.format_allow(agent)


def _log_hook_decision(
    tool: str, tool_input: dict, decision: dict,
    agent: str, total_ms: int,
) -> None:
    """Build and write the log entry. Never raises."""
    try:
        from nah.log import log_decision, redact_input, build_entry
        from nah import __version__

        meta = decision.pop("_meta", None) or {}
        warning = decision.pop("_system_message", "")
        if warning:
            meta["warning"] = warning

        log_config = None
        try:
            from nah.config import get_config
            log_config = get_config().log or None
        except Exception as exc:
            sys.stderr.write(f"nah: config: log: {exc}\n")

        summary = redact_input(tool, tool_input)

        entry = build_entry(
            tool=tool, input_summary=summary,
            decision=decision.get("decision", "allow"),
            reason=decision.get("reason", ""),
            agent=agent, hook_version=__version__,
            total_ms=total_ms, meta=meta,
            transcript_path=_transcript_path,
        )

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
    stage_reason = (
        f"unrecognized tool: {canonical}"
        if action_type == taxonomy.UNKNOWN
        else f"{action_type} → {policy}"
    )

    def with_stage(decision: str, reason: str = "") -> dict:
        result = {"decision": decision}
        if reason:
            result["reason"] = reason
        result["_meta"] = {
            "stages": [{
                "action_type": action_type,
                "decision": decision,
                "policy": policy,
                "reason": reason or stage_reason,
            }],
        }
        return result

    if policy == taxonomy.ALLOW:
        return with_stage(taxonomy.ALLOW)
    if policy == taxonomy.BLOCK:
        return with_stage(taxonomy.BLOCK, stage_reason)
    if policy == taxonomy.CONTEXT:
        decision, reason = context.resolve_context(action_type, tool_input=tool_input)
        return with_stage(decision, reason)
    return with_stage(taxonomy.ASK, stage_reason)


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


def _extract_action_type(meta: dict) -> str:
    """Extract the primary ask-driving action type from hook metadata."""
    stages = meta.get("stages", [])
    for stage in stages:
        if stage.get("decision") == taxonomy.ASK:
            return stage.get("action_type", "")
    if stages:
        return stages[0].get("action_type", "")
    return ""


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
        meta = decision.setdefault("_meta", {})

        if d == taxonomy.ASK and canonical not in _WRITE_LIKE_TOOLS and not meta.get("llm_veto"):
            try:
                from nah.config import get_config
                from nah.llm import try_llm_unified
                from nah.log import redact_input

                cfg = get_config()
                if cfg.llm_mode == "on" and cfg.llm:
                    deny_count, disabled = _read_auto_state(_transcript_path)
                    deny_limit = int(cfg.llm.get("deny_limit", 0))
                    if not disabled or deny_limit <= 0:
                        stages = meta.get("stages", [])
                        action_type = _extract_action_type(meta)
                        if _is_llm_eligible_stages(
                            action_type,
                            stages,
                            cfg.llm_eligible,
                            meta.get("composition_rule", ""),
                        ):
                            llm_call = try_llm_unified(
                                canonical,
                                redact_input(canonical, tool_input),
                                action_type or taxonomy.UNKNOWN,
                                decision.get("reason", ""),
                                cfg.llm,
                                _transcript_path,
                            )
                            meta.update(_build_llm_meta(llm_call, cfg))
                            if llm_call.decision is None:
                                pass
                            elif llm_call.decision.get("decision") == taxonomy.ALLOW:
                                _write_auto_state(_transcript_path, 0, False)
                                decision = {
                                    **llm_call.decision,
                                    "_meta": meta,
                                }
                                d = taxonomy.ALLOW
                            else:
                                # Surface LLM reasoning in the prompt
                                if llm_call.reasoning:
                                    decision["_llm_reason"] = llm_call.reasoning
                                # Compact summary in systemMessage — lands in
                                # transcript so future LLM calls see it as
                                # approval evidence when the tool runs.
                                short = (llm_call.reasoning or "uncertain")[:80]
                                decision["_system_message"] = f"nah: {short}"
                                deny_count += 1
                                if deny_limit > 0:
                                    _write_auto_state(
                                        _transcript_path,
                                        deny_count,
                                        deny_count >= deny_limit,
                                    )
            except ImportError:
                pass
            except Exception as exc:
                sys.stderr.write(f"nah: unified LLM error: {exc}\n")

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
