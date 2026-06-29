"""PreToolUse hook entry point — reads JSON from stdin, returns decision on stdout."""

import json
import sys

from nah import agents, context, paths, taxonomy
from nah.bash import classify_command
from nah.content import is_credential_search
from nah.messages import enrich_decision

_transcript_path: str = ""  # set per-invocation by main()
_POST_TOOL_EVENTS = {
    "PostToolUse": ("post_tool", "executed"),
    "PostToolUseFailure": ("post_tool_failure", "failed"),
}


def _check_write_target(tool_name: str, tool_input: dict) -> dict:
    """Shared handler for Write/Edit: path and boundary checks."""
    file_path = tool_input.get("file_path", "")
    path_check = paths.check_path(tool_name, file_path)
    if path_check:
        return path_check
    boundary_check = paths.check_project_boundary(tool_name, file_path)
    if boundary_check:
        return boundary_check
    return {"decision": taxonomy.ALLOW}


def handle_read(tool_input: dict) -> dict:
    return paths.check_path("Read", tool_input.get("file_path", "")) or {"decision": taxonomy.ALLOW}


def handle_write(tool_input: dict) -> dict:
    return _check_write_target("Write", tool_input)


def handle_edit(tool_input: dict) -> dict:
    return _check_write_target("Edit", tool_input)


def handle_multiedit(tool_input: dict) -> dict:
    """Guard MultiEdit: path + boundary checks."""
    file_path = tool_input.get("file_path", "")
    path_check = paths.check_path("MultiEdit", file_path)
    if path_check:
        return path_check
    boundary_check = paths.check_project_boundary("MultiEdit", file_path)
    if boundary_check:
        return boundary_check
    return {"decision": taxonomy.ALLOW}


def handle_notebookedit(tool_input: dict) -> dict:
    """Guard NotebookEdit: path + boundary checks."""
    file_path = tool_input.get("notebook_path", "")
    path_check = paths.check_path("NotebookEdit", file_path)
    if path_check:
        return path_check
    boundary_check = paths.check_project_boundary("NotebookEdit", file_path)
    if boundary_check:
        return boundary_check
    return {"decision": taxonomy.ALLOW}


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
        if not raw_path:
            return {
                "decision": taxonomy.ASK,
                "reason": "Grep: credential search pattern",
            }
        # Check if searching outside project root
        project_root = paths.get_project_root()
        if project_root:
            resolved_path = paths.resolve_path(raw_path) if raw_path else ""
            if resolved_path and not paths.is_inside_project_boundary(resolved_path):
                return {
                    "decision": taxonomy.ASK,
                    "reason": "Grep: credential search pattern outside project root",
                }
        else:
            # No project root — any credential search is suspicious
            if raw_path:
                return {
                    "decision": taxonomy.ASK,
                    "reason": "Grep: credential search pattern (no project root)",
                }

    return {"decision": taxonomy.ALLOW}


def _format_bash_reason(result) -> str:
    """Build the human-readable reason string from a ClassifyResult."""
    reason = result.reason
    if result.composition_rule:
        reason = f"[{result.composition_rule}] {reason}"
    return f"Bash: {reason}"


def _append_classify_pass(meta: dict, classify, verdict, cfg) -> None:
    """Append the Layer-1 classify pass record to meta['llm_passes'] (for logs)."""
    from nah.log import redact_secret

    cls = classify.classification
    rec: dict = {
        "phase": "classify",
        "provider": classify.provider or "(none)",
        "model": classify.model,
        "ms": classify.latency_ms,
        "mapped_type": cls.action_type if cls else taxonomy.UNKNOWN,
        "evidence": cls.evidence if cls else "",
    }
    if classify.cascade:
        rec["cascade"] = [
            {"provider": a.provider, "status": a.status, "latency_ms": a.latency_ms,
             **({"error": a.error} if a.error else {})}
            for a in classify.cascade
        ]
    if verdict is not None:
        raw_targets = verdict["targets"]
    elif cls is not None:
        raw_targets = [
            {"kind": t.get("kind", "unknown"), "value": t.get("value", ""),
             "floor": "", "reason": ""}
            for t in cls.targets
        ]
    else:
        raw_targets = []
    rec["targets"] = [
        {**t, "value": redact_secret(t.get("value", ""))} for t in raw_targets
    ]
    try:
        if cfg.log and cfg.log.get("llm_prompt", False):
            rec["prompt"] = classify.prompt
    except Exception as exc:
        sys.stderr.write(f"nah: config: log.llm_prompt: {exc}\n")
    meta.setdefault("llm_passes", []).append(rec)


def _apply_layer1_classify(tool_name: str, tool_input: dict, decision: dict) -> dict:
    """Layer 1: classify a deterministically-unknown command, then re-check.

    Maps the unknown to an action type + kind-tagged targets (LLM mode only),
    runs the surfaced targets through the deterministic floor, and returns the
    resulting decision. The mapped type re-enters the normal policy machinery;
    only the floor can clear a target. Fail-open: any error leaves the original
    ask untouched. The classify pass is always logged (even unknown/errored).
    """
    meta = decision.setdefault("_meta", {})
    try:
        from nah.config import get_config
        cfg = get_config()
        if cfg.llm_mode != "on" or not cfg.llm:
            return decision
        from nah import classify_recheck
        from nah.llm import try_llm_classify_unknown
        from nah.log import redact_input

        # Layer 1 maps unknowns into BUILT-IN types only (nah-992) — it does NOT
        # classify into user-defined custom types. Feeding the model the custom
        # types let it collapse a whole unknown compound into a trusted custom
        # `allow` type (e.g. `cd repo && molds update … && molds wontdo …` →
        # `molds_safe` → allow). Keeping Layer 1 on the predictable built-in
        # taxonomy avoids that; a custom type the model names anyway is coerced
        # to `unknown` by the parser, so the deterministic ask stands.
        classify = try_llm_classify_unknown(
            redact_input(tool_name, tool_input),
            cfg.llm,
            custom_types=None,
        )
        cls = classify.classification
        verdict = None
        if cls is not None and cls.action_type != taxonomy.UNKNOWN:
            policy = taxonomy.get_policy(cls.action_type, cfg.actions)
            verdict = classify_recheck.recheck(cls, policy)
        _append_classify_pass(meta, classify, verdict, cfg)

        if verdict is None:
            return decision  # could not classify -> the deterministic ask stands

        meta["action_type_source"] = "llm_classify"
        # Propagate the mapped type into the unknown ask stages so the log's
        # top-level action_type and the Layer-2 eligibility check both see it.
        for sr in meta.get("stages", []):
            if sr.get("action_type") in ("", taxonomy.UNKNOWN):
                sr["action_type"] = cls.action_type

        new_d = verdict["decision"]
        if new_d == taxonomy.ALLOW:
            return {"decision": taxonomy.ALLOW, "_meta": meta}
        if new_d == taxonomy.BLOCK:
            return {"decision": taxonomy.BLOCK, "reason": verdict["reason"], "_meta": meta}
        decision["decision"] = taxonomy.ASK
        decision["reason"] = verdict["reason"]
        return decision
    except ImportError:
        return decision
    except Exception as exc:
        sys.stderr.write(f"nah: Layer 1 classify error: {exc}\n")
        return decision


def maybe_apply_layer1_classify(canonical: str, tool_input: dict, decision: dict) -> dict:
    """Apply the sole LLM job to unknown Bash asks when LLM mode is enabled."""
    if decision.get("decision") != taxonomy.ASK or canonical != "Bash":
        return decision
    meta = decision.setdefault("_meta", {})
    if _extract_action_type(meta) not in ("", taxonomy.UNKNOWN):
        return decision
    return _apply_layer1_classify(canonical, tool_input, decision)


def _classify_meta(result) -> dict:
    """Build classification metadata from ClassifyResult."""
    meta = {
        "stages": [],
    }
    for sr in result.stages:
        stage = {
            "tokens": sr.tokens,
            "action_type": sr.action_type,
            "decision": sr.decision,
            "policy": sr.default_policy,
            "reason": sr.reason,
        }
        if sr.redirect_target:
            stage["redirect_target"] = sr.redirect_target
        meta["stages"].append(stage)
    if result.composition_rule:
        meta["composition_rule"] = result.composition_rule
    return meta


def handle_bash(tool_input: dict, *, llm_review: bool = True) -> dict:
    """Full Bash handler: structural classification."""
    _ = llm_review
    command = tool_input.get("command", "")
    if not command:
        return {"decision": taxonomy.ALLOW}

    result = classify_command(command)
    meta = _classify_meta(result)

    if result.final_decision == taxonomy.BLOCK:
        return {"decision": taxonomy.BLOCK, "reason": _format_bash_reason(result), "_meta": meta}

    if result.final_decision == taxonomy.ASK:
        return {"decision": taxonomy.ASK, "reason": _format_bash_reason(result), "_meta": meta}

    return {"decision": taxonomy.ALLOW, "_meta": meta}


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

def _join_llm_reason(reason: str, llm_reason: str) -> str:
    """Append the LLM reason inline as a second sentence.

    The generic ``human_reason`` carries no trailing punctuation (``brand``
    adds it), so join with a sentence break to avoid running the two
    fragments together (``this runs code. <reason>`` not ``this runs code
    <reason>``). ``brand`` finalizes terminal punctuation on the result.
    """
    if not llm_reason:
        return reason
    base = reason.rstrip()
    sep = "" if base.endswith((".", "!", "?")) else "."
    return f"{base}{sep} {llm_reason}"


def _to_hook_output(decision: dict, agent: str) -> dict:
    """Convert internal decision to agent-appropriate output format."""
    enrich_decision(decision)
    d = decision.get("decision", taxonomy.ALLOW)
    reason = decision.get("human_reason") or decision.get("reason", "")
    if d == taxonomy.BLOCK:
        reason = _join_llm_reason(reason, decision.get("_llm_reason", ""))
        return agents.format_block(reason, agent)
    if d == taxonomy.ASK:
        reason = _join_llm_reason(reason, decision.get("_llm_reason", ""))
        system_message = decision.get("_system_message", "")
        return agents.format_ask(reason, agent, system_message=system_message)
    return agents.format_allow(agent)


def _hook_event_name(data: dict) -> str:
    """Return the runtime hook event name from Claude/Codex-style payloads."""
    return str(data.get("hook_event_name") or data.get("hookEventName") or "PreToolUse")


def _runtime_meta(data: dict, *, phase: str, hook_event_name: str) -> dict:
    """Build runtime correlation metadata without logging raw tool contents."""
    runtime = {
        "phase": phase,
        "hook_event_name": hook_event_name,
    }
    for key in ("session_id", "turn_id", "tool_use_id"):
        value = data.get(key)
        if value:
            runtime[key] = str(value)
    return runtime


def _pre_tool_execution(decision: dict) -> dict:
    """Return conservative execution metadata for a pre-execution decision."""
    d = decision.get("decision", taxonomy.ALLOW)
    if d == taxonomy.BLOCK:
        return {"state": "not_run", "ask_outcome": "not_applicable"}
    if d == taxonomy.ASK:
        return {"state": "requested", "ask_outcome": "requested"}
    return {"state": "requested", "ask_outcome": "not_applicable"}


def _attach_pre_tool_runtime(decision: dict, data: dict) -> None:
    """Attach runtime/execution metadata to an existing pre-tool decision."""
    meta = decision.setdefault("_meta", {})
    event_name = _hook_event_name(data)
    meta["runtime"] = _runtime_meta(data, phase="pre_tool", hook_event_name=event_name)
    meta["execution"] = _pre_tool_execution(decision)


def _apply_ask_fallback(decision: dict, cfg=None) -> dict:
    """Convert a final ask decision to the configured target fallback."""
    if decision.get("decision") != taxonomy.ASK:
        return decision
    if cfg is None:
        from nah.config import get_config

        cfg = get_config()
    mode = getattr(cfg, "ask_fallback", "")
    if mode not in (taxonomy.ALLOW, taxonomy.BLOCK):
        return decision

    original_reason = str(decision.get("reason", "") or "")
    meta = decision.setdefault("_meta", {})
    meta["ask_fallback"] = {
        "mode": mode,
        "from": taxonomy.ASK,
        "to": mode,
        "reason": original_reason,
    }
    decision["decision"] = mode
    verb = "blocked" if mode == taxonomy.BLOCK else "allowed"
    review = original_reason or "review required"
    decision["reason"] = f"ask fallback {verb} unresolved review: {review}"
    decision.pop("human_reason", None)
    meta.pop("human_reason", None)
    return decision


def _post_tool_execution(data: dict, hook_event_name: str) -> dict:
    """Return conservative execution metadata for post-tool hook payloads."""
    _phase, state = _POST_TOOL_EVENTS[hook_event_name]
    execution: dict = {
        "state": state,
        "ask_outcome": "approved_executed" if state == "executed" else "unknown",
    }
    duration = data.get("duration_ms")
    if isinstance(duration, (int, float)):
        execution["duration_ms"] = int(duration)
    if hook_event_name == "PostToolUseFailure":
        error = data.get("error", "")
        if error:
            execution["error"] = _format_error_summary(str(error))
        if "is_interrupt" in data:
            execution["is_interrupt"] = bool(data.get("is_interrupt"))
    return execution


def _format_error_summary(error: str) -> str:
    """Return an error summary with control newlines escaped for log storage."""
    return error.replace("\r", "\\r").replace("\n", "\\n")


def _log_post_tool_event(
    canonical: str,
    tool_input: dict,
    data: dict,
    agent: str,
    total_ms: int,
) -> None:
    """Log a post-tool outcome without emitting a permission decision."""
    hook_event_name = _hook_event_name(data)
    phase, _state = _POST_TOOL_EVENTS[hook_event_name]
    reason = (
        "tool execution failed"
        if hook_event_name == "PostToolUseFailure"
        else "tool execution observed"
    )
    decision = {
        "decision": taxonomy.ALLOW,
        "reason": reason,
        "_meta": {
            "runtime": _runtime_meta(data, phase=phase, hook_event_name=hook_event_name),
            "execution": _post_tool_execution(data, hook_event_name),
        },
    }
    _log_hook_decision(canonical, tool_input, decision, agent, total_ms)


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
            cfg = get_config()
            log_config = cfg.log or None
            if cfg.selected_preset:
                meta["selected_preset"] = cfg.selected_preset
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
        builtin_table = taxonomy.get_builtin_table()

        # MCP tools: project config cannot classify (untrusted, no builtin coverage)
        is_mcp = canonical.startswith("mcp__")
        project_table = None
        if not is_mcp and cfg.project_config_trusted and cfg.classify_project:
            project_table = taxonomy.build_user_table(cfg.classify_project)

        user_actions = cfg.actions or None
    except Exception:
        return {"decision": taxonomy.ASK, "reason": f"unrecognized tool: {canonical}"}

    action_type = taxonomy.classify_tokens(
        [canonical],
        global_table,
        builtin_table,
        project_table,
        trust_project=cfg.project_config_trusted,
    )

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
    hook_event_name = "PreToolUse"
    try:
        import time
        t0 = time.monotonic()

        global _transcript_path
        data = json.loads(sys.stdin.read())
        hook_event_name = _hook_event_name(data)
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})
        if not isinstance(tool_input, dict):
            tool_input = {}
        _transcript_path = data.get("transcript_path", "")

        agent = agents.detect_agent(data)
        try:
            from nah.config import set_active_target
            set_active_target(agent, reset_cache=False)
        except Exception as exc:
            sys.stderr.write(f"nah: target config: {exc}\n")
        canonical = agents.normalize_tool(tool_name)

        if hook_event_name in _POST_TOOL_EVENTS:
            total_ms = int((time.monotonic() - t0) * 1000)
            _log_post_tool_event(canonical, tool_input, data, agent, total_ms)
            return

        handler = HANDLERS.get(canonical)
        if handler is None:
            decision = _classify_unknown_tool(canonical, tool_input)
        else:
            decision = handler(tool_input)

        d = decision.get("decision", taxonomy.ALLOW)
        meta = decision.setdefault("_meta", {})

        decision = maybe_apply_layer1_classify(canonical, tool_input, decision)

        _attach_pre_tool_runtime(decision, data)
        decision = _apply_ask_fallback(decision)
        decision.setdefault("_meta", {})["execution"] = _pre_tool_execution(decision)
        d = decision.get("decision", taxonomy.ALLOW)

        if d != taxonomy.ALLOW or _is_active_allow(canonical):
            enrich_decision(decision, tool=canonical)
            json.dump(_to_hook_output(decision, agent), sys.stdout)
            sys.stdout.write("\n")
            sys.stdout.flush()

        total_ms = int((time.monotonic() - t0) * 1000)
        _log_hook_decision(canonical, tool_input, decision, agent, total_ms)

    except Exception as e:
        sys.stderr.write(f"nah: error: {e}\n")
        if hook_event_name in _POST_TOOL_EVENTS:
            return
        try:
            json.dump(agents.format_error(str(e), agent), sys.stdout)
            sys.stdout.write("\n")
            sys.stdout.flush()
        except BrokenPipeError:
            pass


if __name__ == "__main__":
    main()
