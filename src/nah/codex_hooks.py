"""Codex PermissionRequest and PostToolUse hook adapter."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import time
from datetime import datetime, timezone

from nah import agents, hook, taxonomy
from nah.apply_patch import classify_codex_apply_patch
from nah.messages import enrich_decision

_WRITE_ALIASES = {"apply_patch"}


def main(
    stdin=None,
    stdout=None,
    *,
    default_hook_event: str = "PermissionRequest",
) -> int:
    """Handle a Codex hook invocation.

    PermissionRequest emits allow/deny JSON or no verdict. PostToolUse is
    logging-only and must emit empty stdout.
    """
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    t0 = time.monotonic()
    event_name = default_hook_event

    try:
        payload = json.loads(stdin.read() or "{}")
    except json.JSONDecodeError as exc:
        _log_codex_hook_error(f"invalid {default_hook_event} JSON: {exc}")
        return 0 if default_hook_event == "PostToolUse" else 1

    if not isinstance(payload, dict):
        _log_codex_hook_error(f"{default_hook_event} payload was not an object")
        return 0 if default_hook_event == "PostToolUse" else 1

    try:
        event_name = _hook_event_name(payload, default_hook_event)
        if event_name == "PostToolUse":
            total_ms = int((time.monotonic() - t0) * 1000)
            _log_post_tool_use(payload, total_ms)
            stdout.flush()
            return 0

        decision, canonical, tool_input = _decide(payload)
        _emit_decision(stdout, decision, canonical)
        total_ms = int((time.monotonic() - t0) * 1000)
        _log_decision(canonical, tool_input, decision, total_ms, payload)
        return 0
    except Exception as exc:
        _log_codex_hook_error(f"unexpected {event_name} error: {exc}")
        return 0 if event_name == "PostToolUse" else 1


def _decide(payload: dict) -> tuple[dict, str, dict]:
    from nah.config import set_active_target

    set_active_target(agents.CODEX, reset_cache=False)
    hook._transcript_path = str(payload.get("transcript_path", "") or "")

    tool_name = str(payload.get("tool_name", "") or "")
    raw_tool_input = payload.get("tool_input", {})
    if isinstance(raw_tool_input, dict):
        tool_input = raw_tool_input
    else:
        tool_input = {}
    canonical = agents.normalize_tool(tool_name)

    if canonical == "Bash":
        with _capture_stderr(log=False):
            decision = hook.handle_bash(tool_input)
        decision = _try_codex_llm_for_ask(canonical, tool_input, decision)
        return decision, canonical, tool_input

    if canonical.startswith("mcp__"):
        return hook._classify_unknown_tool(canonical, tool_input), canonical, tool_input

    if canonical in _WRITE_ALIASES:
        if isinstance(raw_tool_input, str):
            tool_input = {"input": raw_tool_input}
        with _capture_stderr(log=False):
            decision, log_input = classify_codex_apply_patch(tool_input, payload)
        return decision, canonical, log_input

    return _unsupported_decision(canonical, tool_input), canonical, tool_input


def _unsupported_decision(canonical: str, _tool_input: dict) -> dict:
    return {
        "decision": taxonomy.ASK,
        "reason": f"Codex tool requires native approval: {canonical or 'unknown'}",
        "_meta": {
            "stages": [{
                "action_type": taxonomy.UNKNOWN,
                "decision": taxonomy.ASK,
                "policy": taxonomy.ASK,
                "reason": f"unsupported Codex PermissionRequest tool: {canonical or 'unknown'}",
            }],
        },
    }


def _try_codex_llm_for_ask(canonical: str, tool_input: dict, decision: dict) -> dict:
    if decision.get("decision") != taxonomy.ASK:
        return decision
    meta = decision.setdefault("_meta", {})
    if meta.get("llm_veto"):
        return decision

    try:
        from nah.config import get_config
        from nah.llm import try_llm_codex_permission_request
        from nah.log import redact_input

        cfg = get_config()
        if cfg.llm_mode != "on" or not cfg.llm:
            return decision
        stages = meta.get("stages", [])
        action_type = hook._extract_action_type(meta)
        if not hook._is_llm_eligible_stages(
            action_type,
            stages,
            cfg.llm_eligible,
            meta.get("composition_rule", ""),
        ):
            return decision
        with _capture_stderr(log=False):
            llm_call = try_llm_codex_permission_request(
                canonical,
                redact_input(canonical, tool_input),
                action_type or taxonomy.UNKNOWN,
                decision.get("reason", ""),
                cfg.llm,
                stages=stages,
            )
        meta.update(hook._build_llm_meta(llm_call, cfg))
        if llm_call.decision is None:
            return decision
        if llm_call.decision.get("decision") == taxonomy.ALLOW:
            return {**llm_call.decision, "_meta": meta}
        if llm_call.reasoning:
            decision["_llm_reason"] = llm_call.reasoning
    except ImportError:
        return decision
    except Exception as exc:
        _log_codex_hook_error(f"codex LLM review failed: {exc}")
    return decision


def _hook_event_name(payload: dict, default: str = "PermissionRequest") -> str:
    return str(payload.get("hook_event_name") or payload.get("hookEventName") or default)


def _runtime_meta(payload: dict, *, phase: str, hook_event_name: str) -> dict:
    runtime = {
        "phase": phase,
        "hook_event_name": hook_event_name,
    }
    for key in ("session_id", "turn_id", "tool_use_id"):
        value = payload.get(key)
        if value:
            runtime[key] = str(value)
    return runtime


def _permission_execution(decision: dict) -> dict:
    d = decision.get("decision", taxonomy.ALLOW)
    if d == taxonomy.BLOCK:
        return {"state": "not_run", "ask_outcome": "not_applicable"}
    if d == taxonomy.ASK:
        return {"state": "requested", "ask_outcome": "requested"}
    return {"state": "requested", "ask_outcome": "not_applicable"}


def _emit_decision(stdout, decision: dict, canonical: str) -> None:
    d = decision.get("decision", taxonomy.ALLOW)
    if d == taxonomy.ASK:
        stdout.flush()
        return
    enrich_decision(decision, tool=canonical)
    reason = decision.get("human_reason") or decision.get("reason", "")
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {},
        },
    }
    if d == taxonomy.BLOCK:
        payload["hookSpecificOutput"]["decision"]["behavior"] = "deny"
        if reason:
            payload["hookSpecificOutput"]["decision"]["message"] = reason
    else:
        payload["hookSpecificOutput"]["decision"]["behavior"] = "allow"
    json.dump(payload, stdout)
    stdout.write("\n")
    stdout.flush()


def _log_decision(
    canonical: str,
    tool_input: dict,
    decision: dict,
    total_ms: int,
    payload: dict,
) -> None:
    old_transcript = hook._transcript_path
    hook._transcript_path = str(payload.get("transcript_path", "") or "")
    try:
        logged = copy.deepcopy(decision)
        meta = logged.setdefault("_meta", {})
        meta["runtime"] = _runtime_meta(
            payload,
            phase="permission_request",
            hook_event_name="PermissionRequest",
        )
        meta["execution"] = _permission_execution(logged)
        hook._log_hook_decision(
            canonical,
            tool_input,
            logged,
            agents.CODEX,
            total_ms,
        )
    finally:
        hook._transcript_path = old_transcript


def _log_post_tool_use(payload: dict, total_ms: int) -> None:
    from nah.config import set_active_target

    set_active_target(agents.CODEX, reset_cache=False)
    old_transcript = hook._transcript_path
    hook._transcript_path = str(payload.get("transcript_path", "") or "")
    try:
        tool_name = str(payload.get("tool_name", "") or "")
        raw_tool_input = payload.get("tool_input", {})
        tool_input = raw_tool_input if isinstance(raw_tool_input, dict) else {}
        canonical = agents.normalize_tool(tool_name)
        decision = {
            "decision": taxonomy.ALLOW,
            "reason": "tool execution observed",
            "_meta": {
                "runtime": _runtime_meta(
                    payload,
                    phase="post_tool",
                    hook_event_name="PostToolUse",
                ),
                "execution": {
                    "state": "executed",
                    "ask_outcome": "approved_executed",
                },
            },
        }
        hook._log_hook_decision(canonical, tool_input, decision, agents.CODEX, total_ms)
    finally:
        hook._transcript_path = old_transcript


@contextlib.contextmanager
def _capture_stderr(*, log: bool):
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        yield
    captured = buf.getvalue().strip()
    if captured and log:
        _log_codex_hook_error(captured)


def _log_codex_hook_error(message: str) -> None:
    try:
        from nah.log import LOG_PATH

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "agent": agents.CODEX,
            "tool": "PermissionRequest",
            "decision": "error",
            "reason": message,
        }
        import os

        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except Exception as exc:
        try:
            sys.stderr.write(f"nah: codex hook log: {exc}\n")
        except Exception:
            pass
