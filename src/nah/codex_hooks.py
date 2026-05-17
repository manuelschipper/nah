"""Codex PreToolUse, PermissionRequest, and PostToolUse hook adapter."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import sys
import time
from datetime import datetime, timezone

from nah import agents, hook, taxonomy
from nah.apply_patch import classify_codex_apply_patch
from nah.messages import enrich_decision

_WRITE_ALIASES = {"apply_patch"}
_CONFIRM_EDITS_ENV = "NAH_CODEX_CONFIRM_EDITS"
_SAFE_APPLY_PATCH_REASON = "apply_patch: safe project edit handled by nah"
_TRUTHY_ENV_VALUES = {"1", "true", "yes", "on"}


def main(
    stdin=None,
    stdout=None,
    *,
    default_hook_event: str = "PermissionRequest",
) -> int:
    """Handle a Codex hook invocation.

    PreToolUse records observation-only taint state, PermissionRequest emits
    allow/deny JSON or no verdict, and PostToolUse records execution outcome.
    """
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    t0 = time.monotonic()
    event_name = default_hook_event

    try:
        payload = json.loads(stdin.read() or "{}")
    except json.JSONDecodeError as exc:
        _log_codex_hook_error(
            f"invalid {default_hook_event} JSON: {exc}",
            event_name=default_hook_event,
        )
        return 0 if _event_fails_open(default_hook_event) else 1

    if not isinstance(payload, dict):
        _log_codex_hook_error(
            f"{default_hook_event} payload was not an object",
            event_name=default_hook_event,
        )
        return 0 if _event_fails_open(default_hook_event) else 1

    try:
        event_name = _hook_event_name(payload, default_hook_event)
        if event_name == "PreToolUse":
            total_ms = int((time.monotonic() - t0) * 1000)
            _log_pre_tool_use(payload, total_ms)
            stdout.flush()
            return 0
        if event_name == "PostToolUse":
            total_ms = int((time.monotonic() - t0) * 1000)
            _log_post_tool_use(payload, total_ms)
            stdout.flush()
            return 0

        decision, canonical, tool_input = _decide(payload)
        _attach_permission_runtime(decision, payload)
        decision = _apply_taint_permission(canonical, tool_input, decision, payload)
        decision = _apply_provenance_permission(canonical, tool_input, decision, payload)
        decision = hook._apply_ask_fallback(decision)
        decision.setdefault("_meta", {})["execution"] = _permission_execution(decision)
        _emit_decision(stdout, decision, canonical)
        total_ms = int((time.monotonic() - t0) * 1000)
        _log_decision(canonical, tool_input, decision, total_ms, payload)
        return 0
    except Exception as exc:
        _log_codex_hook_error(f"unexpected {event_name} error: {exc}", event_name=event_name)
        return 0 if _event_fails_open(event_name) else 1


def _event_fails_open(event_name: str) -> bool:
    """Return whether hook failures should allow Codex to continue."""
    return event_name in {"PreToolUse", "PostToolUse"}


def _decide(payload: dict, *, llm_review: bool = True) -> tuple[dict, str, dict]:
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
            decision = hook.handle_bash(tool_input, llm_review=llm_review)
        if llm_review:
            decision = _try_codex_llm_for_ask(canonical, tool_input, decision)
        return decision, canonical, tool_input

    if canonical.startswith("mcp__"):
        return hook._classify_unknown_tool(canonical, tool_input), canonical, tool_input

    if canonical in _WRITE_ALIASES:
        if isinstance(raw_tool_input, str):
            tool_input = {"input": raw_tool_input}
        with _capture_stderr(log=False):
            decision, log_input = classify_codex_apply_patch(
                tool_input,
                payload,
                llm_review=llm_review,
            )
        decision = _apply_codex_edit_confirmation_policy(
            decision,
            log_input,
            str(payload.get("cwd", "") or ""),
        )
        return decision, canonical, log_input

    return _unsupported_decision(canonical, tool_input), canonical, tool_input


def _observation_decision(classifier_decision: dict) -> dict:
    """Convert a policy decision into an observation that actually continues.

    Codex PreToolUse can only block or continue. This mold's PreToolUse path is
    observation-only, so the top-level decision must reflect the runtime action
    nah actually took: continue. Classifier ask/block decisions stay in stages.
    """
    meta = copy.deepcopy(classifier_decision.get("_meta", {}) or {})
    return {
        "decision": taxonomy.ALLOW,
        "reason": "tool call observed",
        "_meta": meta,
    }


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


def _apply_codex_edit_confirmation_policy(decision: dict, log_input: dict, cwd: str) -> dict:
    """Allow known-safe project edits unless the launcher asked to confirm them."""
    if decision.get("decision") != taxonomy.ASK:
        return decision
    if decision.get("reason") != _SAFE_APPLY_PATCH_REASON:
        return decision
    if _confirm_edits_enabled():
        return decision
    if not _patch_paths_inside_cwd(log_input, cwd):
        return decision

    allowed = copy.deepcopy(decision)
    allowed["decision"] = taxonomy.ALLOW
    allowed["reason"] = "apply_patch: safe project edit allowed by nah"
    meta = allowed.setdefault("_meta", {})
    meta["codex_edit_policy"] = {
        "safe_project_edit": True,
        "confirm_edits": False,
    }
    stages = meta.get("stages")
    if isinstance(stages, list):
        for stage in stages:
            if not isinstance(stage, dict):
                continue
            if stage.get("reason") == _SAFE_APPLY_PATCH_REASON:
                stage["decision"] = taxonomy.ALLOW
                stage["policy"] = taxonomy.ALLOW
                stage["reason"] = allowed["reason"]
    return allowed


def _confirm_edits_enabled() -> bool:
    value = os.environ.get(_CONFIRM_EDITS_ENV, "")
    return value.strip().lower() in _TRUTHY_ENV_VALUES


def _patch_paths_inside_cwd(log_input: dict, cwd: str) -> bool:
    if not cwd:
        return False
    paths = log_input.get("_nah_patch_paths", [])
    if not isinstance(paths, list) or not paths:
        return False
    try:
        root = os.path.abspath(os.path.expanduser(cwd))
        for raw_path in paths:
            path = os.path.abspath(os.path.expanduser(str(raw_path)))
            if os.path.commonpath([root, path]) != root:
                return False
    except (OSError, RuntimeError, ValueError):
        return False
    return True


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


def _pre_tool_execution() -> dict:
    return {"state": "requested", "ask_outcome": "not_applicable"}


def _attach_permission_runtime(decision: dict, payload: dict) -> None:
    """Attach runtime metadata before policy layers can inspect the decision."""
    meta = decision.setdefault("_meta", {})
    meta["runtime"] = _runtime_meta(
        payload,
        phase="permission_request",
        hook_event_name="PermissionRequest",
    )
    meta["execution"] = _permission_execution(decision)


def _apply_taint_permission(
    canonical: str,
    tool_input: dict,
    decision: dict,
    payload: dict,
) -> dict:
    try:
        from nah import taint

        meta = decision.setdefault("_meta", {})
        return taint.apply_pre_tool(
            canonical,
            tool_input,
            decision,
            runtime=agents.CODEX,
            runtime_meta=meta.get("runtime", {}),
            execution=meta.get("execution", {}),
            transcript_path=str(payload.get("transcript_path", "") or ""),
        )
    except Exception as exc:
        _log_codex_hook_error(f"taint permission failed: {exc}")
        return decision


def _apply_taint_pre_tool_observation(
    canonical: str,
    tool_input: dict,
    decision: dict,
    payload: dict,
) -> dict:
    try:
        from nah import taint

        meta = decision.setdefault("_meta", {})
        return taint.apply_pre_tool(
            canonical,
            tool_input,
            decision,
            runtime=agents.CODEX,
            runtime_meta=meta.get("runtime", {}),
            execution=meta.get("execution", {}),
            transcript_path=str(payload.get("transcript_path", "") or ""),
            terminal_audit_only=True,
        )
    except Exception as exc:
        _log_codex_hook_error(f"taint pre-tool failed: {exc}", event_name="PreToolUse")
        return decision


def _apply_provenance_permission(
    canonical: str,
    tool_input: dict,
    decision: dict,
    payload: dict,
) -> dict:
    try:
        from nah import provenance

        meta = decision.setdefault("_meta", {})
        return provenance.apply_pre_tool(
            canonical,
            tool_input,
            decision,
            runtime=agents.CODEX,
            runtime_meta=meta.get("runtime", {}),
            execution=meta.get("execution", {}),
            transcript_path=str(payload.get("transcript_path", "") or ""),
        )
    except Exception as exc:
        _log_codex_hook_error(f"provenance permission failed: {exc}")
        return decision


def _apply_provenance_pre_tool_observation(
    canonical: str,
    tool_input: dict,
    decision: dict,
    payload: dict,
) -> dict:
    try:
        from nah import provenance

        meta = decision.setdefault("_meta", {})
        return provenance.apply_pre_tool(
            canonical,
            tool_input,
            decision,
            runtime=agents.CODEX,
            runtime_meta=meta.get("runtime", {}),
            execution=meta.get("execution", {}),
            transcript_path=str(payload.get("transcript_path", "") or ""),
            terminal_audit_only=True,
        )
    except Exception as exc:
        _log_codex_hook_error(f"provenance pre-tool failed: {exc}", event_name="PreToolUse")
        return decision


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
        meta.setdefault(
            "runtime",
            _runtime_meta(
                payload,
                phase="permission_request",
                hook_event_name="PermissionRequest",
            ),
        )
        meta.setdefault("execution", _permission_execution(logged))
        hook._log_hook_decision(
            canonical,
            tool_input,
            logged,
            agents.CODEX,
            total_ms,
        )
    finally:
        hook._transcript_path = old_transcript


def _log_pre_tool_use(payload: dict, total_ms: int) -> None:
    from nah.config import set_active_target

    set_active_target(agents.CODEX, reset_cache=False)
    old_transcript = hook._transcript_path
    hook._transcript_path = str(payload.get("transcript_path", "") or "")
    try:
        classifier_decision, canonical, tool_input = _decide(payload, llm_review=False)
        decision = _observation_decision(classifier_decision)
        meta = decision.setdefault("_meta", {})
        meta["runtime"] = _runtime_meta(
            payload,
            phase="pre_tool",
            hook_event_name="PreToolUse",
        )
        meta["execution"] = _pre_tool_execution()
        _apply_taint_pre_tool_observation(canonical, tool_input, decision, payload)
        _apply_provenance_pre_tool_observation(canonical, tool_input, decision, payload)
        if meta.get("taint") or meta.get("provenance"):
            hook._log_hook_decision(canonical, tool_input, decision, agents.CODEX, total_ms)
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
        if canonical in _WRITE_ALIASES:
            with _capture_stderr(log=False):
                _decision, tool_input = classify_codex_apply_patch(
                    tool_input if isinstance(raw_tool_input, dict) else {"input": raw_tool_input},
                    payload,
                    llm_review=False,
                )
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
        _apply_taint_post_tool(canonical, tool_input, decision, payload)
        _apply_provenance_post_tool(canonical, tool_input, decision, payload)
        hook._log_hook_decision(canonical, tool_input, decision, agents.CODEX, total_ms)
    finally:
        hook._transcript_path = old_transcript


def _apply_taint_post_tool(
    canonical: str,
    tool_input: dict,
    decision: dict,
    payload: dict,
) -> dict:
    try:
        from nah import taint

        meta = decision.setdefault("_meta", {})
        return taint.apply_post_tool(
            canonical,
            tool_input,
            decision,
            runtime=agents.CODEX,
            runtime_meta=meta.get("runtime", {}),
            execution=meta.get("execution", {}),
            transcript_path=str(payload.get("transcript_path", "") or ""),
        )
    except Exception as exc:
        _log_codex_hook_error(f"taint post-tool failed: {exc}")
        return decision


def _apply_provenance_post_tool(
    canonical: str,
    tool_input: dict,
    decision: dict,
    payload: dict,
) -> dict:
    try:
        from nah import provenance

        meta = decision.setdefault("_meta", {})
        return provenance.apply_post_tool(
            canonical,
            tool_input,
            decision,
            runtime=agents.CODEX,
            runtime_meta=meta.get("runtime", {}),
            execution=meta.get("execution", {}),
            transcript_path=str(payload.get("transcript_path", "") or ""),
        )
    except Exception as exc:
        _log_codex_hook_error(f"provenance post-tool failed: {exc}")
        return decision


@contextlib.contextmanager
def _capture_stderr(*, log: bool):
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        yield
    captured = buf.getvalue().strip()
    if captured and log:
        _log_codex_hook_error(captured)


def _log_codex_hook_error(message: str, *, event_name: str = "PermissionRequest") -> None:
    try:
        from nah.log import LOG_PATH

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "agent": agents.CODEX,
            "tool": event_name,
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
