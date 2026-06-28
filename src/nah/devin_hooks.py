"""Devin CLI PreToolUse, PermissionRequest, and PostToolUse hook adapter.

Devin's hook output vocabulary is only ``approve`` / ``block`` (plus abstain via
exit 0); it has no native ``ask``. nah uses the two events for different jobs:

- ``PreToolUse`` fires before every tool, unconditionally — nah's deterministic
  block floor. Emits ``{"decision": "block", ...}`` or continues (exit 0). No LLM
  here, so a tool call is never classified by the model twice.
- ``PermissionRequest`` fires only when Devin's own logic wants a permission
  decision (Devin's native user prompt) — nah's relaxation point. Runs the full
  pipeline (LLM relax eligible) and maps ``allow -> approve``, ``ask -> abstain``
  (emit nothing, let Devin prompt), ``block -> block``.

The adapter hardcodes ``agents.DEVIN``; the ``_devin-hook`` entry point is the
agent signal, so ``agents.detect_agent`` is never consulted. Output is built
inline here (top-level ``{decision, reason}``) rather than via ``agents.format_*``
(those emit Claude-shaped ``hookSpecificOutput``).
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import sys
import time
from datetime import datetime, timezone

from nah import agents, hook, paths as nah_paths, taxonomy
from nah.messages import enrich_decision

_WRITE_LIKE = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
_DEVIN_PERMISSION_LLM_BUDGET_SECONDS = 10


def main(
    stdin=None,
    stdout=None,
    *,
    default_hook_event: str = "PermissionRequest",
) -> int:
    """Handle a Devin CLI hook invocation.

    PreToolUse enforces the deterministic block floor, PermissionRequest emits
    the approve/block verdict (or abstains on ask), and PostToolUse records the
    execution outcome.
    """
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    t0 = time.monotonic()
    event_name = default_hook_event

    try:
        payload = json.loads(stdin.read() or "{}")
    except json.JSONDecodeError as exc:
        _log_devin_hook_error(
            f"invalid {default_hook_event} JSON: {exc}",
            event_name=default_hook_event,
        )
        # Fail open on every event: a malformed payload must not wedge Devin.
        return 0
    if not isinstance(payload, dict):
        _log_devin_hook_error(
            f"{default_hook_event} payload was not an object",
            event_name=default_hook_event,
        )
        return 0

    try:
        event_name = _hook_event_name(payload, default_hook_event)
        if event_name == "PreToolUse":
            _handle_pre_tool_use(payload, stdout, t0)
            return 0
        if event_name == "PostToolUse":
            total_ms = int((time.monotonic() - t0) * 1000)
            _log_post_tool_use(payload, total_ms)
            stdout.flush()
            return 0
        _handle_permission_request(payload, stdout, t0)
        return 0
    except Exception as exc:
        _log_devin_hook_error(f"unexpected {event_name} error: {exc}", event_name=event_name)
        # Fail open — a hook crash should never block a Devin session. The
        # deterministic block floor is best-effort; surfacing the error in the
        # log is more useful than denying every subsequent tool call.
        return 0


def _hook_event_name(payload: dict, default: str = "PermissionRequest") -> str:
    return str(payload.get("hook_event_name") or payload.get("hookEventName") or default)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _tool_input(payload: dict) -> dict:
    raw = payload.get("tool_input", {})
    return raw if isinstance(raw, dict) else {}


def _classify_deterministic(payload: dict) -> tuple[dict, str, dict]:
    """Deterministic-only classification for the PreToolUse block floor.

    No LLM call ever happens here: Bash runs with ``llm_review=False`` and
    write-like tools use the path/boundary floor directly, skipping the write
    LLM gate (which only escalates allow->ask and so cannot block anyway).
    """
    tool_name = str(payload.get("tool_name", "") or "")
    tool_input = _tool_input(payload)
    canonical = agents.normalize_tool(tool_name)

    if canonical == "Bash":
        decision = hook.handle_bash(tool_input, llm_review=False)
    elif canonical in _WRITE_LIKE:
        decision = _deterministic_write_floor(canonical, tool_input)
    elif canonical in hook.HANDLERS:
        decision = hook.HANDLERS[canonical](tool_input)
    else:
        decision = hook._classify_unknown_tool(canonical, tool_input)
    return decision, canonical, tool_input


def _deterministic_write_floor(canonical: str, tool_input: dict) -> dict:
    """Path + project-boundary floor for write-like tools (no LLM gate)."""
    field = "notebook_path" if canonical == "NotebookEdit" else "file_path"
    file_path = tool_input.get(field, "")
    path_check = nah_paths.check_path(canonical, file_path)
    if path_check:
        return path_check
    boundary_check = nah_paths.check_project_boundary(canonical, file_path)
    if boundary_check:
        return boundary_check
    return {"decision": taxonomy.ALLOW}


def _decide_full(payload: dict) -> tuple[dict, str, dict]:
    """Full pipeline for PermissionRequest: handler + Layer-1 + Layer-2 relax.

    Mirrors ``hook.main``'s post-handler sequence so Devin's LLM behavior matches
    Claude's. With the LLM off (the default) this is the deterministic decision.
    """
    tool_name = str(payload.get("tool_name", "") or "")
    tool_input = _tool_input(payload)
    canonical = agents.normalize_tool(tool_name)

    handler = hook.HANDLERS.get(canonical)
    if handler is hook.handle_bash:
        decision = hook.handle_bash(tool_input, llm_review=True)
    elif handler is not None:
        decision = handler(tool_input)
    else:
        decision = hook._classify_unknown_tool(canonical, tool_input)

    decision = _apply_llm_layers(canonical, tool_input, decision)
    return decision, canonical, tool_input


def _apply_llm_layers(canonical: str, tool_input: dict, decision: dict) -> dict:
    """Run Layer-1 classify + Layer-2 relax on an ask, mirroring hook.main.

    No-ops when the LLM is off. Layer-1 maps an unknown Bash ask to a built-in
    type and re-checks targets through the floor; Layer-2 relaxes an eligible
    non-write ask to allow only when the model cites user intent.
    """
    meta = decision.setdefault("_meta", {})
    d = decision.get("decision", taxonomy.ALLOW)

    if (
        d == taxonomy.ASK
        and canonical == "Bash"
        and hook._extract_action_type(meta) in ("", taxonomy.UNKNOWN)
        and not meta.get("llm_veto")
        and not meta.get("inline_lang_exec_review")
    ):
        decision = hook._apply_layer1_classify(canonical, tool_input, decision)
        meta = decision.setdefault("_meta", {})
        d = decision.get("decision", taxonomy.ALLOW)

    if (
        d == taxonomy.ASK
        and canonical not in _WRITE_LIKE
        and not meta.get("llm_veto")
        and not meta.get("inline_lang_exec_review")
    ):
        try:
            from nah.config import get_config
            from nah.llm import try_llm_relax
            from nah.log import redact_input

            cfg = get_config()
            if cfg.llm_mode == "on" and cfg.llm:
                stages = meta.get("stages", [])
                action_type = hook._extract_action_type(meta)
                if hook._is_llm_eligible_stages(
                    action_type,
                    stages,
                    cfg.llm_eligible,
                    meta.get("composition_rule", ""),
                ):
                    llm_call = try_llm_relax(
                        canonical,
                        redact_input(canonical, tool_input),
                        action_type or taxonomy.UNKNOWN,
                        decision.get("reason", ""),
                        cfg.llm,
                        hook._transcript_path,
                        stages=stages,
                    )
                    decision, _outcome = hook.apply_layer2_relax(decision, llm_call, cfg)
        except ImportError:
            pass
        except Exception as exc:
            _log_devin_hook_error(f"relax LLM error: {exc}")
    return decision


@contextlib.contextmanager
def _permission_llm_budget():
    try:
        from nah.llm import llm_timeout_budget
    except ImportError:
        yield
        return
    with llm_timeout_budget(_DEVIN_PERMISSION_LLM_BUDGET_SECONDS):
        yield


# ---------------------------------------------------------------------------
# Event handlers
# ---------------------------------------------------------------------------

def _handle_pre_tool_use(payload: dict, stdout, t0: float) -> None:
    """Block floor: emit a deny on a deterministic block, else continue."""
    from nah.config import set_active_target

    set_active_target(agents.DEVIN, reset_cache=False)
    old_transcript = hook._transcript_path
    hook._transcript_path = str(payload.get("transcript_path", "") or "")
    try:
        with _capture_stderr():
            decision, canonical, tool_input = _classify_deterministic(payload)
        meta = decision.setdefault("_meta", {})
        meta["runtime"] = _runtime_meta(payload, phase="pre_tool", hook_event_name="PreToolUse")
        meta["execution"] = _pre_tool_execution(decision)
        _apply_taint_observation(canonical, tool_input, decision, payload)
        _apply_provenance_observation(canonical, tool_input, decision, payload)
        total_ms = int((time.monotonic() - t0) * 1000)

        if decision.get("decision") == taxonomy.BLOCK:
            _log_decision(canonical, tool_input, decision, total_ms, payload, "PreToolUse")
            _emit_block(stdout, decision, canonical)
            return
        # Continue. Log only when something interesting happened (a deny is
        # already returned above; taint/provenance observations are worth a
        # record) to avoid a log line for every benign tool call.
        if meta.get("taint") or meta.get("provenance"):
            _log_decision(canonical, tool_input, decision, total_ms, payload, "PreToolUse")
        stdout.flush()
    finally:
        hook._transcript_path = old_transcript


def _handle_permission_request(payload: dict, stdout, t0: float) -> None:
    """Relaxation point: approve / abstain / block via the full pipeline."""
    from nah.config import set_active_target

    set_active_target(agents.DEVIN, reset_cache=False)
    old_transcript = hook._transcript_path
    hook._transcript_path = str(payload.get("transcript_path", "") or "")
    try:
        with _permission_llm_budget():
            with _capture_stderr():
                decision, canonical, tool_input = _decide_full(payload)
            meta = decision.setdefault("_meta", {})
            meta["runtime"] = _runtime_meta(
                payload, phase="permission_request", hook_event_name="PermissionRequest"
            )
            meta["execution"] = _permission_execution(decision)
            decision = _apply_taint_permission(canonical, tool_input, decision, payload)
            decision = _apply_provenance_permission(canonical, tool_input, decision, payload)
            decision = hook._apply_ask_fallback(decision)
            decision.setdefault("_meta", {})["execution"] = _permission_execution(decision)
            total_ms = int((time.monotonic() - t0) * 1000)
            _log_decision(canonical, tool_input, decision, total_ms, payload, "PermissionRequest")
            _emit_permission_decision(stdout, decision, canonical)
    finally:
        hook._transcript_path = old_transcript


def _log_post_tool_use(payload: dict, total_ms: int) -> None:
    from nah.config import set_active_target

    set_active_target(agents.DEVIN, reset_cache=False)
    old_transcript = hook._transcript_path
    hook._transcript_path = str(payload.get("transcript_path", "") or "")
    try:
        tool_name = str(payload.get("tool_name", "") or "")
        tool_input = _tool_input(payload)
        canonical = agents.normalize_tool(tool_name)
        decision = {
            "decision": taxonomy.ALLOW,
            "reason": "tool execution observed",
            "_meta": {
                "runtime": _runtime_meta(
                    payload, phase="post_tool", hook_event_name="PostToolUse"
                ),
                "execution": {"state": "executed", "ask_outcome": "approved_executed"},
            },
        }
        _apply_taint_post_tool(canonical, tool_input, decision, payload)
        _apply_provenance_post_tool(canonical, tool_input, decision, payload)
        hook._log_hook_decision(canonical, tool_input, decision, agents.DEVIN, total_ms)
    finally:
        hook._transcript_path = old_transcript


# ---------------------------------------------------------------------------
# Output (inline — Devin top-level {decision, reason})
# ---------------------------------------------------------------------------

def _emit_permission_decision(stdout, decision: dict, canonical: str) -> None:
    """Emit the PermissionRequest verdict; abstain (no output) on ask."""
    d = decision.get("decision", taxonomy.ALLOW)
    if d == taxonomy.ASK:
        # Abstain: emit nothing and let Devin's native permission prompt fire.
        stdout.flush()
        return
    enrich_decision(decision, tool=canonical)
    if d == taxonomy.BLOCK:
        reason = decision.get("human_reason") or decision.get("reason", "")
        out = {"decision": "block"}
        if reason:
            out["reason"] = reason
    else:
        out = {"decision": "approve"}
    json.dump(out, stdout)
    stdout.write("\n")
    stdout.flush()


def _emit_block(stdout, decision: dict, canonical: str) -> None:
    """Emit a PreToolUse block verdict with its reason."""
    enrich_decision(decision, tool=canonical)
    reason = decision.get("human_reason") or decision.get("reason", "")
    out = {"decision": "block"}
    if reason:
        out["reason"] = reason
    json.dump(out, stdout)
    stdout.write("\n")
    stdout.flush()


# ---------------------------------------------------------------------------
# Runtime / execution metadata
# ---------------------------------------------------------------------------

def _runtime_meta(payload: dict, *, phase: str, hook_event_name: str) -> dict:
    runtime = {"phase": phase, "hook_event_name": hook_event_name}
    for key in ("session_id", "turn_id", "tool_use_id"):
        value = payload.get(key)
        if value:
            runtime[key] = str(value)
    return runtime


def _pre_tool_execution(decision: dict) -> dict:
    if decision.get("decision") == taxonomy.BLOCK:
        return {"state": "not_run", "ask_outcome": "not_applicable"}
    return {"state": "requested", "ask_outcome": "not_applicable"}


def _permission_execution(decision: dict) -> dict:
    d = decision.get("decision", taxonomy.ALLOW)
    if d == taxonomy.BLOCK:
        return {"state": "not_run", "ask_outcome": "not_applicable"}
    if d == taxonomy.ASK:
        return {"state": "requested", "ask_outcome": "requested"}
    return {"state": "requested", "ask_outcome": "not_applicable"}


# ---------------------------------------------------------------------------
# Taint + provenance (runtime=DEVIN)
# ---------------------------------------------------------------------------

def _apply_taint_observation(canonical, tool_input, decision, payload) -> dict:
    try:
        from nah import taint

        meta = decision.setdefault("_meta", {})
        return taint.apply_pre_tool(
            canonical, tool_input, decision,
            runtime=agents.DEVIN,
            runtime_meta=meta.get("runtime", {}),
            execution=meta.get("execution", {}),
            transcript_path=str(payload.get("transcript_path", "") or ""),
            terminal_audit_only=True,
        )
    except Exception as exc:
        _log_devin_hook_error(f"taint pre-tool failed: {exc}", event_name="PreToolUse")
        return decision


def _apply_provenance_observation(canonical, tool_input, decision, payload) -> dict:
    try:
        from nah import provenance

        meta = decision.setdefault("_meta", {})
        return provenance.apply_pre_tool(
            canonical, tool_input, decision,
            runtime=agents.DEVIN,
            runtime_meta=meta.get("runtime", {}),
            execution=meta.get("execution", {}),
            transcript_path=str(payload.get("transcript_path", "") or ""),
            terminal_audit_only=True,
        )
    except Exception as exc:
        _log_devin_hook_error(f"provenance pre-tool failed: {exc}", event_name="PreToolUse")
        return decision


def _apply_taint_permission(canonical, tool_input, decision, payload) -> dict:
    try:
        from nah import taint

        meta = decision.setdefault("_meta", {})
        return taint.apply_pre_tool(
            canonical, tool_input, decision,
            runtime=agents.DEVIN,
            runtime_meta=meta.get("runtime", {}),
            execution=meta.get("execution", {}),
            transcript_path=str(payload.get("transcript_path", "") or ""),
        )
    except Exception as exc:
        _log_devin_hook_error(f"taint permission failed: {exc}")
        return decision


def _apply_provenance_permission(canonical, tool_input, decision, payload) -> dict:
    try:
        from nah import provenance

        meta = decision.setdefault("_meta", {})
        return provenance.apply_pre_tool(
            canonical, tool_input, decision,
            runtime=agents.DEVIN,
            runtime_meta=meta.get("runtime", {}),
            execution=meta.get("execution", {}),
            transcript_path=str(payload.get("transcript_path", "") or ""),
            context_review=True,
        )
    except Exception as exc:
        _log_devin_hook_error(f"provenance permission failed: {exc}")
        return decision


def _apply_taint_post_tool(canonical, tool_input, decision, payload) -> dict:
    try:
        from nah import taint

        meta = decision.setdefault("_meta", {})
        return taint.apply_post_tool(
            canonical, tool_input, decision,
            runtime=agents.DEVIN,
            runtime_meta=meta.get("runtime", {}),
            execution=meta.get("execution", {}),
            transcript_path=str(payload.get("transcript_path", "") or ""),
        )
    except Exception as exc:
        _log_devin_hook_error(f"taint post-tool failed: {exc}", event_name="PostToolUse")
        return decision


def _apply_provenance_post_tool(canonical, tool_input, decision, payload) -> dict:
    try:
        from nah import provenance

        meta = decision.setdefault("_meta", {})
        return provenance.apply_post_tool(
            canonical, tool_input, decision,
            runtime=agents.DEVIN,
            runtime_meta=meta.get("runtime", {}),
            execution=meta.get("execution", {}),
            transcript_path=str(payload.get("transcript_path", "") or ""),
        )
    except Exception as exc:
        _log_devin_hook_error(f"provenance post-tool failed: {exc}", event_name="PostToolUse")
        return decision


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _log_decision(canonical, tool_input, decision, total_ms, payload, hook_event_name) -> None:
    """Log a deep copy so emit/enrich mutations don't disturb the live decision."""
    old_transcript = hook._transcript_path
    hook._transcript_path = str(payload.get("transcript_path", "") or "")
    try:
        logged = copy.deepcopy(decision)
        meta = logged.setdefault("_meta", {})
        meta.setdefault(
            "runtime",
            _runtime_meta(payload, phase="permission_request", hook_event_name=hook_event_name),
        )
        hook._log_hook_decision(canonical, tool_input, logged, agents.DEVIN, total_ms)
    finally:
        hook._transcript_path = old_transcript


@contextlib.contextmanager
def _capture_stderr():
    """Swallow classifier stderr chatter so it never leaks onto the hook's stdout."""
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        yield


def _log_devin_hook_error(message: str, *, event_name: str = "PermissionRequest") -> None:
    try:
        from nah.log import LOG_PATH

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "agent": agents.DEVIN,
            "tool": event_name,
            "decision": "error",
            "reason": message,
        }
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except Exception as exc:
        try:
            sys.stderr.write(f"nah: devin hook log: {exc}\n")
        except Exception:
            pass
