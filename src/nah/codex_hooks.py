"""Codex PermissionRequest hook adapter."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import time
from datetime import datetime, timezone

from nah import agents, hook, taxonomy
from nah.messages import enrich_decision

_WRITE_ALIASES = {"apply_patch"}


def main(
    stdin=None,
    stdout=None,
) -> int:
    """Handle a Codex PermissionRequest hook invocation.

    Codex interprets stdout JSON as an approval decision. ASK/no verdict must
    be empty stdout with a zero exit code so Codex can ask its native reviewer.
    """
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    t0 = time.monotonic()

    try:
        payload = json.loads(stdin.read() or "{}")
    except json.JSONDecodeError as exc:
        _log_codex_hook_error(f"invalid PermissionRequest JSON: {exc}")
        return 1

    if not isinstance(payload, dict):
        _log_codex_hook_error("PermissionRequest payload was not an object")
        return 1

    try:
        decision, canonical, tool_input = _decide(payload)
        _emit_decision(stdout, decision)
        total_ms = int((time.monotonic() - t0) * 1000)
        _log_decision(canonical, tool_input, decision, total_ms, payload)
        return 0
    except Exception as exc:
        _log_codex_hook_error(f"unexpected PermissionRequest error: {exc}")
        return 1


def _decide(payload: dict) -> tuple[dict, str, dict]:
    from nah.config import set_active_target

    set_active_target(agents.CODEX)
    hook._transcript_path = str(payload.get("transcript_path", "") or "")

    tool_name = str(payload.get("tool_name", "") or "")
    tool_input = payload.get("tool_input", {})
    if not isinstance(tool_input, dict):
        tool_input = {}
    canonical = agents.normalize_tool(tool_name)

    if canonical == "Bash":
        with _capture_stderr(log=False):
            decision = hook.handle_bash(tool_input)
        decision = _try_codex_llm_for_ask(canonical, tool_input, decision)
        return decision, canonical, tool_input

    if canonical in _WRITE_ALIASES:
        return _unsupported_decision(canonical, tool_input), canonical, tool_input

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


def _emit_decision(stdout, decision: dict) -> None:
    d = decision.get("decision", taxonomy.ALLOW)
    if d == taxonomy.ASK:
        stdout.flush()
        return
    enrich_decision(decision, tool="Bash")
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
        hook._log_hook_decision(
            canonical,
            tool_input,
            copy.deepcopy(decision),
            agents.CODEX,
            total_ms,
        )
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
