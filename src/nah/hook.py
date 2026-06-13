"""PreToolUse hook entry point — reads JSON from stdin, returns decision on stdout."""

import json
import os
import sys

from nah import agents, context, paths, taxonomy
from nah.bash import classify_command
from nah.content import is_credential_search, get_secret_patterns
from nah.messages import enrich_decision

_transcript_path: str = ""  # set per-invocation by main()
_AUTO_STATE_DIR = os.path.join(os.path.expanduser("~"), ".config", "nah", "auto-state")
_POST_TOOL_EVENTS = {
    "PostToolUse": ("post_tool", "executed"),
    "PostToolUseFailure": ("post_tool_failure", "failed"),
}

_LLM_ELIGIBLE_PRESETS = {
    "strict": (taxonomy.UNKNOWN, taxonomy.LANG_EXEC, taxonomy.CONTEXT),
    "default": (
        "strict",
        taxonomy.PACKAGE_UNINSTALL,
        taxonomy.CONTAINER_EXEC,
        taxonomy.BROWSER_EXEC,
        taxonomy.AGENT_EXEC_READ,
        taxonomy.PROCESS_SIGNAL,
        taxonomy.GIT_REMOTE_WRITE,
    ),
}
_DEFAULT_SAFE_COMPOSITION_RULE = "read | exec"
_DEFAULT_SAFE_COMPOSITION_ALLOWED_ACTIONS = {
    taxonomy.FILESYSTEM_READ,
    taxonomy.LANG_EXEC,
}
_DEFAULT_SAFE_COMPOSITION_FORBIDDEN_ACTIONS = {
    taxonomy.FILESYSTEM_DELETE,
    taxonomy.FILESYSTEM_WRITE,
    taxonomy.GIT_REMOTE_WRITE,
    taxonomy.GIT_DISCARD,
    taxonomy.GIT_HISTORY_REWRITE,
    taxonomy.NETWORK_OUTBOUND,
    taxonomy.NETWORK_WRITE,
    taxonomy.PACKAGE_INSTALL,
    taxonomy.CONTAINER_WRITE,
    taxonomy.CONTAINER_DESTRUCTIVE,
    taxonomy.SERVICE_WRITE,
    taxonomy.SERVICE_DESTRUCTIVE,
    taxonomy.DB_WRITE,
    taxonomy.AGENT_WRITE,
    taxonomy.AGENT_EXEC_WRITE,
    taxonomy.AGENT_EXEC_REMOTE,
    taxonomy.AGENT_SERVER,
    taxonomy.AGENT_EXEC_BYPASS,
    taxonomy.OBFUSCATED,
    taxonomy.UNKNOWN,
}
_INLINE_EXEC_FLAGS = {
    "python": {"-c"},
    "python3": {"-c"},
    "node": {"-e", "--eval", "-p", "--print"},
    "ruby": {"-e"},
    "perl": {"-e"},
    "php": {"-r"},
    "bash": {"-c"},
    "sh": {"-c"},
    "dash": {"-c"},
    "zsh": {"-c"},
    "fish": {"-c"},
    "pwsh": {"-c", "-command", "-encodedcommand"},
    "powershell": {"-c", "-command", "-encodedcommand"},
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


def _is_project_boundary_ask(tool_name: str, det_result: dict) -> bool:
    """Return True for the narrow project-boundary ask class the LLM can relax."""
    reason = det_result.get("reason", "")
    return (
        det_result.get("decision") == taxonomy.ASK
        and (
            reason.startswith(f"{tool_name} outside project:")
            or reason.startswith(f"{tool_name} outside project (no project root):")
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
    """Shared Write/Edit handler: structural check + LLM write review."""
    det_result = _check_write_target(tool_name, tool_input)
    if det_result.get("decision") == taxonomy.BLOCK:
        return det_result
    return _llm_write_review_gate(tool_name, tool_input, det_result)


def handle_write(tool_input: dict) -> dict:
    return _handle_write_with_llm("Write", tool_input, "content")


def handle_edit(tool_input: dict) -> dict:
    return _handle_write_with_llm("Edit", tool_input, "new_string")


def handle_multiedit(tool_input: dict) -> dict:
    """Guard MultiEdit: path + boundary checks + LLM review."""
    file_path = tool_input.get("file_path", "")
    path_check = paths.check_path("MultiEdit", file_path)
    if path_check:
        if path_check.get("decision") == taxonomy.BLOCK:
            return path_check
        return _llm_write_review_gate("MultiEdit", tool_input, path_check)
    boundary_check = paths.check_project_boundary("MultiEdit", file_path)
    if boundary_check:
        return _llm_write_review_gate("MultiEdit", tool_input, boundary_check)
    det_result = {"decision": taxonomy.ALLOW}
    return _llm_write_review_gate("MultiEdit", tool_input, det_result)


def handle_notebookedit(tool_input: dict) -> dict:
    """Guard NotebookEdit: path + boundary checks + LLM review."""
    file_path = tool_input.get("notebook_path", "")
    path_check = paths.check_path("NotebookEdit", file_path)
    if path_check:
        if path_check.get("decision") == taxonomy.BLOCK:
            return path_check
        return _llm_write_review_gate("NotebookEdit", tool_input, path_check)
    boundary_check = paths.check_project_boundary("NotebookEdit", file_path)
    if boundary_check:
        return _llm_write_review_gate("NotebookEdit", tool_input, boundary_check)
    det_result = {"decision": taxonomy.ALLOW}
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
        if (
            _eligible_uses_default_preset(eligible)
            and _is_default_safe_read_exec_composition(stages, composition_rule)
        ):
            return True
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


def _eligible_uses_default_preset(eligible) -> bool:
    """Return whether the raw eligible config explicitly includes default."""
    raw_items = eligible if isinstance(eligible, list) else [eligible]
    return any(str(item) == "default" for item in raw_items)


def _is_default_safe_read_exec_composition(
    stages: list[dict],
    composition_rule: str,
) -> bool:
    """Return True for default-only, visible local read-to-filter pipelines."""
    if composition_rule != _DEFAULT_SAFE_COMPOSITION_RULE or len(stages) < 2:
        return False

    for stage in stages:
        if not _stage_allowed_for_default_read_exec(stage):
            return False
        if _stage_has_forbidden_default_composition_signal(stage):
            return False

    for left, right in zip(stages, stages[1:]):
        if not _stage_is_filesystem_read(left):
            continue
        if _stage_has_visible_inline_exec(right):
            return True
    return False


def _stage_allowed_for_default_read_exec(stage: dict) -> bool:
    if stage.get("decision") == taxonomy.ALLOW:
        return True
    if stage.get("decision") != taxonomy.ASK:
        return False
    return _stage_inline_exec_review_state(stage) == "visible"


def _stage_has_forbidden_default_composition_signal(stage: dict) -> bool:
    action_type = str(stage.get("action_type", ""))
    if action_type not in _DEFAULT_SAFE_COMPOSITION_ALLOWED_ACTIONS:
        return True
    if action_type in _DEFAULT_SAFE_COMPOSITION_FORBIDDEN_ACTIONS:
        return True
    reason = str(stage.get("reason", "")).lower()
    return any(
        needle in reason
        for needle in (
            "sensitive",
            "credential",
            "secret",
            "network",
            "remote",
            "decode",
            "obfuscat",
            "bypass",
            "destructive",
            "delete",
            "write",
        )
    )


def _stage_value(stage, key: str, default=None):
    """Read a StageResult/dataclass or serialized stage dict consistently."""
    if isinstance(stage, dict):
        return stage.get(key, default)
    return getattr(stage, key, default)


def _stage_tokens(stage) -> list:
    tokens = _stage_value(stage, "tokens", [])
    if not isinstance(tokens, list) or len(tokens) < 2:
        return []
    return tokens


def _stage_action_type(stage) -> str:
    return str(_stage_value(stage, "action_type", "") or "")


def _stage_decision(stage) -> str:
    return str(_stage_value(stage, "decision", "") or "")


def _stage_reason(stage) -> str:
    return str(_stage_value(stage, "reason", "") or "")


def _stage_inline_code(stage) -> str:
    return str(_stage_value(stage, "inline_code", "") or "")


def _stage_is_filesystem_read(stage) -> bool:
    return _stage_action_type(stage) == taxonomy.FILESYSTEM_READ


def _stage_has_visible_inline_exec(stage) -> bool:
    return (
        _stage_inline_exec_review_state(stage) == "visible"
        or _stage_token_inline_exec_visibility(stage) == "visible"
    )


def _stage_inline_exec_review_state(stage) -> str:
    """Return visible/opaque when a non-shell inline execution needs review."""
    marker = _stage_value(stage, "inline_exec", None)
    if isinstance(marker, dict) and marker.get("review") == "required":
        return "visible" if marker.get("visible") else "opaque"

    if _stage_action_type(stage) != taxonomy.LANG_EXEC:
        return ""
    if _stage_decision(stage) != taxonomy.ASK:
        return ""
    if _is_shell_inline_stage(stage):
        return ""
    if _stage_inline_code(stage):
        return "visible"

    visibility = _stage_token_inline_exec_visibility(stage)
    if visibility:
        return visibility

    if _stage_reason(stage).startswith("lang_exec: inline execution"):
        return "opaque"
    return ""


def _stage_token_inline_exec_visibility(stage) -> str:
    """Infer whether inline exec payload is visible from stage tokens."""
    tokens = _stage_tokens(stage)
    if len(tokens) < 2:
        return ""
    cmd = _stage_command_name(stage)

    if cmd in {"pwsh", "powershell"}:
        for i, token in enumerate(tokens[1:], 1):
            flag = str(token).lower()
            if flag == "-encodedcommand":
                return "opaque"
            if flag in {"-c", "-command"}:
                return "visible" if i + 1 < len(tokens) else "opaque"
        return ""

    if cmd == "cmd":
        flag = str(tokens[1]).lower()
        if flag in {"/c", "/k"}:
            return "visible" if len(tokens) > 2 else "opaque"
        return ""

    inline_flags = _INLINE_EXEC_FLAGS.get(cmd)
    if not inline_flags:
        return ""
    for i, token in enumerate(tokens[1:], 1):
        if str(token).lower() in inline_flags:
            return "visible" if i + 1 < len(tokens) else "opaque"
    return ""


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
            "tokens": sr.tokens,
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

        classify = try_llm_classify_unknown(
            redact_input(tool_name, tool_input),
            cfg.llm,
            custom_types=cfg.actions or None,
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


def _try_llm_inline_lang_exec(command: str, stage) -> tuple[dict | None, dict]:
    """Attempt LLM review for visible non-shell inline lang_exec code."""
    try:
        from nah.config import get_config
        cfg = get_config()
        if cfg.llm_mode != "on" or not cfg.llm:
            return None, {}
        inline_code = str(getattr(stage, "inline_code", "") or "")
        if not inline_code:
            return None, {}
        from nah.llm import try_llm_inline_lang_exec

        llm_call = try_llm_inline_lang_exec(
            command,
            inline_code,
            cfg.llm,
            _transcript_path,
            stages=[{
                "tokens": stage.tokens,
                "action_type": stage.action_type,
                "decision": stage.decision,
                "policy": stage.default_policy,
                "reason": stage.reason,
            }],
        )
        return llm_call.decision, _build_llm_meta(llm_call, cfg)
    except ImportError:
        return None, {}
    except Exception as exc:
        sys.stderr.write(f"nah: LLM inline lang_exec error: {exc}\n")
        return None, {}


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
        inline_state = _stage_inline_exec_review_state(sr)
        if inline_state:
            stage["inline_exec"] = {
                "review": "required",
                "visible": inline_state == "visible",
            }
        meta["stages"].append(stage)
    if result.composition_rule:
        meta["composition_rule"] = result.composition_rule
    return meta


def handle_bash(tool_input: dict, *, llm_review: bool = True) -> dict:
    """Full Bash handler: structural classification + inline LLM review."""
    command = tool_input.get("command", "")
    if not command:
        return {"decision": taxonomy.ALLOW}

    result = classify_command(command)
    meta = _classify_meta(result)

    if result.final_decision == taxonomy.BLOCK:
        return {"decision": taxonomy.BLOCK, "reason": _format_bash_reason(result), "_meta": meta}

    if result.final_decision == taxonomy.ASK:
        inline_stage = _inline_lang_exec_review_stage(result)
        if inline_stage is not None:
            meta["inline_lang_exec_review"] = "required"
            if _stage_inline_exec_review_state(inline_stage) != "visible":
                meta["inline_lang_exec_review"] = "opaque"
                return {"decision": taxonomy.ASK, "reason": _format_bash_reason(result), "_meta": meta}
            if llm_review:
                llm_decision, llm_meta = _try_llm_inline_lang_exec(command, inline_stage)
                meta.update(llm_meta)
                if llm_decision is not None and llm_decision.get("decision") == taxonomy.ALLOW:
                    meta["inline_lang_exec_review"] = "allow"
                    return {"decision": taxonomy.ALLOW, "_meta": meta}
                if llm_decision is not None:
                    meta["inline_lang_exec_review"] = "ask"
                    meta["llm_veto"] = True
                    return {
                        "decision": taxonomy.ASK,
                        "reason": llm_decision.get("reason", "Bash (LLM): human review needed"),
                        "_meta": meta,
                    }
            meta["inline_lang_exec_review"] = "unavailable"
        return {"decision": taxonomy.ASK, "reason": _format_bash_reason(result), "_meta": meta}

    return {"decision": taxonomy.ALLOW, "_meta": meta}


def _inline_lang_exec_review_stage(result):
    """Return the ASK lang_exec stage that needs inline-code handling."""
    for sr in result.stages:
        if _stage_inline_exec_review_state(sr):
            return sr
    return None


def _stage_command_name(stage) -> str:
    tokens = _stage_value(stage, "tokens", []) or []
    if not tokens:
        return ""
    try:
        return taxonomy._normalize_command_name(str(tokens[0]))
    except AttributeError:
        name = os.path.basename(str(tokens[0])).lower()
        return name[:-4] if name.endswith(".exe") else name


def _is_shell_inline_stage(stage) -> bool:
    return _stage_command_name(stage) in {"bash", "sh", "dash", "zsh"}


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
    enrich_decision(decision)
    d = decision.get("decision", taxonomy.ALLOW)
    reason = decision.get("human_reason") or decision.get("reason", "")
    if d == taxonomy.BLOCK:
        llm_reason = decision.get("_llm_reason", "")
        if llm_reason:
            reason = f"{reason}\n     LLM: {llm_reason}"
        return agents.format_block(reason, agent)
    if d == taxonomy.ASK:
        llm_reason = decision.get("_llm_reason", "")
        if llm_reason:
            reason = f"{reason}\n     LLM: {llm_reason}"
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
            execution["error"] = _redact_error_summary(str(error))
        if "is_interrupt" in data:
            execution["is_interrupt"] = bool(data.get("is_interrupt"))
    return execution


def _redact_error_summary(error: str) -> str:
    """Return an error summary without known inline secret tokens."""
    summary = error.replace("\r", "\\r").replace("\n", "\\n")
    try:
        for pattern, _label in get_secret_patterns():
            summary = pattern.sub("***", summary)
    except Exception:
        # Error summaries are diagnostic-only. If custom content patterns are
        # malformed or unavailable, the raw string is still preferable to
        # dropping the whole post-tool failure row.
        pass
    return summary


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
    _apply_taint_post_tool(canonical, tool_input, decision, agent)
    _apply_provenance_post_tool(canonical, tool_input, decision, agent)
    _log_hook_decision(canonical, tool_input, decision, agent, total_ms)


def _apply_taint_pre_tool(canonical: str, tool_input: dict, decision: dict, agent: str) -> dict:
    """Run the shared taint layer for pre-tool decisions."""
    try:
        from nah import taint

        meta = decision.setdefault("_meta", {})
        return taint.apply_pre_tool(
            canonical,
            tool_input,
            decision,
            runtime=agent,
            runtime_meta=meta.get("runtime", {}),
            execution=meta.get("execution", {}),
            transcript_path=_transcript_path,
        )
    except Exception as exc:
        sys.stderr.write(f"nah: taint pre-tool: {exc}\n")
        return decision


def _apply_taint_post_tool(canonical: str, tool_input: dict, decision: dict, agent: str) -> dict:
    """Run the shared taint finalizer for post-tool outcome rows."""
    try:
        from nah import taint

        meta = decision.setdefault("_meta", {})
        return taint.apply_post_tool(
            canonical,
            tool_input,
            decision,
            runtime=agent,
            runtime_meta=meta.get("runtime", {}),
            execution=meta.get("execution", {}),
            transcript_path=_transcript_path,
        )
    except Exception as exc:
        sys.stderr.write(f"nah: taint post-tool: {exc}\n")
        return decision


def _apply_provenance_pre_tool(canonical: str, tool_input: dict, decision: dict, agent: str) -> dict:
    """Run the shared provenance layer for pre-tool decisions."""
    try:
        from nah import provenance

        meta = decision.setdefault("_meta", {})
        return provenance.apply_pre_tool(
            canonical,
            tool_input,
            decision,
            runtime=agent,
            runtime_meta=meta.get("runtime", {}),
            execution=meta.get("execution", {}),
            transcript_path=_transcript_path,
        )
    except Exception as exc:
        sys.stderr.write(f"nah: provenance pre-tool: {exc}\n")
        return decision


def _apply_provenance_post_tool(canonical: str, tool_input: dict, decision: dict, agent: str) -> dict:
    """Run the shared provenance finalizer for post-tool outcome rows."""
    try:
        from nah import provenance

        meta = decision.setdefault("_meta", {})
        return provenance.apply_post_tool(
            canonical,
            tool_input,
            decision,
            runtime=agent,
            runtime_meta=meta.get("runtime", {}),
            execution=meta.get("execution", {}),
            transcript_path=_transcript_path,
        )
    except Exception as exc:
        sys.stderr.write(f"nah: provenance post-tool: {exc}\n")
        return decision


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

        # Layer 1: classify a deterministically-unknown Bash command, re-check
        # its targets through the floor, and let the result re-enter the normal
        # machinery (allow/ask/block) before the Layer-2 relax pass below.
        if (
            d == taxonomy.ASK
            and canonical == "Bash"
            and _extract_action_type(meta) in ("", taxonomy.UNKNOWN)
            and not meta.get("llm_veto")
            and not meta.get("inline_lang_exec_review")
        ):
            decision = _apply_layer1_classify(canonical, tool_input, decision)
            meta = decision.setdefault("_meta", {})
            d = decision.get("decision", taxonomy.ALLOW)

        if (
            d == taxonomy.ASK
            and canonical not in _WRITE_LIKE_TOOLS
            and not meta.get("llm_veto")
            and not meta.get("inline_lang_exec_review")
        ):
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
                                stages=stages,
                            )
                            meta.update(_build_llm_meta(llm_call, cfg))
                            meta["llm_phase"] = "relax"
                            citation = (getattr(llm_call, "citation", "") or "").strip()
                            llm_allows = (
                                llm_call.decision is not None
                                and llm_call.decision.get("decision") == taxonomy.ALLOW
                            )
                            if llm_call.decision is None:
                                pass
                            elif llm_allows and citation:
                                # Relaxed: a distinct outcome, not a silent allow.
                                # The cited user turn authorizes the ask-class
                                # operation; surface both halves + log it.
                                _write_auto_state(_transcript_path, 0, False)
                                meta["llm_review"] = "relaxed"
                                meta["llm_citation"] = citation
                                would_ask = decision.get("reason", "")
                                decision = {
                                    **llm_call.decision,
                                    "_meta": meta,
                                }
                                decision["_system_message"] = (
                                    f"nah: allowed (relaxed) — normally asks: "
                                    f"{would_ask}; you asked: {citation[:140]}"
                                )
                                d = taxonomy.ALLOW
                            elif llm_allows:
                                # cite-or-ask: an allow with no cited user intent
                                # is not trusted — keep the ask.
                                meta["llm_review"] = "uncited"
                                if llm_call.reasoning:
                                    decision["_llm_reason"] = llm_call.reasoning
                                decision["_system_message"] = (
                                    f"nah: {llm_call.reasoning or 'no cited user intent'}"
                                )
                                deny_count += 1
                                if deny_limit > 0:
                                    _write_auto_state(
                                        _transcript_path,
                                        deny_count,
                                        deny_count >= deny_limit,
                                    )
                            else:
                                # Surface LLM reasoning in the prompt
                                if llm_call.reasoning:
                                    decision["_llm_reason"] = llm_call.reasoning
                                # Summary in systemMessage lands in the
                                # transcript so future LLM calls see it as
                                # approval evidence when the tool runs.
                                decision["_system_message"] = (
                                    f"nah: {llm_call.reasoning or 'uncertain'}"
                                )
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

        _attach_pre_tool_runtime(decision, data)
        decision = _apply_taint_pre_tool(canonical, tool_input, decision, agent)
        decision = _apply_provenance_pre_tool(canonical, tool_input, decision, agent)
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
