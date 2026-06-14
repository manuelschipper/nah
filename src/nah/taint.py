"""Runtime-neutral session taint tracking.

Taint is a downstream-flow layer: normal nah policy still controls immediate
access, while this module tracks successful source reads and evaluates later
activation/boundary sinks.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nah import taxonomy
from nah.messages import system_byline

VALID_MODES = {"off", "audit", "enforce"}
VALID_POLICIES = {"allow", "audit", "ask", "block"}
POLICY_STRICTNESS = {"allow": 0, "audit": 1, "ask": 2, "block": 3}
DECISION_STRICTNESS = {
    taxonomy.ALLOW: 0,
    taxonomy.ASK: 2,
    taxonomy.BLOCK: 3,
}

TRACKABLE_PROPAGATION = {
    taxonomy.FILESYSTEM_WRITE,
    taxonomy.GIT_WRITE,
    taxonomy.BROWSER_FILE,
}

DEFAULT_ACTIVATION = {
    taxonomy.LANG_EXEC,
    taxonomy.PACKAGE_RUN,
    taxonomy.AGENT_EXEC_READ,
    taxonomy.AGENT_EXEC_WRITE,
    taxonomy.AGENT_EXEC_BYPASS,
}

DEFAULT_BOUNDARY = {
    taxonomy.NETWORK_OUTBOUND,
    taxonomy.NETWORK_WRITE,
    taxonomy.NETWORK_DIAGNOSTIC,
    taxonomy.GIT_REMOTE_WRITE,
    taxonomy.GIT_HISTORY_REWRITE,
    taxonomy.DB_READ,
    taxonomy.DB_WRITE,
    taxonomy.SERVICE_READ,
    taxonomy.SERVICE_WRITE,
    taxonomy.SERVICE_DESTRUCTIVE,
    taxonomy.CONTAINER_READ,
    taxonomy.CONTAINER_WRITE,
    taxonomy.CONTAINER_EXEC,
    taxonomy.CONTAINER_DESTRUCTIVE,
    taxonomy.BROWSER_INTERACT,
    taxonomy.BROWSER_STATE,
    taxonomy.BROWSER_NAVIGATE,
    taxonomy.BROWSER_EXEC,
    taxonomy.BROWSER_FILE,
    taxonomy.AGENT_EXEC_REMOTE,
    taxonomy.AGENT_SERVER,
}

_STATE_VERSION = 1


def apply_pre_tool(
    tool: str,
    tool_input: dict,
    decision: dict,
    *,
    runtime: str,
    runtime_meta: dict | None = None,
    execution: dict | None = None,
    transcript_path: str = "",
    terminal_audit_only: bool = False,
) -> dict:
    """Apply taint policy to a pre-execution decision."""
    cfg = _effective_taint_config()
    if cfg.get("mode") == "off":
        return decision

    runtime_meta = dict(runtime_meta or {})
    execution = dict(execution or {})
    session_id = _session_id(runtime, runtime_meta, transcript_path)
    state = _load_state(runtime, session_id)
    event = normalize_event(tool, tool_input, decision, runtime, runtime_meta)

    original_decision = str(decision.get("decision", taxonomy.ALLOW))
    labels = set(_active_labels(state))
    labels.update(_labels_for_tainted_targets(state, event))
    updates: dict[str, Any] = {}

    source_labels = _source_labels(tool, tool_input, event, cfg)
    if source_labels and original_decision != taxonomy.BLOCK:
        source_update = _record_source_pre_tool(
            state,
            event,
            sorted(source_labels),
            original_decision,
            execution,
        )
        if source_update:
            updates["source"] = source_update

    propagated = _record_propagation_pre_tool(
        state,
        event,
        labels,
        original_decision,
        cfg,
        execution,
    )
    if propagated:
        updates["propagated_targets"] = propagated

    policy = _resolve_sink_policy(event, labels, cfg)
    applied = _apply_policy_decision(
        decision,
        event,
        labels,
        policy,
        cfg,
        original_decision,
        terminal_audit_only=terminal_audit_only,
    )

    if updates or applied:
        _save_state(runtime, session_id, state)
        _attach_taint_meta(
            decision,
            cfg=cfg,
            event=event,
            labels=sorted(labels or source_labels),
            original_decision=original_decision,
            policy=policy,
            enforced=bool(applied.get("enforced")),
            audit_only=terminal_audit_only,
            updates=updates,
            chain=_chain_summary(state, sorted(labels or source_labels), event),
        )
    return decision


def apply_post_tool(
    tool: str,
    tool_input: dict,
    decision: dict,
    *,
    runtime: str,
    runtime_meta: dict | None = None,
    execution: dict | None = None,
    transcript_path: str = "",
) -> dict:
    """Finalize pending taint state from a post-tool execution outcome."""
    cfg = _effective_taint_config()
    if cfg.get("mode") == "off":
        return decision

    runtime_meta = dict(runtime_meta or {})
    execution = dict(execution or {})
    session_id = _session_id(runtime, runtime_meta, transcript_path)
    event_id = _event_id(tool, tool_input, runtime_meta)
    state = _load_state(runtime, session_id)
    pending_source = state.get("pending_sources", {}).get(event_id)
    pending_propagation = state.get("pending_propagations", {}).get(event_id)
    if not pending_source and not pending_propagation:
        return decision

    updates: dict[str, Any] = {}
    labels: list[str] = []
    if pending_source:
        status = "ignored"
        labels = [str(label) for label in pending_source.get("labels", []) if str(label)]
        if execution.get("state") == "executed":
            for label in labels:
                state.setdefault("active_labels", {}).setdefault(label, []).append({
                    "source": pending_source.get("target_display", ""),
                    "event_id": event_id,
                    "tool": pending_source.get("tool", tool),
                })
            status = "active"
        else:
            status = str(execution.get("state") or "not_executed")
        updates["source_finalized"] = status
        state.get("pending_sources", {}).pop(event_id, None)

    if pending_propagation:
        prop_status = str(execution.get("state") or "not_executed")
        propagated: list[dict] = []
        if execution.get("state") == "executed":
            entries = pending_propagation.get("entries", [])
            if isinstance(entries, list):
                propagated = _apply_propagation_entries(state, entries)
            prop_status = "active" if propagated else "no_target"
        updates["propagation_finalized"] = prop_status
        if propagated:
            updates["propagated_targets"] = propagated
            for entry in propagated:
                for label in entry.get("labels", []):
                    if label not in labels:
                        labels.append(label)
        state.get("pending_propagations", {}).pop(event_id, None)

    _save_state(runtime, session_id, state)

    event = normalize_event(tool, tool_input, decision, runtime, runtime_meta)
    _attach_taint_meta(
        decision,
        cfg=cfg,
        event=event,
        labels=labels,
        original_decision=str(decision.get("decision", taxonomy.ALLOW)),
        policy={},
        enforced=False,
        audit_only=False,
        updates=updates,
        chain=_chain_summary(state, labels, event),
    )
    return decision


def normalize_event(
    tool: str,
    tool_input: dict,
    decision: dict,
    runtime: str,
    runtime_meta: dict | None = None,
) -> dict:
    """Return a compact runtime-neutral event from a guarded tool call."""
    runtime_meta = runtime_meta or {}
    action_types = _action_types(tool, decision)
    target = _target(tool, tool_input, action_types, decision)
    return {
        "runtime": runtime,
        "session_id": str(runtime_meta.get("session_id", "")),
        "event_id": _event_id(tool, tool_input, runtime_meta),
        "event_id_explicit": bool(runtime_meta.get("tool_use_id") or runtime_meta.get("event_id")),
        "tool": tool,
        "action_types": action_types,
        "action_type": action_types[0] if action_types else "",
        "target": target,
        "decision": str(decision.get("decision", taxonomy.ALLOW)),
    }


def state_path(runtime: str, session_id: str) -> str:
    """Return the session state path for tests and diagnostics."""
    from nah.platform_paths import nah_config_dir

    safe_runtime = _safe_filename(runtime or "unknown")
    safe_session = _safe_filename(session_id or "unknown")
    return os.path.join(nah_config_dir(), "taint", "sessions", safe_runtime, f"{safe_session}.json")


def reset_state() -> None:
    """Remove all local taint session state. Intended for tests."""
    from nah.platform_paths import nah_config_dir

    root = os.path.join(nah_config_dir(), "taint", "sessions")
    try:
        shutil.rmtree(root)
    except FileNotFoundError:
        return
    except OSError as exc:
        sys.stderr.write(f"nah: taint: reset state: {exc}\n")


def _effective_taint_config() -> dict:
    try:
        from nah.config import get_config

        cfg = get_config()
        taint = cfg.taint if isinstance(cfg.taint, dict) else {}
    except Exception as exc:
        sys.stderr.write(f"nah: taint config: {exc}\n")
        taint = {}
    return _fill_taint_defaults(taint)


def _fill_taint_defaults(raw: dict) -> dict:
    cfg = {
        "mode": "off",
        "inherit_sensitive_paths": True,
        "labels": {},
        "sources": [],
        "propagation": {
            taxonomy.FILESYSTEM_WRITE: True,
            taxonomy.GIT_WRITE: True,
            taxonomy.BROWSER_FILE: True,
        },
        "categories": {
            "activation": {"add": [], "remove": []},
            "boundary": {"add": [], "remove": []},
        },
        "policies": {
            "default": {
                "activation": "audit",
                "boundary": "ask",
                "unknown": "ask",
            },
        },
    }
    if not isinstance(raw, dict):
        return cfg
    cfg.update({k: v for k, v in raw.items() if k not in ("propagation", "categories", "policies")})
    cfg["mode"] = cfg["mode"] if cfg.get("mode") in VALID_MODES else "off"
    if isinstance(raw.get("propagation"), dict):
        cfg["propagation"].update({
            str(k): bool(v)
            for k, v in raw["propagation"].items()
            if str(k) in TRACKABLE_PROPAGATION
        })
    if isinstance(raw.get("categories"), dict):
        for name in ("activation", "boundary"):
            data = raw["categories"].get(name, {})
            if isinstance(data, dict):
                cfg["categories"][name] = {
                    "add": [str(v) for v in data.get("add", []) if str(v)],
                    "remove": [str(v) for v in data.get("remove", []) if str(v)],
                }
    if isinstance(raw.get("policies"), dict):
        cfg["policies"] = raw["policies"]
    return cfg


def _load_state(runtime: str, session_id: str) -> dict:
    path = state_path(runtime, session_id)
    if not os.path.exists(path):
        return _empty_state(runtime, session_id)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or data.get("version") != _STATE_VERSION:
            return _empty_state(runtime, session_id)
        data.setdefault("active_labels", {})
        data.setdefault("pending_sources", {})
        data.setdefault("pending_propagations", {})
        data.setdefault("tainted_targets", {})
        data.setdefault("seq", 0)
        return data
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        sys.stderr.write(f"nah: taint: ignoring unreadable session state: {exc}\n")
        return _empty_state(runtime, session_id)


def _save_state(runtime: str, session_id: str, state: dict) -> None:
    state["updated_at"] = _now()
    state["seq"] = int(state.get("seq", 0)) + 1
    path = state_path(runtime, session_id)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, sort_keys=True, separators=(",", ":"))
            f.write("\n")
        os.replace(tmp, path)
    except OSError as exc:
        sys.stderr.write(f"nah: taint: state write: {exc}\n")


def _empty_state(runtime: str, session_id: str) -> dict:
    now = _now()
    return {
        "version": _STATE_VERSION,
        "runtime": runtime,
        "session_id": session_id,
        "created_at": now,
        "updated_at": now,
        "seq": 0,
        "active_labels": {},
        "pending_sources": {},
        "pending_propagations": {},
        "tainted_targets": {},
        "recent_chain": [],
    }


def _record_source_pre_tool(
    state: dict,
    event: dict,
    labels: list[str],
    decision: str,
    execution: dict,
) -> dict:
    event_id = event["event_id"]
    target = event.get("target", {})
    entry = {
        "tool": event.get("tool", ""),
        "target": target.get("identity", ""),
        "target_display": target.get("display", ""),
        "labels": labels,
    }
    if _requires_post_confirmation(event):
        state.setdefault("pending_sources", {})[event_id] = entry
        return {"status": "pending", "labels": labels}
    if decision == taxonomy.ALLOW or execution.get("state") in ("executed", "approved_to_run"):
        for label in labels:
            state.setdefault("active_labels", {}).setdefault(label, []).append({
                "source": target.get("display", ""),
                "event_id": event_id,
                "tool": event.get("tool", ""),
            })
        return {"status": "active", "labels": labels}
    state.setdefault("pending_sources", {})[event_id] = entry
    return {"status": "pending", "labels": labels}


def _requires_post_confirmation(event: dict) -> bool:
    return bool(event.get("event_id_explicit"))


def _record_propagation_pre_tool(
    state: dict,
    event: dict,
    labels: set[str],
    decision: str,
    cfg: dict,
    execution: dict,
) -> list[dict]:
    if not labels or decision == taxonomy.BLOCK:
        return []
    entries = _propagation_entries(state, event, labels, cfg)
    if not entries:
        return []
    if _requires_post_confirmation(event):
        state.setdefault("pending_propagations", {})[event["event_id"]] = {
            "tool": event.get("tool", ""),
            "entries": entries,
        }
        updates = [dict(entry, status="pending") for entry in entries]
        return updates
    if decision == taxonomy.ALLOW or execution.get("state") in ("executed", "approved_to_run"):
        return _apply_propagation_entries(state, entries)
    return []


def _propagation_entries(
    state: dict,
    event: dict,
    labels: set[str],
    cfg: dict,
) -> list[dict]:
    propagation = cfg.get("propagation", {})
    entries: list[dict] = []
    for action_type in event.get("action_types", []):
        if action_type not in TRACKABLE_PROPAGATION or not propagation.get(action_type, True):
            continue
        identity = _propagation_identity(event, action_type)
        if not identity:
            continue
        target = event.get("target", {})
        entries.append({
            "identity": identity,
            "display": target.get("display") or identity,
            "action_type": action_type,
            "labels": sorted(labels),
            "source_event_ids": _source_event_ids(state, labels),
            "created_event_id": event.get("event_id", ""),
        })
    return entries


def _apply_propagation_entries(state: dict, entries: list[dict]) -> list[dict]:
    updates: list[dict] = []
    for entry in entries:
        identity = str(entry.get("identity", ""))
        if not identity:
            continue
        target_entry = {
            "labels": [str(label) for label in entry.get("labels", []) if str(label)],
            "source_event_ids": [
                str(event_id)
                for event_id in entry.get("source_event_ids", [])
                if str(event_id)
            ],
            "created_event_id": str(entry.get("created_event_id", "")),
            "display": str(entry.get("display") or identity),
            "action_type": str(entry.get("action_type", "")),
        }
        state.setdefault("tainted_targets", {})[identity] = target_entry
        updates.append({
            "identity": identity,
            "display": target_entry["display"],
            "action_type": target_entry["action_type"],
            "labels": target_entry["labels"],
        })
    return updates


def _resolve_sink_policy(event: dict, labels: set[str], cfg: dict) -> dict:
    if not labels:
        return {}
    category, action_type = _sink_category(event, cfg)
    if not category:
        return {}

    best = "allow"
    best_expr = ""
    for label in sorted(labels):
        policy, key, source = _first_policy_for_label(label, action_type, category, cfg)
        if not policy:
            policy, key, source = _first_policy_for_label("default", action_type, category, cfg)
        if category == "unknown" and policy in ("", "allow", "audit"):
            policy = "ask"
            key = "unknown"
            source = label
        if policy and POLICY_STRICTNESS[policy] > POLICY_STRICTNESS[best]:
            best = policy
            best_expr = f"{source} + {key} = {policy}"
    if best == "allow":
        return {}
    return {
        "category": category,
        "action_type": action_type,
        "decision": best,
        "expr": best_expr or f"default + {category} = {best}",
    }


def _apply_policy_decision(
    decision: dict,
    event: dict,
    labels: set[str],
    policy: dict,
    cfg: dict,
    original_decision: str,
    *,
    terminal_audit_only: bool,
) -> dict:
    if not policy:
        return {}
    mode = cfg.get("mode", "off")
    policy_decision = policy.get("decision", "allow")
    enforced = (
        mode == "enforce"
        and not terminal_audit_only
        and policy_decision in (taxonomy.ASK, taxonomy.BLOCK)
        and POLICY_STRICTNESS[policy_decision] > DECISION_STRICTNESS.get(original_decision, 0)
    )
    if enforced:
        decision["decision"] = policy_decision
        reason = _policy_reason(policy)
        decision["reason"] = reason
        decision["_system_message"] = system_byline(policy_decision, reason)
    elif original_decision == taxonomy.ASK and policy_decision in (taxonomy.ASK, taxonomy.BLOCK):
        decision.setdefault("_meta", {})["taint_hint"] = _policy_reason(policy)
    return {"enforced": enforced, "labels": sorted(labels)}


def _attach_taint_meta(
    decision: dict,
    *,
    cfg: dict,
    event: dict,
    labels: list[str],
    original_decision: str,
    policy: dict,
    enforced: bool,
    audit_only: bool,
    updates: dict,
    chain: str,
) -> None:
    meta = decision.setdefault("_meta", {})
    taint: dict[str, Any] = {
        "mode": cfg.get("mode", "off"),
        "labels": labels,
        "event": {
            "tool": event.get("tool", ""),
            "action_type": event.get("action_type", ""),
            "action_types": event.get("action_types", []),
            "target": event.get("target", {}),
            "event_id": event.get("event_id", ""),
        },
        "actual_decision": original_decision,
        "enforced": enforced,
    }
    if chain:
        taint["chain"] = chain
    if policy:
        taint["category"] = policy.get("category", "")
        taint["policy"] = policy.get("expr", "")
        taint["policy_decision"] = policy.get("decision", "")
        if cfg.get("mode") == "audit" or audit_only:
            taint["would_decision"] = policy.get("decision", "")
    if updates:
        taint["updates"] = updates
    meta["taint"] = taint


def _source_labels(tool: str, tool_input: dict, event: dict, cfg: dict) -> set[str]:
    if taxonomy.FILESYSTEM_READ not in event.get("action_types", []) and tool != "Read":
        return set()
    raw_paths = _read_paths(tool, tool_input, event)
    labels: set[str] = set()
    for raw_path in raw_paths:
        labels.update(_explicit_source_labels(raw_path, cfg))
        if cfg.get("inherit_sensitive_paths", True):
            try:
                from nah import paths

                matched, _pattern, policy, _resolved = paths.inherited_sensitive_taint_source(raw_path)
                if matched and policy in (taxonomy.ASK, taxonomy.BLOCK):
                    labels.add("secret")
            except Exception as exc:
                sys.stderr.write(f"nah: taint: sensitive source match: {exc}\n")
    return labels


def _explicit_source_labels(raw_path: str, cfg: dict) -> set[str]:
    labels: set[str] = set()
    from nah import paths

    resolved = paths.resolve_path(raw_path)
    basename = os.path.basename(resolved)
    friendly = paths.friendly_path(resolved)
    candidates = {raw_path, resolved, friendly, basename}
    for source in cfg.get("sources", []):
        for pattern in source.get("paths", []):
            pattern = str(pattern)
            if any(fnmatch.fnmatch(candidate, pattern) for candidate in candidates):
                labels.update(str(label) for label in source.get("labels", []) if str(label))
    return labels


def _read_paths(tool: str, tool_input: dict, event: dict) -> list[str]:
    if tool in ("Read", "Glob", "Grep"):
        raw = tool_input.get("file_path") or tool_input.get("path") or tool_input.get("pattern")
        return [str(raw)] if raw else []
    if tool == "Bash":
        target = event.get("target", {})
        if target.get("kind") == "path" and target.get("raw"):
            return [str(target["raw"])]
    return []


def _active_labels(state: dict) -> list[str]:
    labels = state.get("active_labels", {})
    if not isinstance(labels, dict):
        return []
    return [str(label) for label, entries in labels.items() if entries]


def _labels_for_tainted_targets(state: dict, event: dict) -> set[str]:
    labels: set[str] = set()
    targets = state.get("tainted_targets", {})
    if not isinstance(targets, dict):
        return labels
    for identity in _sink_identities(event):
        entry = targets.get(identity)
        if isinstance(entry, dict):
            labels.update(str(label) for label in entry.get("labels", []) if str(label))
    return labels


def _sink_identities(event: dict) -> list[str]:
    identities: list[str] = []
    target = event.get("target", {})
    identity = target.get("identity", "")
    if identity:
        identities.append(identity)
    repo = _repo_identity()
    if repo:
        identities.append(repo)
    return list(dict.fromkeys(identities))


def _source_event_ids(state: dict, labels: set[str]) -> list[str]:
    ids: list[str] = []
    for label in labels:
        for entry in state.get("active_labels", {}).get(label, []):
            event_id = entry.get("event_id", "")
            if event_id and event_id not in ids:
                ids.append(event_id)
    return ids


def _action_types(tool: str, decision: dict) -> list[str]:
    meta = decision.get("_meta", {}) if isinstance(decision, dict) else {}
    stages = meta.get("stages", [])
    result: list[str] = []
    if isinstance(stages, list):
        for stage in stages:
            if not isinstance(stage, dict):
                continue
            action = str(stage.get("action_type", ""))
            if action and action not in result:
                result.append(action)
    if result:
        return result
    if tool in ("Read", "Glob", "Grep"):
        return [taxonomy.FILESYSTEM_READ]
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"):
        return [taxonomy.FILESYSTEM_WRITE]
    return [taxonomy.UNKNOWN]


def _target(tool: str, tool_input: dict, action_types: list[str], decision: dict) -> dict:
    if tool in ("Read", "Glob", "Grep"):
        raw = tool_input.get("file_path") or tool_input.get("path") or tool_input.get("pattern") or ""
        return _path_target(raw)
    if tool in ("Write", "Edit", "MultiEdit"):
        return _path_target(tool_input.get("file_path", ""))
    if tool == "NotebookEdit":
        return _path_target(tool_input.get("notebook_path", ""))
    if tool == "apply_patch":
        paths = tool_input.get("_nah_patch_paths", [])
        if isinstance(paths, list) and paths:
            return _path_target(str(paths[0]))
    if tool == "Bash":
        return _bash_target(tool_input, action_types, decision)
    if tool.startswith("mcp__"):
        return {"kind": "mcp", "display": tool, "identity": f"mcp:{tool}"}
    return {"kind": "unknown", "display": tool, "identity": ""}


def _bash_target(tool_input: dict, action_types: list[str], decision: dict) -> dict:
    meta = decision.get("_meta", {}) if isinstance(decision, dict) else {}
    stages = meta.get("stages", [])
    if isinstance(stages, list):
        for stage in stages:
            if not isinstance(stage, dict):
                continue
            redirect = stage.get("redirect_target", "")
            if redirect:
                return _path_target(str(redirect))
            tokens = stage.get("tokens", [])
            action_type = stage.get("action_type")
            if action_type in (taxonomy.FILESYSTEM_READ, taxonomy.LANG_EXEC):
                raw = _first_path_arg(tokens)
                if raw:
                    return _path_target(raw)
            if action_type == taxonomy.FILESYSTEM_WRITE:
                raw = _last_path_arg(tokens)
                if raw:
                    return _path_target(raw)
    if any(a in (taxonomy.GIT_WRITE, taxonomy.GIT_REMOTE_WRITE) for a in action_types):
        repo = _repo_identity()
        return {"kind": "repo", "display": repo.replace("repo:", "", 1), "identity": repo}
    command = str(tool_input.get("command", ""))
    display = command[:80]
    return {"kind": "command", "display": display, "identity": _command_identity(command)}


def _path_target(raw: Any) -> dict:
    raw_text = str(raw or "")
    if not raw_text:
        return {"kind": "unknown", "display": "", "identity": ""}
    from nah import paths

    resolved = paths.resolve_path(raw_text)
    return {
        "kind": "path",
        "raw": raw_text,
        "display": paths.friendly_path(resolved),
        "identity": f"path:{resolved}",
        "extension": Path(resolved).suffix,
    }


def _propagation_identity(event: dict, action_type: str) -> str:
    if action_type == taxonomy.GIT_WRITE:
        return _repo_identity()
    target = event.get("target", {})
    if target.get("kind") == "path":
        return target.get("identity", "")
    return ""


def _repo_identity() -> str:
    try:
        from nah import paths

        root = paths.get_project_root() or os.getcwd()
        return f"repo:{paths.resolve_path(root)}"
    except Exception:
        return f"repo:{os.getcwd()}"


def _sink_category(event: dict, cfg: dict) -> tuple[str, str]:
    activation = set(DEFAULT_ACTIVATION)
    boundary = set(DEFAULT_BOUNDARY)
    categories = cfg.get("categories", {})
    for name, target in (("activation", activation), ("boundary", boundary)):
        data = categories.get(name, {}) if isinstance(categories, dict) else {}
        if not isinstance(data, dict):
            continue
        target.update(str(v) for v in data.get("add", []) if str(v))
        target.difference_update(str(v) for v in data.get("remove", []) if str(v))

    for action_type in event.get("action_types", []):
        if action_type == taxonomy.UNKNOWN:
            return "unknown", taxonomy.UNKNOWN
        if action_type in boundary:
            return "boundary", action_type
        if action_type in activation:
            return "activation", action_type
    return "", event.get("action_type", "")


def _policy_for(label: str, key: str, cfg: dict) -> str:
    policies = cfg.get("policies", {})
    if not isinstance(policies, dict):
        return ""
    label_policies = policies.get(label, {})
    if not isinstance(label_policies, dict):
        return ""
    policy = label_policies.get(key, "")
    if policy in VALID_POLICIES:
        return policy
    return ""


def _first_policy_for_label(
    label: str,
    action_type: str,
    category: str,
    cfg: dict,
) -> tuple[str, str, str]:
    """Resolve policy order for one label: specific action before group."""
    for key in (action_type, category):
        policy = _policy_for(label, key, cfg)
        if policy:
            return policy, key, label
    return "", "", label


def _policy_reason(policy: dict) -> str:
    category = policy.get("category", "")
    if category == "boundary":
        return "sensitive data may be crossing a trust boundary."
    if category == "activation":
        return "this executes code after sensitive data was read earlier in this session."
    if category == "unknown":
        return "an unrecognized action follows sensitive data access."
    return "sensitive data read earlier may flow into this action."


def _chain_summary(state: dict, labels: list[str], event: dict) -> str:
    if not labels:
        return ""
    sources: list[str] = []
    for label in labels:
        entries = state.get("active_labels", {}).get(label, [])
        if entries:
            source = entries[-1].get("source", "")
            sources.append(f"Read {source or '?'} {label}")
        else:
            sources.append(f"{label} source")
    target = event.get("target", {}).get("display") or event.get("tool", "")
    return " -> ".join([*sources[:2], f"{event.get('tool', '')} {target}".strip()])


def _event_id(tool: str, tool_input: dict, runtime_meta: dict) -> str:
    explicit = runtime_meta.get("tool_use_id") or runtime_meta.get("event_id")
    if explicit:
        return str(explicit)
    return _fallback_event_id({"tool": tool, "tool_input": tool_input})


def _fallback_event_id(event: dict) -> str:
    payload = json.dumps(event, sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()[:24]


def _session_id(runtime: str, runtime_meta: dict, transcript_path: str = "") -> str:
    explicit = runtime_meta.get("session_id")
    if explicit:
        return str(explicit)
    if transcript_path:
        return os.path.basename(transcript_path)
    if runtime == "terminal":
        env = os.environ.get("NAH_SESSION_ID")
        if env:
            return env
        tty = os.environ.get("TTY") or "terminal"
        return f"{tty}:{os.getppid()}:{datetime.now(timezone.utc).date().isoformat()}"
    return "unknown"


def _safe_filename(value: str) -> str:
    text = str(value or "unknown")
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("._")
    if safe:
        return safe[:160]
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:32]


def _command_identity(command: str) -> str:
    return "command:" + hashlib.sha256(command.encode("utf-8", "replace")).hexdigest()[:24]


def _first_path_arg(tokens: Any) -> str:
    if not isinstance(tokens, list):
        return ""
    for token in tokens[1:]:
        text = str(token)
        if not text or text.startswith("-"):
            continue
        if "/" in text or text.startswith(".") or text.startswith("~"):
            return text
    return ""


def _last_path_arg(tokens: Any) -> str:
    if not isinstance(tokens, list):
        return ""
    candidates: list[str] = []
    last_non_flag = ""
    for token in tokens[1:]:
        text = str(token)
        if not text or text.startswith("-"):
            continue
        last_non_flag = text
        if "/" in text or text.startswith(".") or text.startswith("~"):
            candidates.append(text)
    return candidates[-1] if candidates else last_non_flag


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
