"""Runtime-neutral session provenance tracking.

Provenance is an authorship layer: normal nah policy still controls immediate
access, while this module remembers files/repo state written during the guarded
run and evaluates later activation/boundary actions against that session delta.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nah import taxonomy

VALID_MODES = {"off", "audit", "enforce"}
VALID_POLICIES = {"allow", "context", "ask", "block"}
POLICY_STRICTNESS = {"allow": 0, "context": 1, "ask": 2, "block": 3}
DECISION_STRICTNESS = {
    taxonomy.ALLOW: 0,
    taxonomy.ASK: 2,
    taxonomy.BLOCK: 3,
}

DEFAULT_REVIEW = {
    "max_files": 50,
    "max_bytes_per_file": 16384,
    "max_bytes_total": 131072,
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
_RUN_ID_ENV = "NAH_PROVENANCE_RUN_ID"
_SOURCE_EXTENSIONS = {
    ".bash",
    ".c",
    ".cc",
    ".cpp",
    ".cjs",
    ".go",
    ".js",
    ".jsx",
    ".mjs",
    ".php",
    ".pl",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".ts",
    ".tsx",
}
_MANIFEST_NAMES = {
    "Cargo.toml",
    "Makefile",
    "Pipfile",
    "composer.json",
    "deno.json",
    "go.mod",
    "justfile",
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "pyproject.toml",
    "requirements.txt",
    "taskfile.yml",
    "tox.ini",
    "uv.lock",
    "yarn.lock",
}


def new_run_id() -> str:
    """Return a fresh process/run id suitable for NAH_PROVENANCE_RUN_ID."""
    return f"run-{uuid.uuid4().hex}"


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
    context_review: bool = True,
) -> dict:
    """Apply provenance policy to a pre-execution decision."""
    cfg = _effective_provenance_config()
    if cfg.get("mode") == "off":
        return decision

    runtime_meta = dict(runtime_meta or {})
    execution = dict(execution or {})
    run_id = _run_id(runtime, runtime_meta, transcript_path)
    session_id = _session_id(runtime, runtime_meta, transcript_path)
    state = _load_state(run_id)
    _register_session(state, session_id)
    event = normalize_event(tool, tool_input, decision, runtime, runtime_meta)
    original_decision = str(decision.get("decision", taxonomy.ALLOW))

    updates: dict[str, Any] = {}
    write_update = _record_write_candidate(state, event, decision, original_decision, execution)
    if write_update:
        updates["write"] = write_update

    policy = _resolve_sink_policy(state, event, cfg)
    applied = _apply_policy_decision(
        decision,
        event,
        state,
        policy,
        cfg,
        original_decision,
        terminal_audit_only=terminal_audit_only,
        context_review=context_review,
    )

    if updates or policy or applied:
        _save_state(run_id, state)
        _attach_provenance_meta(
            decision,
            cfg=cfg,
            event=event,
            run_id=run_id,
            original_decision=original_decision,
            policy=policy,
            applied=applied,
            audit_only=terminal_audit_only,
            updates=updates,
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
    """Finalize pending provenance state from a post-tool execution outcome."""
    cfg = _effective_provenance_config()
    if cfg.get("mode") == "off":
        return decision

    runtime_meta = dict(runtime_meta or {})
    execution = dict(execution or {})
    run_id = _run_id(runtime, runtime_meta, transcript_path)
    session_id = _session_id(runtime, runtime_meta, transcript_path)
    state = _load_state(run_id)
    _register_session(state, session_id)
    event = normalize_event(tool, tool_input, decision, runtime, runtime_meta)
    event_id = event["event_id"]
    pending = state.get("pending_writes", {}).pop(event_id, None)

    status = "ignored"
    finalized: list[dict] = []
    if execution.get("state") == "executed":
        descriptors = pending.get("descriptors", []) if isinstance(pending, dict) else []
        if not descriptors:
            descriptors = _write_descriptors(event, decision)
        finalized = _finalize_descriptors(state, descriptors, event)
        status = "active" if finalized else "no_write_target"
    elif pending:
        status = str(execution.get("state") or "not_executed")

    if pending or finalized:
        _save_state(run_id, state)
        _attach_provenance_meta(
            decision,
            cfg=cfg,
            event=event,
            run_id=run_id,
            original_decision=str(decision.get("decision", taxonomy.ALLOW)),
            policy={},
            applied={},
            audit_only=False,
            updates={"write_finalized": status, "artifacts": finalized},
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
    targets = _targets(tool, tool_input, action_types, decision)
    target = targets[0] if targets else {"kind": "unknown", "display": "", "identity": ""}
    return {
        "runtime": runtime,
        "session_id": str(runtime_meta.get("session_id", "")),
        "event_id": _event_id(tool, tool_input, runtime_meta),
        "event_id_explicit": bool(runtime_meta.get("tool_use_id") or runtime_meta.get("event_id")),
        "tool": tool,
        "action_types": action_types,
        "action_type": action_types[0] if action_types else "",
        "target": target,
        "targets": targets,
        "decision": str(decision.get("decision", taxonomy.ALLOW)),
    }


def state_path(run_id: str) -> str:
    """Return the run state path for tests and diagnostics."""
    from nah.platform_paths import nah_config_dir

    return os.path.join(nah_config_dir(), "provenance", "runs", f"{_safe_filename(run_id)}.json")


def reset_state() -> None:
    """Remove all local provenance run state. Intended for tests."""
    from nah.platform_paths import nah_config_dir

    root = os.path.join(nah_config_dir(), "provenance", "runs")
    try:
        shutil.rmtree(root)
    except FileNotFoundError:
        return
    except OSError as exc:
        sys.stderr.write(f"nah: provenance: reset state: {exc}\n")


def _effective_provenance_config() -> dict:
    try:
        from nah.config import get_config

        cfg = get_config()
        raw = cfg.provenance if isinstance(cfg.provenance, dict) else {}
    except Exception as exc:
        sys.stderr.write(f"nah: provenance config: {exc}\n")
        raw = {}
    return _fill_provenance_defaults(raw)


def _fill_provenance_defaults(raw: dict) -> dict:
    cfg = {
        "mode": "off",
        "categories": {
            "activation": {"add": [], "remove": []},
            "boundary": {"add": [], "remove": []},
        },
        "policies": {
            "activation": "context",
            "boundary": "ask",
        },
        "review": dict(DEFAULT_REVIEW),
    }
    if not isinstance(raw, dict):
        return cfg
    cfg.update({k: v for k, v in raw.items() if k not in ("categories", "policies", "review")})
    if cfg.get("mode") not in VALID_MODES:
        cfg["mode"] = "off"
    if isinstance(raw.get("categories"), dict):
        for name in ("activation", "boundary"):
            data = raw["categories"].get(name, {})
            if isinstance(data, dict):
                cfg["categories"][name] = {
                    "add": [str(v) for v in data.get("add", []) if str(v)],
                    "remove": [str(v) for v in data.get("remove", []) if str(v)],
                }
    if isinstance(raw.get("policies"), dict):
        cfg["policies"] = {
            str(k): str(v)
            for k, v in raw["policies"].items()
            if str(v) in VALID_POLICIES
        }
    if isinstance(raw.get("review"), dict):
        for key, default in DEFAULT_REVIEW.items():
            try:
                value = int(raw["review"].get(key, default))
            except (TypeError, ValueError):
                value = default
            cfg["review"][key] = value if value > 0 else default
    return cfg


def _load_state(run_id: str) -> dict:
    path = state_path(run_id)
    if not os.path.exists(path):
        return _empty_state(run_id)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or data.get("version") != _STATE_VERSION:
            return _empty_state(run_id)
        data.setdefault("sessions", [])
        data.setdefault("repos", {})
        data.setdefault("artifacts", {})
        data.setdefault("pending_writes", {})
        data.setdefault("seq", 0)
        return data
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        sys.stderr.write(f"nah: provenance: ignoring unreadable run state: {exc}\n")
        return _empty_state(run_id)


def _save_state(run_id: str, state: dict) -> None:
    state["updated_at"] = _now()
    state["seq"] = int(state.get("seq", 0)) + 1
    path = state_path(run_id)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, sort_keys=True, separators=(",", ":"))
            f.write("\n")
        os.replace(tmp, path)
    except OSError as exc:
        sys.stderr.write(f"nah: provenance: state write: {exc}\n")


def _empty_state(run_id: str) -> dict:
    now = _now()
    return {
        "version": _STATE_VERSION,
        "run_id": run_id,
        "created_at": now,
        "updated_at": now,
        "seq": 0,
        "sessions": [],
        "repos": {},
        "artifacts": {},
        "pending_writes": {},
    }


def _register_session(state: dict, session_id: str) -> None:
    if session_id and session_id not in state.setdefault("sessions", []):
        state["sessions"].append(session_id)


def _record_write_candidate(
    state: dict,
    event: dict,
    decision: dict,
    original_decision: str,
    execution: dict,
) -> dict:
    if original_decision == taxonomy.BLOCK:
        return {}
    descriptors = _write_descriptors(event, decision)
    if not descriptors:
        return {}
    event_id = event["event_id"]
    if event.get("event_id_explicit"):
        state.setdefault("pending_writes", {})[event_id] = {
            "tool": event.get("tool", ""),
            "descriptors": descriptors,
        }
        return {"status": "pending", "targets": _descriptor_displays(descriptors)}
    if original_decision == taxonomy.ALLOW or execution.get("state") in ("executed", "approved_to_run"):
        finalized = _finalize_descriptors(state, descriptors, event)
        return {"status": "active", "artifacts": finalized}
    state.setdefault("pending_writes", {})[event_id] = {
        "tool": event.get("tool", ""),
        "descriptors": descriptors,
    }
    return {"status": "pending", "targets": _descriptor_displays(descriptors), "confidence": "fallback"}


def _write_descriptors(event: dict, decision: dict) -> list[dict]:
    tool = event.get("tool", "")
    descriptors: list[dict] = []
    for target in event.get("targets", []) or []:
        if target.get("kind") == "path" and _is_write_target(tool, event, target):
            descriptors.append(_path_descriptor(target, event, decision))
    action_types = event.get("action_types", [])
    if taxonomy.GIT_WRITE in action_types:
        descriptors.append({
            "kind": "repo",
            "repo": _repo_identity(),
            "display": _repo_identity().replace("repo:", "", 1),
            "action_type": taxonomy.GIT_WRITE,
            "stamp": "indexed",
        })
    if not descriptors and _has_local_write(action_types):
        repo = _repo_identity()
        descriptors.append({
            "kind": "incomplete",
            "repo": repo,
            "display": repo.replace("repo:", "", 1),
            "action_type": _first_write_action(action_types),
            "stamp": "incomplete",
        })
    return descriptors


def _path_descriptor(target: dict, event: dict, decision: dict) -> dict:
    identity = target.get("identity", "")
    path = identity.replace("path:", "", 1) if identity.startswith("path:") else ""
    info = _file_fingerprint(path)
    stamp = "flagged" if _has_deterministic_flag(decision) else "indexed"
    return {
        "kind": "path",
        "identity": identity,
        "raw": target.get("raw", ""),
        "display": target.get("display", ""),
        "repo": _repo_identity_for_path(path),
        "action_type": target.get("action_type") or _first_write_action(event.get("action_types", [])),
        "tool": event.get("tool", ""),
        "stamp": stamp,
        "pre_hash": info.get("hash", ""),
        "pre_size": info.get("size", 0),
    }


def _finalize_descriptors(state: dict, descriptors: list[dict], event: dict) -> list[dict]:
    finalized: list[dict] = []
    for desc in descriptors:
        kind = desc.get("kind", "")
        repo = desc.get("repo") or _repo_identity()
        if kind == "path":
            identity = desc.get("identity", "")
            path = identity.replace("path:", "", 1) if identity.startswith("path:") else ""
            info = _file_fingerprint(path)
            stamp = desc.get("stamp") if desc.get("stamp") == "flagged" else "clean_local"
            if not path or not os.path.exists(path):
                stamp = "incomplete"
            artifact = {
                "repo": repo,
                "tool": desc.get("tool") or event.get("tool", ""),
                "action_type": desc.get("action_type") or event.get("action_type", ""),
                "event_id": event.get("event_id", ""),
                "stamp": stamp,
                "pre_hash": desc.get("pre_hash", ""),
                "post_hash": info.get("hash", ""),
                "size": info.get("size", 0),
                "display": desc.get("display", ""),
                "updated_at": _now(),
            }
            state.setdefault("artifacts", {})[identity] = artifact
            repo_entry = state.setdefault("repos", {}).setdefault(
                repo,
                {"paths": [], "dirty_git_state": False, "incomplete_writes": 0},
            )
            if identity and identity not in repo_entry.setdefault("paths", []):
                repo_entry["paths"].append(identity)
            finalized.append({
                "identity": identity,
                "display": desc.get("display", ""),
                "stamp": stamp,
            })
        elif kind == "repo":
            repo_entry = state.setdefault("repos", {}).setdefault(
                repo,
                {"paths": [], "dirty_git_state": False, "incomplete_writes": 0},
            )
            repo_entry["dirty_git_state"] = True
            finalized.append({"repo": repo, "stamp": "indexed"})
        elif kind == "incomplete":
            repo_entry = state.setdefault("repos", {}).setdefault(
                repo,
                {"paths": [], "dirty_git_state": False, "incomplete_writes": 0},
            )
            repo_entry["incomplete_writes"] = int(repo_entry.get("incomplete_writes", 0)) + 1
            finalized.append({"repo": repo, "stamp": "incomplete"})
    return finalized


def _resolve_sink_policy(state: dict, event: dict, cfg: dict) -> dict:
    category, action_type = _sink_category(event, cfg)
    if not category:
        return {}
    match = _match_session_state(state, event, category, action_type)
    if not match:
        return {}
    policy = _policy_for(action_type, category, cfg)
    if category == "unknown" and policy in ("", "allow", "context"):
        policy = "ask"
    if not policy or policy == "allow":
        return {}
    return {
        "category": category,
        "action_type": action_type,
        "decision": policy,
        "expr": f"{action_type if action_type else category} = {policy}",
        "match": match,
    }


def _apply_policy_decision(
    decision: dict,
    event: dict,
    state: dict,
    policy: dict,
    cfg: dict,
    original_decision: str,
    *,
    terminal_audit_only: bool,
    context_review: bool,
) -> dict:
    if not policy:
        return {}
    mode = cfg.get("mode", "off")
    policy_decision = policy.get("decision", "allow")
    applied = {
        "enforced": False,
        "review": {},
        "decision": policy_decision,
    }
    if mode != "enforce" or terminal_audit_only:
        return applied
    if original_decision == taxonomy.BLOCK:
        return applied

    final_decision = policy_decision
    reason = _policy_reason(policy)
    review_meta: dict[str, Any] = {}
    if policy_decision == taxonomy.CONTEXT:
        if context_review:
            final_decision, reason, review_meta = _resolve_context_review(
                state,
                event,
                policy,
                cfg,
            )
        else:
            final_decision = taxonomy.ASK
            reason = "session provenance context review unavailable in headless deterministic mode"
            review_meta = {"status": "disabled_for_headless"}
        applied["review"] = review_meta

    if final_decision not in (taxonomy.ASK, taxonomy.BLOCK):
        return applied
    if DECISION_STRICTNESS[final_decision] > DECISION_STRICTNESS.get(original_decision, 0):
        decision["decision"] = final_decision
        decision["reason"] = reason
        decision["_system_message"] = f"nah paused: {reason}"
        applied["enforced"] = True
    return applied


def _resolve_context_review(
    state: dict,
    event: dict,
    policy: dict,
    cfg: dict,
) -> tuple[str, str, dict]:
    packet = build_review_packet(state, event, policy, cfg)
    review_meta: dict[str, Any] = {
        "packet_complete": bool(packet.get("complete")),
        "files": len(packet.get("files", [])),
        "omitted": len(packet.get("omitted", [])),
    }
    if not packet.get("complete"):
        return taxonomy.ASK, "session provenance review needs complete changed-file context", review_meta

    try:
        from nah.config import get_config
        from nah.llm import try_llm_provenance_review

        config = get_config()
        if config.llm_mode != "on" or not config.llm:
            review_meta["status"] = "no_provider"
            return taxonomy.ASK, "session provenance context review unavailable", review_meta
        llm_call = try_llm_provenance_review(packet, config.llm)
        review_meta.update({
            "provider": llm_call.provider,
            "model": llm_call.model,
            "latency_ms": llm_call.latency_ms,
            "decision": (
                llm_call.decision.get("decision", "")
                if llm_call.decision is not None else ""
            ),
            "reasoning": llm_call.reasoning,
            "reasoning_long": getattr(llm_call, "reasoning_long", ""),
        })
        if llm_call.decision and llm_call.decision.get("decision") == taxonomy.ALLOW:
            return taxonomy.ALLOW, "session provenance reviewer allowed activation", review_meta
        return taxonomy.ASK, llm_call.reasoning or "session provenance reviewer was uncertain", review_meta
    except Exception as exc:
        review_meta["error"] = str(exc)[:200]
        return taxonomy.ASK, "session provenance context review failed", review_meta


def build_review_packet(state: dict, event: dict, policy: dict, cfg: dict) -> dict:
    """Build a bounded session-delta packet for provenance context review."""
    review = cfg.get("review", {})
    max_files = int(review.get("max_files", DEFAULT_REVIEW["max_files"]))
    max_per_file = int(review.get("max_bytes_per_file", DEFAULT_REVIEW["max_bytes_per_file"]))
    max_total = int(review.get("max_bytes_total", DEFAULT_REVIEW["max_bytes_total"]))
    identities = _review_identities(state, event, policy)
    packet = {
        "version": 1,
        "action": {
            "tool": event.get("tool", ""),
            "action_type": policy.get("action_type", ""),
            "category": policy.get("category", ""),
            "target": event.get("target", {}),
        },
        "limits": {
            "max_files": max_files,
            "max_bytes_per_file": max_per_file,
            "max_bytes_total": max_total,
        },
        "files": [],
        "omitted": [],
        "complete": True,
    }
    used = 0
    for identity in identities:
        if len(packet["files"]) >= max_files:
            packet["omitted"].append({"identity": identity, "reason": "max_files"})
            packet["complete"] = False
            continue
        artifact = state.get("artifacts", {}).get(identity, {})
        path = identity.replace("path:", "", 1) if identity.startswith("path:") else ""
        try:
            size = os.path.getsize(path)
            if size > max_per_file:
                packet["omitted"].append({"identity": identity, "reason": "max_bytes_per_file"})
                packet["complete"] = False
                continue
            if used + size > max_total:
                packet["omitted"].append({"identity": identity, "reason": "max_bytes_total"})
                packet["complete"] = False
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            used += len(content.encode("utf-8", "replace"))
            packet["files"].append({
                "identity": identity,
                "path": path,
                "display": artifact.get("display", path),
                "action_type": artifact.get("action_type", ""),
                "stamp": artifact.get("stamp", ""),
                "size": size,
                "content": content,
            })
        except OSError as exc:
            packet["omitted"].append({"identity": identity, "reason": f"unreadable: {exc}"})
            packet["complete"] = False
    for repo_id, repo in state.get("repos", {}).items():
        if repo.get("incomplete_writes"):
            packet["omitted"].append({"repo": repo_id, "reason": "incomplete_write_target"})
            packet["complete"] = False
        if repo.get("dirty_git_state") and not repo.get("paths"):
            packet["omitted"].append({"repo": repo_id, "reason": "dirty_git_state_without_file_delta"})
            packet["complete"] = False
    return packet


def _review_identities(state: dict, event: dict, policy: dict) -> list[str]:
    direct: list[str] = []
    for target in event.get("targets", []) or []:
        identity = target.get("identity", "")
        if identity in state.get("artifacts", {}):
            direct.append(identity)
    repos = _matched_repos(state, event, policy.get("category", ""), policy.get("action_type", ""))
    repo_paths: list[str] = []
    for repo in repos:
        repo_paths.extend(state.get("repos", {}).get(repo, {}).get("paths", []))
    identities = [*direct, *_prioritized_paths(state, repo_paths)]
    return list(dict.fromkeys(identities))


def _prioritized_paths(state: dict, identities: list[str]) -> list[str]:
    def key(identity: str) -> tuple[int, str]:
        path = identity.replace("path:", "", 1)
        name = os.path.basename(path)
        suffix = Path(path).suffix
        priority = 2
        if name in _MANIFEST_NAMES:
            priority = 0
        elif suffix in _SOURCE_EXTENSIONS:
            priority = 1
        updated = state.get("artifacts", {}).get(identity, {}).get("updated_at", "")
        return priority, updated

    return sorted(dict.fromkeys(identities), key=key)


def _match_session_state(state: dict, event: dict, category: str, action_type: str) -> dict:
    artifacts = state.get("artifacts", {})
    for target in event.get("targets", []) or []:
        identity = target.get("identity", "")
        if identity and identity in artifacts:
            return {"scope": "path", "identity": identity}
    repos = _matched_repos(state, event, category, action_type)
    if repos:
        return {"scope": "repo", "repos": repos}
    if category == "unknown" and _state_has_written_material(state):
        return {"scope": "run"}
    return {}


def _matched_repos(state: dict, event: dict, category: str, action_type: str) -> list[str]:
    repo = _event_repo(event)
    if repo and repo in state.get("repos", {}):
        if category == "boundary":
            return [repo]
        if action_type in {
            taxonomy.PACKAGE_RUN,
            taxonomy.AGENT_EXEC_READ,
            taxonomy.AGENT_EXEC_WRITE,
            taxonomy.AGENT_EXEC_BYPASS,
        }:
            return [repo]
        if action_type == taxonomy.LANG_EXEC and not _event_has_path_target(event):
            return [repo]
    return []


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


def _policy_for(action_type: str, category: str, cfg: dict) -> str:
    policies = cfg.get("policies", {})
    if not isinstance(policies, dict):
        return ""
    for key in (action_type, category):
        policy = policies.get(key, "")
        if policy in VALID_POLICIES:
            return policy
    return ""


def _policy_reason(policy: dict) -> str:
    category = policy.get("category", "")
    if category == "boundary":
        return "session-written code or data may be crossing a trust boundary."
    if category == "activation":
        return "this activates code or repo state written earlier in this guarded session."
    if category == "unknown":
        return "an unrecognized action follows session-written state."
    return "session-written state affects this action."


def _attach_provenance_meta(
    decision: dict,
    *,
    cfg: dict,
    event: dict,
    run_id: str,
    original_decision: str,
    policy: dict,
    applied: dict,
    audit_only: bool,
    updates: dict,
) -> None:
    meta = decision.setdefault("_meta", {})
    provenance: dict[str, Any] = {
        "mode": cfg.get("mode", "off"),
        "run_id": run_id,
        "event": {
            "tool": event.get("tool", ""),
            "action_type": event.get("action_type", ""),
            "action_types": event.get("action_types", []),
            "target": event.get("target", {}),
            "event_id": event.get("event_id", ""),
        },
        "actual_decision": original_decision,
        "enforced": bool(applied.get("enforced")),
    }
    if policy:
        provenance["category"] = policy.get("category", "")
        provenance["policy"] = policy.get("expr", "")
        provenance["policy_decision"] = policy.get("decision", "")
        provenance["match"] = policy.get("match", {})
        if cfg.get("mode") == "audit" or audit_only:
            provenance["would_decision"] = policy.get("decision", "")
    if applied.get("review"):
        provenance["review"] = applied["review"]
    if updates:
        provenance["updates"] = updates
    meta["provenance"] = provenance


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


def _targets(tool: str, tool_input: dict, action_types: list[str], decision: dict) -> list[dict]:
    if tool in ("Read", "Glob", "Grep"):
        raw = tool_input.get("file_path") or tool_input.get("path") or tool_input.get("pattern") or ""
        return [_path_target(raw)] if raw else []
    if tool in ("Write", "Edit", "MultiEdit"):
        target = _path_target(tool_input.get("file_path", ""))
        target["action_type"] = taxonomy.FILESYSTEM_WRITE
        return [target]
    if tool == "NotebookEdit":
        target = _path_target(tool_input.get("notebook_path", ""))
        target["action_type"] = taxonomy.FILESYSTEM_WRITE
        return [target]
    if tool == "apply_patch":
        paths = tool_input.get("_nah_patch_paths", [])
        if isinstance(paths, list):
            targets = []
            for p in paths:
                if not str(p):
                    continue
                target = _path_target(str(p))
                target["action_type"] = taxonomy.FILESYSTEM_WRITE
                targets.append(target)
            return targets
        return []
    if tool == "Bash":
        return _bash_targets(tool_input, action_types, decision)
    if tool.startswith("mcp__"):
        return [{"kind": "mcp", "display": tool, "identity": f"mcp:{tool}"}]
    return [{"kind": "unknown", "display": tool, "identity": ""}]


def _bash_targets(tool_input: dict, action_types: list[str], decision: dict) -> list[dict]:
    meta = decision.get("_meta", {}) if isinstance(decision, dict) else {}
    stages = meta.get("stages", [])
    targets: list[dict] = []
    if isinstance(stages, list):
        for stage in stages:
            if not isinstance(stage, dict):
                continue
            redirect = stage.get("redirect_target", "")
            if redirect:
                target = _path_target(str(redirect))
                target["action_type"] = taxonomy.FILESYSTEM_WRITE
                targets.append(target)
                continue
            tokens = stage.get("tokens", [])
            action_type = stage.get("action_type")
            raw = ""
            if action_type in (taxonomy.FILESYSTEM_READ, taxonomy.FILESYSTEM_WRITE):
                raw = _last_path_arg(tokens) if action_type == taxonomy.FILESYSTEM_WRITE else _first_path_arg(tokens)
            elif action_type == taxonomy.LANG_EXEC:
                raw = _lang_exec_path_arg(tokens)
            if raw:
                target = _path_target(raw)
                target["action_type"] = str(action_type or "")
                targets.append(target)
    if any(a in (taxonomy.GIT_WRITE, taxonomy.GIT_REMOTE_WRITE) for a in action_types):
        repo = _repo_identity()
        targets.append({"kind": "repo", "display": repo.replace("repo:", "", 1), "identity": repo})
    if targets:
        return targets
    command = str(tool_input.get("command", ""))
    return [{"kind": "command", "display": command[:80], "identity": _command_identity(command)}]


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


def _is_write_target(tool: str, event: dict, target: dict) -> bool:
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"):
        return True
    if tool != "Bash":
        return False
    return target.get("action_type") in {taxonomy.FILESYSTEM_WRITE, taxonomy.BROWSER_FILE}


def _has_local_write(action_types: list[str]) -> bool:
    return any(a in {taxonomy.FILESYSTEM_WRITE, taxonomy.GIT_WRITE, taxonomy.BROWSER_FILE} for a in action_types)


def _first_write_action(action_types: list[str]) -> str:
    for action in action_types:
        if action in {taxonomy.FILESYSTEM_WRITE, taxonomy.GIT_WRITE, taxonomy.BROWSER_FILE}:
            return action
    return taxonomy.FILESYSTEM_WRITE


def _has_deterministic_flag(decision: dict) -> bool:
    meta = decision.get("_meta", {}) if isinstance(decision, dict) else {}
    return bool(meta.get("content_match") or meta.get("warning") or decision.get("decision") == taxonomy.BLOCK)


def _event_has_path_target(event: dict) -> bool:
    return any(t.get("kind") == "path" for t in event.get("targets", []) or [])


def _event_repo(event: dict) -> str:
    for target in event.get("targets", []) or []:
        if target.get("kind") == "path":
            identity = target.get("identity", "")
            path = identity.replace("path:", "", 1) if identity.startswith("path:") else ""
            return _repo_identity_for_path(path)
        if target.get("kind") == "repo" and target.get("identity"):
            return str(target["identity"])
    return _repo_identity()


def _repo_identity() -> str:
    try:
        from nah import paths

        root = paths.get_project_root() or os.getcwd()
        return f"repo:{paths.resolve_path(root)}"
    except Exception:
        return f"repo:{os.getcwd()}"


def _repo_identity_for_path(path: str) -> str:
    try:
        from nah import paths

        project_root = paths.get_project_root()
        if project_root:
            resolved = paths.resolve_path(path)
            root = paths.resolve_path(project_root)
            if resolved == root or resolved.startswith(root + os.sep):
                return f"repo:{root}"
        return _repo_identity()
    except Exception:
        return _repo_identity()


def _state_has_written_material(state: dict) -> bool:
    return bool(state.get("artifacts") or state.get("repos"))


def _descriptor_displays(descriptors: list[dict]) -> list[str]:
    result = []
    for desc in descriptors:
        result.append(desc.get("display") or desc.get("identity") or desc.get("repo") or desc.get("kind", ""))
    return [value for value in result if value]


def _file_fingerprint(path: str) -> dict:
    if not path:
        return {}
    try:
        h = hashlib.sha256()
        size = 0
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                size += len(chunk)
                h.update(chunk)
        return {"hash": f"sha256:{h.hexdigest()}", "size": size}
    except OSError:
        return {}


def _event_id(tool: str, tool_input: dict, runtime_meta: dict) -> str:
    explicit = runtime_meta.get("tool_use_id") or runtime_meta.get("event_id")
    if explicit:
        return str(explicit)
    return _fallback_event_id({"tool": tool, "tool_input": tool_input})


def _fallback_event_id(event: dict) -> str:
    payload = json.dumps(event, sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()[:24]


def _run_id(runtime: str, runtime_meta: dict, transcript_path: str = "") -> str:
    env = os.environ.get(_RUN_ID_ENV)
    if env:
        return env
    explicit = runtime_meta.get("run_id")
    if explicit:
        return str(explicit)
    session_id = _session_id(runtime, runtime_meta, transcript_path)
    if session_id and session_id != "unknown":
        return f"session:{session_id}"
    return "unknown"


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
        if "/" in text or text.startswith(".") or text.startswith("~") or Path(text).suffix:
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
        if "/" in text or text.startswith(".") or text.startswith("~") or Path(text).suffix:
            candidates.append(text)
    return candidates[-1] if candidates else last_non_flag


def _lang_exec_path_arg(tokens: Any) -> str:
    if not isinstance(tokens, list) or len(tokens) < 2:
        return ""
    skip_next_for = {"-m", "-c", "-e", "--eval"}
    i = 1
    while i < len(tokens):
        text = str(tokens[i])
        if text in skip_next_for:
            return ""
        if text.startswith("-"):
            i += 1
            continue
        if "/" in text or text.startswith(".") or text.startswith("~") or Path(text).suffix in _SOURCE_EXTENSIONS:
            return text
        i += 1
    return ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
