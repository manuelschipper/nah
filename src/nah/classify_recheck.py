"""Layer-1 target re-check (nah-982).

Layer 1 (the LLM) extracts a type + kind-tagged targets; this module runs those
targets through the SAME deterministic floor a known command hits, then combines
the result with the mapped type's policy to produce the Layer-1 verdict. The LLM
extracts; the floor matches — matching never moves into the model.

Dispatch is target-kind -> checker (NOT action_type -> checker), so the floor
stays target-keyed and custom action types need no resource-kind metadata.
"""

from nah import taxonomy
from nah.context import check_container_target, check_db_target, check_host
from nah.paths import check_path_basic_raw, check_project_boundary

# Restrictiveness ranking over final decisions only (allow < ask < block).
_RANK = {taxonomy.ALLOW: 0, taxonomy.ASK: 1, taxonomy.BLOCK: 2}

# Label used in boundary reasons for re-checked targets.
_RECHECK_TOOL = "command"

# Allow-policy types that are safe with no surfaced target (they act on no
# externally-sensitive resource). Every other allow/context type that surfaces
# no target falls back to ask — we cannot verify what it touches.
_TARGET_INSENSITIVE_ALLOW = frozenset({
    taxonomy.GIT_SAFE,
    taxonomy.NETWORK_DIAGNOSTIC,
    taxonomy.PACKAGE_RUN,
})


def _worst(a: str, b: str) -> str:
    """Return the more-restrictive of two decisions."""
    return a if _RANK.get(a, 1) >= _RANK.get(b, 1) else b


def _check_path_target(value: str) -> tuple[str, str]:
    """Run a path through the sensitive-path floor + project boundary."""
    basic = check_path_basic_raw(value)
    decision, reason = basic if basic else (taxonomy.ALLOW, "")
    boundary = check_project_boundary(_RECHECK_TOOL, value)
    if boundary:
        decision = _worst(decision, boundary.get("decision", taxonomy.ASK))
        reason = reason or boundary.get("reason", "")
    return decision, (reason or "path ok")


def _check_host_target(value: str, action_type: str) -> tuple[str, str]:
    return check_host(value, action_type)


def _check_target(target: dict, action_type: str) -> tuple[str, str]:
    """Route one kind-tagged target to the right deterministic checker."""
    kind = target.get("kind", "unknown")
    value = target.get("value", "")
    if not value:
        return taxonomy.ASK, "empty target"
    if kind == "path":
        return _check_path_target(value)
    if kind == "host":
        return _check_host_target(value, action_type)
    if kind == "db":
        # Route through the SAME config-driven allowlist the deterministic floor
        # uses (db_targets); no match -> ask, matching resolve_database_context.
        return check_db_target(value)
    if kind == "container":
        # Route through trusted_containers, mirroring the deterministic floor.
        return check_container_target(value)
    # unknown / unroutable kind: sniff as both path and host, worst wins, so a
    # mislabeled sensitive path or host is still caught.
    pd, pr = _check_path_target(value)
    hd, hr = _check_host_target(value, action_type)
    worst = _worst(pd, hd)
    if worst == pd and pd != taxonomy.ALLOW:
        return pd, pr
    if hd != taxonomy.ALLOW:
        return hd, hr
    return taxonomy.ALLOW, "no floor match"


def _is_target_sensitive(action_type: str, policy: str) -> bool:
    """Whether the type needs a verifiable target to be safely auto-allowed."""
    if policy == taxonomy.CONTEXT:
        return True
    if policy == taxonomy.ALLOW:
        return action_type not in _TARGET_INSENSITIVE_ALLOW
    return False


def recheck(classification, policy: str) -> dict:
    """Run Layer-1 targets through the floor and combine with the type policy.

    `classification` is duck-typed (`.action_type`, `.targets`). Returns
    `{"decision", "reason", "targets": [{kind, value, floor, reason}]}` where the
    per-target list is the audit trail of what the model claimed and how the
    floor ruled on each.
    """
    action_type = classification.action_type
    target_results: list = []
    worst = taxonomy.ALLOW
    worst_reason = ""
    for t in classification.targets:
        decision, reason = _check_target(t, action_type)
        target_results.append({
            "kind": t.get("kind", "unknown"),
            "value": t.get("value", ""),
            "floor": decision,
            "reason": reason,
        })
        if _worst(worst, decision) != worst:
            worst, worst_reason = decision, reason

    # The mapped type's own policy comes first for the non-allow tiers.
    if policy == taxonomy.BLOCK:
        return {"decision": taxonomy.BLOCK,
                "reason": f"{action_type} → block", "targets": target_results}
    if policy == taxonomy.ASK:
        return {"decision": taxonomy.ASK,
                "reason": f"{action_type} → ask", "targets": target_results}

    # allow / context: the surfaced targets decide.
    if worst == taxonomy.BLOCK:
        return {"decision": taxonomy.BLOCK,
                "reason": worst_reason or f"{action_type}: target blocked",
                "targets": target_results}
    if worst == taxonomy.ASK:
        return {"decision": taxonomy.ASK,
                "reason": worst_reason or f"{action_type}: target needs review",
                "targets": target_results}
    if not classification.targets and _is_target_sensitive(action_type, policy):
        return {"decision": taxonomy.ASK,
                "reason": f"{action_type}: no verifiable target",
                "targets": target_results}
    return {"decision": taxonomy.ALLOW,
            "reason": f"{action_type}: targets cleared",
            "targets": target_results}
