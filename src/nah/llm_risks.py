"""Canonical LLM safety risk categories used by prompt renderers."""

from dataclasses import dataclass


@dataclass(frozen=True)
class LLMRiskCategory:
    """One code-owned risk category shared by LLM prompt surfaces."""

    id: str
    label: str
    description: str
    # Layer-2 veto tier (nah-986). "hard": a citation can never relax an action
    # that visibly involves this category. "soft": a citation MAY relax it — the
    # per-action allow-list in the Layer-2 prompt (_RELAX_ENABLED) decides which
    # soft categories are actually relaxable for a given action type. Defaults to
    # "hard": a new category vetoes until deliberately marked soft (fail-safe).
    tier: str = "hard"


LLM_RISK_CATEGORIES: tuple[LLMRiskCategory, ...] = (
    LLMRiskCategory(
        "credentials",
        "Credentials and sensitive paths",
        "credentials, tokens, private keys, passwords, sensitive paths, or broader secret access",
    ),
    LLMRiskCategory(
        "exfiltration",
        "Exfiltration or unauthorized access",
        "local data, environment values, repository content, credentials, or user data sent to unauthorized remote destinations",
    ),
    LLMRiskCategory(
        "untrusted_execution",
        "Untrusted or obfuscated execution",
        "downloaded, generated, obfuscated, hidden, or injection-prone execution",
    ),
    LLMRiskCategory(
        "persistence_boundary",
        "Persistence and trust-boundary changes",
        "startup files, hooks, package lifecycle scripts, CI/deploy/release automation, auth/session config, or other trust-boundary changes",
        tier="soft",
    ),
    LLMRiskCategory(
        "privileged_state",
        "Privileged runtime or system state",
        "process, service, container, database, system, or privileged runtime state changes",
        tier="soft",
    ),
    LLMRiskCategory(
        "destructive_state",
        "Destructive or hard-to-reverse state changes",
        "broad deletion, overwrite, migration, reset, purge, force/history rewrite, or hard-to-reverse state mutation",
        tier="soft",
    ),
    LLMRiskCategory(
        "external_mutation",
        "Production, shared, remote, or external mutations",
        "production, shared, remote, or externally visible mutation",
        tier="soft",
    ),
    LLMRiskCategory(
        "safety_bypass",
        "Safety, sandbox, approval, or audit bypass",
        "sandbox, approval, audit, policy, hook, or guard bypass",
    ),
    LLMRiskCategory(
        "user_scope_conflict",
        "Explicit user safety-scope conflict",
        "recent user instructions constrain credentials, production, deploys, auth, persistence, external writes, safety controls, or similar boundaries, and the operation visibly crosses that constraint",
    ),
)


def llm_risk_category_ids() -> tuple[str, ...]:
    """Return stable internal category IDs for tests and maintenance."""

    return tuple(category.id for category in LLM_RISK_CATEGORIES)


def render_llm_risk_categories() -> str:
    """Render canonical risk categories as prompt bullets."""

    return "\n".join(
        f"- {category.label}: {category.description}."
        for category in LLM_RISK_CATEGORIES
    )


def llm_risk_tiers() -> dict[str, str]:
    """Return {category_id: tier} for tests and the Layer-2 prompt builder."""

    return {category.id: category.tier for category in LLM_RISK_CATEGORIES}


def render_llm_risk_labels(exclude: tuple[str, ...] = ()) -> str:
    """Render the canonical risk categories as a compact inline checklist.

    Labels only (no example sub-lists), semicolon-separated — for token-tight
    prompts that still want every category as a checklist. Same source as the
    verbose renderers, so the two can never drift. ``exclude`` drops categories
    by id, used by the Layer-2 prompt to lift a soft category's veto for the
    specific action types that are allowed to relax it (nah-986).
    """

    return "; ".join(
        category.label.lower()
        for category in LLM_RISK_CATEGORIES
        if category.id not in exclude
    )


def render_llm_risk_section(intro: str) -> str:
    """Render an intro plus the canonical risk category bullets."""

    return f"{intro}\n{render_llm_risk_categories()}"
