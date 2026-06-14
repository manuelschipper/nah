"""Canonical LLM safety risk categories used by prompt renderers."""

from dataclasses import dataclass


@dataclass(frozen=True)
class LLMRiskCategory:
    """One code-owned risk category shared by LLM prompt surfaces."""

    id: str
    label: str
    description: str


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
    ),
    LLMRiskCategory(
        "privileged_state",
        "Privileged runtime or system state",
        "process, service, container, database, system, or privileged runtime state changes",
    ),
    LLMRiskCategory(
        "destructive_state",
        "Destructive or hard-to-reverse state changes",
        "broad deletion, overwrite, migration, reset, purge, force/history rewrite, or hard-to-reverse state mutation",
    ),
    LLMRiskCategory(
        "external_mutation",
        "Production, shared, remote, or external mutations",
        "production, shared, remote, or externally visible mutation",
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


def render_llm_risk_labels() -> str:
    """Render the canonical risk categories as a compact inline checklist.

    Labels only (no example sub-lists), semicolon-separated — for token-tight
    prompts that still want every category as a checklist. Same source as the
    verbose renderers, so the two can never drift.
    """

    return "; ".join(category.label.lower() for category in LLM_RISK_CATEGORIES)


def render_llm_risk_section(intro: str) -> str:
    """Render an intro plus the canonical risk category bullets."""

    return f"{intro}\n{render_llm_risk_categories()}"
