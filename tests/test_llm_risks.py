"""Tests for canonical LLM risk categories."""

from nah.llm_risks import (
    LLM_RISK_CATEGORIES,
    llm_risk_category_ids,
    render_llm_risk_categories,
    render_llm_risk_section,
)


EXPECTED_IDS = (
    "credentials",
    "exfiltration",
    "untrusted_execution",
    "persistence_boundary",
    "privileged_state",
    "destructive_state",
    "external_mutation",
    "safety_bypass",
    "user_scope_conflict",
)


def test_llm_risk_category_ids_are_stable():
    assert llm_risk_category_ids() == EXPECTED_IDS


def test_llm_risk_categories_have_human_labels_and_descriptions():
    assert len(LLM_RISK_CATEGORIES) == len(EXPECTED_IDS)
    for category in LLM_RISK_CATEGORIES:
        assert category.id
        assert category.label
        assert category.description
        assert category.id not in category.label


def test_rendered_categories_include_every_label_once():
    rendered = render_llm_risk_categories()

    for category in LLM_RISK_CATEGORIES:
        assert rendered.count(category.label) == 1
        assert category.description in rendered


def test_rendered_section_keeps_surface_specific_intro():
    rendered = render_llm_risk_section("Choose uncertain when the script visibly does:")

    assert rendered.startswith("Choose uncertain when the script visibly does:")
    assert "Credentials and sensitive paths" in rendered
    assert "Explicit user safety-scope conflict" in rendered
