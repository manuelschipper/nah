"""Tests for the threat-model coverage audit module."""

from __future__ import annotations

import json

from nah import audit_threat_model as audit


def _sample_node_ids() -> list[str]:
    return [
        "tests/test_bash.py::TestComposition::test_curl_pipe_bash_block",
        "tests/test_content.py::TestIsCredentialSearch::test_detects_secret_scan",
        "tests/test_fd080_write_llm.py::TestVetoGate::test_private_key_escalates",
        "tests/test_bash.py::TestFD017Regressions::test_git_push_force_short_flag_ask",
        "tests/test_bash.py::TestDecomposition::test_redirect_write_detection",
        "tests/test_bash.py::TestProcessSubstitutionInspection::test_process_substitution_blocks_exec",
        'tests/test_bash.py::TestPassthroughWrappers::test_passthrough_wrappers_preserve_safe_inner_classification[env bash -c "git status"]',
        "tests/test_paths.py::TestIsSensitive::test_ssh_path_is_sensitive",
        "tests/test_fd079_script_exec.py::TestContextResolver::test_outside_project_asks",
        "tests/test_taxonomy.py::TestFD019PackageInstall::test_package_install[tokens0]",
        "tests/test_bash.py::TestContainerDestructiveCoverage::test_container_destructive_entries_ask[docker rm]",
        "tests/test_paths.py::TestIsHookPath::test_claude_hook_path",
        "tests/test_agents.py::TestDetectAgent::test_unknown_defaults_claude",
    ]


def test_rules_cover_every_survey_category():
    assert tuple(rule.category for rule in audit.RULES) == audit.CATEGORY_ORDER


def test_audit_node_ids_matches_categories_and_reports_overlap():
    report = audit.audit_node_ids(_sample_node_ids())

    for category in audit.CATEGORY_ORDER:
        assert report["categories"][category]["count"] > 0

    overlap = next(
        item
        for item in report["overlaps"]
        if item["node_id"] == "tests/test_bash.py::TestComposition::test_curl_pipe_bash_block"
    )
    assert overlap["categories"] == ["rce", "credential_exfil"]
    assert report["unmatched"] == ["tests/test_agents.py::TestDetectAgent::test_unknown_defaults_claude"]


def test_renderers_include_all_categories():
    report = audit.audit_node_ids(_sample_node_ids())

    summary_lines = audit.render_summary(report).splitlines()
    assert len(summary_lines) == len(audit.CATEGORY_ORDER)

    payload = json.loads(audit.render_json(report))
    assert set(payload["categories"]) == set(audit.CATEGORY_ORDER)

    markdown = audit.render_markdown(report)
    assert "# Threat model coverage audit" in markdown
    assert "## package_escalation" in markdown
