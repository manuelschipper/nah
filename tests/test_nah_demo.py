"""Tests for the packaged /nah-demo cases."""

import pytest

from nah import config, content, context, paths, taxonomy
from nah.bash import classify_command
from nah.config import NahConfig
from nah.demo_cases import load_nah_demo_cases
from nah.hook import (
    _classify_unknown_tool,
    handle_edit,
    handle_glob,
    handle_grep,
    handle_read,
    handle_write,
)


CASES = load_nah_demo_cases()
REQUIRED_FIELDS = {
    "id",
    "story",
    "category",
    "tool",
    "input",
    "expected",
    "mode",
    "narration",
    "description",
}
STORIES = {
    "safe_operations",
    "remote_code_execution",
    "data_exfiltration",
    "obfuscated_execution",
    "path_boundary_protection",
    "destructive_operations",
    "credential_secret_detection",
    "network_context",
}
TOOLS = {"Bash", "Read", "Write", "Edit", "Glob", "Grep", "MCP"}
DECISIONS = {"allow", "ask", "block"}
MODES = {"live", "dry_run"}


def _case_id(case: dict) -> str:
    return f"{case['id']}:{case['tool']}:{case['expected']}"


def _reset_runtime_config() -> None:
    config._cached_config = NahConfig(
        llm_mode="off",
        trusted_paths=["/tmp", "/private/tmp"],
    )
    paths.reset_sensitive_paths()
    content.reset_content_patterns()
    context.reset_known_hosts()
    taxonomy.reset_exec_sinks()
    taxonomy.reset_decode_commands()


def _decision_for(case: dict) -> str:
    tool = case["tool"]
    tool_input = dict(case["input"])

    if tool == "Bash":
        return classify_command(tool_input["command"]).final_decision
    if tool == "Read":
        return handle_read(tool_input)["decision"]
    if tool == "Write":
        return handle_write(tool_input)["decision"]
    if tool == "Edit":
        return handle_edit(tool_input)["decision"]
    if tool == "Glob":
        return handle_glob(tool_input)["decision"]
    if tool == "Grep":
        return handle_grep(tool_input)["decision"]
    if tool == "MCP":
        return _classify_unknown_tool(
            tool_input["tool_name"],
            tool_input.get("tool_input", {}),
        )["decision"]

    raise AssertionError(f"unsupported demo tool: {tool}")


def test_demo_has_exactly_25_cases():
    assert len(CASES) == 25


def test_demo_cases_have_required_shape():
    seen_ids = set()

    for case in CASES:
        assert set(case) == REQUIRED_FIELDS
        assert case["id"] not in seen_ids
        seen_ids.add(case["id"])
        assert case["story"] in STORIES
        assert case["tool"] in TOOLS
        assert case["expected"] in DECISIONS
        assert case["mode"] in MODES
        assert isinstance(case["input"], dict)
        assert case["narration"]
        assert case["description"]


def test_demo_covers_all_stories():
    assert {case["story"] for case in CASES} == STORIES


def test_live_demo_cases_are_stable_allows():
    assert all(case["expected"] == "allow" for case in CASES if case["mode"] == "live")


@pytest.mark.parametrize("case", CASES, ids=_case_id)
def test_demo_expected_decisions(case, project_root, monkeypatch):
    _reset_runtime_config()
    monkeypatch.chdir(project_root)

    assert _decision_for(case) == case["expected"]
