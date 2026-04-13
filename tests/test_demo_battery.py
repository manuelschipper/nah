"""Regression tests for the packaged nah demo battery."""

import json
from pathlib import Path

import pytest

from nah import config, content, context, paths, taxonomy
from nah.bash import classify_command
from nah.config import NahConfig, apply_override
from nah.hook import (
    _classify_unknown_tool,
    handle_edit,
    handle_glob,
    handle_grep,
    handle_read,
    handle_write,
)


BATTERY_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "nah"
    / "data"
    / "test_battery.json"
)
BATTERY = json.loads(BATTERY_PATH.read_text())


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

    raise AssertionError(f"unsupported battery tool: {tool}")


@pytest.mark.parametrize("case", BATTERY["base"], ids=_case_id)
def test_base_battery_expected_decisions(case, project_root, monkeypatch):
    _reset_runtime_config()
    monkeypatch.chdir(project_root)

    assert _decision_for(case) == case["expected"]


@pytest.mark.parametrize("case", BATTERY["variants"], ids=_case_id)
def test_variant_battery_expected_decisions(case, project_root, monkeypatch):
    _reset_runtime_config()
    apply_override(case["config"])
    monkeypatch.chdir(project_root)

    assert _decision_for(case) == case["expected"]
