"""Hook-level tests for the single LLM classify job."""

import io
import json
import sys
from unittest.mock import patch

from nah import config, hook, taxonomy
from nah.config import NahConfig
from nah.llm import LLMClassification, LLMClassifyResult, ProviderAttempt


def _run_hook(payload: dict) -> dict:
    stdin_mock = io.StringIO(json.dumps(payload))
    stdout_mock = io.StringIO()
    old_stdin, old_stdout = sys.stdin, sys.stdout
    sys.stdin, sys.stdout = stdin_mock, stdout_mock
    try:
        hook.main()
    finally:
        sys.stdin, sys.stdout = old_stdin, old_stdout
    return json.loads(stdout_mock.getvalue())


def _classify(action_type, targets, evidence="ev"):
    return LLMClassifyResult(
        classification=LLMClassification(action_type, targets, evidence),
        provider="fake",
        model="test",
        latency_ms=3,
        cascade=[ProviderAttempt("fake", "success", 3, "test")],
    )


def _unknown_ask_decision():
    return {
        "decision": taxonomy.ASK,
        "reason": "Bash: unknown command",
        "_meta": {
            "stages": [{
                "action_type": taxonomy.UNKNOWN,
                "decision": taxonomy.ASK,
                "policy": taxonomy.ASK,
                "reason": "unknown command",
            }],
        },
    }


def test_handle_bash_does_not_clear_inline_python(project_root):
    config._cached_config = NahConfig(
        llm_mode="on",
        llm={"providers": ["fake"], "fake": {"model": "test"}},
    )

    with patch("nah.llm.try_llm_classify_unknown") as classify:
        result = hook.handle_bash({"command": "python3 -c 'print(1)'"})

    assert result["decision"] == taxonomy.ASK
    assert "llm_passes" not in result.get("_meta", {})
    classify.assert_not_called()


def test_maybe_apply_layer1_classify_maps_unknown_to_allow(monkeypatch):
    monkeypatch.setattr(
        "nah.config.get_config",
        lambda: NahConfig(
            llm_mode="on",
            llm={"providers": ["fake"], "fake": {"model": "test"}},
        ),
    )
    monkeypatch.setattr(
        "nah.llm.try_llm_classify_unknown",
        lambda *_args, **_kwargs: _classify(
            taxonomy.NETWORK_OUTBOUND,
            [{"kind": "host", "value": "github.com"}],
            "github.com",
        ),
    )

    out = hook.maybe_apply_layer1_classify(
        "Bash",
        {"command": "mystery github.com"},
        _unknown_ask_decision(),
    )

    assert out["decision"] == taxonomy.ALLOW
    assert out["_meta"]["action_type_source"] == "llm_classify"
    assert out["_meta"]["llm_passes"][0]["phase"] == "classify"


def test_maybe_apply_layer1_classify_skips_known_ask(monkeypatch):
    def fail(*_args, **_kwargs):
        raise AssertionError("known action should not call the LLM")

    monkeypatch.setattr("nah.llm.try_llm_classify_unknown", fail)
    decision = {
        "decision": taxonomy.ASK,
        "reason": "Bash: unknown host",
        "_meta": {"stages": [{"action_type": taxonomy.NETWORK_OUTBOUND}]},
    }

    out = hook.maybe_apply_layer1_classify(
        "Bash",
        {"command": "curl -I https://example.invalid"},
        decision,
    )

    assert out is decision


def test_main_applies_classify_unknown(monkeypatch):
    monkeypatch.setattr(
        "nah.config.get_config",
        lambda: NahConfig(
            llm_mode="on",
            llm={"providers": ["fake"], "fake": {"model": "test"}},
        ),
    )
    monkeypatch.setattr(
        "nah.llm.try_llm_classify_unknown",
        lambda *_args, **_kwargs: _classify(
            taxonomy.NETWORK_OUTBOUND,
            [{"kind": "host", "value": "github.com"}],
            "github.com",
        ),
    )
    with patch("nah.hook._log_hook_decision"):
        result = _run_hook({
            "tool_name": "Bash",
            "tool_input": {"command": "mystery github.com"},
            "transcript_path": "",
        })

    assert result["hookSpecificOutput"]["permissionDecision"] == "allow"
