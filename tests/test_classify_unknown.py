"""Layer-1 classify-unknown (nah-982): try_llm_classify_unknown + parser."""

import json

import pytest

import nah.llm as llm_mod
from nah.llm import (
    LLMClassification,
    _classify_parser,
    _normalize_classify_targets,
    reset_classify_cache,
    try_llm_classify_unknown,
)


@pytest.fixture(autouse=True)
def _clear_cache():
    reset_classify_cache()
    yield
    reset_classify_cache()


def _fake_provider_returning(payload: str):
    """Build a fake provider that feeds `payload` through the supplied parser."""
    calls = {"n": 0}

    def fake(_config, _prompt, parse=None):
        calls["n"] += 1
        return parse(payload)

    return fake, calls


_CFG = {"providers": ["fake"], "fake": {"model": "test-model"}}


# --- parser ---


def test_parser_accepts_valid_classification():
    parse = _classify_parser(frozenset({"filesystem_read"}))
    out = parse(json.dumps({
        "action_type": "filesystem_read",
        "targets": [{"kind": "path", "value": "~/notes.txt"}],
        "evidence": "cat ~/notes.txt",
    }))
    assert out.action_type == "filesystem_read"
    assert out.targets == [{"kind": "path", "value": "~/notes.txt"}]
    assert out.evidence


def test_parser_unknown_when_type_not_in_set():
    parse = _classify_parser(frozenset({"filesystem_read"}))
    out = parse(json.dumps({
        "action_type": "made_up_type", "targets": [], "evidence": "x",
    }))
    assert out.action_type == "unknown"


def test_parser_unknown_when_evidence_empty():
    parse = _classify_parser(frozenset({"filesystem_read"}))
    out = parse(json.dumps({
        "action_type": "filesystem_read",
        "targets": [{"kind": "path", "value": "x"}],
        "evidence": "",
    }))
    assert out.action_type == "unknown"


def test_parser_none_on_malformed_json():
    parse = _classify_parser(frozenset({"filesystem_read"}))
    assert parse("not json at all") is None


def test_parser_strips_code_fence():
    parse = _classify_parser(frozenset({"git_safe"}))
    fenced = "```json\n" + json.dumps({
        "action_type": "git_safe", "targets": [], "evidence": "git status",
    }) + "\n```"
    out = parse(fenced)
    assert out.action_type == "git_safe"


# --- target normalization ---


def test_normalize_drops_missing_value_and_coerces_bad_kind():
    out = _normalize_classify_targets([
        {"kind": "path", "value": "a.txt"},
        {"kind": "bogus", "value": "evil.com"},   # bad kind -> unknown
        {"kind": "host"},                          # no value -> dropped
        "not a dict",                              # dropped
    ])
    assert out == [
        {"kind": "path", "value": "a.txt"},
        {"kind": "unknown", "value": "evil.com"},
    ]


def test_normalize_caps_target_count():
    many = [{"kind": "path", "value": f"f{i}"} for i in range(100)]
    out = _normalize_classify_targets(many)
    assert len(out) == 32


# --- end-to-end via mocked provider ---


def test_classify_maps_unknown_to_type(monkeypatch):
    fake, calls = _fake_provider_returning(json.dumps({
        "action_type": "filesystem_read",
        "targets": [{"kind": "path", "value": "foo.txt"}],
        "evidence": "wrappercat foo.txt",
    }))
    monkeypatch.setitem(llm_mod._PROVIDERS, "fake", fake)
    res = try_llm_classify_unknown("wrappercat foo.txt", _CFG)
    assert res.classification.action_type == "filesystem_read"
    assert res.classification.targets == [{"kind": "path", "value": "foo.txt"}]
    assert res.provider == "fake"
    assert res.model == "test-model"
    assert res.cascade[0].status == "success"


def test_classify_unknown_response_is_terminal(monkeypatch):
    fake, calls = _fake_provider_returning(json.dumps({
        "action_type": "unknown", "targets": [], "evidence": "",
    }))
    monkeypatch.setitem(llm_mod._PROVIDERS, "fake", fake)
    res = try_llm_classify_unknown("gibberish zorp", _CFG)
    assert res.classification.action_type == "unknown"
    assert res.cascade[0].status == "uncertain"


def test_classify_none_when_all_providers_error(monkeypatch):
    def fake(_config, _prompt, parse=None):
        return None  # transport/parse failure

    monkeypatch.setitem(llm_mod._PROVIDERS, "fake", fake)
    res = try_llm_classify_unknown("somecmd", _CFG)
    assert res.classification is None
    assert res.cascade[0].status == "error"


def test_classify_caches_by_command(monkeypatch):
    fake, calls = _fake_provider_returning(json.dumps({
        "action_type": "git_safe", "targets": [], "evidence": "git status",
    }))
    monkeypatch.setitem(llm_mod._PROVIDERS, "fake", fake)
    try_llm_classify_unknown("samecmd", _CFG)
    try_llm_classify_unknown("samecmd", _CFG)
    assert calls["n"] == 1  # second call served from cache, no provider hit


def test_classify_does_not_cache_all_errored(monkeypatch):
    state = {"n": 0}

    def fake(_config, _prompt, parse=None):
        state["n"] += 1
        return None

    monkeypatch.setitem(llm_mod._PROVIDERS, "fake", fake)
    try_llm_classify_unknown("errcmd", _CFG)
    try_llm_classify_unknown("errcmd", _CFG)
    assert state["n"] == 2  # errored verdict not cached -> retried


def test_classify_accepts_custom_type(monkeypatch):
    fake, calls = _fake_provider_returning(json.dumps({
        "action_type": "my_custom_type",
        "targets": [{"kind": "host", "value": "api.internal"}],
        "evidence": "mytool",
    }))
    monkeypatch.setitem(llm_mod._PROVIDERS, "fake", fake)
    res = try_llm_classify_unknown(
        "mytool", _CFG, custom_types={"my_custom_type": "ask"},
    )
    assert res.classification.action_type == "my_custom_type"
