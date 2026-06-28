"""Unit tests for the LLM classify provider layer."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from nah import taxonomy
from nah.llm import (
    PromptParts,
    _build_classify_prompt,
    _classify_parser,
    _try_providers_classify,
    try_llm_classify_unknown,
)


@pytest.fixture(autouse=True)
def _disable_keyring(monkeypatch):
    monkeypatch.setattr("nah.llm_keys._load_keyring", lambda: None)


def _prompt():
    return _build_classify_prompt(
        "mystery github.com",
        {taxonomy.NETWORK_OUTBOUND: "contacts a network host"},
    )


def _parse():
    return _classify_parser(frozenset({taxonomy.NETWORK_OUTBOUND, taxonomy.GIT_SAFE}))


def _payload(action_type=taxonomy.NETWORK_OUTBOUND):
    return json.dumps({
        "action_type": action_type,
        "targets": [{"kind": "host", "value": "github.com"}],
        "evidence": "github.com",
    })


def _cfg(provider, data=None):
    return {
        "providers": [provider],
        provider: {"model": "test-model", **(data or {})},
    }


def test_prompt_contains_command_only():
    prompt = _prompt()

    assert isinstance(prompt, PromptParts)
    assert "mystery github.com" in prompt.user
    assert "Action types:" in prompt.system
    assert "recent user messages" not in prompt.user


def test_provider_cascade_accepts_classification(monkeypatch):
    def fake(_config, _prompt, parse):
        return parse(_payload())

    import nah.llm as llm_mod

    monkeypatch.setitem(llm_mod._PROVIDERS, "fake", fake)
    result = _try_providers_classify(_prompt(), _cfg("fake"), _parse())

    assert result.classification.action_type == taxonomy.NETWORK_OUTBOUND
    assert result.provider == "fake"
    assert result.cascade[0].status == "success"


def test_provider_cascade_records_unknown_as_uncertain(monkeypatch):
    def fake(_config, _prompt, parse):
        return parse(json.dumps({
            "action_type": "not_real",
            "targets": [],
            "evidence": "not_real",
        }))

    import nah.llm as llm_mod

    monkeypatch.setitem(llm_mod._PROVIDERS, "fake", fake)
    result = _try_providers_classify(_prompt(), _cfg("fake"), _parse())

    assert result.classification.action_type == taxonomy.UNKNOWN
    assert result.cascade[0].status == "uncertain"


def test_all_providers_error_returns_no_classification(monkeypatch):
    def fake(_config, _prompt, _parse):
        return None

    import nah.llm as llm_mod

    monkeypatch.setitem(llm_mod._PROVIDERS, "fake", fake)
    result = _try_providers_classify(_prompt(), _cfg("fake"), _parse())

    assert result.classification is None
    assert result.cascade[0].status == "error"


@patch("nah.llm.urllib.request.urlopen")
def test_ollama_generate_payload(mock_urlopen):
    captured = []

    def capture(req, **_kw):
        captured.append(json.loads(req.data.decode()))
        resp = MagicMock()
        resp.read.return_value = json.dumps({"response": _payload()}).encode()
        return resp

    mock_urlopen.side_effect = capture
    result = _try_providers_classify(
        _prompt(),
        _cfg("ollama", {"url": "http://localhost:11434/api/generate"}),
        _parse(),
    )

    assert result.classification.action_type == taxonomy.NETWORK_OUTBOUND
    assert "prompt" in captured[0]


@patch("nah.llm.urllib.request.urlopen")
def test_ollama_chat_payload(mock_urlopen):
    captured = []

    def capture(req, **_kw):
        captured.append(json.loads(req.data.decode()))
        resp = MagicMock()
        resp.read.return_value = json.dumps({"message": {"content": _payload()}}).encode()
        return resp

    mock_urlopen.side_effect = capture
    result = _try_providers_classify(_prompt(), _cfg("ollama"), _parse())

    assert result.classification.action_type == taxonomy.NETWORK_OUTBOUND
    assert captured[0]["messages"][0]["role"] == "system"


@patch("nah.llm.urllib.request.urlopen")
def test_openai_responses_provider(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({
        "output": [{"type": "message", "content": [
            {"type": "output_text", "text": _payload()},
        ]}],
    }).encode()
    mock_urlopen.return_value = mock_resp

    with patch("nah.llm.resolve_key", return_value="resolved-key") as resolve:
        result = _try_providers_classify(
            _prompt(),
            _cfg("openai", {"url": "https://api.openai.com/v1/responses", "key_env": "TEST_KEY"}),
            _parse(),
        )

    assert result.classification.action_type == taxonomy.NETWORK_OUTBOUND
    resolve.assert_called_once_with("TEST_KEY")


@patch("nah.llm.urllib.request.urlopen")
def test_openrouter_provider(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({
        "choices": [{"message": {"content": _payload()}}],
    }).encode()
    mock_urlopen.return_value = mock_resp

    with patch("nah.llm.resolve_key", return_value="resolved-key") as resolve:
        result = _try_providers_classify(
            _prompt(),
            _cfg("openrouter", {
                "url": "http://fake.api/v1/chat/completions",
                "key_env": "OPENROUTER_TEST",
            }),
            _parse(),
        )

    assert result.classification.action_type == taxonomy.NETWORK_OUTBOUND
    resolve.assert_called_once_with("OPENROUTER_TEST")


@patch("nah.llm.urllib.request.urlopen")
def test_anthropic_provider(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({
        "content": [{"type": "text", "text": _payload()}],
    }).encode()
    mock_urlopen.return_value = mock_resp

    with patch("nah.llm.resolve_key", return_value="resolved-key") as resolve:
        result = _try_providers_classify(
            _prompt(),
            _cfg("anthropic", {"key_env": "ANTHROPIC_TEST"}),
            _parse(),
        )

    assert result.classification.action_type == taxonomy.NETWORK_OUTBOUND
    resolve.assert_called_once_with("ANTHROPIC_TEST")


@patch("nah.llm.urllib.request.urlopen")
def test_cortex_provider(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({
        "choices": [{"message": {"content": _payload()}}],
    }).encode()
    mock_urlopen.return_value = mock_resp

    with patch.dict(os.environ, {"SNOWFLAKE_PAT": "fake-pat"}):
        result = _try_providers_classify(
            _prompt(),
            _cfg("cortex", {
                "url": "https://snowhouse.snowflakecomputing.com/api/v2/cortex/inference:complete",
            }),
            _parse(),
        )

    assert result.classification.action_type == taxonomy.NETWORK_OUTBOUND


@patch("nah.llm.urllib.request.urlopen")
def test_azure_provider(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({
        "output": [{"type": "message", "content": [
            {"type": "output_text", "text": _payload()},
        ]}],
    }).encode()
    mock_urlopen.return_value = mock_resp

    with patch("nah.llm.resolve_key", return_value="resolved-key") as resolve:
        result = _try_providers_classify(
            _prompt(),
            _cfg("azure", {
                "url": "https://resource.openai.azure.com/openai/v1/responses",
                "key_env": "AZURE_TEST",
            }),
            _parse(),
        )

    assert result.classification.action_type == taxonomy.NETWORK_OUTBOUND
    resolve.assert_called_once_with("AZURE_TEST")


def test_try_llm_classify_unknown_does_not_accept_custom_types(monkeypatch):
    import nah.llm as llm_mod

    def fake(_config, _prompt, parse):
        return parse(json.dumps({
            "action_type": "custom_safe",
            "targets": [{"kind": "path", "value": "x"}],
            "evidence": "custom_safe",
        }))

    monkeypatch.setitem(llm_mod._PROVIDERS, "fake", fake)
    result = try_llm_classify_unknown(
        "custom_safe x",
        _cfg("fake"),
        custom_types={"custom_safe": "allow"},
    )

    assert result.classification.action_type == taxonomy.UNKNOWN
