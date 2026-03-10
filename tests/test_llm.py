"""Unit tests for the LLM layer."""

import json
import os
from unittest.mock import patch, MagicMock

from nah.bash import ClassifyResult, StageResult
from nah import taxonomy
from nah.llm import (
    LLMResult,
    _build_prompt,
    _parse_response,
    try_llm,
)


# -- _parse_response tests --


class TestParseResponse:
    def test_allow(self):
        r = _parse_response('{"decision": "allow", "reasoning": "safe"}')
        assert r.decision == "allow"
        assert r.reasoning == "safe"

    def test_block(self):
        r = _parse_response('{"decision": "block", "reasoning": "dangerous"}')
        assert r.decision == "block"
        assert r.reasoning == "dangerous"

    def test_uncertain(self):
        r = _parse_response('{"decision": "uncertain", "reasoning": "not sure"}')
        assert r.decision == "uncertain"
        assert r.reasoning == "not sure"

    def test_uppercase_decision(self):
        r = _parse_response('{"decision": "ALLOW", "reasoning": "ok"}')
        assert r.decision == "allow"

    def test_markdown_wrapped(self):
        raw = '```json\n{"decision": "allow", "reasoning": "safe"}\n```'
        r = _parse_response(raw)
        assert r.decision == "allow"

    def test_json_embedded_in_text(self):
        raw = 'Here is my answer: {"decision": "block", "reasoning": "bad"} done.'
        r = _parse_response(raw)
        assert r.decision == "block"

    def test_invalid_json(self):
        assert _parse_response("not json at all") is None

    def test_missing_decision(self):
        assert _parse_response('{"reasoning": "something"}') is None

    def test_invalid_decision_value(self):
        assert _parse_response('{"decision": "maybe", "reasoning": "x"}') is None

    def test_reasoning_truncated(self):
        long_reason = "x" * 300
        r = _parse_response(f'{{"decision": "allow", "reasoning": "{long_reason}"}}')
        assert len(r.reasoning) == 200

    def test_empty_string(self):
        assert _parse_response("") is None

    def test_no_reasoning_field(self):
        r = _parse_response('{"decision": "allow"}')
        assert r.decision == "allow"
        assert r.reasoning == ""

    def test_whitespace_around(self):
        r = _parse_response('  \n {"decision": "allow", "reasoning": "ok"} \n  ')
        assert r.decision == "allow"


# -- _build_prompt tests --


class TestBuildPrompt:
    def _make_result(self, command="ls -la", action_type=taxonomy.UNKNOWN, decision="ask", reason="unknown command"):
        sr = StageResult(
            tokens=command.split(),
            action_type=action_type,
            default_policy=taxonomy.ASK,
            decision=decision,
            reason=reason,
        )
        return ClassifyResult(command=command, stages=[sr], final_decision=decision, reason=reason)

    def test_contains_command(self):
        prompt = _build_prompt(self._make_result(command="foobar --baz"))
        assert "foobar --baz" in prompt

    def test_contains_action_type(self):
        prompt = _build_prompt(self._make_result(action_type="lang_exec"))
        assert "lang_exec" in prompt

    def test_contains_reason(self):
        prompt = _build_prompt(self._make_result(reason="some reason here"))
        assert "some reason here" in prompt

    def test_long_command_truncated(self):
        long_cmd = "x" * 1000
        result = self._make_result(command=long_cmd)
        prompt = _build_prompt(result)
        assert long_cmd[:500] in prompt
        assert long_cmd not in prompt

    def test_empty_stages(self):
        result = ClassifyResult(command="test", stages=[], final_decision="ask", reason="test")
        prompt = _build_prompt(result)
        assert "unknown" in prompt  # falls back to "unknown" action type

    def test_finds_driving_ask_stage(self):
        allow_stage = StageResult(tokens=["echo"], action_type="filesystem_read", decision="allow", reason="safe")
        ask_stage = StageResult(tokens=["rm"], action_type=taxonomy.UNKNOWN, decision="ask", reason="unknown cmd")
        result = ClassifyResult(command="echo | rm", stages=[allow_stage, ask_stage], final_decision="ask", reason="unknown cmd")
        prompt = _build_prompt(result)
        assert taxonomy.UNKNOWN in prompt


# -- try_llm tests --


class TestTryLlm:
    def _make_result(self):
        sr = StageResult(
            tokens=["foobar"],
            action_type=taxonomy.UNKNOWN,
            default_policy=taxonomy.ASK,
            decision=taxonomy.ASK,
            reason="unknown command",
        )
        return ClassifyResult(command="foobar", stages=[sr], final_decision=taxonomy.ASK, reason="unknown command")

    def _ollama_config(self):
        return {
            "backends": ["ollama"],
            "ollama": {"url": "http://localhost:11434/api/generate", "model": "test"},
        }

    @patch("nah.llm.urllib.request.urlopen")
    def test_backend_returns_allow(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "response": '{"decision": "allow", "reasoning": "safe cmd"}'
        }).encode()
        mock_urlopen.return_value = mock_resp

        result = try_llm(self._make_result(), self._ollama_config())
        assert result["decision"] == "allow"
        assert "LLM" in result.get("message", "")

    @patch("nah.llm.urllib.request.urlopen")
    def test_backend_returns_block(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "response": '{"decision": "block", "reasoning": "dangerous"}'
        }).encode()
        mock_urlopen.return_value = mock_resp

        result = try_llm(self._make_result(), self._ollama_config())
        assert result["decision"] == "block"
        assert "LLM" in result["reason"]

    @patch("nah.llm.urllib.request.urlopen")
    def test_backend_returns_uncertain(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "response": '{"decision": "uncertain", "reasoning": "not sure"}'
        }).encode()
        mock_urlopen.return_value = mock_resp

        result = try_llm(self._make_result(), self._ollama_config())
        assert result is None

    @patch("nah.llm.urllib.request.urlopen")
    def test_backend_unavailable_tries_next(self, mock_urlopen):
        from urllib.error import URLError
        call_count = [0]

        def side_effect(*a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                raise URLError("connection refused")
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({
                "choices": [{"message": {"content": '{"decision": "allow", "reasoning": "ok"}'}}]
            }).encode()
            return mock_resp

        mock_urlopen.side_effect = side_effect

        config = {
            "backends": ["ollama", "openrouter"],
            "ollama": {"url": "http://localhost:11434/api/generate", "model": "test"},
            "openrouter": {"url": "http://fake.api/v1/chat/completions", "model": "test", "key_env": "TEST_KEY"},
        }
        with patch.dict("os.environ", {"TEST_KEY": "fake-key"}):
            result = try_llm(self._make_result(), config)
        assert result["decision"] == "allow"
        assert call_count[0] == 2

    @patch("nah.llm.urllib.request.urlopen")
    def test_all_backends_unavailable(self, mock_urlopen):
        from urllib.error import URLError
        mock_urlopen.side_effect = URLError("connection refused")

        result = try_llm(self._make_result(), self._ollama_config())
        assert result is None

    def test_empty_backends_list(self):
        result = try_llm(self._make_result(), {"backends": []})
        assert result is None

    def test_no_backends_key(self):
        result = try_llm(self._make_result(), {})
        assert result is None

    def test_backend_not_in_config(self):
        result = try_llm(self._make_result(), {"backends": ["ollama"]})
        assert result is None  # ollama key missing -> skip

    @patch("nah.llm.urllib.request.urlopen")
    def test_openai_backend_allow(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "output": [{"type": "message", "content": [
                {"type": "output_text", "text": '{"decision": "allow", "reasoning": "safe"}'}
            ]}]
        }).encode()
        mock_urlopen.return_value = mock_resp

        config = {
            "backends": ["openai"],
            "openai": {"url": "https://api.openai.com/v1/responses", "model": "gpt-4.1-nano", "key_env": "TEST_KEY"},
        }
        with patch.dict("os.environ", {"TEST_KEY": "fake-key"}):
            result = try_llm(self._make_result(), config)
        assert result["decision"] == "allow"

    @patch("nah.llm.urllib.request.urlopen")
    def test_anthropic_backend_allow(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "content": [{"type": "text", "text": '{"decision": "allow", "reasoning": "safe"}'}]
        }).encode()
        mock_urlopen.return_value = mock_resp

        config = {
            "backends": ["anthropic"],
            "anthropic": {"model": "claude-haiku-4-5", "key_env": "TEST_KEY"},
        }
        with patch.dict("os.environ", {"TEST_KEY": "fake-key"}):
            result = try_llm(self._make_result(), config)
        assert result["decision"] == "allow"

    def test_anthropic_no_key_skips(self):
        config = {
            "backends": ["anthropic"],
            "anthropic": {"model": "claude-haiku-4-5", "key_env": "NONEXISTENT_KEY_12345"},
        }
        result = try_llm(self._make_result(), config)
        assert result is None

    @patch("nah.llm.urllib.request.urlopen")
    def test_allow_without_reasoning(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "response": '{"decision": "allow"}'
        }).encode()
        mock_urlopen.return_value = mock_resp

        result = try_llm(self._make_result(), self._ollama_config())
        assert result["decision"] == "allow"
        assert "message" not in result  # no reasoning = no message
