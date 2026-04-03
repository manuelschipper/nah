"""Unified LLM mode tests."""

import io
import json
import sys
from unittest.mock import MagicMock, patch

import pytest

from nah import hook, taxonomy
from nah.bash import ClassifyResult, StageResult
from nah.config import NahConfig
from nah.llm import (
    LLMCallResult,
    ProviderAttempt,
    PromptParts,
    _build_unified_prompt,
    _read_claude_md,
    _read_transcript_tail,
    try_llm_unified,
)


def _jsonl(*entries):
    return "\n".join(json.dumps(entry) for entry in entries) + "\n"


def _user_msg(text):
    return {
        "type": "user",
        "message": {"content": [{"type": "text", "text": text}]},
    }


def _assistant_msg(text, tool_uses=None):
    content = [{"type": "text", "text": text}]
    for tool_use in tool_uses or []:
        content.append({"type": "tool_use", **tool_use})
    return {"type": "assistant", "message": {"content": content}}


def _ask_result(command: str = "rm -rf dist/") -> ClassifyResult:
    stage = StageResult(
        tokens=["rm", "-rf", "dist/"],
        action_type="filesystem_delete",
        default_policy=taxonomy.CONTEXT,
        decision=taxonomy.ASK,
        reason="outside project",
    )
    return ClassifyResult(
        command=command,
        stages=[stage],
        final_decision=taxonomy.ASK,
        reason="outside project",
    )


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


@pytest.fixture(autouse=True)
def _isolate_auto_state(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "_AUTO_STATE_DIR", str(tmp_path / "auto-state"))
    yield


class TestUnifiedPrompt:
    def test_includes_command_action_transcript_and_claude_md(self):
        prompt = _build_unified_prompt(
            "Bash",
            "rm -rf dist/",
            "filesystem_delete",
            "outside project",
            "User: clean the build output",
            "Project instructions",
        )

        assert isinstance(prompt, PromptParts)
        assert "Bash" in prompt.user
        assert "rm -rf dist/" in prompt.user
        assert "filesystem_delete" in prompt.user
        assert "outside project" in prompt.user
        assert "User: clean the build output" in prompt.user
        assert "Project instructions" in prompt.user

    def test_missing_claude_md_uses_placeholder(self):
        prompt = _build_unified_prompt(
            "Bash",
            "rm -rf dist/",
            "filesystem_delete",
            "outside project",
            "",
            "",
        )
        assert "(not available)" in prompt.user


class TestTranscriptRoles:
    def test_roles_user_filters_assistant_text_but_keeps_tool_summary(self, tmp_path):
        transcript = tmp_path / "transcript.jsonl"
        transcript.write_text(_jsonl(
            _user_msg("remove the dist directory"),
            _assistant_msg(
                "I will do it",
                [{"name": "Bash", "input": {"command": "rm -rf dist/"}}],
            ),
        ))

        result = _read_transcript_tail(str(transcript), 4000, roles=("user",))

        assert "User: remove the dist directory" in result
        assert "I will do it" not in result
        assert "[Bash: rm -rf dist/]" in result


class TestReadClaudeMd:
    def test_reads_from_project_root(self, tmp_path):
        (tmp_path / "CLAUDE.md").write_text("project instructions")

        with patch("nah.paths.get_project_root", return_value=str(tmp_path)):
            assert _read_claude_md() == "project instructions"

    def test_missing_project_root_returns_empty(self):
        with patch("nah.paths.get_project_root", return_value=None):
            assert _read_claude_md() == ""

    def test_missing_file_returns_empty(self, tmp_path):
        with patch("nah.paths.get_project_root", return_value=str(tmp_path)):
            assert _read_claude_md() == ""


class TestUnifiedTryLlm:
    @patch("nah.llm.urllib.request.urlopen")
    def test_block_response_is_treated_as_uncertain(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "response": '{"decision": "block", "reasoning": "too risky"}',
        }).encode()
        mock_urlopen.return_value = mock_resp

        result = try_llm_unified(
            "Bash",
            "rm -rf dist/",
            "filesystem_delete",
            "outside project",
            {
                "providers": ["ollama"],
                "ollama": {
                    "url": "http://localhost:11434/api/generate",
                    "model": "test",
                },
            },
        )

        assert result.decision["decision"] == "uncertain"
        assert result.cascade[0].status == "uncertain"


class TestEligibility:
    def test_default_context_ask_is_eligible(self):
        stages = [{
            "action_type": "filesystem_delete",
            "decision": "ask",
            "policy": taxonomy.CONTEXT,
            "reason": "outside project",
        }]
        assert hook._is_llm_eligible_stages(
            "filesystem_delete", stages, "default",
        ) is True

    def test_sensitive_context_is_not_eligible_by_default(self):
        stages = [{
            "action_type": "filesystem_read",
            "decision": "ask",
            "policy": taxonomy.CONTEXT,
            "reason": "targets sensitive path: ~/.ssh",
        }]
        assert hook._is_llm_eligible_stages(
            "filesystem_read", stages, "default",
        ) is False


class TestHookIntegration:
    def _payload(self, transcript_path="session.jsonl"):
        return {
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf dist/"},
            "transcript_path": transcript_path,
        }

    def _cfg(self):
        return NahConfig(
            llm_mode="on",
            llm={"providers": ["ollama"], "ollama": {"model": "test"}},
            llm_eligible=["filesystem_delete"],
        )

    def test_allow_resets_counter(self):
        hook._write_auto_state("session.jsonl", 2, False)
        allow = LLMCallResult(
            decision={"decision": "allow", "reason": "Bash (LLM): user asked for cleanup"},
            provider="ollama",
            model="qwen3",
            latency_ms=12,
            reasoning="user asked for cleanup",
            cascade=[ProviderAttempt("ollama", "success", 12, "qwen3")],
        )

        with patch("nah.config.get_config", return_value=self._cfg()), \
             patch("nah.hook.classify_command", return_value=_ask_result()), \
             patch("nah.llm.try_llm_unified", return_value=allow), \
             patch("nah.hook._log_hook_decision"):
            result = _run_hook(self._payload())

        assert result["hookSpecificOutput"]["permissionDecision"] == "allow"
        assert hook._read_auto_state("session.jsonl") == (0, False)

    def test_transient_error_keeps_ask_without_counting(self):
        failed = LLMCallResult(
            decision=None,
            cascade=[ProviderAttempt("ollama", "error", 10, "qwen3", "timeout")],
        )

        with patch("nah.config.get_config", return_value=self._cfg()), \
             patch("nah.hook.classify_command", return_value=_ask_result()), \
             patch("nah.llm.try_llm_unified", return_value=failed), \
             patch("nah.hook._log_hook_decision"):
            result = _run_hook(self._payload())

        assert result["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert hook._read_auto_state("session.jsonl") == (0, False)

    def test_three_consecutive_uncertain_disables_session(self):
        """deny_limit must be explicitly set to enable session disabling."""
        uncertain = LLMCallResult(
            decision={"decision": "uncertain", "reason": "Bash (LLM): not clear enough"},
            provider="ollama",
            model="qwen3",
            latency_ms=12,
            reasoning="not clear enough",
            cascade=[ProviderAttempt("ollama", "uncertain", 12, "qwen3")],
        )
        cfg = NahConfig(
            llm_mode="on",
            llm={"providers": ["ollama"], "ollama": {"model": "test"}, "deny_limit": 3},
            llm_eligible=["filesystem_delete"],
        )

        with patch("nah.config.get_config", return_value=cfg), \
             patch("nah.hook.classify_command", return_value=_ask_result()), \
             patch("nah.llm.try_llm_unified", return_value=uncertain) as mock_try_llm, \
             patch("nah.hook._log_hook_decision"):
            for _ in range(4):
                result = _run_hook(self._payload())
                assert result["hookSpecificOutput"]["permissionDecision"] == "ask"

        assert mock_try_llm.call_count == 3
        assert hook._read_auto_state("session.jsonl") == (3, True)

    def test_timeout_fails_closed_to_ask(self):
        timeout = LLMCallResult(
            decision=None,
            cascade=[ProviderAttempt("ollama", "error", 1000, "qwen3", "TimeoutError: timed out")],
        )

        with patch("nah.config.get_config", return_value=self._cfg()), \
             patch("nah.hook.classify_command", return_value=_ask_result()), \
             patch("nah.llm.try_llm_unified", return_value=timeout), \
             patch("nah.hook._log_hook_decision"):
            result = _run_hook(self._payload())

        assert result["hookSpecificOutput"]["permissionDecision"] == "ask"
