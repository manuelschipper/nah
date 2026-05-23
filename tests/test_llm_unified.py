"""Unified LLM mode tests."""

import io
import json
import sys
from unittest.mock import MagicMock, patch

import pytest

import nah.llm as llm_mod
from nah import hook, taxonomy
from nah.bash import ClassifyResult, StageResult
from nah.config import NahConfig
from nah.llm import (
    LLMCallResult,
    ProviderAttempt,
    PromptParts,
    _build_codex_permission_request_prompt,
    _build_unified_prompt,
    _read_instruction_context,
    _try_providers,
    llm_timeout_budget,
    _read_claude_md,
    _read_project_instruction_files,
    _read_transcript_tail,
    try_llm_codex_permission_request,
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


def test_llm_timeout_budget_caps_provider_timeout(monkeypatch):
    seen = []

    def fake_provider(provider_config, _prompt):
        seen.append(provider_config["timeout"])
        return None

    monkeypatch.setitem(llm_mod._PROVIDERS, "fake", fake_provider)

    with llm_timeout_budget(10):
        result = _try_providers(
            PromptParts("system", "user"),
            {"providers": ["fake"], "fake": {"timeout": 99, "model": "test"}},
            "Bash",
        )

    assert result.cascade[0].status == "error"
    assert 0 < seen[0] <= 10


def test_llm_timeout_budget_skips_provider_when_exhausted(monkeypatch):
    called = False

    def fake_provider(_provider_config, _prompt):
        nonlocal called
        called = True
        return None

    monkeypatch.setitem(llm_mod._PROVIDERS, "fake", fake_provider)

    with llm_timeout_budget(0.001):
        result = _try_providers(
            PromptParts("system", "user"),
            {"providers": ["fake"], "fake": {"timeout": 99, "model": "test"}},
            "Bash",
        )

    assert called is False
    assert result.cascade[0].status == "error"
    assert result.cascade[0].error == "LLM budget exhausted before provider"


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
        stages = [{
            "action_type": "filesystem_delete",
            "decision": "ask",
            "policy": "context",
            "reason": "outside project",
        }]
        prompt = _build_unified_prompt(
            "Bash",
            "rm -rf dist/",
            "filesystem_delete",
            "outside project",
            "User: clean the build output",
            "Project instructions",
            stages=stages,
        )

        assert isinstance(prompt, PromptParts)
        assert 'eligible "ask" decision' in prompt.user
        assert "Runtime: Claude Code" in prompt.user
        assert "Bash" in prompt.user
        assert "rm -rf dist/" in prompt.user
        assert "filesystem_delete" in prompt.user
        assert "outside project" in prompt.user
        assert '"action_type":"filesystem_delete"' in prompt.user
        assert "User: clean the build output" in prompt.user
        assert "Project instructions" in prompt.user
        assert "blocks stay blocked" in prompt.user
        assert "High-impact actions are not categorically forbidden here" in prompt.user
        assert "safe local read-to-filter pipelines" in prompt.user
        assert "For process signals" in prompt.user

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

    def test_codex_prompt_uses_shared_rules_with_agent_context(self):
        prompt = _build_codex_permission_request_prompt(
            "Bash",
            "git push origin main",
            "git_write",
            "git write requires confirmation",
            stages=[{
                "action_type": "git_write",
                "decision": "ask",
                "policy": "ask",
                "reason": "git write requires confirmation",
            }],
            transcript_text="User: push the current branch",
            project_instructions_text="File: AGENTS.md\nProject-specific rules",
        )

        assert isinstance(prompt, PromptParts)
        assert "Runtime: Codex PermissionRequest" in prompt.user
        assert "nah returns an allow verdict to Codex" in prompt.user
        assert "User: push the current branch" in prompt.user
        assert "File: AGENTS.md" in prompt.user
        assert '"action_type":"git_write"' in prompt.user
        assert "deterministic classification as the safety boundary" in prompt.user
        assert "High-impact actions are not categorically forbidden here" in prompt.user
        assert "safe local read-to-filter pipelines" in prompt.user
        assert "For process signals" in prompt.user


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

    def test_reads_labeled_project_instruction_files(self, tmp_path):
        (tmp_path / "AGENTS.md").write_text("agent instructions")

        with patch("nah.paths.get_project_root", return_value=str(tmp_path)):
            result = _read_project_instruction_files(("AGENTS.md",))

        assert result == "File: AGENTS.md\nagent instructions"

    def test_claude_instruction_context_reads_project_global_and_local_include(
        self,
        tmp_path,
        monkeypatch,
    ):
        home = tmp_path / "home"
        project = tmp_path / "project"
        home.mkdir()
        project.mkdir()
        (project / "CLAUDE.md").write_text("Project Claude rules\n@AGENTS.md")
        (project / "AGENTS.md").write_text("Shared agent rules")
        (home / ".claude").mkdir()
        (home / ".claude" / "CLAUDE.md").write_text("Global Claude rules")
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.chdir(project)

        with patch("nah.paths.get_project_root", return_value=str(project)):
            result = _read_instruction_context("claude")

        assert "Project instructions:" in result
        assert str(project / "CLAUDE.md") in result
        assert "Project Claude rules" in result
        assert "Included file:" in result
        assert "Shared agent rules" in result
        assert "Global instructions:" in result
        assert "Global Claude rules" in result

    def test_codex_instruction_context_prefers_overrides_and_reads_global(
        self,
        tmp_path,
        monkeypatch,
    ):
        project = tmp_path / "project"
        codex_home = tmp_path / "codex"
        project.mkdir()
        codex_home.mkdir()
        (project / "AGENTS.md").write_text("Project base rules")
        (project / "AGENTS.override.md").write_text("Project override rules\n@CLAUDE.md")
        (project / "CLAUDE.md").write_text("Local Claude include")
        (codex_home / "AGENTS.md").write_text("Global base rules")
        (codex_home / "AGENTS.override.md").write_text("Global override rules")
        monkeypatch.setenv("CODEX_HOME", str(codex_home))
        monkeypatch.chdir(project)

        with patch("nah.paths.get_project_root", return_value=str(project)):
            result = _read_instruction_context("codex")

        assert "Project override rules" in result
        assert "Project base rules" not in result
        assert "Included file:" in result
        assert "Local Claude include" in result
        assert "Global override rules" in result
        assert "Global base rules" not in result

    def test_instruction_context_truncates_with_visible_marker(
        self,
        tmp_path,
        monkeypatch,
    ):
        project = tmp_path / "project"
        codex_home = tmp_path / "codex"
        project.mkdir()
        codex_home.mkdir()
        (project / "AGENTS.md").write_text("A" * 5000)
        monkeypatch.setenv("CODEX_HOME", str(codex_home))
        monkeypatch.chdir(project)

        with patch("nah.paths.get_project_root", return_value=str(project)):
            result = _read_instruction_context("codex", max_chars=1000)

        assert "[truncated:" in result
        assert len(result) <= 1100


class TestUnifiedTryLlm:
    def test_try_unified_passes_stages_and_project_instructions(self, tmp_path):
        (tmp_path / "CLAUDE.md").write_text("Claude project rules")
        captured = {}

        def fake_try_providers(prompt, _cfg, _label):
            captured["prompt"] = prompt
            return LLMCallResult(decision={"decision": "uncertain"})

        with patch("nah.paths.get_project_root", return_value=str(tmp_path)), \
             patch("nah.llm._try_providers", side_effect=fake_try_providers):
            try_llm_unified(
                "Bash",
                "remove build output",
                "filesystem_delete",
                "outside project",
                {},
                stages=[{
                    "action_type": "filesystem_delete",
                    "decision": "ask",
                    "policy": "context",
                    "reason": "outside project",
                }],
            )

        assert "Project instructions:" in captured["prompt"].user
        assert "CLAUDE.md" in captured["prompt"].user
        assert "Claude project rules" in captured["prompt"].user
        assert '"action_type":"filesystem_delete"' in captured["prompt"].user

    def test_try_codex_reads_transcript_and_agents_md(self, tmp_path):
        transcript = tmp_path / "transcript.jsonl"
        transcript.write_text(_jsonl(_user_msg("push the current branch")))
        (tmp_path / "AGENTS.md").write_text("Codex project rules")
        captured = {}

        def fake_try_providers(prompt, _cfg, _label):
            captured["prompt"] = prompt
            return LLMCallResult(decision={"decision": "uncertain"})

        with patch("nah.paths.get_project_root", return_value=str(tmp_path)), \
             patch("nah.llm._try_providers", side_effect=fake_try_providers):
            try_llm_codex_permission_request(
                "Bash",
                "git push origin main",
                "git_write",
                "git write requires confirmation",
                {},
                stages=[{
                    "action_type": "git_write",
                    "decision": "ask",
                    "policy": "ask",
                    "reason": "git write requires confirmation",
                }],
                transcript_path=str(transcript),
            )

        assert "User: push the current branch" in captured["prompt"].user
        assert "Project instructions:" in captured["prompt"].user
        assert "AGENTS.md" in captured["prompt"].user
        assert "Codex project rules" in captured["prompt"].user
        assert '"action_type":"git_write"' in captured["prompt"].user

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

    def test_default_includes_package_uninstall(self):
        stages = [{
            "action_type": "package_uninstall",
            "decision": "ask",
            "policy": taxonomy.ASK,
            "reason": "package_uninstall → ask",
        }]
        assert hook._is_llm_eligible_stages(
            "package_uninstall", stages, "default",
        ) is True

    def test_default_excludes_service_write(self):
        stages = [{
            "action_type": "service_write",
            "decision": "ask",
            "policy": taxonomy.ASK,
            "reason": "service_write → ask",
        }]
        assert hook._is_llm_eligible_stages(
            "service_write", stages, "default",
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

    def test_browser_exec_fallback_is_eligible_under_default(self):
        allow = LLMCallResult(
            decision={"decision": "allow", "reason": "Bash (LLM): browser debugging"},
            provider="ollama",
            model="qwen3",
            latency_ms=12,
            reasoning="browser debugging",
            cascade=[ProviderAttempt("ollama", "success", 12, "qwen3")],
        )
        cfg = NahConfig(
            llm_mode="on",
            llm={"providers": ["ollama"], "ollama": {"model": "test"}},
            llm_eligible="default",
        )
        payload = {
            "tool_name": "mcp__playwright__browser_evaluate",
            "tool_input": {"code": "document.title"},
            "transcript_path": "session.jsonl",
        }

        with patch("nah.config.get_config", return_value=cfg), \
             patch("nah.llm.try_llm_unified", return_value=allow) as mock_try_llm, \
             patch("nah.hook._log_hook_decision"):
            result = _run_hook(payload)

        assert result["hookSpecificOutput"]["permissionDecision"] == "allow"
        mock_try_llm.assert_called_once()

    def test_service_write_fallback_is_not_eligible_under_default(self):
        cfg = NahConfig(
            llm_mode="on",
            llm={"providers": ["ollama"], "ollama": {"model": "test"}},
            llm_eligible="default",
            classify_global={"service_write": ["CustomServiceTool"]},
        )
        payload = {
            "tool_name": "CustomServiceTool",
            "tool_input": {},
            "transcript_path": "session.jsonl",
        }

        with patch("nah.config.get_config", return_value=cfg), \
             patch("nah.llm.try_llm_unified") as mock_try_llm, \
             patch("nah.hook._log_hook_decision"):
            result = _run_hook(payload)

        assert result["hookSpecificOutput"]["permissionDecision"] == "ask"
        mock_try_llm.assert_not_called()
