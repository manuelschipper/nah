"""Tests for FD-079: Script Execution Inspection.

Covers: flag classifier, context resolver, script path resolution,
LLM veto gate, prompt enrichment, and end-to-end pipeline.
"""

import json
import os
import stat

import pytest
from unittest.mock import MagicMock, patch

from nah import paths, taxonomy
from nah.bash import classify_command, _resolve_script_path, _resolve_module_path
from nah.context import resolve_lang_exec_context
from nah.config import reset_config


# Helper: classify tokens via taxonomy (Phase 2 flag classifier path)
def _ct(tokens):
    return taxonomy.classify_tokens(tokens)


def _write(path, content="print('hello')\n"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


# ===================================================================
# 1. FLAG CLASSIFIER (_classify_script_exec)
# ===================================================================

class TestFlagClassifier:
    """Phase 2 flag classifier: interpreter + file → lang_exec."""

    @pytest.mark.parametrize("tokens", [
        ["python", "script.py"],
        ["python3", "script.py"],
        ["node", "index.js"],
        ["ruby", "script.rb"],
        ["perl", "script.pl"],
        ["bash", "script.sh"],
        ["sh", "deploy.sh"],
        ["dash", "run.sh"],
        ["zsh", "init.zsh"],
        ["php", "app.php"],
        ["tsx", "src/index.ts"],
    ])
    def test_interpreters_classify_as_lang_exec(self, tokens):
        assert _ct(tokens) == "lang_exec"

    @pytest.mark.parametrize("tokens", [
        ["python", "-c", "print(1)"],
        ["python3", "-c", "code"],
        ["node", "-e", "console.log(1)"],
        ["node", "-p", "1+1"],
        ["node", "--eval", "1"],
        ["ruby", "-e", "puts 1"],
        ["perl", "-e", "print 1"],
        ["perl", "-E", "say 1"],
        ["php", "-r", "echo 1"],
        ["bash", "-c", "echo hi"],
    ])
    def test_inline_code_flag_classifier_returns_none(self, tokens):
        """Inline flags (-c, -e, etc.) → flag classifier returns None (falls through)."""
        assert taxonomy._classify_script_exec(tokens) is None

    @pytest.mark.parametrize("tokens", [
        ["python"],
        ["python3"],
        ["node"],
        ["ruby"],
    ])
    def test_bare_repl_not_lang_exec(self, tokens):
        """Bare interpreter without args falls through to unknown."""
        assert _ct(tokens) == "unknown"

    def test_python_m_flag_classifier_returns_none(self):
        """python -m → flag classifier returns None (Phase 3 table handles)."""
        assert taxonomy._classify_script_exec(["python", "-m", "http.server"]) is None

    def test_python_m_full_pipeline_is_lang_exec(self):
        """python -m http.server → full pipeline → lang_exec (via classify table)."""
        r = classify_command("python -m http.server")
        assert r.stages[0].action_type == "lang_exec"

    def test_python_m_pytest_full_pipeline_is_package_run(self):
        """python -m pytest → full pipeline → package_run (more specific prefix)."""
        r = classify_command("python -m pytest")
        assert r.stages[0].action_type == "package_run"

    def test_python3_m_pytest_full_pipeline_is_package_run(self):
        r = classify_command("python3 -m pytest")
        assert r.stages[0].action_type == "package_run"

    # Value-taking flags
    def test_value_flag_W_skipped(self):
        assert _ct(["python", "-W", "ignore", "script.py"]) == "lang_exec"

    def test_value_flag_X_skipped(self):
        assert _ct(["python", "-X", "utf8", "script.py"]) == "lang_exec"

    def test_node_require_skipped(self):
        assert _ct(["node", "-r", "dotenv", "index.js"]) == "lang_exec"

    def test_ruby_I_skipped(self):
        assert _ct(["ruby", "-I", "lib", "script.rb"]) == "lang_exec"

    def test_perl_M_skipped(self):
        assert _ct(["perl", "-M", "strict", "script.pl"]) == "lang_exec"

    # Extension detection (./script.py after basename normalization)
    @pytest.mark.parametrize("cmd", [
        "script.py", "deploy.sh", "run.rb", "index.js",
        "app.ts", "handler.php", "main.pl", "component.tsx",
    ])
    def test_extension_detection(self, cmd):
        """Files with script extensions classify as lang_exec."""
        assert _ct([cmd]) == "lang_exec"

    def test_no_extension_not_matched(self):
        """Files without script extensions fall through."""
        assert _ct(["deploy"]) != "lang_exec"

    # Non-interpreter commands unaffected
    @pytest.mark.parametrize("tokens", [
        ["ls", "file.py"],
        ["cat", "script.py"],
        ["git", "status"],
        ["curl", "example.com"],
        ["echo", "hello"],
    ])
    def test_non_interpreter_unaffected(self, tokens):
        result = _ct(tokens)
        assert result != "lang_exec" or tokens[0] in taxonomy._SCRIPT_INTERPRETERS

    # bash -c is NOT script exec (handled by shell wrapper unwrapping)
    def test_bash_c_not_script_exec(self):
        """bash -c falls through (inline flag), not classified as script exec.
        Covered in the parametrized test above; this verifies the full pipeline."""
        r = classify_command('bash -c "echo hi"')
        # _unwrap_shell handles bash -c, classifies inner command
        assert r.stages[0].action_type == "filesystem_read"


# ===================================================================
# 2. CONTEXT RESOLVER (resolve_lang_exec_context)
# ===================================================================

class TestContextResolver:
    """Context resolution for lang_exec: path + content inspection."""

    def test_inline_no_file(self):
        decision, reason = resolve_lang_exec_context(None)
        assert decision == "ask"
        assert "inline execution" in reason

    def test_clean_script_inside_project(self, project_root):
        path = os.path.join(project_root, "safe.py")
        _write(path, "print('hello')\n")
        decision, reason = resolve_lang_exec_context(path)
        assert decision == "allow"
        assert reason.startswith("script clean:")

    def test_dangerous_script_os_remove(self, project_root):
        path = os.path.join(project_root, "evil.py")
        _write(path, "import os\nos.remove('/important')\n")
        decision, reason = resolve_lang_exec_context(path)
        assert decision == "ask"
        assert "os.remove" in reason

    def test_dangerous_script_shutil_rmtree(self, project_root):
        path = os.path.join(project_root, "nuke.py")
        _write(path, "import shutil\nshutil.rmtree('/')\n")
        decision, reason = resolve_lang_exec_context(path)
        assert decision == "ask"
        assert "shutil.rmtree" in reason

    def test_secret_in_script(self, project_root):
        path = os.path.join(project_root, "key.py")
        _write(path, 'key = "-----BEGIN PRIVATE KEY-----"\n')
        decision, reason = resolve_lang_exec_context(path)
        assert decision == "ask"
        assert "private key" in reason

    def test_script_outside_project(self, project_root, tmp_path):
        outside = str(tmp_path / "outside.py")
        _write(outside, "print('safe')\n")
        decision, reason = resolve_lang_exec_context(outside)
        assert decision == "ask"
        assert "outside project" in reason

    def test_script_not_found(self, project_root):
        path = os.path.join(project_root, "nonexistent.py")
        decision, reason = resolve_lang_exec_context(path)
        assert decision == "ask"
        assert "script not found" in reason

    @pytest.mark.skipif(os.getuid() == 0, reason="root can read anything")
    def test_script_not_readable(self, project_root):
        path = os.path.join(project_root, "locked.py")
        _write(path, "print('secret')\n")
        os.chmod(path, 0o000)
        try:
            decision, reason = resolve_lang_exec_context(path)
            assert decision == "ask"
            assert "not readable" in reason
        finally:
            os.chmod(path, 0o644)

    def test_profile_none_allows(self, project_root):
        from nah.config import apply_override
        apply_override({"profile": "none"})
        path = os.path.join(project_root, "any.py")
        _write(path, "os.remove('/')\n")
        decision, reason = resolve_lang_exec_context(path)
        assert decision == "allow"
        assert "profile: none" in reason


# ===================================================================
# 3. SCRIPT PATH RESOLUTION (_resolve_script_path)
# ===================================================================

class TestScriptPathResolution:
    """Extract script file path from interpreter tokens."""

    def test_basic_path(self, project_root):
        path = os.path.join(project_root, "script.py")
        _write(path)
        result = _resolve_script_path(["python", path])
        assert result == path

    def test_relative_path(self, project_root):
        path = os.path.join(project_root, "script.py")
        _write(path)
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            result = _resolve_script_path(["python", "script.py"])
            assert result is not None
            assert result.endswith("script.py")
        finally:
            os.chdir(old_cwd)

    def test_inline_returns_none(self):
        result = _resolve_script_path(["python", "-c", "print(1)"])
        assert result is None

    def test_module_resolves_main_py(self, project_root):
        mod_dir = os.path.join(project_root, "mymod")
        main_file = os.path.join(mod_dir, "__main__.py")
        _write(main_file, "print('main')\n")
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            result = _resolve_script_path(["python", "-m", "mymod"])
            assert result == main_file
        finally:
            os.chdir(old_cwd)

    def test_module_resolves_module_py(self, project_root):
        mod_file = os.path.join(project_root, "mymod.py")
        _write(mod_file, "print('module')\n")
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            result = _resolve_script_path(["python", "-m", "mymod"])
            assert result == mod_file
        finally:
            os.chdir(old_cwd)

    def test_value_flag_skipped(self, project_root):
        path = os.path.join(project_root, "script.py")
        _write(path)
        result = _resolve_script_path(["python", "-W", "ignore", path])
        assert result == path

    def test_nonexistent_returns_path(self):
        """Returns path even if file doesn't exist (context resolver handles the error)."""
        result = _resolve_script_path(["python", "/tmp/nonexistent_fd079.py"])
        assert result == "/tmp/nonexistent_fd079.py"

    def test_bare_repl_returns_none(self):
        result = _resolve_script_path(["python"])
        assert result is None

    def test_all_flags_returns_none(self):
        result = _resolve_script_path(["python", "-v"])
        assert result is None


# ===================================================================
# 4. FULL PIPELINE INTEGRATION (classify_command)
# ===================================================================

class TestPipelineIntegration:
    """End-to-end classify_command with real files."""

    def test_clean_script_allows(self, project_root):
        path = os.path.join(project_root, "safe.py")
        _write(path, "print('hello')\n")
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            r = classify_command("python safe.py")
            assert r.final_decision == "allow"
            assert r.stages[0].action_type == "lang_exec"
            assert r.stages[0].reason.startswith("script clean:")
        finally:
            os.chdir(old_cwd)

    def test_dangerous_script_asks(self, project_root):
        path = os.path.join(project_root, "evil.py")
        _write(path, "import shutil\nshutil.rmtree('/')\n")
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            r = classify_command("python evil.py")
            assert r.final_decision == "ask"
            assert "content inspection" in r.reason
        finally:
            os.chdir(old_cwd)

    def test_inline_code_clean_allows(self):
        """Safe inline code is allowed via content inspection (nah-koi.1)."""
        r = classify_command("python -c 'print(1)'")
        assert r.final_decision == "allow"
        assert "inline clean" in r.reason

    def test_nonexistent_asks(self, project_root):
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            r = classify_command("python nonexistent.py")
            assert r.final_decision == "ask"
            assert "script not found" in r.reason
        finally:
            os.chdir(old_cwd)

    def test_bash_c_still_unwraps(self):
        """bash -c 'echo hi' is unwrapped, not treated as script execution."""
        r = classify_command('bash -c "echo hi"')
        assert r.final_decision == "allow"
        assert r.stages[0].action_type == "filesystem_read"

    def test_policy_is_context(self, project_root):
        path = os.path.join(project_root, "test.py")
        _write(path)
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            r = classify_command("python test.py")
            assert r.stages[0].default_policy == "context"
        finally:
            os.chdir(old_cwd)

    def test_value_flag_W_in_pipeline(self, project_root):
        path = os.path.join(project_root, "script.py")
        _write(path, "print('ok')\n")
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            r = classify_command("python -W ignore script.py")
            assert r.final_decision == "allow"
            assert r.stages[0].action_type == "lang_exec"
            assert "script clean:" in r.stages[0].reason
        finally:
            os.chdir(old_cwd)


# ===================================================================
# 5. LLM VETO GATE
# ===================================================================

class TestVetoGate:
    """LLM veto gate: fires for clean scripts, can only block."""

    def test_has_script_true_for_clean(self, project_root):
        from nah.hook import _has_lang_exec_script
        path = os.path.join(project_root, "clean.py")
        _write(path)
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            result = classify_command("python clean.py")
            assert _has_lang_exec_script(result) is True
        finally:
            os.chdir(old_cwd)

    def test_has_script_false_for_inline(self):
        from nah.hook import _has_lang_exec_script
        result = classify_command("python -c 'print(1)'")
        assert _has_lang_exec_script(result) is False

    def test_has_script_false_for_not_found(self, project_root):
        from nah.hook import _has_lang_exec_script
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            result = classify_command("python missing.py")
            assert _has_lang_exec_script(result) is False
        finally:
            os.chdir(old_cwd)

    def test_has_script_false_for_dangerous(self, project_root):
        """Dangerous scripts resolve to ask, not allow — veto gate doesn't fire."""
        from nah.hook import _has_lang_exec_script
        path = os.path.join(project_root, "evil.py")
        _write(path, "import os\nos.remove('/')\n")
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            result = classify_command("python evil.py")
            assert _has_lang_exec_script(result) is False
        finally:
            os.chdir(old_cwd)

    def _handle_with_mock_llm(self, command, llm_return, project_root=None):
        """Run handle_bash with a mocked _try_llm."""
        import nah.hook as hook_mod
        original = hook_mod._try_llm
        hook_mod._try_llm = lambda result: llm_return
        try:
            return hook_mod.handle_bash({"command": command})
        finally:
            hook_mod._try_llm = original

    def test_veto_gate_llm_blocks(self, project_root):
        from nah.config import get_config
        # Override llm_max_decision to allow block (default caps at ask)
        get_config().llm_max_decision = "block"
        path = os.path.join(project_root, "sneaky.py")
        _write(path, "# looks clean but LLM disagrees\nprint('hi')\n")
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            result = self._handle_with_mock_llm(
                "python sneaky.py",
                ({"decision": "block", "reason": "LLM threat"}, {"llm_provider": "test"}),
            )
            assert result["decision"] == "block"
        finally:
            os.chdir(old_cwd)

    def test_veto_gate_llm_block_capped_to_ask(self, project_root):
        """Default llm_max_decision=ask means LLM block is capped to ask."""
        path = os.path.join(project_root, "sneaky.py")
        _write(path, "print('hi')\n")
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            result = self._handle_with_mock_llm(
                "python sneaky.py",
                ({"decision": "block", "reason": "LLM threat"}, {"llm_provider": "test"}),
            )
            # With default cap=ask, block is downgraded — veto gate doesn't fire
            assert result["decision"] == "allow"
        finally:
            os.chdir(old_cwd)

    def test_veto_gate_llm_allows(self, project_root):
        path = os.path.join(project_root, "safe.py")
        _write(path)
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            result = self._handle_with_mock_llm(
                "python safe.py",
                ({"decision": "allow", "reason": "safe"}, {"llm_provider": "test"}),
            )
            assert result["decision"] == "allow"
        finally:
            os.chdir(old_cwd)

    def test_veto_gate_llm_error_keeps_allow(self, project_root):
        path = os.path.join(project_root, "safe.py")
        _write(path)
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            result = self._handle_with_mock_llm(
                "python safe.py",
                (None, {}),  # LLM unavailable
            )
            assert result["decision"] == "allow"
        finally:
            os.chdir(old_cwd)

    def test_inline_does_not_reach_script_veto_gate(self, project_root):
        """Inline code is allowed via content scan, not the script veto gate.
        _has_lang_exec_script returns False because reason is 'inline clean' not 'script clean'."""
        from nah.hook import _has_lang_exec_script
        result = classify_command("python -c 'print(1)'")
        assert result.final_decision == "allow"
        assert _has_lang_exec_script(result) is False

    def test_veto_gate_skips_not_found(self, project_root):
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            result = self._handle_with_mock_llm(
                "python nonexistent.py",
                (None, {}),
            )
            assert result["decision"] == "ask"
        finally:
            os.chdir(old_cwd)


# ===================================================================
# 6. LLM PROMPT ENRICHMENT
# ===================================================================

class TestPromptEnrichment:
    """Script content and content inspection results in LLM prompt."""

    def _build_prompt_for(self, command, project_root=None):
        from nah.llm import _build_prompt
        result = classify_command(command)
        return _build_prompt(result)

    def test_prompt_includes_script_content(self, project_root):
        path = os.path.join(project_root, "hello.py")
        _write(path, "print('hello world')\n")
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            prompt = self._build_prompt_for("python hello.py")
            assert "Script about to execute:" in prompt.user
            assert "print('hello world')" in prompt.user
        finally:
            os.chdir(old_cwd)

    def test_prompt_includes_no_flags(self, project_root):
        path = os.path.join(project_root, "clean.py")
        _write(path, "x = 1\n")
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            prompt = self._build_prompt_for("python clean.py")
            assert "Content inspection: no flags" in prompt.user
        finally:
            os.chdir(old_cwd)

    def test_prompt_includes_match_details(self, project_root):
        path = os.path.join(project_root, "danger.py")
        _write(path, "import os\nos.remove('/etc/passwd')\n")
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            prompt = self._build_prompt_for("python danger.py")
            assert "Content inspection:" in prompt.user
            assert "os.remove" in prompt.user
        finally:
            os.chdir(old_cwd)

    def test_prompt_includes_inline_code(self):
        """Inline code is now included in LLM prompt for enrichment (nah-koi.1)."""
        from nah.llm import _build_prompt
        result = classify_command("python -c 'print(1)'")
        prompt = _build_prompt(result)
        assert "Script about to execute:" in prompt.user
        assert "print(1)" in prompt.user

    def test_prompt_no_content_for_nonexistent(self, project_root):
        old_cwd = os.getcwd()
        os.chdir(project_root)
        try:
            prompt = self._build_prompt_for("python nonexistent.py")
            assert "Script about to execute:" not in prompt.user
        finally:
            os.chdir(old_cwd)


# ===================================================================
# 7. _read_script_for_llm UNIT TESTS
# ===================================================================

class TestReadScriptForLlm:
    """Direct tests for the LLM script reader."""

    def test_basic_read(self, project_root):
        from nah.llm import _read_script_for_llm
        path = os.path.join(project_root, "test.py")
        _write(path, "print('hello')\n")
        content = _read_script_for_llm(["python", path])
        assert content == "print('hello')\n"

    def test_inline_returns_code_string(self):
        """Inline code is now returned for LLM enrichment (nah-koi.1)."""
        from nah.llm import _read_script_for_llm
        assert _read_script_for_llm(["python", "-c", "print(1)"]) == "print(1)"

    def test_module_returns_none(self):
        from nah.llm import _read_script_for_llm
        assert _read_script_for_llm(["python", "-m", "http.server"]) is None

    def test_value_flag_skipped(self, project_root):
        from nah.llm import _read_script_for_llm
        path = os.path.join(project_root, "script.py")
        _write(path, "x = 1\n")
        content = _read_script_for_llm(["python", "-W", "ignore", path])
        assert content == "x = 1\n"

    def test_single_token_direct_exec(self, project_root):
        from nah.llm import _read_script_for_llm
        path = os.path.join(project_root, "run.py")
        _write(path, "print('direct')\n")
        content = _read_script_for_llm([path])
        assert content == "print('direct')\n"

    def test_nonexistent_returns_none(self):
        from nah.llm import _read_script_for_llm
        assert _read_script_for_llm(["python", "/tmp/fd079_nonexistent.py"]) is None

    def test_empty_tokens_returns_none(self):
        from nah.llm import _read_script_for_llm
        assert _read_script_for_llm([]) is None

    def test_size_cap(self, project_root):
        from nah.llm import _read_script_for_llm
        path = os.path.join(project_root, "big.py")
        _write(path, "x" * 20000)
        content = _read_script_for_llm(["python", path], max_chars=100)
        assert len(content) == 100
