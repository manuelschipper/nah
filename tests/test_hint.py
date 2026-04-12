"""Tests for hint flow — actionable ask messages (FD-027)."""

import json
import os
from unittest.mock import patch

import pytest

from nah import paths, taxonomy
from nah.config import reset_config


@pytest.fixture(autouse=True)
def _reset(tmp_path):
    paths.set_project_root(str(tmp_path))
    paths.reset_sensitive_paths()
    reset_config()
    yield
    paths.reset_project_root()
    paths.reset_sensitive_paths()
    reset_config()


class TestBashHints:
    """Bash ask decisions should include actionable hints."""

    def test_action_policy_hint(self):
        """Action policy ask → reason contains 'nah allow {type}'."""
        from nah.hook import handle_bash, _to_hook_output
        decision = handle_bash({"command": "git push --force origin main"})
        assert decision["decision"] == taxonomy.ASK
        hint = decision.get("_hint", "")
        assert "nah allow git_history_rewrite" in hint

        # Check it appears in formatted output
        output = _to_hook_output(decision, "claude")
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "nah allow git_history_rewrite" in reason

    def test_unknown_hint(self):
        """Unknown command → reason contains 'nah classify' and 'nah types'."""
        from nah.hook import handle_bash
        # Use a truly unknown command
        decision = handle_bash({"command": "zzz_unknown_tool_xyz --flag"})
        assert decision["decision"] == taxonomy.ASK
        hint = decision.get("_hint", "")
        assert "nah classify" in hint
        assert "nah types" in hint

    def test_missing_source_has_no_unknown_classify_hint(self, tmp_path):
        from nah.hook import handle_bash
        decision = handle_bash({"command": f"source {tmp_path / 'missing.sh'}"})
        assert decision["decision"] == taxonomy.ASK
        assert "script not found" in decision["reason"]
        hint = decision.get("_hint", "")
        assert "nah classify source" not in hint

    def test_missing_dot_source_has_no_unknown_classify_hint(self, tmp_path):
        from nah.hook import handle_bash
        decision = handle_bash({"command": f". {tmp_path / 'missing.sh'}"})
        assert decision["decision"] == taxonomy.ASK
        assert "script not found" in decision["reason"]
        hint = decision.get("_hint", "")
        assert "nah classify ." not in hint

    def test_export_assignment_chain_does_not_hint_classify_export(self):
        """Benign export assignment should not be the ask/hint source."""
        from nah.hook import handle_bash
        decision = handle_bash({"command": "export PATH=/opt/bin:$PATH && zzz_unknown_tool_xyz"})
        assert decision["decision"] == taxonomy.ASK
        hint = decision.get("_hint", "")
        assert "nah classify zzz_unknown_tool_xyz" in hint
        assert "nah classify export" not in hint

    def test_export_p_does_not_get_benign_export_allow_hint(self):
        """Non-assignment export forms remain unknown, not export-assignment allows."""
        from nah.hook import handle_bash
        decision = handle_bash({"command": "export -p"})
        assert decision["decision"] == taxonomy.ASK
        hint = decision.get("_hint", "")
        assert "nah classify export" in hint
        assert "nah allow filesystem_read" not in hint

    def test_sensitive_path_hint(self):
        """Bash ask for sensitive path → reason contains 'nah allow-path'."""
        from nah.hook import handle_bash
        decision = handle_bash({"command": "cat ~/.aws/config"})
        assert decision["decision"] == taxonomy.ASK
        hint = decision.get("_hint", "")
        assert "nah allow-path" in hint

    def test_composition_rule_no_hint(self):
        """Composition rule ask → no hint (not rememberable)."""
        from nah.hook import handle_bash
        decision = handle_bash({"command": "cat file.txt | bash"})
        # Composition rules may block or ask
        hint = decision.get("_hint")
        assert hint is None

    def test_subshell_syntax_does_not_hint_parenthesized_command(self):
        """Subshell groups should not produce `nah classify (cmd <type>` hints."""
        from nah.hook import handle_bash
        decision = handle_bash({"command": "(cd /tmp && ls)"})
        assert "nah classify (cd" not in decision.get("_hint", "")

    def test_brace_group_does_not_hint_brace_command(self):
        """Unsupported brace groups should ask without suggesting `nah classify { <type>`."""
        from nah.hook import handle_bash
        decision = handle_bash({"command": "{ echo a; echo b; }"})
        assert decision["decision"] == taxonomy.ASK
        assert "nah classify {" not in decision.get("_hint", "")


class TestPathHints:
    """Path ask decisions should include actionable hints."""

    def test_sensitive_path_hint(self):
        """Sensitive path ask → reason contains 'nah allow-path'."""
        result = paths.check_path("Read", "~/.aws/config")
        assert result is not None
        assert result["decision"] == taxonomy.ASK
        hint = result.get("_hint", "")
        assert "nah allow-path" in hint
        assert "~/.aws" in hint

    def test_hook_directory_read_allowed(self):
        """Hook directory read → allowed (no decision dict)."""
        result = paths.check_path("Read", "~/.claude/hooks/something.py")
        assert result is None  # reads on hooks are allowed


class TestContentHints:
    """Content inspection asks should have non-rememberable hint."""

    def test_write_content_hint(self, project_root):
        """Content inspection ask → hint says cannot be remembered."""
        from nah.hook import handle_write
        # Write content with something that looks like a secret (inside project)
        target = os.path.join(project_root, "test.py")
        decision = handle_write({
            "file_path": target,
            "content": "AKIAIOSFODNN7EXAMPLE",  # AWS-style key
        })
        if decision["decision"] == taxonomy.ASK:
            hint = decision.get("_hint", "")
            assert "cannot be remembered" in hint


class TestGrepHints:
    """Grep credential search asks should have non-rememberable hint."""

    def test_credential_search_hint(self, tmp_path):
        """Credential search ask → hint says cannot be remembered."""
        from nah.hook import handle_grep
        decision = handle_grep({
            "pattern": "AKIA[A-Z0-9]{16}",
            "path": "/etc",
        })
        if decision["decision"] == taxonomy.ASK:
            hint = decision.get("_hint", "")
            assert "cannot be remembered" in hint


class TestHintInOutput:
    """Hints should be rendered in formatted hook output."""

    def test_hint_appended_to_reason(self):
        """_to_hook_output appends hint to reason string."""
        from nah.hook import _to_hook_output
        decision = {
            "decision": taxonomy.ASK,
            "reason": "Bash: git_history_rewrite → ask",
            "_hint": "To always allow: nah allow git_history_rewrite",
        }
        output = _to_hook_output(decision, "claude")
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "nah allow git_history_rewrite" in reason
        assert "git_history_rewrite → ask" in reason

    def test_no_hint_no_change(self):
        """Without _hint, output is unchanged."""
        from nah.hook import _to_hook_output
        decision = {
            "decision": taxonomy.ASK,
            "reason": "Bash: some reason",
        }
        output = _to_hook_output(decision, "claude")
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "nah?" in reason
        assert "some reason" in reason

    def test_hint_in_meta_for_llm_resolved(self):
        """Hint should be in _meta even for LLM-resolved asks."""
        from nah.hook import handle_bash, _classify_meta, _build_bash_hint
        from nah.bash import classify_command
        result = classify_command("git push --force origin main")
        hint = _build_bash_hint(result)
        assert hint is not None
        assert "nah allow" in hint
        meta = _classify_meta(result)
        # When handle_bash runs, hint goes into meta
        decision = handle_bash({"command": "git push --force origin main"})
        meta = decision.get("_meta", {})
        if "hint" in meta:
            assert "nah allow" in meta["hint"]
