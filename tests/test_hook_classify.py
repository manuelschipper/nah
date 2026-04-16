"""Unit tests for _classify_unknown_tool + Write/Edit boundary + active allow — FD-037 + FD-024 + FD-045 + FD-054 + FD-094."""

import json
import os
import subprocess

import pytest

from nah.hook import _classify_unknown_tool, handle_write, handle_edit, handle_read, handle_grep
from nah import config, paths
from nah.config import NahConfig


def _make_git_worktree(tmp_path):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    (repo / ".claude" / "skills").mkdir(parents=True)
    (repo / ".claude" / "skills" / "demo.md").write_text("skill\n", encoding="utf-8")
    (repo / "file.txt").write_text("x\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True, text=True)
    worktree = repo / ".worktrees" / "feature"
    subprocess.run(
        ["git", "worktree", "add", "-b", "feature", str(worktree)],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return repo, worktree


class TestClassifyUnknownTool:
    def setup_method(self):
        config._cached_config = NahConfig()

    def teardown_method(self):
        config._cached_config = None

    def test_no_config_returns_ask(self):
        d = _classify_unknown_tool("SomeTool")
        assert d["decision"] == "ask"
        assert "unrecognized tool" in d["reason"]

    def test_global_classify_allow(self):
        config._cached_config = NahConfig(
            classify_global={"mcp_trusted": ["MyTool"]},
            actions={"mcp_trusted": "allow"},
        )
        d = _classify_unknown_tool("MyTool")
        assert d["decision"] == "allow"

    def test_global_classify_ask(self):
        config._cached_config = NahConfig(
            classify_global={"db_write": ["DbTool"]},
        )
        d = _classify_unknown_tool("DbTool")
        assert d["decision"] == "ask"
        assert d["_meta"]["stages"] == [{
            "action_type": "db_write",
            "decision": "ask",
            "policy": "context",
            "reason": "unknown database target",
        }]

    def test_mcp_skips_project_classify(self):
        config._cached_config = NahConfig(
            classify_project={"mcp_trusted": ["mcp__evil__exfil"]},
            actions={"mcp_trusted": "allow"},
        )
        d = _classify_unknown_tool("mcp__evil__exfil")
        assert d["decision"] == "ask"  # project ignored

    def test_non_mcp_uses_project_classify(self):
        config._cached_config = NahConfig(
            classify_project={"package_run": ["CustomRunner"]},
        )
        d = _classify_unknown_tool("CustomRunner")
        assert d["decision"] == "allow"  # package_run → allow

    # --- FD-024 adversarial tests ---

    def test_mcp_classify_prefix_collision(self):
        """mcp__postgres in config must NOT match mcp__postgres__query."""
        config._cached_config = NahConfig(
            classify_global={"mcp_trusted": ["mcp__postgres"]},
            actions={"mcp_trusted": "allow"},
        )
        # Exact match
        d = _classify_unknown_tool("mcp__postgres")
        assert d["decision"] == "allow"
        # Different tool — no match (single-token prefix, not substring)
        d = _classify_unknown_tool("mcp__postgres__query")
        assert d["decision"] == "ask"

    def test_mcp_classified_global_allow(self):
        """Global config can classify and allow MCP tools."""
        config._cached_config = NahConfig(
            classify_global={"mcp_trusted": ["mcp__memory__search"]},
            actions={"mcp_trusted": "allow"},
        )
        d = _classify_unknown_tool("mcp__memory__search")
        assert d["decision"] == "allow"

    # --- nah-875 MCP wildcard classification ---

    def test_mcp_wildcard_allows_server_tools(self):
        """mcp__github* covers every tool under the github MCP server."""
        config._cached_config = NahConfig(
            classify_global={"mcp_github": ["mcp__github*"]},
            actions={"mcp_github": "allow"},
        )
        assert _classify_unknown_tool("mcp__github__get_issue")["decision"] == "allow"
        assert _classify_unknown_tool("mcp__github__create_pr")["decision"] == "allow"
        assert _classify_unknown_tool("mcp__github__list_issues")["decision"] == "allow"

    def test_mcp_wildcard_does_not_leak_to_other_servers(self):
        """mcp__github* must not match tools on a different server."""
        config._cached_config = NahConfig(
            classify_global={"mcp_github": ["mcp__github*"]},
            actions={"mcp_github": "allow"},
        )
        d = _classify_unknown_tool("mcp__other__tool")
        assert d["decision"] == "ask"  # falls through to unknown

    def test_mcp_exact_entry_overrides_wildcard(self):
        """An exact block entry beats a wildcard allow at equal prefix length."""
        config._cached_config = NahConfig(
            classify_global={
                "mcp_github": ["mcp__github*"],
                "mcp_danger": ["mcp__github__delete_repo"],
            },
            actions={"mcp_github": "allow", "mcp_danger": "block"},
        )
        assert _classify_unknown_tool("mcp__github__delete_repo")["decision"] == "block"
        assert _classify_unknown_tool("mcp__github__get_issue")["decision"] == "allow"

    def test_mcp_wildcard_in_project_still_ignored(self):
        """FD-024: project config cannot classify MCP tools, wildcards included."""
        config._cached_config = NahConfig(
            classify_project={"mcp_evil": ["mcp__github*"]},
            actions={"mcp_evil": "allow"},
        )
        d = _classify_unknown_tool("mcp__github__get_issue")
        assert d["decision"] == "ask"  # project wildcard ignored for MCP

    # --- FD-045 configurable unknown tool policy ---

    def test_unknown_default_ask(self):
        """No actions config → unknown defaults to ask."""
        d = _classify_unknown_tool("BrandNewTool")
        assert d["decision"] == "ask"
        assert "unrecognized tool" in d["reason"]

    def test_unknown_actions_block(self):
        """actions.unknown: block → block unknown tools."""
        config._cached_config = NahConfig(actions={"unknown": "block"})
        d = _classify_unknown_tool("BrandNewTool")
        assert d["decision"] == "block"
        assert "unrecognized tool" in d["reason"]

    def test_unknown_actions_allow(self):
        """actions.unknown: allow → allow unknown tools."""
        config._cached_config = NahConfig(actions={"unknown": "allow"})
        d = _classify_unknown_tool("BrandNewTool")
        assert d["decision"] == "allow"

    def test_unknown_context_falls_to_ask(self):
        """actions.unknown: context → ask (no context resolver for 'unknown' type)."""
        config._cached_config = NahConfig(actions={"unknown": "context"})
        d = _classify_unknown_tool("BrandNewTool")
        assert d["decision"] == "ask"
        assert "no context resolver" in d["reason"]


class TestClassifyUnknownToolContext:
    """FD-055: MCP tools with context policy resolve context via tool_input."""

    def setup_method(self):
        config._cached_config = NahConfig(
            classify_global={"db_write": ["mcp__snowflake__execute_sql"]},
            actions={"db_write": "context"},
            db_targets=[
                {"database": "SANDBOX"},
                {"database": "SALES", "schema": "DEV"},
            ],
        )

    def teardown_method(self):
        config._cached_config = None

    def test_mcp_db_write_matching_target_allow(self):
        """MCP tool_input with matching database → allow."""
        d = _classify_unknown_tool(
            "mcp__snowflake__execute_sql",
            {"database": "SANDBOX", "query": "INSERT INTO t VALUES (1)"},
        )
        assert d["decision"] == "allow"
        assert "allowed target" in d["reason"]

    def test_mcp_db_write_matching_db_schema_allow(self):
        """MCP tool_input with matching database+schema → allow."""
        d = _classify_unknown_tool(
            "mcp__snowflake__execute_sql",
            {"database": "SALES", "schema": "DEV", "query": "INSERT INTO t VALUES (1)"},
        )
        assert d["decision"] == "allow"
        assert "SALES.DEV" in d["reason"]

    def test_mcp_db_write_non_matching_target_ask(self):
        """MCP tool_input with non-matching database → ask."""
        d = _classify_unknown_tool(
            "mcp__snowflake__execute_sql",
            {"database": "PRODUCTION", "query": "DROP TABLE users"},
        )
        assert d["decision"] == "ask"
        assert "unrecognized target" in d["reason"]

    def test_mcp_db_write_no_database_key_ask(self):
        """MCP tool_input without database key → ask."""
        d = _classify_unknown_tool(
            "mcp__snowflake__execute_sql",
            {"query": "SELECT 1"},
        )
        assert d["decision"] == "ask"
        assert "unknown database target" in d["reason"]

    def test_mcp_db_write_no_tool_input_ask(self):
        """MCP with no tool_input → ask."""
        d = _classify_unknown_tool("mcp__snowflake__execute_sql")
        assert d["decision"] == "ask"

    def test_mcp_db_write_no_db_targets_ask(self):
        """No db_targets configured → ask even with matching input."""
        config._cached_config = NahConfig(
            classify_global={"db_write": ["mcp__snowflake__execute_sql"]},
            actions={"db_write": "context"},
            db_targets=[],
        )
        d = _classify_unknown_tool(
            "mcp__snowflake__execute_sql",
            {"database": "SANDBOX", "query": "INSERT INTO t VALUES (1)"},
        )
        assert d["decision"] == "ask"
        assert "no db_targets configured" in d["reason"]

    def test_mcp_db_write_empty_tool_input_ask(self):
        """Empty dict {} (what main() actually passes) → ask."""
        d = _classify_unknown_tool("mcp__snowflake__execute_sql", {})
        assert d["decision"] == "ask"
        assert "unknown database target" in d["reason"]

    def test_mcp_db_write_case_insensitive(self):
        """Database name matching is case-insensitive."""
        d = _classify_unknown_tool(
            "mcp__snowflake__execute_sql",
            {"database": "sandbox", "query": "INSERT INTO t VALUES (1)"},
        )
        assert d["decision"] == "allow"
        assert "SANDBOX" in d["reason"]

    def test_mcp_non_db_context_falls_to_ask(self):
        """MCP tool classified as network_outbound + context → ask (no tokens)."""
        config._cached_config = NahConfig(
            classify_global={"network_outbound": ["mcp__api__fetch"]},
            actions={"network_outbound": "context"},
        )
        d = _classify_unknown_tool(
            "mcp__api__fetch",
            {"url": "https://example.com"},
        )
        assert d["decision"] == "ask"
        assert "unknown host" in d["reason"]

    def test_mcp_db_write_default_policy_context_with_targets(self):
        """db_write with default policy (context) + matching db_targets → allow."""
        config._cached_config = NahConfig(
            classify_global={"db_write": ["mcp__snowflake__execute_sql"]},
            db_targets=[{"database": "SANDBOX"}],
        )
        d = _classify_unknown_tool(
            "mcp__snowflake__execute_sql",
            {"database": "SANDBOX", "query": "INSERT INTO t VALUES (1)"},
        )
        assert d["decision"] == "allow"
        assert "allowed target" in d.get("reason", "")


class TestPlaywrightMcpClassification:
    def setup_method(self):
        config._cached_config = NahConfig()

    def teardown_method(self):
        config._cached_config = None

    @pytest.mark.parametrize("tool", [
        "mcp__plugin_playwright_playwright__browser_snapshot",
        "mcp__playwright__browser_snapshot",
    ])
    def test_browser_read_allow(self, tool):
        d = _classify_unknown_tool(tool)
        assert d["decision"] == "allow"

    @pytest.mark.parametrize("tool", [
        "mcp__plugin_playwright_playwright__browser_click",
        "mcp__playwright__browser_click",
    ])
    def test_browser_interact_allow(self, tool):
        d = _classify_unknown_tool(tool)
        assert d["decision"] == "allow"

    @pytest.mark.parametrize("tool", [
        "mcp__plugin_playwright_playwright__browser_cookie_set",
        "mcp__playwright__browser_cookie_set",
    ])
    def test_browser_state_allow(self, tool):
        d = _classify_unknown_tool(tool)
        assert d["decision"] == "allow"

    @pytest.mark.parametrize("tool", [
        "mcp__plugin_playwright_playwright__browser_navigate",
        "mcp__playwright__browser_navigate",
    ])
    def test_browser_navigate_asks_with_browser_reason(self, tool):
        d = _classify_unknown_tool(tool)
        assert d["decision"] == "ask"
        assert d["reason"] == "browser_navigate: url extraction pending"

    @pytest.mark.parametrize("tool", [
        "mcp__plugin_playwright_playwright__browser_evaluate",
        "mcp__playwright__browser_evaluate",
    ])
    def test_browser_exec_asks_with_browser_reason(self, tool):
        d = _classify_unknown_tool(tool)
        assert d["decision"] == "ask"
        assert d["reason"] == "browser_exec → ask"
        assert d["_meta"]["stages"] == [{
            "action_type": "browser_exec",
            "decision": "ask",
            "policy": "ask",
            "reason": "browser_exec → ask",
        }]

    @pytest.mark.parametrize("tool", [
        "mcp__plugin_playwright_playwright__browser_file_upload",
        "mcp__playwright__browser_file_upload",
    ])
    def test_browser_file_asks_with_browser_reason(self, tool):
        d = _classify_unknown_tool(tool)
        assert d["decision"] == "ask"
        assert d["reason"] == "browser_file: path extraction pending"


# --- FD-054: Write/Edit project boundary tests ---


class TestWriteEditBoundary:
    """FD-054: Write/Edit enforce project boundary check."""

    def setup_method(self):
        config._cached_config = NahConfig()

    def teardown_method(self):
        config._cached_config = None

    def test_write_inside_project(self, project_root):
        target = os.path.join(project_root, "file.txt")
        d = handle_write({"file_path": target, "content": "hello"})
        assert d["decision"] == "allow"

    def test_write_outside_project(self, project_root):
        d = handle_write({"file_path": "/tmp/outside.txt", "content": "hello"})
        assert d["decision"] == "ask"
        assert "outside project" in d["reason"]

    def test_edit_outside_project(self, project_root):
        d = handle_edit({"file_path": "/tmp/outside.txt", "old_string": "a", "new_string": "b"})
        assert d["decision"] == "ask"
        assert "outside project" in d["reason"]

    def test_write_to_trusted_path(self, project_root):
        config._cached_config = NahConfig(trusted_paths=["/tmp"])
        d = handle_write({"file_path": "/tmp/trusted.txt", "content": "hello"})
        assert d["decision"] == "allow"


class TestGrepCredentialBoundary:
    """Credential grep checks use the same worktree-aware project boundary."""

    def setup_method(self):
        config._cached_config = NahConfig()

    def teardown_method(self):
        config._cached_config = None

    def test_main_repo_path_not_outside_project_from_worktree(self, tmp_path, monkeypatch):
        repo, worktree = _make_git_worktree(tmp_path)
        monkeypatch.chdir(worktree)
        paths.reset_project_root()

        d = handle_grep({
            "path": str(repo / ".claude" / "skills"),
            "pattern": "password",
        })

        assert d["decision"] == "allow"

    def test_unrelated_path_still_asks_from_worktree(self, tmp_path, monkeypatch):
        _repo, worktree = _make_git_worktree(tmp_path)
        outside = tmp_path / "outside"
        outside.mkdir()
        monkeypatch.chdir(worktree)
        paths.reset_project_root()

        d = handle_grep({
            "path": str(outside),
            "pattern": "password",
        })

        assert d["decision"] == "ask"
        assert "outside project" in d["reason"]

    def test_write_sensitive_unchanged(self, project_root):
        """Sensitive paths still block even with boundary check."""
        d = handle_write({"file_path": "~/.ssh/config", "content": "host"})
        assert d["decision"] == "block"

    def test_write_hook_unchanged(self, project_root):
        """Hook self-protection still blocks."""
        d = handle_write({"file_path": "~/.claude/hooks/evil.py", "content": "x"})
        assert d["decision"] == "block"

    def test_read_outside_no_boundary(self, project_root):
        """Read tool has no boundary check — still allows outside reads."""
        d = handle_read({"file_path": "/tmp/outside.txt"})
        assert d["decision"] == "allow"

    def test_trusted_does_not_override_sensitive(self, project_root):
        """trusted_paths cannot bypass sensitive path block."""
        home = os.path.expanduser("~")
        config._cached_config = NahConfig(trusted_paths=[home])
        d = handle_write({"file_path": "~/.ssh/id_rsa", "content": "key"})
        assert d["decision"] == "block"

    def test_profile_none_disables_boundary(self, project_root):
        """profile: none disables boundary check for Write."""
        config._cached_config = NahConfig(profile="none")
        paths._sensitive_paths_merged = False  # allow re-merge
        d = handle_write({"file_path": "/tmp/anywhere.txt", "content": "hello"})
        assert d["decision"] == "allow"

    def test_profile_none_clears_sensitive_dirs(self, project_root):
        """profile: none clears _SENSITIVE_DIRS, allowing ~/.ssh."""
        config._cached_config = NahConfig(profile="none")
        paths._sensitive_paths_merged = False  # allow re-merge
        d = handle_write({"file_path": "~/.ssh/config", "content": "host"})
        # Sensitive dirs cleared, but...
        # Note: check_path runs before boundary, and hook check is first.
        # With profile: none, _SENSITIVE_DIRS is cleared, so sensitive check passes.
        # Hook check only applies to ~/.claude/hooks. So ~/.ssh should allow.
        assert d["decision"] == "allow"

    def test_hook_self_protection_immutable_under_none(self, project_root):
        """Hook self-protection is immutable even under profile: none."""
        config._cached_config = NahConfig(profile="none")
        paths._sensitive_paths_merged = False  # allow re-merge
        d = handle_write({"file_path": "~/.claude/hooks/guard.py", "content": "x"})
        assert d["decision"] == "block"

    def test_write_outside_hint(self, project_root):
        """Outside-project ask includes hint suggesting nah trust."""
        d = handle_write({"file_path": "/tmp/foo/bar.txt", "content": "hello"})
        assert d["decision"] == "ask"
        assert "_hint" in d
        assert "nah trust" in d["_hint"]

    def test_write_nested_trusted(self, project_root):
        """Nested path inside trusted directory is allowed."""
        config._cached_config = NahConfig(trusted_paths=["/tmp"])
        d = handle_write({"file_path": "/tmp/deep/nested/file.txt", "content": "hello"})
        assert d["decision"] == "allow"

    def test_write_no_project_root(self):
        """No project root → ask with hint."""
        paths.set_project_root(None)
        d = handle_write({"file_path": "/tmp/file.txt", "content": "hello"})
        assert d["decision"] == "ask"
        assert "no git root" in d["reason"]


# --- FD-094: Active allow emission tests ---


class TestActiveAllowEmission:
    """FD-094: Verify hook.main() emits JSON for ALLOW decisions based on active_allow config."""

    def setup_method(self):
        config._cached_config = NahConfig()

    def teardown_method(self):
        config._cached_config = None

    def _run_hook(self, tool_name: str, tool_input: dict) -> str:
        """Run hook.main() with mocked stdin/stdout and return stdout output."""
        import io
        payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
        stdin_mock = io.StringIO(payload)
        stdout_mock = io.StringIO()
        import sys
        old_stdin, old_stdout = sys.stdin, sys.stdout
        sys.stdin, sys.stdout = stdin_mock, stdout_mock
        try:
            from nah.hook import main
            main()
        finally:
            sys.stdin, sys.stdout = old_stdin, old_stdout
        return stdout_mock.getvalue()

    def test_default_active_allow_emits_json(self):
        """Default (active_allow: True): ALLOW decision emits JSON with permissionDecision."""
        output = self._run_hook("Bash", {"command": "ls"})
        assert output.strip(), "Expected JSON output for active allow"
        result = json.loads(output)
        assert result["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_active_allow_false_emits_nothing(self):
        """active_allow: False: ALLOW decision emits nothing."""
        config._cached_config = NahConfig(active_allow=False)
        output = self._run_hook("Bash", {"command": "ls"})
        assert not output.strip(), "Expected no output when active_allow is False"

    def test_active_allow_list_matching_tool(self):
        """active_allow: [Bash, Read]: Bash ALLOW emits JSON."""
        config._cached_config = NahConfig(active_allow=["Bash", "Read"])
        output = self._run_hook("Bash", {"command": "ls"})
        assert output.strip(), "Expected JSON output for Bash in active_allow list"
        result = json.loads(output)
        assert result["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_active_allow_list_non_matching_tool(self):
        """active_allow: [Bash]: Glob ALLOW emits nothing (Glob not in list)."""
        config._cached_config = NahConfig(active_allow=["Bash"])
        output = self._run_hook("Glob", {"pattern": "*.py"})
        assert not output.strip(), "Expected no output for Glob not in active_allow list"

    def test_ask_decision_emits_regardless(self):
        """ASK decisions emit JSON regardless of active_allow setting."""
        config._cached_config = NahConfig(active_allow=False)
        output = self._run_hook("Bash", {"command": "rm -rf /"})
        assert output.strip(), "ASK/BLOCK should always emit"
        result = json.loads(output)
        assert result["hookSpecificOutput"]["permissionDecision"] in ("deny", "ask")

    def test_block_decision_emits_regardless(self):
        """BLOCK decisions emit JSON regardless of active_allow setting."""
        config._cached_config = NahConfig(active_allow=False)
        output = self._run_hook("Write", {"file_path": "~/.ssh/id_rsa", "content": "key"})
        assert output.strip(), "BLOCK should always emit"
        result = json.loads(output)
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def _run_hook_with_write_llm_allow(self, tool_name: str, tool_input: dict) -> str:
        """Run hook.main() with write LLM mocked to allow."""
        import nah.hook as hook_mod

        original = hook_mod._try_llm_write
        hook_mod._try_llm_write = lambda tn, ti, d: (
            {"decision": "allow", "reason": "safe"},
            {"llm_provider": "test"},
        )
        try:
            return self._run_hook(tool_name, tool_input)
        finally:
            hook_mod._try_llm_write = original

    def test_llm_refined_write_allow_emits_when_active_allowed(self, project_root):
        """LLM-refined Write allow emits JSON when Write is in active_allow."""
        config._cached_config = NahConfig(
            active_allow=["Write"],
            llm_mode="on",
            llm={"providers": ["ollama"], "ollama": {"model": "test"}},
        )
        output = self._run_hook_with_write_llm_allow(
            "Write",
            {"file_path": "/tmp/outside.txt", "content": "alias ads='ads-tool'\n"},
        )
        assert output.strip(), "Expected refined Write allow to emit for active Write"
        result = json.loads(output)
        assert result["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_llm_refined_write_allow_falls_through_when_not_active_allowed(self, project_root):
        """LLM-refined Write allow emits nothing when Write is not in active_allow."""
        config._cached_config = NahConfig(
            active_allow=["Bash"],
            llm_mode="on",
            llm={"providers": ["ollama"], "ollama": {"model": "test"}},
        )
        output = self._run_hook_with_write_llm_allow(
            "Write",
            {"file_path": "/tmp/outside.txt", "content": "alias ads='ads-tool'\n"},
        )
        assert not output.strip(), "Expected refined Write allow to fall through"

    def test_write_review_ask_does_not_fall_through_to_unified_llm(self):
        """Write asks left by write review cannot be relaxed by unified LLM."""
        import nah.hook as hook_mod
        import nah.llm as llm_mod
        from nah.llm import LLMCallResult

        config._cached_config = NahConfig(
            llm_mode="on",
            llm_eligible="all",
            llm={"providers": ["ollama"], "ollama": {"model": "test"}},
        )
        called = []
        original_write = hook_mod._try_llm_write
        original_unified = llm_mod.try_llm_unified
        hook_mod._try_llm_write = lambda tn, ti, d: (
            {"decision": "allow", "reason": "safe"},
            {"llm_provider": "test"},
        )

        def fake_unified(*args, **kwargs):
            called.append(True)
            return LLMCallResult(decision={"decision": "allow", "reason": "unified allow"})

        llm_mod.try_llm_unified = fake_unified
        try:
            output = self._run_hook(
                "Write",
                {"file_path": "~/.aws/credentials", "content": "region = us-east-1\n"},
            )
        finally:
            hook_mod._try_llm_write = original_write
            llm_mod.try_llm_unified = original_unified

        assert called == []
        result = json.loads(output)
        assert result["hookSpecificOutput"]["permissionDecision"] == "ask"
