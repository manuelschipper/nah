"""Tests for CLI UX — custom type confirmation and comment warnings (FD-047)."""

import argparse
import os
from unittest.mock import patch

import pytest

from nah import paths
from nah.config import reset_config
from nah.content import reset_content_patterns


@pytest.fixture(autouse=True)
def _reset(tmp_path):
    """Reset caches between tests."""
    paths.set_project_root(str(tmp_path / "project"))
    (tmp_path / "project").mkdir()
    reset_config()
    yield
    paths.reset_project_root()
    reset_config()


@pytest.fixture
def global_cfg(tmp_path):
    return str(tmp_path / "global" / "config.yaml")


@pytest.fixture
def project_cfg(tmp_path):
    return str(tmp_path / "project" / ".nah.yaml")


@pytest.fixture
def patched_paths(global_cfg, project_cfg, tmp_path):
    """Patch config paths to use tmp dirs."""
    with patch("nah.remember.get_global_config_path", return_value=global_cfg), \
         patch("nah.remember.get_project_config_path", return_value=project_cfg), \
         patch("nah.remember.get_project_root", return_value=str(tmp_path / "project")):
        yield


class TestCmdAllowCustomType:
    def test_confirmed(self, patched_paths, global_cfg):
        from nah.cli import cmd_allow
        from nah.remember import _read_config
        args = argparse.Namespace(action_type="my_custom", project=False)
        with patch("nah.cli._confirm", return_value=True), \
             patch("nah.cli._warn_comments"):
            cmd_allow(args)
        data = _read_config(global_cfg)
        assert data["actions"]["my_custom"] == "allow"

    def test_denied(self, patched_paths):
        from nah.cli import cmd_allow
        args = argparse.Namespace(action_type="my_custom", project=False)
        with patch("nah.cli._confirm", return_value=False), \
             patch("nah.cli._warn_comments"):
            with pytest.raises(SystemExit):
                cmd_allow(args)


class TestCmdDenyCustomType:
    def test_confirmed(self, patched_paths, global_cfg):
        from nah.cli import cmd_deny
        from nah.remember import _read_config
        args = argparse.Namespace(action_type="my_custom", project=False)
        with patch("nah.cli._confirm", return_value=True), \
             patch("nah.cli._warn_comments"):
            cmd_deny(args)
        data = _read_config(global_cfg)
        assert data["actions"]["my_custom"] == "block"


class TestCmdClassifyCustomType:
    def test_confirmed(self, patched_paths, global_cfg):
        from nah.cli import cmd_classify
        from nah.remember import _read_config
        args = argparse.Namespace(command_prefix="mycmd", type="my_custom", project=False)
        with patch("nah.cli._confirm", return_value=True), \
             patch("nah.cli._warn_comments"):
            cmd_classify(args)
        data = _read_config(global_cfg)
        assert "mycmd" in data["classify"]["my_custom"]

    def test_denied(self, patched_paths):
        from nah.cli import cmd_classify
        args = argparse.Namespace(command_prefix="mycmd", type="my_custom", project=False)
        with patch("nah.cli._confirm", return_value=False), \
             patch("nah.cli._warn_comments"):
            with pytest.raises(SystemExit):
                cmd_classify(args)


class TestCommentWarning:
    def test_warns_when_comments_present(self, patched_paths, global_cfg):
        """Config with comments triggers confirmation prompt."""
        from nah.cli import cmd_allow
        os.makedirs(os.path.dirname(global_cfg), exist_ok=True)
        with open(global_cfg, "w") as f:
            f.write("# My comments\nactions:\n  git_safe: allow\n")
        args = argparse.Namespace(action_type="git_safe", project=False)
        with patch("nah.cli._confirm", return_value=True) as mock_confirm, \
             patch("nah.remember.get_global_config_path", return_value=global_cfg), \
             patch("nah.config.get_global_config_path", return_value=global_cfg):
            cmd_allow(args)
        # _confirm called for comment warning
        assert mock_confirm.called
        assert "comments" in mock_confirm.call_args[0][0]

    def test_no_warning_without_comments(self, patched_paths, global_cfg):
        """Config without comments doesn't trigger prompt."""
        from nah.cli import cmd_allow
        os.makedirs(os.path.dirname(global_cfg), exist_ok=True)
        with open(global_cfg, "w") as f:
            f.write("actions:\n  git_safe: allow\n")
        args = argparse.Namespace(action_type="git_safe", project=False)
        with patch("nah.cli._confirm", return_value=True) as mock_confirm, \
             patch("nah.remember.get_global_config_path", return_value=global_cfg), \
             patch("nah.config.get_global_config_path", return_value=global_cfg):
            cmd_allow(args)
        # _confirm should NOT have been called (no comments, built-in type)
        assert not mock_confirm.called


class TestConfirmHelper:
    def test_non_interactive_returns_false(self):
        from nah.cli import _confirm
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            assert _confirm("test?") is False

    def test_yes_returns_true(self):
        from nah.cli import _confirm
        with patch("sys.stdin") as mock_stdin, \
             patch("builtins.input", return_value="y"):
            mock_stdin.isatty.return_value = True
            assert _confirm("test?") is True

    def test_no_returns_false(self):
        from nah.cli import _confirm
        with patch("sys.stdin") as mock_stdin, \
             patch("builtins.input", return_value="n"):
            mock_stdin.isatty.return_value = True
            assert _confirm("test?") is False

    def test_eof_returns_false(self):
        from nah.cli import _confirm
        with patch("sys.stdin") as mock_stdin, \
             patch("builtins.input", side_effect=EOFError):
            mock_stdin.isatty.return_value = True
            assert _confirm("test?") is False


# --- Shadow warnings (FD-062) ---


class TestCmdStatusShadowAnnotation:
    """Shadow annotations in nah status output."""

    def test_table_shadow(self, patched_paths, global_cfg, capsys):
        os.makedirs(os.path.dirname(global_cfg), exist_ok=True)
        with open(global_cfg, "w") as f:
            f.write("classify:\n  container_destructive:\n    - docker\n")
        from nah.cli import cmd_status
        cmd_status(argparse.Namespace())
        out = capsys.readouterr().out
        assert "shadows" in out
        assert "built-in rule" in out

    def test_flag_classifier_shadow(self, patched_paths, global_cfg, capsys):
        os.makedirs(os.path.dirname(global_cfg), exist_ok=True)
        with open(global_cfg, "w") as f:
            f.write("classify:\n  network_outbound:\n    - curl\n")
        from nah.cli import cmd_status
        cmd_status(argparse.Namespace())
        out = capsys.readouterr().out
        assert "flag classifier" in out

    def test_no_shadow_for_unique_entry(self, patched_paths, global_cfg, capsys):
        os.makedirs(os.path.dirname(global_cfg), exist_ok=True)
        with open(global_cfg, "w") as f:
            f.write("classify:\n  lang_exec:\n    - mycustomcmd\n")
        from nah.cli import cmd_status
        cmd_status(argparse.Namespace())
        out = capsys.readouterr().out
        assert "mycustomcmd" in out
        assert "shadow" not in out


class TestCmdTypesShadowAnnotation:
    """Override notes in nah types output."""

    def test_override_note(self, patched_paths, global_cfg, capsys):
        os.makedirs(os.path.dirname(global_cfg), exist_ok=True)
        with open(global_cfg, "w") as f:
            f.write("classify:\n  container_destructive:\n    - docker\n")
        from nah.cli import cmd_types
        cmd_types(argparse.Namespace())
        out = capsys.readouterr().out
        assert "overrides" in out
        assert "nah forget docker" in out

    def test_no_override_without_classify(self, patched_paths, global_cfg, capsys):
        from nah.cli import cmd_types
        cmd_types(argparse.Namespace())
        out = capsys.readouterr().out
        assert "overrides" not in out


# --- nah test full tool support (FD-069) ---


class TestCmdTest:
    """Tests for nah test with Write/Edit content, Grep patterns, and MCP tools."""

    @pytest.fixture(autouse=True)
    def _reset_content(self):
        reset_content_patterns()
        yield
        reset_content_patterns()

    def test_write_secret_content(self, tmp_path, capsys):
        from nah.cli import cmd_test
        target = str(tmp_path / "project" / "config.py")
        args = argparse.Namespace(
            tool="Write", path=target,
            content="AKIA1234567890ABCDEF", pattern=None, args=[],
        )
        cmd_test(args)
        out = capsys.readouterr().out
        assert "ASK" in out
        assert "AWS access key" in out

    def test_write_safe_content(self, tmp_path, capsys):
        from nah.cli import cmd_test
        target = str(tmp_path / "project" / "test.txt")
        args = argparse.Namespace(
            tool="Write", path=target,
            content="hello world", pattern=None, args=[],
        )
        cmd_test(args)
        out = capsys.readouterr().out
        assert "ALLOW" in out

    def test_edit_secret_content(self, tmp_path, capsys):
        from nah.cli import cmd_test
        target = str(tmp_path / "project" / "app.py")
        args = argparse.Namespace(
            tool="Edit", path=target,
            content="api_secret = 'hunter2hunter2'", pattern=None, args=[],
        )
        cmd_test(args)
        out = capsys.readouterr().out
        assert "ASK" in out
        assert "hardcoded API key" in out

    def test_grep_credential_pattern_outside_project(self, capsys):
        from nah.cli import cmd_test
        args = argparse.Namespace(
            tool="Grep", path="/tmp",
            content=None, pattern=r"password\s*=", args=[],
        )
        cmd_test(args)
        out = capsys.readouterr().out
        assert "ASK" in out
        assert "credential" in out.lower()

    def test_grep_safe_pattern(self, capsys):
        from nah.cli import cmd_test
        args = argparse.Namespace(
            tool="Grep", path=".",
            content=None, pattern="TODO", args=[],
        )
        cmd_test(args)
        out = capsys.readouterr().out
        assert "ALLOW" in out

    def test_mcp_unknown_tool(self, capsys):
        from nah.cli import cmd_test
        args = argparse.Namespace(
            tool="mcp__example__tool", path=None,
            content=None, pattern=None, args=[],
        )
        cmd_test(args)
        out = capsys.readouterr().out
        assert "ASK" in out
        assert "unrecognized tool" in out.lower() or "mcp__example__tool" in out

    def test_backward_compat_positional_path(self, capsys):
        from nah.cli import cmd_test
        args = argparse.Namespace(
            tool="Read", path=None,
            content=None, pattern=None, args=["./README.md"],
        )
        cmd_test(args)
        out = capsys.readouterr().out
        assert "ALLOW" in out

    def test_bash_no_args_exits(self):
        from nah.cli import cmd_test
        args = argparse.Namespace(
            tool=None, path=None,
            content=None, pattern=None, config=None, args=[],
        )
        with pytest.raises(SystemExit):
            cmd_test(args)

    def test_config_classify_override(self, capsys):
        """FD-076: --config classify override reclassifies command."""
        from nah.cli import cmd_test
        args = argparse.Namespace(
            tool=None, path=None, content=None, pattern=None,
            config='{"classify": {"git_safe": ["git push --force"]}}',
            args=["git", "push", "--force"],
        )
        cmd_test(args)
        out = capsys.readouterr().out
        assert "ALLOW" in out

    def test_config_action_override(self, capsys):
        """FD-076: --config actions override changes policy."""
        from nah.cli import cmd_test
        args = argparse.Namespace(
            tool=None, path=None, content=None, pattern=None,
            config='{"actions": {"filesystem_delete": "block"}}',
            args=["rm", "foo.txt"],
        )
        cmd_test(args)
        out = capsys.readouterr().out
        assert "BLOCK" in out

    def test_config_profile_none(self, capsys):
        """FD-076: --config profile:none makes everything unknown → ask."""
        from nah.cli import cmd_test
        args = argparse.Namespace(
            tool=None, path=None, content=None, pattern=None,
            config='{"profile": "none"}',
            args=["git", "status"],
        )
        cmd_test(args)
        out = capsys.readouterr().out
        assert "ASK" in out
