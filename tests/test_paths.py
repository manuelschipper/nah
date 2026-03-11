"""Unit tests for nah.paths — path resolution, sensitive checks, project root."""

import os
from unittest.mock import patch

import pytest

from nah import paths
from nah.config import NahConfig


# --- resolve_path ---


class TestResolvePath:
    def test_tilde_expansion(self):
        result = paths.resolve_path("~/file.txt")
        assert result.startswith("/")
        assert "~" not in result

    def test_relative_path(self):
        result = paths.resolve_path("./file.txt")
        assert os.path.isabs(result)

    def test_absolute_path(self):
        assert paths.resolve_path("/usr/bin/env") == os.path.realpath("/usr/bin/env")

    def test_empty(self):
        assert paths.resolve_path("") == ""


# --- friendly_path ---


class TestFriendlyPath:
    def test_home_prefix(self):
        home = os.path.expanduser("~")
        assert paths.friendly_path(home + "/file.txt") == "~/file.txt"

    def test_home_exact(self):
        home = os.path.expanduser("~")
        assert paths.friendly_path(home) == "~"

    def test_non_home(self):
        assert paths.friendly_path("/usr/bin/env") == "/usr/bin/env"


# --- is_hook_path ---


class TestIsHookPath:
    def test_exact_hooks_dir(self):
        hooks = os.path.realpath(os.path.join(os.path.expanduser("~"), ".claude", "hooks"))
        assert paths.is_hook_path(hooks) is True

    def test_child_of_hooks(self):
        hooks = os.path.realpath(os.path.join(os.path.expanduser("~"), ".claude", "hooks"))
        assert paths.is_hook_path(hooks + "/nah_guard.py") is True

    def test_not_hooks(self):
        assert paths.is_hook_path("/tmp/something") is False

    def test_claude_but_not_hooks(self):
        claude = os.path.realpath(os.path.join(os.path.expanduser("~"), ".claude"))
        assert paths.is_hook_path(claude + "/settings.json") is False

    def test_empty(self):
        assert paths.is_hook_path("") is False


# --- is_sensitive ---


class TestIsSensitive:
    def test_ssh_block(self):
        resolved = paths.resolve_path("~/.ssh/id_rsa")
        matched, pattern, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert pattern == "~/.ssh"
        assert policy == "block"

    def test_gnupg_block(self):
        resolved = paths.resolve_path("~/.gnupg/key")
        matched, _, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert policy == "block"

    def test_git_credentials_block(self):
        resolved = paths.resolve_path("~/.git-credentials")
        matched, _, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert policy == "block"

    def test_netrc_block(self):
        resolved = paths.resolve_path("~/.netrc")
        matched, _, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert policy == "block"

    def test_aws_ask(self):
        resolved = paths.resolve_path("~/.aws/credentials")
        matched, _, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert policy == "ask"

    def test_gcloud_ask(self):
        resolved = paths.resolve_path("~/.config/gcloud/credentials.json")
        matched, _, policy = paths.is_sensitive(resolved)
        assert matched is True
        assert policy == "ask"

    def test_env_basename(self):
        matched, pattern, policy = paths.is_sensitive("/project/.env")
        assert matched is True
        assert pattern == ".env"
        assert policy == "ask"

    def test_env_local_not_matched(self):
        matched, _, _ = paths.is_sensitive("/project/.env.local")
        assert matched is False

    def test_normal_path(self):
        matched, _, _ = paths.is_sensitive("/tmp/normal.txt")
        assert matched is False

    def test_empty(self):
        matched, _, _ = paths.is_sensitive("")
        assert matched is False


# --- check_path ---


class TestCheckPath:
    def setup_method(self):
        paths._sensitive_paths_merged = True  # isolate from live config

    def test_hook_block_for_write(self):
        result = paths.check_path("Write", "~/.claude/hooks/evil.py")
        assert result is not None
        assert result["decision"] == "block"
        assert "self-modification" in result["reason"]

    def test_hook_block_for_edit(self):
        result = paths.check_path("Edit", "~/.claude/hooks/nah_guard.py")
        assert result is not None
        assert result["decision"] == "block"

    def test_hook_ask_for_read(self):
        result = paths.check_path("Read", "~/.claude/hooks/nah_guard.py")
        assert result is not None
        assert result["decision"] == "ask"
        assert "hook directory" in result["reason"]

    def test_hook_ask_for_bash(self):
        result = paths.check_path("Bash", "~/.claude/hooks/")
        assert result is not None
        assert result["decision"] == "ask"

    def test_sensitive_block(self):
        result = paths.check_path("Read", "~/.ssh/id_rsa")
        assert result is not None
        assert result["decision"] == "block"
        assert "~/.ssh" in result["reason"]

    def test_sensitive_ask(self):
        result = paths.check_path("Read", "~/.aws/credentials")
        assert result is not None
        assert result["decision"] == "ask"

    def test_clean_path(self):
        result = paths.check_path("Read", "/tmp/safe.txt")
        assert result is None

    def test_empty_path(self):
        assert paths.check_path("Read", "") is None


# --- set/reset/get project root ---


class TestProjectRoot:
    def test_set_and_get(self):
        paths.set_project_root("/fake/project")
        assert paths.get_project_root() == "/fake/project"

    def test_reset_clears(self):
        paths.set_project_root("/fake/project")
        paths.reset_project_root()
        # After reset, get_project_root will auto-detect (via git).
        # We can't assert a specific value, but we can verify it doesn't
        # return the old value if we reset and set again.
        paths.set_project_root("/other/project")
        assert paths.get_project_root() == "/other/project"

    def test_autouse_fixture_resets(self):
        # This test runs after the autouse _reset_paths fixture,
        # so any previous set_project_root should be cleared.
        # We just verify set/get works from a clean state.
        paths.set_project_root("/test/root")
        assert paths.get_project_root() == "/test/root"


# --- sensitive path config override ---


class TestSensitivePathConfigOverride:
    """FD-025: Verify config can override hardcoded sensitive path policies."""

    def _mock_config(self, sensitive_paths):
        return NahConfig(sensitive_paths=sensitive_paths)

    def test_override_ssh_block_to_ask(self):
        """Global config can relax ~/.ssh from block to ask."""
        with patch("nah.config.get_config", return_value=self._mock_config({"~/.ssh": "ask"})):
            paths.reset_sensitive_paths()
            result = paths.check_path("Read", "~/.ssh/id_rsa")
        assert result is not None
        assert result["decision"] == "ask"

    def test_unoverridden_path_keeps_default(self):
        """Paths not in config keep their hardcoded policy."""
        with patch("nah.config.get_config", return_value=self._mock_config({"~/.ssh": "ask"})):
            paths.reset_sensitive_paths()
            result = paths.check_path("Read", "~/.gnupg/key")
        assert result is not None
        assert result["decision"] == "block"

    def test_add_new_sensitive_path(self):
        """Config can add entirely new sensitive paths."""
        with patch("nah.config.get_config", return_value=self._mock_config({"~/.kube": "ask"})):
            paths.reset_sensitive_paths()
            result = paths.check_path("Read", "~/.kube/config")
        assert result is not None
        assert result["decision"] == "ask"

    def test_hook_path_immutable(self):
        """~/.claude/hooks stays blocked regardless of config."""
        with patch("nah.config.get_config", return_value=self._mock_config({})):
            paths.reset_sensitive_paths()
            result = paths.check_path("Edit", "~/.claude/hooks/nah_guard.py")
        assert result is not None
        assert result["decision"] == "block"
        assert "self-modification" in result["reason"]

    def test_merge_happens_once(self):
        """Merge is lazy and only runs once per lifecycle."""
        cfg = self._mock_config({"~/.ssh": "ask"})
        with patch("nah.config.get_config", return_value=cfg):
            paths.reset_sensitive_paths()
            paths._ensure_sensitive_paths_merged()
            assert paths._sensitive_paths_merged is True
            # Calling again should not re-merge (flag stays True)
            paths._ensure_sensitive_paths_merged()
            assert paths._sensitive_paths_merged is True
