"""Tests for remember.py — config writer (FD-027)."""

import os
from unittest.mock import patch

import pytest

from nah import paths, taxonomy
from nah.config import reset_config
from nah.remember import CustomTypeError


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


class TestWriteAction:
    def test_valid_type_writes(self, patched_paths, global_cfg):
        from nah.remember import write_action, _read_config
        msg = write_action("git_history_rewrite", "allow")
        assert "git_history_rewrite" in msg
        assert "allow" in msg
        data = _read_config(global_cfg)
        assert data["actions"]["git_history_rewrite"] == "allow"

    def test_unknown_type_raises(self, patched_paths):
        from nah.remember import write_action
        with pytest.raises(ValueError, match="Unknown action type"):
            write_action("git_histori_rewritr", "allow")

    def test_unknown_type_suggests(self, patched_paths):
        from nah.remember import write_action
        with pytest.raises(ValueError, match="Did you mean"):
            write_action("git_histori_rewrite", "allow")

    def test_project_loosening_raises(self, patched_paths, global_cfg):
        from nah.remember import write_action
        # Default for git_history_rewrite is 'ask'. Trying to set project to 'allow' should fail.
        with pytest.raises(ValueError, match="cannot loosen"):
            write_action("git_history_rewrite", "allow", project=True)

    def test_project_tightening_ok(self, patched_paths, project_cfg):
        from nah.remember import write_action, _read_config
        msg = write_action("git_history_rewrite", "block", project=True)
        assert "block" in msg
        data = _read_config(project_cfg)
        assert data["actions"]["git_history_rewrite"] == "block"

    def test_duplicate_handling(self, patched_paths, global_cfg):
        from nah.remember import write_action
        write_action("git_history_rewrite", "allow")
        msg = write_action("git_history_rewrite", "allow")
        assert "already" in msg.lower()


class TestWriteAllowPath:
    def test_writes_to_global(self, patched_paths, global_cfg, tmp_path):
        from nah.remember import write_allow_path, _read_config
        msg = write_allow_path("~/.aws/config")
        assert "Allowed" in msg
        data = _read_config(global_cfg)
        assert "allow_paths" in data
        # Check structure: resolved path → [project_root]
        for key, roots in data["allow_paths"].items():
            assert isinstance(roots, list)
            assert str(tmp_path / "project") in roots

    def test_no_project_root_raises(self, global_cfg):
        from nah.remember import write_allow_path
        with patch("nah.remember.get_global_config_path", return_value=global_cfg), \
             patch("nah.remember.get_project_root", return_value=None):
            with pytest.raises(ValueError, match="cannot determine project root"):
                write_allow_path("~/.aws")

    def test_deduplicates(self, patched_paths, global_cfg):
        from nah.remember import write_allow_path
        write_allow_path("~/.aws/config")
        msg = write_allow_path("~/.aws/config")
        assert "Already" in msg


class TestWriteClassify:
    def test_appends_to_list(self, patched_paths, global_cfg):
        from nah.remember import write_classify, _read_config
        msg = write_classify("just", "package_run")
        assert "Classified" in msg
        data = _read_config(global_cfg)
        assert "just" in data["classify"]["package_run"]

    def test_validates_action_type(self, patched_paths):
        from nah.remember import write_classify
        with pytest.raises(CustomTypeError):
            write_classify("just", "invalid_type")

    def test_deduplicates(self, patched_paths):
        from nah.remember import write_classify
        write_classify("just", "package_run")
        msg = write_classify("just", "package_run")
        assert "Already" in msg


class TestWriteTrustHost:
    def test_appends_to_list(self, patched_paths, global_cfg):
        from nah.remember import write_trust_host, _read_config
        msg = write_trust_host("api.example.com")
        assert "Trusted" in msg
        data = _read_config(global_cfg)
        assert "api.example.com" in data["known_registries"]

    def test_deduplicates(self, patched_paths):
        from nah.remember import write_trust_host
        write_trust_host("api.example.com")
        msg = write_trust_host("api.example.com")
        assert "Already" in msg


class TestForgetRule:
    def test_removes_action(self, patched_paths, global_cfg):
        from nah.remember import write_action, forget_rule, _read_config
        write_action("git_history_rewrite", "allow")
        msg = forget_rule("git_history_rewrite")
        assert "Removed" in msg
        data = _read_config(global_cfg)
        assert "actions" not in data or "git_history_rewrite" not in data.get("actions", {})

    def test_removes_classify(self, patched_paths, global_cfg):
        from nah.remember import write_classify, forget_rule, _read_config
        write_classify("just", "package_run")
        msg = forget_rule("just")
        assert "Removed" in msg
        data = _read_config(global_cfg)
        classify = data.get("classify", {})
        assert "just" not in classify.get("package_run", [])

    def test_removes_host(self, patched_paths, global_cfg):
        from nah.remember import write_trust_host, forget_rule, _read_config
        write_trust_host("api.example.com")
        msg = forget_rule("api.example.com")
        assert "Removed" in msg
        data = _read_config(global_cfg)
        assert "api.example.com" not in data.get("known_registries", [])

    def test_not_found_raises(self, patched_paths):
        from nah.remember import forget_rule
        with pytest.raises(ValueError, match="No rule found"):
            forget_rule("nonexistent_thing")

    def test_ambiguous_raises(self, patched_paths):
        from nah.remember import write_action, write_classify, forget_rule
        # Create a rule in actions AND classify with the same name
        write_action("package_run", "allow")
        write_classify("package_run", "package_run")
        with pytest.raises(ValueError, match="Ambiguous"):
            forget_rule("package_run")


class TestValidateActionScope:
    def test_loosening_detected(self, patched_paths):
        from nah.remember import _validate_action_scope
        # Default for git_history_rewrite is 'ask', trying to set 'allow' in project should fail
        with pytest.raises(ValueError, match="cannot loosen"):
            _validate_action_scope("git_history_rewrite", "allow", project=True)

    def test_tightening_ok(self, patched_paths):
        from nah.remember import _validate_action_scope
        # Tightening from 'ask' to 'block' should be fine
        _validate_action_scope("git_history_rewrite", "block", project=True)

    def test_global_always_ok(self, patched_paths):
        from nah.remember import _validate_action_scope
        # Global config can do anything
        _validate_action_scope("git_history_rewrite", "allow", project=False)

    def test_trust_project_config_allows_loosening(self, patched_paths):
        from nah.remember import _validate_action_scope
        from nah import config
        from nah.config import NahConfig
        config._cached_config = NahConfig(trust_project_config=True)
        # With trust_project_config, project loosening is allowed
        _validate_action_scope("git_history_rewrite", "allow", project=True)
        config._cached_config = None


class TestMissingYaml:
    def test_raises_runtime_error(self):
        from nah.remember import _ensure_yaml
        with patch.dict("sys.modules", {"yaml": None}):
            # We need to actually make import fail
            import importlib
            with patch("builtins.__import__", side_effect=ImportError("no yaml")):
                with pytest.raises(RuntimeError, match="PyYAML required"):
                    _ensure_yaml()


class TestCustomTypeError:
    def test_custom_type_raises_custom_error(self, patched_paths):
        from nah.remember import write_action
        with pytest.raises(CustomTypeError):
            write_action("my_custom", "allow")

    def test_typo_still_raises_valueerror(self, patched_paths):
        from nah.remember import write_action
        # Close match → ValueError with suggestion, NOT CustomTypeError
        with pytest.raises(ValueError, match="Did you mean"):
            write_action("git_histori_rewrite", "allow")
        # Verify it's not a CustomTypeError
        with pytest.raises(ValueError) as exc_info:
            write_action("git_histori_rewrite", "allow")
        assert not isinstance(exc_info.value, CustomTypeError)

    def test_allow_custom_bypasses_validation(self, patched_paths, global_cfg):
        from nah.remember import write_action, _read_config
        msg = write_action("my_custom", "allow", allow_custom=True)
        assert "my_custom" in msg
        data = _read_config(global_cfg)
        assert data["actions"]["my_custom"] == "allow"

    def test_classify_custom_type_raises(self, patched_paths):
        from nah.remember import write_classify
        with pytest.raises(CustomTypeError):
            write_classify("mycmd", "my_custom")

    def test_classify_allow_custom(self, patched_paths, global_cfg):
        from nah.remember import write_classify, _read_config
        msg = write_classify("mycmd", "my_custom", allow_custom=True)
        assert "Classified" in msg
        data = _read_config(global_cfg)
        assert "mycmd" in data["classify"]["my_custom"]


class TestHasComments:
    def test_has_comments_true(self, tmp_path):
        from nah.remember import has_comments
        f = tmp_path / "config.yaml"
        f.write_text("# This is a comment\nactions:\n  git_safe: allow\n")
        assert has_comments(str(f)) is True

    def test_has_comments_false(self, tmp_path):
        from nah.remember import has_comments
        f = tmp_path / "config.yaml"
        f.write_text("actions:\n  git_safe: allow\n")
        assert has_comments(str(f)) is False

    def test_has_comments_missing_file(self):
        from nah.remember import has_comments
        assert has_comments("/nonexistent/path/config.yaml") is False

    def test_has_comments_shebang_ignored(self, tmp_path):
        from nah.remember import has_comments
        f = tmp_path / "script.yaml"
        f.write_text("#!/bin/bash\nactions:\n  git_safe: allow\n")
        assert has_comments(str(f)) is False


class TestListRules:
    def test_returns_structured_dict(self, patched_paths):
        from nah.remember import write_action, write_trust_host, list_rules
        write_action("git_history_rewrite", "allow")
        write_trust_host("api.example.com")
        rules = list_rules()
        assert "global" in rules
        assert "project" in rules
        assert rules["global"]["actions"]["git_history_rewrite"] == "allow"
        assert "api.example.com" in rules["global"]["known_registries"]
