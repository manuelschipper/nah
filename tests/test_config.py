"""Tests for config loading and merging (FD-006)."""

import os
from unittest.mock import patch

import pytest

from nah.config import (
    NahConfig,
    get_config,
    reset_config,
    is_path_allowed,
    _merge_configs,
    _load_yaml_file,
)
from nah import paths


class TestDefaults:
    """Config defaults when no YAML files exist."""

    def test_default_config(self, tmp_path):
        """Without any config files, get_config returns sensible defaults."""
        paths.set_project_root(str(tmp_path))
        reset_config()
        with patch("nah.config._GLOBAL_CONFIG", str(tmp_path / "nonexistent.yaml")):
            cfg = get_config()
        assert isinstance(cfg, NahConfig)
        assert cfg.profile == "full"
        assert cfg.classify_global == {}
        assert cfg.classify_project == {}
        assert cfg.actions == {}
        assert cfg.sensitive_paths_default == "ask"
        assert cfg.sensitive_paths == {}
        assert cfg.allow_paths == {}
        assert cfg.known_registries == []

    def test_config_cached(self, tmp_path):
        """get_config returns same instance on second call."""
        paths.set_project_root(str(tmp_path))
        reset_config()
        cfg1 = get_config()
        cfg2 = get_config()
        assert cfg1 is cfg2

    def test_reset_clears_cache(self, tmp_path):
        paths.set_project_root(str(tmp_path))
        reset_config()
        cfg1 = get_config()
        reset_config()
        cfg2 = get_config()
        assert cfg1 is not cfg2


class TestLoadYaml:
    def test_missing_file(self):
        assert _load_yaml_file("/nonexistent/path.yaml") == {}

    def test_valid_yaml(self, tmp_path):
        f = tmp_path / "test.yaml"
        try:
            import yaml
            f.write_text(yaml.dump({"key": "value"}))
            result = _load_yaml_file(str(f))
            assert result == {"key": "value"}
        except ImportError:
            # PyYAML not installed — should return {}
            f.write_text("key: value\n")
            result = _load_yaml_file(str(f))
            assert result == {}

    def test_non_dict_yaml(self, tmp_path):
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")
        f = tmp_path / "test.yaml"
        f.write_text("- item1\n- item2\n")
        assert _load_yaml_file(str(f)) == {}


class TestMergeConfigs:
    """Test config merging rules."""

    def test_empty_merge(self):
        cfg = _merge_configs({}, {})
        assert cfg.classify_global == {}
        assert cfg.classify_project == {}
        assert cfg.actions == {}

    def test_classify_kept_separate(self):
        """Global and project classify are stored separately, not unioned."""
        global_cfg = {"classify": {"package_run": ["just build"]}}
        project_cfg = {"classify": {"package_run": ["task dev"]}}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert cfg.classify_global == {"package_run": ["just build"]}
        assert cfg.classify_project == {"package_run": ["task dev"]}

    def test_actions_tighten_only(self):
        """Project can tighten actions but not loosen."""
        global_cfg = {"actions": {"filesystem_read": "allow", "network_outbound": "ask"}}
        project_cfg = {"actions": {"filesystem_read": "ask", "network_outbound": "allow"}}
        cfg = _merge_configs(global_cfg, project_cfg)
        # filesystem_read: allow → ask (tightened) ✓
        assert cfg.actions["filesystem_read"] == "ask"
        # network_outbound: ask → allow (loosened) — stays at ask
        assert cfg.actions["network_outbound"] == "ask"

    def test_actions_project_adds_new(self):
        """Project can add new action types."""
        global_cfg = {"actions": {}}
        project_cfg = {"actions": {"custom_type": "block"}}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert cfg.actions["custom_type"] == "block"

    def test_sensitive_paths_tighten_only(self):
        """Sensitive paths tighten only per path."""
        global_cfg = {"sensitive_paths": {"~/.custom": "ask"}}
        project_cfg = {"sensitive_paths": {"~/.custom": "block"}}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert cfg.sensitive_paths["~/.custom"] == "block"

    def test_sensitive_paths_no_loosen(self):
        global_cfg = {"sensitive_paths": {"~/.custom": "block"}}
        project_cfg = {"sensitive_paths": {"~/.custom": "ask"}}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert cfg.sensitive_paths["~/.custom"] == "block"

    def test_sensitive_paths_union(self):
        global_cfg = {"sensitive_paths": {"~/.a": "ask"}}
        project_cfg = {"sensitive_paths": {"~/.b": "block"}}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert "~/.a" in cfg.sensitive_paths
        assert "~/.b" in cfg.sensitive_paths

    def test_allow_paths_global_only(self):
        """allow_paths from project config are silently ignored."""
        global_cfg = {"allow_paths": {"~/.aws": ["/home/user/project"]}}
        project_cfg = {"allow_paths": {"~/.ssh": ["/home/user/project"]}}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert "~/.aws" in cfg.allow_paths
        assert "~/.ssh" not in cfg.allow_paths

    def test_known_registries_union(self):
        global_cfg = {"known_registries": ["custom.registry.io"]}
        project_cfg = {"known_registries": ["another.registry.io"]}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert "custom.registry.io" in cfg.known_registries
        assert "another.registry.io" in cfg.known_registries

    def test_known_registries_dedup(self):
        global_cfg = {"known_registries": ["custom.registry.io"]}
        project_cfg = {"known_registries": ["custom.registry.io"]}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert cfg.known_registries.count("custom.registry.io") == 1

    def test_invalid_types_handled(self):
        """Non-dict/non-list values don't crash merge."""
        global_cfg = {"classify": "not a dict", "actions": 42, "known_registries": "string"}
        project_cfg = {"sensitive_paths": None}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert isinstance(cfg, NahConfig)


class TestIsPathAllowed:
    def test_allowed(self, tmp_path):
        """Path in allow_paths for current project root is exempted."""
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        paths.set_project_root(str(project_dir))
        reset_config()

        # Manually set config with allow_paths
        from nah import config
        config._cached_config = NahConfig(
            allow_paths={"~/.aws": [str(project_dir)]},
        )

        assert is_path_allowed("~/.aws", str(project_dir)) is True
        assert is_path_allowed("~/.aws/credentials", str(project_dir)) is True

    def test_not_allowed_wrong_root(self, tmp_path):
        """Path in allow_paths but for different project root."""
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        other_dir = tmp_path / "other"
        other_dir.mkdir()
        paths.set_project_root(str(project_dir))
        reset_config()

        from nah import config
        config._cached_config = NahConfig(
            allow_paths={"~/.aws": [str(other_dir)]},
        )

        assert is_path_allowed("~/.aws", str(project_dir)) is False

    def test_no_project_root(self):
        reset_config()
        assert is_path_allowed("~/.aws", None) is False

    def test_empty_allow_paths(self, tmp_path):
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        paths.set_project_root(str(project_dir))
        reset_config()

        from nah import config
        config._cached_config = NahConfig()
        assert is_path_allowed("~/.aws", str(project_dir)) is False


class TestSensitivePathsDefault:
    def test_global_default(self):
        cfg = _merge_configs({"sensitive_paths_default": "block"}, {})
        assert cfg.sensitive_paths_default == "block"

    def test_project_tightens(self):
        cfg = _merge_configs(
            {"sensitive_paths_default": "ask"},
            {"sensitive_paths_default": "block"},
        )
        assert cfg.sensitive_paths_default == "block"

    def test_project_cannot_loosen(self):
        cfg = _merge_configs(
            {"sensitive_paths_default": "block"},
            {"sensitive_paths_default": "ask"},
        )
        assert cfg.sensitive_paths_default == "block"


class TestProfile:
    """Profile loading and validation."""

    def test_profile_from_global(self):
        cfg = _merge_configs({"profile": "minimal"}, {})
        assert cfg.profile == "minimal"

    def test_profile_none(self):
        cfg = _merge_configs({"profile": "none"}, {})
        assert cfg.profile == "none"

    def test_profile_default_full(self):
        cfg = _merge_configs({}, {})
        assert cfg.profile == "full"

    def test_profile_ignored_in_project(self):
        """Project config cannot set the profile."""
        cfg = _merge_configs({}, {"profile": "none"})
        assert cfg.profile == "full"

    def test_profile_invalid_fallback(self):
        """Invalid profile falls back to 'full'."""
        cfg = _merge_configs({"profile": "turbo"}, {})
        assert cfg.profile == "full"

    def test_profile_global_overrides_project(self):
        """Global profile wins; project profile ignored."""
        cfg = _merge_configs({"profile": "minimal"}, {"profile": "none"})
        assert cfg.profile == "minimal"


class TestLlmMaxDecision:
    """llm.max_decision config loading."""

    def test_llm_max_decision_from_global(self):
        cfg = _merge_configs({"llm": {"max_decision": "ask"}}, {})
        assert cfg.llm_max_decision == "ask"

    def test_llm_max_decision_invalid_ignored(self):
        cfg = _merge_configs({"llm": {"max_decision": "turbo"}}, {})
        assert cfg.llm_max_decision == "ask"  # keeps default

    def test_llm_max_decision_default_ask(self):
        cfg = _merge_configs({}, {})
        assert cfg.llm_max_decision == "ask"


class TestLlmEligible:
    """llm.eligible config loading."""

    def test_default_when_omitted(self):
        cfg = _merge_configs({}, {})
        assert cfg.llm_eligible == "default"

    def test_default_explicit(self):
        cfg = _merge_configs({"llm": {"eligible": "default"}}, {})
        assert cfg.llm_eligible == "default"

    def test_all(self):
        cfg = _merge_configs({"llm": {"eligible": "all"}}, {})
        assert cfg.llm_eligible == "all"

    def test_list(self):
        cfg = _merge_configs({"llm": {"eligible": ["unknown", "composition"]}}, {})
        assert cfg.llm_eligible == ["unknown", "composition"]

    def test_invalid_string_falls_back(self):
        cfg = _merge_configs({"llm": {"eligible": "turbo"}}, {})
        assert cfg.llm_eligible == "default"

    def test_invalid_type_falls_back(self):
        cfg = _merge_configs({"llm": {"eligible": 42}}, {})
        assert cfg.llm_eligible == "default"

    def test_project_config_ignored(self):
        cfg = _merge_configs({}, {"llm": {"eligible": "all"}})
        assert cfg.llm_eligible == "default"  # llm is global-only
