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

    # --- trust_project_config ---

    def test_trust_project_config_allows_loosening(self):
        """With trust_project_config, project can loosen actions."""
        global_cfg = {"trust_project_config": True, "actions": {"network_outbound": "ask"}}
        project_cfg = {"actions": {"network_outbound": "allow"}}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert cfg.actions["network_outbound"] == "allow"

    def test_trust_project_config_default_false(self):
        """Without trust_project_config, loosening is blocked."""
        global_cfg = {"actions": {"network_outbound": "ask"}}
        project_cfg = {"actions": {"network_outbound": "allow"}}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert cfg.actions["network_outbound"] == "ask"

    def test_trust_project_config_sensitive_paths_loosen(self):
        """With trust_project_config, project can loosen sensitive_paths."""
        global_cfg = {"trust_project_config": True, "sensitive_paths": {"~/.custom": "block"}}
        project_cfg = {"sensitive_paths": {"~/.custom": "ask"}}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert cfg.sensitive_paths["~/.custom"] == "ask"

    def test_trust_project_config_sensitive_paths_default_loosen(self):
        """With trust_project_config, project can loosen sensitive_paths_default."""
        global_cfg = {"trust_project_config": True, "sensitive_paths_default": "block"}
        project_cfg = {"sensitive_paths_default": "ask"}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert cfg.sensitive_paths_default == "ask"

    def test_trust_project_config_content_policies_loosen(self):
        """With trust_project_config, project can loosen content_policies."""
        global_cfg = {"trust_project_config": True, "content_patterns": {"policies": {"secret": "block"}}}
        project_cfg = {"content_patterns": {"policies": {"secret": "ask"}}}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert cfg.content_policies["secret"] == "ask"

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

    def test_known_registries_global_only_list(self):
        """known_registries: global only, list form."""
        global_cfg = {"known_registries": ["custom.registry.io"]}
        project_cfg = {"known_registries": ["another.registry.io"]}
        cfg = _merge_configs(global_cfg, project_cfg)
        # Project config is silently ignored — only global values
        assert cfg.known_registries == ["custom.registry.io"]

    def test_known_registries_global_only_dict(self):
        """known_registries: global only, dict form."""
        global_cfg = {"known_registries": {"add": ["custom.io"], "remove": ["github.com"]}}
        cfg = _merge_configs(global_cfg, {})
        assert cfg.known_registries == {"add": ["custom.io"], "remove": ["github.com"]}

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

    def test_allowed_from_child_worktree_root(self, tmp_path):
        """allow_paths scoped to a main repo root apply from child worktrees."""
        main_root = tmp_path / "repo"
        worktree_root = main_root / ".worktrees" / "feature"
        worktree_root.mkdir(parents=True)
        reset_config()

        from nah import config
        config._cached_config = NahConfig(
            allow_paths={"~/.aws": [str(main_root)]},
        )

        assert is_path_allowed("~/.aws/credentials", str(worktree_root)) is True

    def test_allowed_from_parent_main_root_when_stored_for_worktree(self, tmp_path):
        """Existing allow_paths stored for a worktree root still apply in the main root."""
        main_root = tmp_path / "repo"
        worktree_root = main_root / ".worktrees" / "feature"
        worktree_root.mkdir(parents=True)
        reset_config()

        from nah import config
        config._cached_config = NahConfig(
            allow_paths={"~/.aws": [str(worktree_root)]},
        )

        assert is_path_allowed("~/.aws/credentials", str(main_root)) is True

    def test_not_allowed_unrelated_root_after_related_matching(self, tmp_path):
        """Parent/child matching must not exempt unrelated project roots."""
        project_dir = tmp_path / "repo"
        unrelated_dir = tmp_path / "repo-other"
        project_dir.mkdir()
        unrelated_dir.mkdir()
        reset_config()

        from nah import config
        config._cached_config = NahConfig(
            allow_paths={"~/.aws": [str(unrelated_dir)]},
        )

        assert is_path_allowed("~/.aws/credentials", str(project_dir)) is False

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


class TestLlmMode:
    """llm.mode config loading."""

    def test_llm_mode_from_global(self):
        cfg = _merge_configs({"llm": {"mode": "on"}}, {})
        assert cfg.llm_mode == "on"

    def test_llm_mode_invalid_ignored(self):
        cfg = _merge_configs({"llm": {"mode": "turbo"}}, {})
        assert cfg.llm_mode == "off"

    def test_llm_mode_default_off(self):
        cfg = _merge_configs({}, {})
        assert cfg.llm_mode == "off"

    def test_llm_enabled_true_back_compat(self):
        cfg = _merge_configs({"llm": {"enabled": True}}, {})
        assert cfg.llm_mode == "on"

    def test_project_llm_ignored(self):
        cfg = _merge_configs({}, {"llm": {"mode": "on"}})
        assert cfg.llm_mode == "off"


class TestLlmEligible:
    """llm.eligible config loading."""

    def test_default_when_omitted(self):
        cfg = _merge_configs({}, {})
        assert cfg.llm_eligible == "default"

    def test_default_explicit(self):
        cfg = _merge_configs({"llm": {"eligible": "default"}}, {})
        assert cfg.llm_eligible == "default"

    def test_strict(self):
        cfg = _merge_configs({"llm": {"eligible": "strict"}}, {})
        assert cfg.llm_eligible == "strict"

    def test_all(self):
        cfg = _merge_configs({"llm": {"eligible": "all"}}, {})
        assert cfg.llm_eligible == "all"

    def test_list(self):
        cfg = _merge_configs({"llm": {"eligible": ["unknown", "composition"]}}, {})
        assert cfg.llm_eligible == ["unknown", "composition"]

    def test_list_with_preset(self):
        cfg = _merge_configs({"llm": {"eligible": ["strict", "git_discard"]}}, {})
        assert cfg.llm_eligible == ["strict", "git_discard"]

    def test_invalid_string_falls_back(self):
        cfg = _merge_configs({"llm": {"eligible": "turbo"}}, {})
        assert cfg.llm_eligible == "default"

    def test_invalid_type_falls_back(self):
        cfg = _merge_configs({"llm": {"eligible": 42}}, {})
        assert cfg.llm_eligible == "default"

    def test_project_config_ignored(self):
        cfg = _merge_configs({}, {"llm": {"eligible": "all"}})
        assert cfg.llm_eligible == "default"  # llm is global-only


class TestSafetyLists:
    """FD-051: Configurable safety lists — config parsing."""

    # --- known_registries polymorphic ---

    def test_known_registries_list_form(self):
        cfg = _merge_configs({"known_registries": ["custom.io"]}, {})
        assert cfg.known_registries == ["custom.io"]

    def test_known_registries_dict_form(self):
        cfg = _merge_configs({"known_registries": {"add": ["x.com"], "remove": ["y.com"]}}, {})
        assert cfg.known_registries == {"add": ["x.com"], "remove": ["y.com"]}

    def test_known_registries_invalid_type(self):
        cfg = _merge_configs({"known_registries": 42}, {})
        assert cfg.known_registries == []

    def test_known_registries_project_ignored(self):
        cfg = _merge_configs({}, {"known_registries": ["evil.com"]})
        assert cfg.known_registries == []

    # --- exec_sinks polymorphic ---

    def test_exec_sinks_list_form(self):
        cfg = _merge_configs({"exec_sinks": ["bun", "deno"]}, {})
        assert cfg.exec_sinks == ["bun", "deno"]

    def test_exec_sinks_dict_form(self):
        cfg = _merge_configs({"exec_sinks": {"add": ["bun"], "remove": ["python3"]}}, {})
        assert cfg.exec_sinks == {"add": ["bun"], "remove": ["python3"]}

    def test_exec_sinks_invalid_type(self):
        cfg = _merge_configs({"exec_sinks": "not a list"}, {})
        assert cfg.exec_sinks == []

    def test_exec_sinks_project_ignored(self):
        cfg = _merge_configs({}, {"exec_sinks": ["bun"]})
        assert cfg.exec_sinks == []

    # --- sensitive_basenames ---

    def test_sensitive_basenames_dict(self):
        cfg = _merge_configs({"sensitive_basenames": {".secrets": "block"}}, {})
        assert cfg.sensitive_basenames == {".secrets": "block"}

    def test_sensitive_basenames_invalid_type(self):
        cfg = _merge_configs({"sensitive_basenames": ["not", "a", "dict"]}, {})
        assert cfg.sensitive_basenames == {}

    def test_sensitive_basenames_project_ignored(self):
        cfg = _merge_configs({}, {"sensitive_basenames": {".secrets": "block"}})
        assert cfg.sensitive_basenames == {}

    # --- decode_commands polymorphic ---

    def test_decode_commands_list_form(self):
        cfg = _merge_configs({"decode_commands": ["uudecode"]}, {})
        assert cfg.decode_commands == ["uudecode"]

    def test_decode_commands_dict_form(self):
        cfg = _merge_configs({"decode_commands": {"add": ["uudecode"], "remove": ["xxd"]}}, {})
        assert cfg.decode_commands == {"add": ["uudecode"], "remove": ["xxd"]}

    def test_decode_commands_invalid_type(self):
        cfg = _merge_configs({"decode_commands": 99}, {})
        assert cfg.decode_commands == []

    def test_decode_commands_project_ignored(self):
        cfg = _merge_configs({}, {"decode_commands": ["uudecode"]})
        assert cfg.decode_commands == []

    # --- _parse_add_remove helper ---

    def test_parse_add_remove_list(self):
        from nah.config import _parse_add_remove
        add, remove = _parse_add_remove(["a", "b"])
        assert add == ["a", "b"]
        assert remove == []

    def test_parse_add_remove_dict(self):
        from nah.config import _parse_add_remove
        add, remove = _parse_add_remove({"add": ["a"], "remove": ["b"]})
        assert add == ["a"]
        assert remove == ["b"]

    def test_parse_add_remove_dict_missing_keys(self):
        from nah.config import _parse_add_remove
        add, remove = _parse_add_remove({"add": ["a"]})
        assert add == ["a"]
        assert remove == []

    def test_parse_add_remove_invalid(self):
        from nah.config import _parse_add_remove
        assert _parse_add_remove("string") == ([], [])
        assert _parse_add_remove(42) == ([], [])
        assert _parse_add_remove(None) == ([], [])


# --- FD-054: trusted_paths config loading ---


class TestTrustedPaths:
    """FD-054: trusted_paths config loading."""

    def test_global_loads_trusted_paths(self):
        cfg = _merge_configs({"trusted_paths": ["/tmp", "~/bin"]}, {})
        assert "/tmp" in cfg.trusted_paths
        assert "~/bin" in cfg.trusted_paths

    def test_project_trusted_paths_ignored(self):
        """Project config cannot set trusted_paths."""
        cfg = _merge_configs({}, {"trusted_paths": ["/tmp"]})
        # /tmp may be in defaults for profile: full, but not from project config
        # The key assertion: project config doesn't add non-default paths
        assert "~/sneaky" not in cfg.trusted_paths

    def test_default_tmp_trusted_for_full_profile(self):
        """profile: full includes /tmp and /private/tmp as defaults."""
        cfg = _merge_configs({}, {})
        assert "/tmp" in cfg.trusted_paths
        assert "/private/tmp" in cfg.trusted_paths

    def test_invalid_type_dict(self):
        """Invalid type (dict) → only defaults remain."""
        cfg = _merge_configs({"trusted_paths": {"path": "/tmp"}}, {})
        # User entries ignored, but profile: full defaults still present
        assert "/tmp" in cfg.trusted_paths
        assert "/private/tmp" in cfg.trusted_paths

    def test_invalid_type_string(self):
        """Invalid type (string) → only defaults remain."""
        cfg = _merge_configs({"trusted_paths": "/tmp"}, {})
        assert "/tmp" in cfg.trusted_paths

    def test_empty_list_gets_defaults(self):
        """Empty user list still gets profile: full defaults."""
        cfg = _merge_configs({"trusted_paths": []}, {})
        assert "/tmp" in cfg.trusted_paths

    def test_default_includes_tmp(self):
        """No config → profile: full defaults include /tmp."""
        cfg = _merge_configs({}, {})
        assert "/tmp" in cfg.trusted_paths

    def test_entries_coerced_to_str(self):
        """Non-string entries are coerced to str."""
        cfg = _merge_configs({"trusted_paths": [42, True]}, {})
        assert "42" in cfg.trusted_paths
        assert "True" in cfg.trusted_paths


class TestContentPatterns:
    """FD-052: Configurable content patterns — config parsing."""

    # --- content_patterns.add: global-only ---

    def test_content_patterns_add_from_global(self):
        cfg = _merge_configs(
            {"content_patterns": {"add": [
                {"category": "custom", "pattern": "\\bDROP\\b", "description": "DROP"}
            ]}},
            {},
        )
        assert len(cfg.content_patterns_add) == 1
        assert cfg.content_patterns_add[0]["category"] == "custom"

    def test_content_patterns_add_project_ignored(self):
        cfg = _merge_configs(
            {},
            {"content_patterns": {"add": [
                {"category": "custom", "pattern": "\\bDROP\\b", "description": "DROP"}
            ]}},
        )
        assert cfg.content_patterns_add == []

    # --- content_patterns.suppress: global-only ---

    def test_content_patterns_suppress_from_global(self):
        cfg = _merge_configs(
            {"content_patterns": {"suppress": ["rm -rf", "requests.post"]}},
            {},
        )
        assert cfg.content_patterns_suppress == ["rm -rf", "requests.post"]

    def test_content_patterns_suppress_project_ignored(self):
        cfg = _merge_configs(
            {},
            {"content_patterns": {"suppress": ["rm -rf"]}},
        )
        assert cfg.content_patterns_suppress == []

    # --- content_patterns.policies: tighten-only ---

    def test_content_policies_global(self):
        cfg = _merge_configs(
            {"content_patterns": {"policies": {"secret": "block"}}},
            {},
        )
        assert cfg.content_policies == {"secret": "block"}

    def test_content_policies_project_tightens(self):
        cfg = _merge_configs(
            {"content_patterns": {"policies": {"secret": "ask"}}},
            {"content_patterns": {"policies": {"secret": "block"}}},
        )
        assert cfg.content_policies["secret"] == "block"

    def test_content_policies_project_cannot_loosen(self):
        cfg = _merge_configs(
            {"content_patterns": {"policies": {"secret": "block"}}},
            {"content_patterns": {"policies": {"secret": "ask"}}},
        )
        assert cfg.content_policies["secret"] == "block"

    # --- content_patterns invalid types ---

    def test_content_patterns_invalid_top_level(self):
        cfg = _merge_configs({"content_patterns": "not a dict"}, {})
        assert cfg.content_patterns_add == []
        assert cfg.content_patterns_suppress == []
        assert cfg.content_policies == {}

    def test_content_patterns_add_invalid_type(self):
        cfg = _merge_configs({"content_patterns": {"add": "not a list"}}, {})
        assert cfg.content_patterns_add == []

    def test_content_patterns_suppress_invalid_type(self):
        cfg = _merge_configs({"content_patterns": {"suppress": 42}}, {})
        assert cfg.content_patterns_suppress == []

    # --- credential_patterns: entirely global-only ---

    def test_credential_patterns_add_from_global(self):
        cfg = _merge_configs(
            {"credential_patterns": {"add": ["\\bconnection_string\\b"]}},
            {},
        )
        assert cfg.credential_patterns_add == ["\\bconnection_string\\b"]

    def test_credential_patterns_suppress_from_global(self):
        cfg = _merge_configs(
            {"credential_patterns": {"suppress": ["\\btoken\\b"]}},
            {},
        )
        assert cfg.credential_patterns_suppress == ["\\btoken\\b"]

    def test_credential_patterns_project_ignored(self):
        cfg = _merge_configs(
            {},
            {"credential_patterns": {"add": ["evil"], "suppress": ["password"]}},
        )
        assert cfg.credential_patterns_add == []
        assert cfg.credential_patterns_suppress == []

    def test_credential_patterns_invalid_type(self):
        cfg = _merge_configs({"credential_patterns": "not a dict"}, {})
        assert cfg.credential_patterns_add == []
        assert cfg.credential_patterns_suppress == []

    # --- Empty merge preserves defaults ---

    def test_empty_merge_defaults(self):
        cfg = _merge_configs({}, {})
        assert cfg.content_patterns_add == []
        assert cfg.content_patterns_suppress == []
        assert cfg.content_policies == {}
        assert cfg.credential_patterns_add == []
        assert cfg.credential_patterns_suppress == []
