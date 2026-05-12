"""Tests for config loading and merging (FD-006)."""

import os
from unittest.mock import patch

import pytest

from nah.config import (
    NahConfig,
    apply_override,
    get_config,
    reset_config,
    use_defaults,
    is_path_allowed,
    _merge_configs,
    _load_yaml_file,
    _is_project_config_trusted,
)
from nah import paths
from nah.platform_paths import nah_config_dir


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
        assert cfg.ui == {}
        assert cfg.ui_color == "auto"
        assert cfg.project_root == str(tmp_path)
        assert cfg.project_config_trusted is False
        assert cfg.trusted_project_configs == []
        assert cfg.taint["mode"] == "off"
        assert cfg.taint["inherit_sensitive_paths"] is True

    def test_windows_global_config_dir_uses_appdata(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setenv("APPDATA", r"C:\Users\test\AppData\Roaming")
        result = nah_config_dir()
        assert result.startswith(r"C:\Users\test\AppData\Roaming")
        assert result.endswith("nah")

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

    def test_apply_override_can_disable_llm_mode(self, tmp_path):
        paths.set_project_root(str(tmp_path))
        reset_config()
        apply_override({"llm": {"mode": "on", "providers": ["ollama"]}})
        assert get_config().llm_mode == "on"
        apply_override({"llm_mode": "off", "llm": {}})
        assert get_config().llm_mode == "off"
        assert get_config().llm == {}

    def test_apply_override_accepts_boolean_llm_mode(self, tmp_path):
        paths.set_project_root(str(tmp_path))
        reset_config()
        apply_override({"llm": {"mode": True, "providers": ["ollama"]}})
        assert get_config().llm_mode == "on"
        apply_override({"llm_mode": False, "llm": {}})
        assert get_config().llm_mode == "off"

    def test_apply_override_can_set_ui_color(self, tmp_path):
        paths.set_project_root(str(tmp_path))
        reset_config()
        apply_override({"ui": {"color": "always"}})
        assert get_config().ui_color == "always"
        apply_override({"ui_color": "never"})
        assert get_config().ui_color == "never"

    def test_apply_override_minimal_profile_deprecated_to_full(self, tmp_path, capsys):
        paths.set_project_root(str(tmp_path))
        reset_config()
        with patch("nah.config._GLOBAL_CONFIG", str(tmp_path / "nonexistent.yaml")):
            apply_override({"profile": "minimal"})
        assert get_config().profile == "full"
        assert "profile 'minimal' is deprecated" in capsys.readouterr().err

    def test_apply_override_invalid_profile_preserves_current_profile(self, capsys):
        from nah import config
        try:
            config._cached_config = NahConfig(profile="none")
            config._cached_target = None
            apply_override({"profile": "turbo"})
            assert get_config().profile == "none"
            assert capsys.readouterr().err == ""
        finally:
            reset_config()

    def test_apply_override_trusted_project_configs_enables_project_classify(self, tmp_path):
        paths.set_project_root(str(tmp_path))
        (tmp_path / ".nah.yaml").write_text(
            "classify:\n  db_read:\n    - inspect-db\n",
            encoding="utf-8",
        )
        reset_config()
        with patch("nah.config._GLOBAL_CONFIG", str(tmp_path / "nonexistent.yaml")):
            apply_override({"trusted_project_configs": [str(tmp_path)]})
            cfg = get_config()
        assert cfg.project_config_trusted is True
        assert cfg.classify_project == {"db_read": ["inspect-db"]}

    def test_use_defaults_ignores_cached_custom_config(self, tmp_path):
        """use_defaults replaces any active config with merged packaged defaults."""
        paths.set_project_root(str(tmp_path))
        reset_config()
        from nah import config
        try:
            config._cached_config = NahConfig(
                profile="none",
                actions={"git_safe": "block"},
                trusted_paths=["/custom"],
            )
            use_defaults()
            cfg = get_config()
            assert cfg.profile == "full"
            assert cfg.actions == {}
            assert "/tmp" in cfg.trusted_paths
            assert "/private/tmp" in cfg.trusted_paths
            assert "/custom" not in cfg.trusted_paths
        finally:
            reset_config()

    def test_get_config_loads_non_git_cwd_project_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".nah.yaml").write_text("actions:\n  package_run: block\n")
        paths.reset_project_root()
        reset_config()
        with patch("nah.config._GLOBAL_CONFIG", str(tmp_path / "missing-global.yaml")):
            cfg = get_config()
        assert cfg.project_root == str(tmp_path)
        assert cfg.project_config_path == str(tmp_path / ".nah.yaml")
        assert cfg.actions["package_run"] == "block"

    def test_get_config_without_non_git_project_file_has_no_project_root(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        paths.reset_project_root()
        reset_config()
        with patch("nah.config._GLOBAL_CONFIG", str(tmp_path / "missing-global.yaml")):
            cfg = get_config()
        assert cfg.project_root == ""
        assert cfg.project_config_path == ""

    def test_trusted_project_configs_exact_root_only(self, tmp_path):
        parent = tmp_path / "workspace"
        child = parent / "child"
        child.mkdir(parents=True)
        global_cfg = {"trusted_project_configs": [str(parent)]}
        assert _is_project_config_trusted(str(parent), global_cfg) is True
        assert _is_project_config_trusted(str(child), global_cfg) is False
        cfg = _merge_configs(
            global_cfg,
            {"actions": {"network_outbound": "allow"}},
            project_root=str(child),
            project_config_path=str(child / ".nah.yaml"),
            project_config_trusted=False,
        )
        assert cfg.project_config_trusted is False
        assert cfg.actions.get("network_outbound") != "allow"

    def test_use_defaults_resets_lazy_content_cache(self, tmp_path):
        """use_defaults clears lazy caches already merged from a custom config."""
        paths.set_project_root(str(tmp_path))
        reset_config()
        from nah import config
        from nah.content import reset_content_patterns, scan_content
        try:
            config._cached_config = NahConfig(profile="none")
            reset_content_patterns()
            assert scan_content("api_secret = 'hunter2hunter2'") == []

            use_defaults()
            assert scan_content("api_secret = 'hunter2hunter2'")
        finally:
            reset_content_patterns()
            reset_config()


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
        assert cfg.taint["mode"] == "off"

    def test_taint_config_parses_defaults_when_enabled(self):
        cfg = _merge_configs({"taint": {"mode": "audit"}} , {})
        assert cfg.taint["mode"] == "audit"
        assert cfg.taint["inherit_sensitive_paths"] is True
        assert cfg.taint["propagation"]["filesystem_write"] is True
        assert cfg.taint["policies"]["default"]["boundary"] == "ask"

    def test_taint_rejects_propagate_policy(self, capsys):
        cfg = _merge_configs(
            {"taint": {"mode": "audit", "policies": {"secret": {"boundary": "propagate"}}}},
            {},
        )
        assert "boundary" not in cfg.taint["policies"].get("secret", {})
        assert "cannot be 'propagate'" in capsys.readouterr().err

    def test_taint_rejects_custom_propagation_targets(self, capsys):
        cfg = _merge_configs(
            {"taint": {"mode": "audit", "propagation": {"mytool_write": True}}},
            {},
        )
        assert "mytool_write" not in cfg.taint["propagation"]
        assert "not supported in v1" in capsys.readouterr().err

    def test_taint_custom_actions_are_category_sinks(self):
        cfg = _merge_configs(
            {
                "taint": {
                    "mode": "audit",
                    "categories": {"boundary": {"add": ["service_write"]}},
                }
            },
            {},
        )
        assert "service_write" in cfg.taint["categories"]["boundary"]["add"]

    def test_untrusted_project_cannot_disable_taint_but_can_tighten_policy(self):
        cfg = _merge_configs(
            {"taint": {"mode": "enforce", "inherit_sensitive_paths": True}},
            {
                "taint": {
                    "mode": "off",
                    "inherit_sensitive_paths": False,
                    "policies": {"default": {"boundary": "block"}},
                }
            },
            project_config_trusted=False,
        )
        assert cfg.taint["mode"] == "enforce"
        assert cfg.taint["inherit_sensitive_paths"] is True
        assert cfg.taint["policies"]["default"]["boundary"] == "block"

    def test_trusted_project_can_add_taint_sources(self):
        cfg = _merge_configs(
            {"taint": {"mode": "audit"}},
            {"taint": {"sources": [{"paths": ["client/**"], "labels": ["client"]}]}},
            project_config_trusted=True,
        )
        assert {"paths": ["client/**"], "labels": ["client"]} in cfg.taint["sources"]

    def test_trusted_project_still_cannot_change_global_taint_mode(self):
        cfg = _merge_configs(
            {"taint": {"mode": "enforce", "inherit_sensitive_paths": True}},
            {"taint": {"mode": "off", "inherit_sensitive_paths": False}},
            project_config_trusted=True,
        )
        assert cfg.taint["mode"] == "enforce"
        assert cfg.taint["inherit_sensitive_paths"] is True

    def test_untrusted_project_classify_ignored(self):
        """Project classify is ignored before the project config root is trusted."""
        global_cfg = {"classify": {"package_run": ["just build"]}}
        project_cfg = {"classify": {"package_run": ["task dev"]}}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert cfg.classify_global == {"package_run": ["just build"]}
        assert cfg.classify_project == {}

    def test_trusted_project_classify_kept_separate(self):
        """Trusted project classify is stored separately, not unioned."""
        global_cfg = {"classify": {"package_run": ["just build"]}}
        project_cfg = {"classify": {"package_run": ["task dev"]}}
        cfg = _merge_configs(global_cfg, project_cfg, project_config_trusted=True)
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

    def test_target_actions_apply(self):
        global_cfg = {
            "actions": {"network_outbound": "context"},
            "targets": {"bash": {"actions": {"network_outbound": "ask"}}},
        }
        cfg = _merge_configs(global_cfg, {}, target="bash")
        assert cfg.target == "bash"
        assert cfg.actions["network_outbound"] == "ask"

    def test_project_target_cannot_loosen(self):
        global_cfg = {"targets": {"bash": {"actions": {"network_outbound": "ask"}}}}
        project_cfg = {"targets": {"bash": {"actions": {"network_outbound": "allow"}}}}
        cfg = _merge_configs(global_cfg, project_cfg, target="bash")
        assert cfg.actions["network_outbound"] == "ask"

    def test_trusted_project_target_can_loosen(self):
        global_cfg = {
            "targets": {"bash": {"actions": {"network_outbound": "ask"}}},
        }
        project_cfg = {"targets": {"bash": {"actions": {"network_outbound": "allow"}}}}
        cfg = _merge_configs(global_cfg, project_cfg, target="bash", project_config_trusted=True)
        assert cfg.actions["network_outbound"] == "allow"

    def test_terminal_targets_default_llm_off(self):
        global_cfg = {
            "llm": {
                "mode": "on",
                "providers": ["openrouter"],
                "openrouter": {"key_env": "OPENROUTER_API_KEY"},
            }
        }
        assert _merge_configs(global_cfg, {}, target="claude").llm_mode == "on"
        assert _merge_configs(global_cfg, {}, target="bash").llm_mode == "off"

    def test_terminal_target_can_enable_llm_explicitly(self):
        global_cfg = {
            "llm": {"mode": "on", "providers": ["openrouter"]},
            "targets": {"bash": {"llm": {"mode": "on"}}},
        }
        cfg = _merge_configs(global_cfg, {}, target="bash")
        assert cfg.llm_mode == "on"

    def test_terminal_target_accepts_boolean_llm_mode(self):
        global_cfg = {
            "llm": {"mode": True, "providers": ["openrouter"]},
            "targets": {"bash": {"llm": {"mode": True}}},
        }
        cfg = _merge_configs(global_cfg, {}, target="bash")
        assert cfg.llm_mode == "on"

    def test_untrusted_project_target_cannot_enable_terminal_llm(self):
        global_cfg = {"llm": {"mode": "on", "providers": ["openrouter"]}}
        project_cfg = {"targets": {"bash": {"llm": {"mode": "on"}}}}
        cfg = _merge_configs(global_cfg, project_cfg, target="bash")
        assert cfg.llm_mode == "off"

    def test_trusted_project_target_can_enable_terminal_llm(self):
        global_cfg = {
            "llm": {"mode": "on", "providers": ["openrouter"]},
        }
        project_cfg = {"targets": {"bash": {"llm": {"mode": "on"}}}}
        cfg = _merge_configs(global_cfg, project_cfg, target="bash", project_config_trusted=True)
        assert cfg.llm_mode == "on"

    def test_target_terminal_options_apply(self):
        global_cfg = {"targets": {"bash": {"terminal": {"bypass_env": "CUSTOM_BYPASS"}}}}
        cfg = _merge_configs(global_cfg, {}, target="bash")
        assert cfg.terminal["bypass_env"] == "CUSTOM_BYPASS"

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

    def test_untrusted_project_target_cannot_change_terminal_options(self):
        global_cfg = {"targets": {"bash": {"terminal": {"bypass_env": "GLOBAL_BYPASS"}}}}
        project_cfg = {"targets": {"bash": {"terminal": {"bypass_env": "PROJECT_BYPASS"}}}}
        cfg = _merge_configs(global_cfg, project_cfg, target="bash")
        assert cfg.terminal["bypass_env"] == "GLOBAL_BYPASS"

    def test_trusted_project_target_can_change_terminal_options(self):
        global_cfg = {"targets": {"bash": {"terminal": {"bypass_env": "GLOBAL_BYPASS"}}}}
        project_cfg = {"targets": {"bash": {"terminal": {"bypass_env": "PROJECT_BYPASS"}}}}
        cfg = _merge_configs(global_cfg, project_cfg, target="bash", project_config_trusted=True)
        assert cfg.terminal["bypass_env"] == "PROJECT_BYPASS"

    # --- trusted project config ---

    def test_trusted_project_config_allows_loosening(self):
        """With project_config_trusted, project can loosen actions."""
        global_cfg = {"actions": {"network_outbound": "ask"}}
        project_cfg = {"actions": {"network_outbound": "allow"}}
        cfg = _merge_configs(global_cfg, project_cfg, project_config_trusted=True)
        assert cfg.actions["network_outbound"] == "allow"

    def test_project_config_default_untrusted(self):
        """Without project_config_trusted, loosening is blocked."""
        global_cfg = {"actions": {"network_outbound": "ask"}}
        project_cfg = {"actions": {"network_outbound": "allow"}}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert cfg.actions["network_outbound"] == "ask"

    def test_trusted_project_config_sensitive_paths_loosen(self):
        """With project_config_trusted, project can loosen sensitive_paths."""
        global_cfg = {"sensitive_paths": {"~/.custom": "block"}}
        project_cfg = {"sensitive_paths": {"~/.custom": "ask"}}
        cfg = _merge_configs(global_cfg, project_cfg, project_config_trusted=True)
        assert cfg.sensitive_paths["~/.custom"] == "ask"

    def test_trusted_project_config_sensitive_paths_default_loosen(self):
        """With project_config_trusted, project can loosen sensitive_paths_default."""
        global_cfg = {"sensitive_paths_default": "block"}
        project_cfg = {"sensitive_paths_default": "ask"}
        cfg = _merge_configs(global_cfg, project_cfg, project_config_trusted=True)
        assert cfg.sensitive_paths_default == "ask"

    def test_trusted_project_config_content_policies_loosen(self):
        """With project_config_trusted, project can loosen content_policies."""
        global_cfg = {"content_patterns": {"policies": {"secret": "block"}}}
        project_cfg = {"content_patterns": {"policies": {"secret": "ask"}}}
        cfg = _merge_configs(global_cfg, project_cfg, project_config_trusted=True)
        assert cfg.content_policies["secret"] == "ask"

    def test_legacy_trust_project_config_ignored(self, capsys):
        """The removed broad trust switch warns and does not loosen policy."""
        global_cfg = {"trust_project_config": True, "actions": {"network_outbound": "ask"}}
        project_cfg = {"actions": {"network_outbound": "allow"}}
        cfg = _merge_configs(global_cfg, project_cfg)
        assert cfg.actions["network_outbound"] == "ask"
        assert cfg.trust_project_config is False
        assert "trust_project_config is no longer supported" in capsys.readouterr().err

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

    def test_profile_minimal_from_global_deprecated_to_full(self, capsys):
        cfg = _merge_configs({"profile": "minimal"}, {})
        assert cfg.profile == "full"
        assert "profile 'minimal' is deprecated" in capsys.readouterr().err

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

    def test_profile_non_string_fallback(self, capsys):
        """Malformed profile values fall back without crashing config load."""
        cfg = _merge_configs({"profile": ["minimal"]}, {})
        assert cfg.profile == "full"
        assert "unknown profile ['minimal']" in capsys.readouterr().err

    def test_profile_global_overrides_project(self):
        """Global profile wins; project profile ignored."""
        cfg = _merge_configs({"profile": "none"}, {"profile": "full"})
        assert cfg.profile == "none"


class TestLlmMode:
    """llm.mode config loading."""

    def test_llm_mode_from_global(self):
        cfg = _merge_configs({"llm": {"mode": "on"}}, {})
        assert cfg.llm_mode == "on"

    def test_llm_mode_accepts_yaml_boolean_on_off(self):
        assert _merge_configs({"llm": {"mode": True}}, {}).llm_mode == "on"
        assert _merge_configs({"llm": {"mode": False}}, {}).llm_mode == "off"

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


class TestUiConfig:
    """ui config loading."""

    def test_ui_color_from_global(self):
        cfg = _merge_configs({"ui": {"color": "always"}}, {})
        assert cfg.ui == {"color": "always"}
        assert cfg.ui_color == "always"

    def test_ui_color_bool_values(self):
        assert _merge_configs({"ui": {"color": True}}, {}).ui_color == "always"
        assert _merge_configs({"ui": {"color": False}}, {}).ui_color == "never"

    def test_ui_color_invalid_falls_back_to_auto(self):
        cfg = _merge_configs({"ui": {"color": "sparkles"}}, {})
        assert cfg.ui_color == "auto"

    def test_project_ui_color_ignored(self):
        cfg = _merge_configs({}, {"ui": {"color": "always"}})
        assert cfg.ui_color == "auto"

    def test_target_ui_color_from_global_target(self):
        cfg = _merge_configs({"targets": {"claude": {"ui": {"color": "never"}}}}, {}, target="claude")
        assert cfg.ui_color == "never"


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
