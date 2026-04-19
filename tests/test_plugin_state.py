"""Tests for Claude plugin/direct-hook install-state detection."""

import json

from nah import plugin_state


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_enabled_nah_plugins_detects_exact_plugin_name():
    settings = {
        "enabledPlugins": {
            "nah@local": True,
            "nah": True,
            "nah-tools@local": True,
            "nah@disabled": False,
            "nah@string": "true",
        }
    }

    assert plugin_state.enabled_nah_plugins(settings) == ["nah@local", "nah"]


def test_detects_user_project_and_local_enabled_plugins(tmp_path):
    user = _write(tmp_path / "user" / "settings.json", {"enabledPlugins": {"nah@user": True}})
    project = _write(tmp_path / "project" / ".claude" / "settings.json", {"enabledPlugins": {"nah@project": True}})
    local = _write(tmp_path / "project" / ".claude" / "settings.local.json", {"enabledPlugins": {"nah@local": True}})

    state = plugin_state.detect_nah_install_state(settings_paths=[user, project, local])

    assert state.mode == "plugin"
    assert {finding.detail for finding in state.enabled_plugins} == {
        "nah@user",
        "nah@project",
        "nah@local",
    }


def test_detects_mixed_direct_and_plugin_hooks(tmp_path):
    settings = _write(
        tmp_path / "settings.json",
        {
            "enabledPlugins": {"nah@local": True},
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "python3 ~/.claude/hooks/nah_guard.py"}],
                    },
                    {
                        "matcher": "Read",
                        "hooks": [{"type": "command", "command": "sh ${CLAUDE_PLUGIN_ROOT}/bin/nah-plugin-hook"}],
                    },
                ]
            },
        },
    )

    state = plugin_state.detect_nah_install_state(settings_paths=[settings])

    assert state.mode == "mixed"
    assert state.has_legacy
    assert state.has_plugin
    assert len(state.legacy_hooks) == 1
    assert len(state.plugin_hooks) == 1


def test_malformed_settings_reports_error(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text("{not json", encoding="utf-8")

    state = plugin_state.detect_nah_install_state(settings_paths=[settings])

    assert state.mode == "none"
    assert state.errors
