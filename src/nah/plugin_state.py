"""Claude plugin/direct-hook install-state detection."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

LEGACY_HOOK_MARKERS = ("nah_guard.py",)
PLUGIN_HOOK_MARKERS = ("nah-plugin-hook", "nah_plugin_runner.py")


@dataclass(frozen=True)
class SettingsFinding:
    """A nah-related setting found in a Claude settings file."""

    path: Path
    detail: str


@dataclass
class NahInstallState:
    """Detected nah installation state across Claude settings files."""

    legacy_hooks: list[SettingsFinding] = field(default_factory=list)
    plugin_hooks: list[SettingsFinding] = field(default_factory=list)
    enabled_plugins: list[SettingsFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_legacy(self) -> bool:
        return bool(self.legacy_hooks)

    @property
    def has_plugin(self) -> bool:
        return bool(self.plugin_hooks or self.enabled_plugins)

    @property
    def mode(self) -> str:
        if self.has_legacy and self.has_plugin:
            return "mixed"
        if self.has_plugin:
            return "plugin"
        if self.has_legacy:
            return "legacy"
        return "none"


def is_legacy_nah_hook(hook_entry: dict) -> bool:
    """Return True when a PreToolUse entry points at nah's direct hook shim."""
    for hook in hook_entry.get("hooks", []):
        if not isinstance(hook, dict):
            continue
        command = hook.get("command", "")
        if isinstance(command, str) and any(marker in command for marker in LEGACY_HOOK_MARKERS):
            return True
    return False


def is_plugin_nah_hook(hook_entry: dict) -> bool:
    """Return True when a PreToolUse entry points at nah's plugin hook."""
    for hook in hook_entry.get("hooks", []):
        if not isinstance(hook, dict):
            continue
        command = hook.get("command", "")
        if not isinstance(command, str):
            continue
        if any(marker in command for marker in PLUGIN_HOOK_MARKERS):
            return True
        if "${CLAUDE_PLUGIN_ROOT}" in command and "/nah/" in command:
            return True
    return False


def enabled_nah_plugins(settings: dict) -> list[str]:
    """Return enabled Claude plugin ids whose plugin name is exactly ``nah``."""
    enabled = settings.get("enabledPlugins", {})
    if not isinstance(enabled, dict):
        return []

    result = []
    for plugin_id, is_enabled in enabled.items():
        if not is_enabled or not isinstance(plugin_id, str):
            continue
        plugin_name = plugin_id.split("@", 1)[0]
        if plugin_name == "nah":
            result.append(plugin_id)
    return result


def project_settings_paths(project_root: str | os.PathLike | None = None) -> list[Path]:
    """Return Claude project-scope settings paths for a project root."""
    root = Path(project_root) if project_root is not None else Path.cwd()
    claude_dir = root / ".claude"
    return [
        claude_dir / "settings.json",
        claude_dir / "settings.local.json",
    ]


def default_settings_paths(project_root: str | os.PathLike | None = None) -> list[Path]:
    """Return user and project Claude settings paths worth scanning."""
    return [Path.home() / ".claude" / "settings.json"] + project_settings_paths(project_root)


def _dedupe_paths(paths: Iterable[Path]) -> list[Path]:
    seen = set()
    result = []
    for path in paths:
        expanded = Path(path).expanduser()
        try:
            key = expanded.resolve(strict=False)
        except OSError:
            key = expanded.absolute()
        if key in seen:
            continue
        seen.add(key)
        result.append(expanded)
    return result


def detect_nah_install_state(
    *,
    project_root: str | os.PathLike | None = None,
    settings_paths: Iterable[Path] | None = None,
) -> NahInstallState:
    """Detect direct-hook and plugin-managed nah installs.

    Missing settings files are ignored. Present but unreadable or malformed
    settings files are reported in ``errors`` so callers can surface the
    diagnostic without silently guessing.
    """
    paths = _dedupe_paths(settings_paths or default_settings_paths(project_root))
    state = NahInstallState()

    for path in paths:
        if not path.exists():
            continue
        try:
            with open(path, encoding="utf-8") as f:
                settings = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            state.errors.append(f"{path}: {exc}")
            continue

        if not isinstance(settings, dict):
            state.errors.append(f"{path}: settings root is not an object")
            continue

        for plugin_id in enabled_nah_plugins(settings):
            state.enabled_plugins.append(SettingsFinding(path, plugin_id))

        hooks = settings.get("hooks", {})
        if not isinstance(hooks, dict):
            continue
        pre_tool_use = hooks.get("PreToolUse", [])
        if not isinstance(pre_tool_use, list):
            continue
        for index, entry in enumerate(pre_tool_use):
            if not isinstance(entry, dict):
                continue
            if is_legacy_nah_hook(entry):
                state.legacy_hooks.append(SettingsFinding(path, f"PreToolUse[{index}]"))
            if is_plugin_nah_hook(entry):
                state.plugin_hooks.append(SettingsFinding(path, f"PreToolUse[{index}]"))

    return state
