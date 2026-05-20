"""Tests for installed nah executable hook command generation."""

from __future__ import annotations

import shlex

import pytest

from nah import hook_command


def _exe(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def test_resolver_prefers_path_link_when_it_targets_running_executable(tmp_path):
    store_nah = _exe(tmp_path / "store" / "bin" / "nah")
    path_nah = tmp_path / "profile" / "bin" / "nah"
    path_nah.parent.mkdir(parents=True)
    path_nah.symlink_to(store_nah)

    result = hook_command.resolve_nah_executable(
        store_nah,
        which=lambda _name: str(path_nah),
    )

    assert result == str(path_nah)


def test_resolver_prefers_running_executable_when_path_points_elsewhere(tmp_path):
    running = _exe(tmp_path / "nix" / "bin" / "nah")
    other = _exe(tmp_path / "old" / "bin" / "nah")

    result = hook_command.resolve_nah_executable(
        running,
        which=lambda _name: other,
    )

    assert result == running


def test_resolver_uses_path_when_running_executable_is_not_identifiable(tmp_path):
    path_nah = _exe(tmp_path / "venv" / "bin" / "nah")

    result = hook_command.resolve_nah_executable(
        "/usr/bin/python3",
        which=lambda _name: path_nah,
    )

    assert result == path_nah


def test_resolver_fails_without_a_usable_executable():
    with pytest.raises(hook_command.HookCommandError):
        hook_command.resolve_nah_executable(
            "/usr/bin/python3",
            which=lambda _name: None,
        )


def test_claude_command_uses_executable_and_hidden_hook(monkeypatch):
    monkeypatch.setattr(hook_command, "resolve_nah_executable", lambda: "/opt/nah bin/nah")

    command = hook_command.claude_hook_command()

    assert command == '"/opt/nah bin/nah" "_claude-hook"'
    assert "python" not in command
    parts = shlex.split(command)
    assert parts == ["/opt/nah bin/nah", "_claude-hook"]


def test_claude_command_normalizes_windows_backslashes(monkeypatch):
    monkeypatch.setattr(hook_command, "resolve_nah_executable", lambda: r"C:\Program Files\nah\nah.exe")

    command = hook_command.claude_hook_command()

    assert "\\" not in command
    assert 'C:/Program Files/nah/nah.exe' in command


def test_codex_command_uses_shell_quoting(monkeypatch):
    monkeypatch.setattr(hook_command, "resolve_nah_executable", lambda: "/opt/nah bin/nah")

    command = hook_command.codex_hook_command("_codex-pre-tool-use")

    assert shlex.split(command) == ["/opt/nah bin/nah", "_codex-pre-tool-use"]


def test_codex_command_uses_windows_quoting(monkeypatch):
    monkeypatch.setattr(hook_command, "resolve_nah_executable", lambda: r"C:\Program Files\nah\nah.exe")
    monkeypatch.setattr(hook_command.os, "name", "nt")

    command = hook_command.codex_hook_command("_codex-permission-request")

    assert '"C:\\Program Files\\nah\\nah.exe"' in command
    assert "_codex-permission-request" in command
