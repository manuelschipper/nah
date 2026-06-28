"""Agent hook command construction for installed nah entrypoints."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable


class HookCommandError(RuntimeError):
    """Raised when nah cannot build a usable persistent hook command."""


def _is_nah_basename(path: str) -> bool:
    return Path(path).name.lower() in {"nah", "nah.exe"}


def _same_target(left: str, right: str) -> bool:
    try:
        return os.path.samefile(left, right)
    except OSError:
        try:
            return Path(left).resolve(strict=False) == Path(right).resolve(strict=False)
        except OSError:
            return os.path.abspath(left) == os.path.abspath(right)


def _existing_nah_executable(path: str) -> str:
    if not path:
        return ""
    expanded = os.path.expanduser(path)
    if not os.path.isabs(expanded) or not _is_nah_basename(expanded):
        return ""
    if not os.path.exists(expanded):
        return ""
    if os.name != "nt" and not os.access(expanded, os.X_OK):
        return ""
    return expanded


def resolve_nah_executable(
    argv0: str | None = None,
    *,
    which: Callable[[str], str | None] | None = None,
) -> str:
    """Resolve the installed ``nah`` executable used for agent hook commands.

    Persistent agent hooks must call the package-manager wrapper, not a raw
    Python interpreter. Prefer the currently running absolute nah executable
    when it is identifiable. If PATH resolves to the same target, keep the PATH
    path because it is often the stable profile, venv, or pipx link.
    """
    lookup = shutil.which if which is None else which
    raw_argv0 = sys.argv[0] if argv0 is None else argv0
    running = _existing_nah_executable(raw_argv0)
    path_match = lookup("nah")
    path_executable = _existing_nah_executable(path_match or "")

    if running and path_executable and _same_target(running, path_executable):
        return path_executable
    if running:
        return running
    if path_executable:
        return path_executable
    raise HookCommandError(
        "could not resolve an installed nah executable; run this command through "
        "the `nah` CLI instead of `python -m nah`"
    )


def quote_claude_argv(argv: list[str]) -> str:
    """Quote argv for Claude settings using double quotes and forward slashes."""
    quoted = []
    for arg in argv:
        normalized = str(arg).replace("\\", "/").replace('"', r'\"')
        quoted.append(f'"{normalized}"')
    return " ".join(quoted)


def quote_shell_argv(argv: list[str], *, windows: bool | None = None) -> str:
    """Quote argv for Codex hook command strings."""
    use_windows = os.name == "nt" if windows is None else windows
    if use_windows:
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


def claude_hook_command() -> str:
    """Return the command Claude Code should run for direct nah hooks."""
    return quote_claude_argv([resolve_nah_executable(), "_claude-hook"])


def codex_hook_command(hidden_command: str) -> str:
    """Return the command Codex should run for a nah hidden hook entrypoint."""
    return quote_shell_argv([resolve_nah_executable(), hidden_command])
