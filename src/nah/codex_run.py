"""Codex launcher with nah-owned PermissionRequest hook overrides."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys


class CodexRunError(Exception):
    """Raised when `nah run codex` cannot safely launch Codex."""


_BYPASS_FLAGS = {
    "--dangerously-bypass-approvals-and-sandbox",
    "--yolo",
}
_REJECT_VALUE_FLAGS = {
    "-a",
    "--ask-for-approval",
    "-s",
    "--sandbox",
    "--remote",
    "--remote-auth-token-env",
}
_OWNED_CONFIG_KEYS = {
    "approval_policy",
    "approvals_reviewer",
    "default_permissions",
    "features.codex_hooks",
    "hooks",
    "hooks.PermissionRequest",
    "permission_profile",
    "permissions",
    "sandbox_mode",
}
_CODEX_VALUE_FLAGS = {
    "-c",
    "--config",
    "--enable",
    "--disable",
    "--remote",
    "--remote-auth-token-env",
    "-i",
    "--image",
    "-m",
    "--model",
    "--local-provider",
    "-p",
    "--profile",
    "-s",
    "--sandbox",
    "-a",
    "--ask-for-approval",
    "-C",
    "--cd",
    "--add-dir",
}
_CODEX_LONG_VALUE_FLAGS = {flag for flag in _CODEX_VALUE_FLAGS if flag.startswith("--")}
_UNSUPPORTED_SUBCOMMANDS = {"exec", "e", "review", "cloud"}


def _toml_string(value: str) -> str:
    """Return a TOML-compatible quoted string."""
    return json.dumps(value)


def codex_hook_command() -> str:
    """Return the shell command Codex should run for PermissionRequest hooks."""
    argv = [sys.executable, "-m", "nah.cli", "_codex-permission-request"]
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


def injected_overrides() -> list[str]:
    """Return root-level Codex config overrides owned by nah."""
    hook_command = codex_hook_command()
    hook_config = (
        "hooks.PermissionRequest=[{ hooks = [{ "
        "type = \"command\", "
        f"command = {_toml_string(hook_command)}, "
        "timeout = 5, "
        "statusMessage = \"nah reviewing\" "
        "}] }]"
    )
    return [
        "-c", "features.codex_hooks=true",
        "-c", 'approval_policy="on-request"',
        "-c", 'sandbox_mode="workspace-write"',
        "-c", 'approvals_reviewer="user"',
        "-c", hook_config,
    ]


def build_codex_argv(user_args: list[str], *, codex_path: str | None = None) -> list[str]:
    """Build a validated Codex argv with nah overrides before user args."""
    executable = codex_path or shutil.which("codex")
    if executable is None:
        raise CodexRunError("nah run codex: 'codex' not found on PATH")
    _validate_user_args(user_args)
    return [executable] + injected_overrides() + list(user_args)


def run_codex(user_args: list[str]) -> int:
    """Exec Codex with nah-owned PermissionRequest hooks enabled."""
    try:
        argv = build_codex_argv(user_args)
    except CodexRunError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if os.name == "nt":
        return subprocess.call(argv)
    os.execvp(argv[0], [os.path.basename(argv[0])] + argv[1:])
    return 127


def _validate_user_args(args: list[str]) -> None:
    """Reject user flags/subcommands that can disable or bypass nah's hook path."""
    _reject_dangerous_flags(args)
    _reject_unsupported_subcommands(args)


def _reject_dangerous_flags(args: list[str]) -> None:
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            return
        if tok in _BYPASS_FLAGS:
            raise CodexRunError(
                f"nah run codex: {tok} bypasses approvals and sandboxing",
            )
        if tok in {"-c", "--config"}:
            if i + 1 >= len(args):
                return
            _reject_owned_config(args[i + 1])
            i += 2
            continue
        if tok.startswith("--config="):
            _reject_owned_config(tok.split("=", 1)[1])
            i += 1
            continue
        if tok in {"--disable", "--enable"}:
            if i + 1 < len(args) and args[i + 1] == "codex_hooks":
                raise CodexRunError("nah run codex: codex_hooks is managed by nah")
            i += 2
            continue
        if tok.startswith("--disable=") and tok.split("=", 1)[1] == "codex_hooks":
            raise CodexRunError("nah run codex: codex_hooks is managed by nah")
        if tok.startswith("--enable=") and tok.split("=", 1)[1] == "codex_hooks":
            raise CodexRunError("nah run codex: codex_hooks is managed by nah")
        if tok in _REJECT_VALUE_FLAGS or any(
            tok.startswith(flag + "=") for flag in _REJECT_VALUE_FLAGS if flag.startswith("--")
        ):
            name = tok.split("=", 1)[0]
            raise CodexRunError(f"nah run codex: {name} is managed by nah")
        if _is_codex_joined_value_flag(tok):
            i += 1
            continue
        if tok in _CODEX_VALUE_FLAGS:
            i += 2
            continue
        i += 1


def _reject_owned_config(value: str) -> None:
    key = value.split("=", 1)[0].strip()
    key = key.strip("'\"")
    if _is_owned_config_key(key):
        raise CodexRunError(f"nah run codex: -c {key}=... is managed by nah")


def _is_owned_config_key(key: str) -> bool:
    for owned in _OWNED_CONFIG_KEYS:
        if key == owned or key.startswith(owned + "."):
            return True
    return False


def _reject_unsupported_subcommands(args: list[str]) -> None:
    sub = _first_subcommand(args)
    if sub in _UNSUPPORTED_SUBCOMMANDS:
        if sub in {"exec", "e", "review"}:
            raise CodexRunError(
                f"nah run codex: codex {sub} does not use interactive approvals safely yet",
            )
        raise CodexRunError("nah run codex: remote/cloud Codex runs are not supported yet")


def _first_subcommand(args: list[str]) -> str:
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            return ""
        if _is_codex_joined_value_flag(tok):
            i += 1
            continue
        if tok in _CODEX_VALUE_FLAGS:
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        return tok
    return ""


def _is_codex_joined_value_flag(tok: str) -> bool:
    if not tok.startswith("--") or "=" not in tok:
        return False
    return tok.split("=", 1)[0] in _CODEX_LONG_VALUE_FLAGS
