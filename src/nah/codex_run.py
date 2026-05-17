"""Codex launcher with nah-owned Codex hook overrides."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass

from nah.codex_authority import CodexAuthorityError, codex_home, ensure_authority_rules
from nah.codex_preflight import CodexPreflightError, ensure_preflight


class CodexRunError(Exception):
    """Raised when `nah run codex` cannot safely launch Codex."""


@dataclass(frozen=True)
class CodexLaunch:
    argv: list[str]
    env: dict[str, str]
    sandbox_mode: str = ""
    approval_policy: str = ""
    authority_rules_path: str = ""
    confirm_edits: bool = False
    network: bool = False
    selected_preset: str = ""


_BYPASS_FLAGS = {
    "--dangerously-bypass-approvals-and-sandbox",
    "--yolo",
}
_DEFAULT_SANDBOX_MODE = "danger-full-access"
_DEFAULT_APPROVAL_POLICY = "untrusted"
_CONFIRM_EDITS_FLAG = "--confirm-edits"
_CONFIRM_EDITS_ENV = "NAH_CODEX_CONFIRM_EDITS"
_PRESET_FLAG = "--preset"
_PRESET_ENV = "NAH_PRESET"
_NETWORK_FLAG = "--network"
_ALLOWED_SANDBOX_MODES = {"danger-full-access", "read-only", "workspace-write"}
_REJECT_VALUE_FLAGS = {
    "-a",
    "--ask-for-approval",
    "--remote",
    "--remote-auth-token-env",
}
_OWNED_CONFIG_KEYS = {
    "approval_policy",
    "approvals_reviewer",
    "default_permissions",
    "features.apps",
    "features.codex_hooks",
    "features.hooks",
    "features.skill_mcp_dependency_install",
    "hooks",
    "hooks.PermissionRequest",
    "hooks.PreToolUse",
    "hooks.PostToolUse",
    "permission_profile",
    "permissions",
    "rules",
    "sandbox_mode",
}
_MANAGED_ENABLE_FLAGS = {
    "apps",
    "codex_hooks",
    "hooks",
    "skill_mcp_dependency_install",
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
_UNSUPPORTED_SUBCOMMANDS = {"exec", "e", "review", "apply", "a", "cloud"}


def _toml_string(value: str) -> str:
    """Return a TOML-compatible quoted string."""
    return json.dumps(value)


def codex_hook_command() -> str:
    """Return the shell command Codex should run for PermissionRequest hooks."""
    argv = [sys.executable, "-m", "nah.cli", "_codex-permission-request"]
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


def codex_pre_tool_hook_command() -> str:
    """Return the shell command Codex should run for PreToolUse hooks."""
    argv = [sys.executable, "-m", "nah.cli", "_codex-pre-tool-use"]
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


def codex_post_tool_hook_command() -> str:
    """Return the shell command Codex should run for PostToolUse hooks."""
    argv = [sys.executable, "-m", "nah.cli", "_codex-post-tool-use"]
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


def injected_overrides(
    *,
    sandbox_mode: str = _DEFAULT_SANDBOX_MODE,
    approval_policy: str = _DEFAULT_APPROVAL_POLICY,
    network: bool = False,
) -> list[str]:
    """Return root-level Codex config overrides owned by nah."""
    pre_tool_command = codex_pre_tool_hook_command()
    hook_command = codex_hook_command()
    post_tool_command = codex_post_tool_hook_command()
    pre_tool_hook_config = (
        "hooks.PreToolUse=[{ hooks = [{ "
        "type = \"command\", "
        f"command = {_toml_string(pre_tool_command)}, "
        "timeout = 5, "
        "statusMessage = \"nah observing\" "
        "}] }]"
    )
    permission_hook_config = (
        "hooks.PermissionRequest=[{ hooks = [{ "
        "type = \"command\", "
        f"command = {_toml_string(hook_command)}, "
        "timeout = 5, "
        "statusMessage = \"nah reviewing\" "
        "}] }]"
    )
    post_tool_hook_config = (
        "hooks.PostToolUse=[{ hooks = [{ "
        "type = \"command\", "
        f"command = {_toml_string(post_tool_command)}, "
        "timeout = 5, "
        "statusMessage = \"nah logging\" "
        "}] }]"
    )
    overrides = [
        "-c", "features.apps=false",
        "-c", "features.hooks=true",
        "-c", "features.skill_mcp_dependency_install=false",
        "-c", f"approval_policy={_toml_string(approval_policy)}",
        "-c", f"sandbox_mode={_toml_string(sandbox_mode)}",
        "-c", 'approvals_reviewer="user"',
        "-c", pre_tool_hook_config,
        "-c", permission_hook_config,
        "-c", post_tool_hook_config,
    ]
    if network and sandbox_mode == "workspace-write":
        overrides += ["-c", "sandbox_workspace_write.network_access=true"]
    return overrides


def build_codex_argv(
    user_args: list[str],
    *,
    codex_path: str | None = None,
    preflight: bool = True,
) -> list[str]:
    """Build a validated Codex argv with nah overrides before user args."""
    return build_codex_launch(
        user_args,
        codex_path=codex_path,
        preflight=preflight,
    ).argv


def build_codex_launch(
    user_args: list[str],
    *,
    codex_path: str | None = None,
    preflight: bool = True,
    base_env: dict[str, str] | None = None,
) -> CodexLaunch:
    """Build a validated Codex launch plan with nah-owned environment."""
    executable = codex_path or shutil.which("codex")
    if executable is None:
        raise CodexRunError("nah run codex: 'codex' not found on PATH")
    codex_args, confirm_edits, sandbox_mode, network, selected_preset = _extract_nah_run_flags(
        list(user_args),
    )
    _validate_user_args(codex_args)
    env = dict(base_env if base_env is not None else os.environ)
    if "NAH_PROVENANCE_RUN_ID" not in env:
        from nah.provenance import new_run_id

        env["NAH_PROVENANCE_RUN_ID"] = new_run_id()
    if selected_preset:
        env[_PRESET_ENV] = selected_preset
    selected_effective_preset = selected_preset or env.get(_PRESET_ENV, "").strip()
    if selected_effective_preset:
        try:
            from nah.config import ConfigError, get_config

            get_config(target="codex", preset=selected_effective_preset)
        except ConfigError as exc:
            raise CodexRunError(f"nah run codex: {exc}") from exc
    if confirm_edits:
        env[_CONFIRM_EDITS_ENV] = "1"
    else:
        env.pop(_CONFIRM_EDITS_ENV, None)
    authority_rules_path = ""
    if preflight:
        root = codex_home(env)
        try:
            status = ensure_authority_rules(home=root)
            authority_rules_path = str(status.path)
            ensure_preflight(home=root)
        except CodexAuthorityError as exc:
            raise CodexRunError(f"nah run codex: {exc}") from exc
        except CodexPreflightError as exc:
            raise CodexRunError(str(exc)) from exc
    argv = [executable] + injected_overrides(
        sandbox_mode=sandbox_mode,
        approval_policy=_DEFAULT_APPROVAL_POLICY,
        network=network,
    ) + codex_args
    return CodexLaunch(
        argv=argv,
        env=env,
        sandbox_mode=sandbox_mode,
        approval_policy=_DEFAULT_APPROVAL_POLICY,
        authority_rules_path=authority_rules_path,
        confirm_edits=confirm_edits,
        network=network,
        selected_preset=selected_effective_preset,
    )


def run_codex(user_args: list[str]) -> int:
    """Exec Codex with nah-owned approval and post-tool hooks enabled."""
    try:
        launch = build_codex_launch(user_args)
    except CodexRunError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if os.name == "nt":
        return subprocess.call(launch.argv, env=launch.env)
    os.execvpe(
        launch.argv[0],
        [os.path.basename(launch.argv[0])] + launch.argv[1:],
        launch.env,
    )
    return 127


def _validate_user_args(args: list[str]) -> None:
    """Reject user flags/subcommands that can disable or bypass nah's hook path."""
    _reject_dangerous_flags(args)
    _reject_unsupported_subcommands(args)


def _extract_nah_run_flags(args: list[str]) -> tuple[list[str], bool, str, bool, str]:
    """Extract nah-owned launcher flags before handing the rest to Codex."""
    codex_args: list[str] = []
    confirm_edits = False
    sandbox_mode = _DEFAULT_SANDBOX_MODE
    network = False
    selected_preset = ""
    after_separator = False
    i = 0
    while i < len(args):
        tok = args[i]
        if after_separator:
            codex_args.append(tok)
            i += 1
            continue
        if tok == "--":
            after_separator = True
            codex_args.append(tok)
            i += 1
            continue
        if tok == _CONFIRM_EDITS_FLAG:
            confirm_edits = True
            i += 1
            continue
        if tok.startswith(_CONFIRM_EDITS_FLAG + "="):
            raise CodexRunError(
                f"nah run codex: {_CONFIRM_EDITS_FLAG} does not take a value",
            )
        if tok == _NETWORK_FLAG:
            network = True
            i += 1
            continue
        if tok.startswith(_NETWORK_FLAG + "="):
            raise CodexRunError(
                f"nah run codex: {_NETWORK_FLAG} does not take a value",
            )
        if tok == _PRESET_FLAG:
            if i + 1 >= len(args) or args[i + 1].startswith("-"):
                raise CodexRunError("nah run codex: --preset requires a value")
            selected_preset = args[i + 1]
            i += 2
            continue
        if tok.startswith(_PRESET_FLAG + "="):
            selected_preset = tok.split("=", 1)[1]
            if not selected_preset:
                raise CodexRunError("nah run codex: --preset requires a value")
            i += 1
            continue
        if tok in {"-s", "--sandbox"}:
            if i + 1 >= len(args) or args[i + 1].startswith("-"):
                raise CodexRunError("nah run codex: --sandbox requires a value")
            sandbox_mode = _validate_sandbox_mode(args[i + 1])
            i += 2
            continue
        if tok.startswith("--sandbox="):
            sandbox_mode = _validate_sandbox_mode(tok.split("=", 1)[1])
            i += 1
            continue
        if tok.startswith("-s="):
            sandbox_mode = _validate_sandbox_mode(tok.split("=", 1)[1])
            i += 1
            continue
        codex_args.append(tok)
        i += 1
    if network and sandbox_mode == "read-only":
        raise CodexRunError(
            "nah run codex: --network requires --sandbox workspace-write "
            "or danger-full-access",
        )
    return codex_args, confirm_edits, sandbox_mode, network, selected_preset


def _validate_sandbox_mode(value: str) -> str:
    """Return a supported Codex sandbox mode or raise a launcher error."""
    if value in _ALLOWED_SANDBOX_MODES:
        return value
    allowed = ", ".join(sorted(_ALLOWED_SANDBOX_MODES))
    raise CodexRunError(f"nah run codex: --sandbox must be one of: {allowed}")


def _reject_dangerous_flags(args: list[str]) -> None:
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            return
        if tok in _BYPASS_FLAGS:
            raise CodexRunError(
                f"nah run codex: {tok} is not allowed because it disables "
                "Codex approvals and sandboxing. Run `nah run codex` without "
                f"{tok}, or run `codex {tok}` directly if you intentionally "
                "want an unguarded Codex session.",
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
            if i + 1 < len(args) and args[i + 1] in _MANAGED_ENABLE_FLAGS:
                raise CodexRunError(f"nah run codex: {args[i + 1]} is managed by nah")
            i += 2
            continue
        if tok.startswith("--disable=") and tok.split("=", 1)[1] in _MANAGED_ENABLE_FLAGS:
            raise CodexRunError(f"nah run codex: {tok.split('=', 1)[1]} is managed by nah")
        if tok.startswith("--enable=") and tok.split("=", 1)[1] in _MANAGED_ENABLE_FLAGS:
            raise CodexRunError(f"nah run codex: {tok.split('=', 1)[1]} is managed by nah")
        if tok in _REJECT_VALUE_FLAGS or any(
            tok.startswith(flag + "=") for flag in _REJECT_VALUE_FLAGS if flag.startswith("--")
        ):
            name = tok.split("=", 1)[0]
            raise CodexRunError(
                f"nah run codex: {name} is managed by nah. Run `nah run codex` "
                "without overriding Codex safety settings, or run `codex` "
                "directly if you intentionally want an unguarded session.",
            )
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
        raise CodexRunError(
            f"nah run codex: -c {key}=... is managed by nah. Run `nah run codex` "
            "without overriding Codex safety settings, or run `codex` directly "
            "if you intentionally want an unguarded session.",
        )


def _is_owned_config_key(key: str) -> bool:
    for owned in _OWNED_CONFIG_KEYS:
        if key == owned or key.startswith(owned + "."):
            return True
    return False


def _reject_unsupported_subcommands(args: list[str]) -> None:
    sub = _first_subcommand(args)
    if sub in _UNSUPPORTED_SUBCOMMANDS:
        if sub in {"exec", "e", "review", "apply", "a"}:
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
