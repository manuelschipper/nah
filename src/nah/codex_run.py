"""Codex launcher with nah-owned Codex hook overrides."""

from __future__ import annotations

import json
import hashlib
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime

from nah import hook_command
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
    headless: bool = False
    headless_ask_fallback: str = ""


_BYPASS_FLAGS = {
    "--dangerously-bypass-approvals-and-sandbox",
    "--yolo",
}
_DEFAULT_SANDBOX_MODE = "danger-full-access"
_DEFAULT_APPROVAL_POLICY = "untrusted"
_INTERACTIVE_PRE_TOOL_TIMEOUT = 10
_INTERACTIVE_PERMISSION_TIMEOUT = 14
_INTERACTIVE_POST_TOOL_TIMEOUT = 10
_HEADLESS_PRE_TOOL_TIMEOUT = 30
_HEADLESS_PERMISSION_TIMEOUT = 14
_HEADLESS_POST_TOOL_TIMEOUT = 10
_CONFIRM_EDITS_FLAG = "--confirm-edits"
_CONFIRM_EDITS_ENV = "NAH_CODEX_CONFIRM_EDITS"
_PRESET_FLAG = "--preset"
_PRESET_ENV = "NAH_PRESET"
_NETWORK_FLAG = "--network"
_HEADLESS_ENV = "NAH_CODEX_HEADLESS"
_HEADLESS_ASK_FALLBACK_ENV = "NAH_CODEX_HEADLESS_ASK_FALLBACK"
_HEADLESS_SANDBOX_ENV = "NAH_CODEX_SANDBOX"
_HEADLESS_NETWORK_ENV = "NAH_CODEX_NETWORK"
_ALLOWED_SANDBOX_MODES = {"danger-full-access", "read-only", "workspace-write"}
_HEADLESS_EXEC_SUBCOMMANDS = {"exec", "e"}
_HEADLESS_NESTED_UNSUPPORTED = {"review", "resume", "apply", "a", "cloud"}
_HEADLESS_DISABLED_FEATURES = {"unified_exec", "code_mode", "code_mode_only"}
_HEADLESS_REJECT_FLAGS = {
    "--dangerously-bypass-hook-trust",
    "--ignore-user-config",
    "--ignore-rules",
}
_HEADLESS_INTERNAL_EXEC_FLAGS = ["--ignore-rules"]
_HOOK_TRUST_KEY_PREFIX = "/<session-flags>/config.toml"
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
    "--profile-v2",
    "-s",
    "--sandbox",
    "-a",
    "--ask-for-approval",
    "-C",
    "--cd",
    "--add-dir",
    "-o",
    "--output-last-message",
    "--output-schema",
    "--color",
}
_CODEX_LONG_VALUE_FLAGS = {flag for flag in _CODEX_VALUE_FLAGS if flag.startswith("--")}
_UNSUPPORTED_SUBCOMMANDS = {"review", "apply", "a", "cloud"}


def _toml_string(value: str) -> str:
    """Return a TOML-compatible quoted string."""
    return json.dumps(value)


def codex_hook_command() -> str:
    """Return the shell command Codex should run for PermissionRequest hooks."""
    return hook_command.codex_hook_command("_codex-permission-request")


def codex_pre_tool_hook_command() -> str:
    """Return the shell command Codex should run for PreToolUse hooks."""
    return hook_command.codex_hook_command("_codex-pre-tool-use")


def codex_post_tool_hook_command() -> str:
    """Return the shell command Codex should run for PostToolUse hooks."""
    return hook_command.codex_hook_command("_codex-post-tool-use")


def injected_overrides(
    *,
    sandbox_mode: str = _DEFAULT_SANDBOX_MODE,
    approval_policy: str = _DEFAULT_APPROVAL_POLICY,
    network: bool = False,
    headless: bool = False,
) -> list[str]:
    """Return root-level Codex config overrides owned by nah."""
    pre_tool_command = codex_pre_tool_hook_command()
    hook_command = codex_hook_command()
    post_tool_command = codex_post_tool_hook_command()
    pre_tool_timeout = (
        _HEADLESS_PRE_TOOL_TIMEOUT if headless else _INTERACTIVE_PRE_TOOL_TIMEOUT
    )
    permission_timeout = (
        _HEADLESS_PERMISSION_TIMEOUT if headless else _INTERACTIVE_PERMISSION_TIMEOUT
    )
    post_tool_timeout = (
        _HEADLESS_POST_TOOL_TIMEOUT if headless else _INTERACTIVE_POST_TOOL_TIMEOUT
    )
    pre_tool_hook_config = (
        "hooks.PreToolUse=[{ hooks = [{ "
        "type = \"command\", "
        f"command = {_toml_string(pre_tool_command)}, "
        f"timeout = {pre_tool_timeout}, "
        f"statusMessage = {_toml_string('nah enforcing' if headless else 'nah observing')} "
        "}] }]"
    )
    permission_hook_config = (
        "hooks.PermissionRequest=[{ hooks = [{ "
        "type = \"command\", "
        f"command = {_toml_string(hook_command)}, "
        f"timeout = {permission_timeout}, "
        "statusMessage = \"nah reviewing\" "
        "}] }]"
    )
    post_tool_hook_config = (
        "hooks.PostToolUse=[{ hooks = [{ "
        "type = \"command\", "
        f"command = {_toml_string(post_tool_command)}, "
        f"timeout = {post_tool_timeout}, "
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
    if headless:
        overrides += [
            "-c", "features.unified_exec=false",
            "-c", "features.code_mode=false",
            "-c", "features.code_mode_only=false",
        ]
    return overrides


def _ensure_headless_hook_trust(env: dict[str, str]) -> None:
    """Trust the session-scoped nah hook commands for headless Codex exec."""
    from nah.codex_preflight import _ensure_toml_values

    config_path = codex_home(env) / "config.toml"
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    edits = [
        (
            ("hooks", "state", _hook_trust_key("pre_tool_use")),
            "trusted_hash",
            _hook_trust_hash(
                "pre_tool_use",
                codex_pre_tool_hook_command(),
                "nah enforcing",
                timeout=_HEADLESS_PRE_TOOL_TIMEOUT,
            ),
        ),
        (
            ("hooks", "state", _hook_trust_key("permission_request")),
            "trusted_hash",
            _hook_trust_hash(
                "permission_request",
                codex_hook_command(),
                "nah reviewing",
                timeout=_HEADLESS_PERMISSION_TIMEOUT,
            ),
        ),
        (
            ("hooks", "state", _hook_trust_key("post_tool_use")),
            "trusted_hash",
            _hook_trust_hash(
                "post_tool_use",
                codex_post_tool_hook_command(),
                "nah logging",
                timeout=_HEADLESS_POST_TOOL_TIMEOUT,
            ),
        ),
    ]
    _ensure_toml_values(config_path, edits, timestamp)


def _hook_trust_key(event_label: str) -> str:
    return f"{_HOOK_TRUST_KEY_PREFIX}:{event_label}:0:0"


def _hook_trust_hash(
    event_label: str,
    command: str,
    status_message: str,
    *,
    timeout: int,
) -> str:
    identity = {
        "event_name": event_label,
        "hooks": [{
            "type": "command",
            "command": command,
            "timeout": timeout,
            "statusMessage": status_message,
            "async": False,
        }],
    }
    serialized = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(serialized).hexdigest()


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
    headless = _is_headless_exec(codex_args)
    _validate_user_args(codex_args, headless=headless)
    if headless:
        codex_args = _inject_headless_exec_args(codex_args)
    env = dict(base_env if base_env is not None else os.environ)
    if "NAH_PROVENANCE_RUN_ID" not in env:
        from nah.provenance import new_run_id

        env["NAH_PROVENANCE_RUN_ID"] = new_run_id()
    if selected_preset:
        env[_PRESET_ENV] = selected_preset
    selected_effective_preset = selected_preset or env.get(_PRESET_ENV, "").strip()
    effective_cfg = None
    if selected_effective_preset or headless:
        try:
            from nah.config import ConfigError, get_config

            effective_cfg = get_config(target="codex", preset=selected_effective_preset)
        except ConfigError as exc:
            raise CodexRunError(f"nah run codex: {exc}") from exc
    if confirm_edits:
        env[_CONFIRM_EDITS_ENV] = "1"
    else:
        env.pop(_CONFIRM_EDITS_ENV, None)
    headless_ask_fallback = ""
    if headless:
        # 'defer' has no meaning in non-interactive headless runs (nothing to defer
        # to), so coerce it — like an empty fallback — to the safe 'block'.
        _cfg_fallback = getattr(effective_cfg, "ask_fallback", "")
        headless_ask_fallback = _cfg_fallback if _cfg_fallback in ("allow", "block") else "block"
        env[_HEADLESS_ENV] = "1"
        env[_HEADLESS_ASK_FALLBACK_ENV] = headless_ask_fallback
        env[_HEADLESS_SANDBOX_ENV] = sandbox_mode
        env[_HEADLESS_NETWORK_ENV] = "1" if network else "0"
    else:
        env.pop(_HEADLESS_ENV, None)
        env.pop(_HEADLESS_ASK_FALLBACK_ENV, None)
        env.pop(_HEADLESS_SANDBOX_ENV, None)
        env.pop(_HEADLESS_NETWORK_ENV, None)
    authority_rules_path = ""
    if preflight:
        root = codex_home(env)
        try:
            status = ensure_authority_rules(home=root)
            authority_rules_path = str(status.path)
            ensure_preflight(home=root)
            if headless:
                _ensure_headless_hook_trust(env)
        except CodexAuthorityError as exc:
            raise CodexRunError(f"nah run codex: {exc}") from exc
        except CodexPreflightError as exc:
            raise CodexRunError(str(exc)) from exc
    argv = (
        [executable]
        + injected_overrides(
            sandbox_mode=sandbox_mode,
            approval_policy=_DEFAULT_APPROVAL_POLICY,
            network=network,
            headless=headless,
        )
        + codex_args
    )
    return CodexLaunch(
        argv=argv,
        env=env,
        sandbox_mode=sandbox_mode,
        approval_policy=_DEFAULT_APPROVAL_POLICY,
        authority_rules_path=authority_rules_path,
        confirm_edits=confirm_edits,
        network=network,
        selected_preset=selected_effective_preset,
        headless=headless,
        headless_ask_fallback=headless_ask_fallback,
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


def _validate_user_args(args: list[str], *, headless: bool = False) -> None:
    """Reject user flags/subcommands that can disable or bypass nah's hook path."""
    _reject_dangerous_flags(args, headless=headless)
    _reject_unsupported_subcommands(args)
    if headless:
        _reject_unsupported_headless_exec(args)


def _extract_nah_run_flags(args: list[str]) -> tuple[list[str], bool, str, bool, str]:
    """Extract nah-owned launcher flags before handing the rest to Codex."""
    codex_args: list[str] = []
    confirm_edits = False
    sandbox_mode = _DEFAULT_SANDBOX_MODE
    network = False
    selected_preset = ""
    after_separator = False
    seen_subcommand = False
    i = 0
    while i < len(args):
        tok = args[i]
        if after_separator or seen_subcommand:
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
        if _is_codex_joined_value_flag(tok):
            codex_args.append(tok)
            i += 1
            continue
        if tok in _CODEX_VALUE_FLAGS:
            codex_args.append(tok)
            if i + 1 < len(args):
                codex_args.append(args[i + 1])
            i += 2
            continue
        if not tok.startswith("-"):
            seen_subcommand = True
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


def _reject_dangerous_flags(args: list[str], *, headless: bool = False) -> None:
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
        if headless and tok in _HEADLESS_REJECT_FLAGS:
            raise CodexRunError(
                f"nah run codex: {tok} is not supported for guarded headless exec",
            )
        if tok in {"-c", "--config"}:
            if i + 1 >= len(args):
                return
            _reject_owned_config(args[i + 1])
            if headless:
                _reject_headless_config(args[i + 1])
            i += 2
            continue
        if tok.startswith("--config="):
            value = tok.split("=", 1)[1]
            _reject_owned_config(value)
            if headless:
                _reject_headless_config(value)
            i += 1
            continue
        if tok in {"--disable", "--enable"}:
            if i + 1 < len(args) and args[i + 1] in _MANAGED_ENABLE_FLAGS:
                raise CodexRunError(f"nah run codex: {args[i + 1]} is managed by nah")
            if headless and tok == "--enable" and i + 1 < len(args):
                _reject_headless_feature(args[i + 1])
            i += 2
            continue
        if tok.startswith("--disable=") and tok.split("=", 1)[1] in _MANAGED_ENABLE_FLAGS:
            raise CodexRunError(f"nah run codex: {tok.split('=', 1)[1]} is managed by nah")
        if tok.startswith("--enable=") and tok.split("=", 1)[1] in _MANAGED_ENABLE_FLAGS:
            raise CodexRunError(f"nah run codex: {tok.split('=', 1)[1]} is managed by nah")
        if headless and tok.startswith("--enable="):
            _reject_headless_feature(tok.split("=", 1)[1])
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


def _reject_headless_feature(feature: str) -> None:
    if feature in _HEADLESS_DISABLED_FEATURES:
        raise CodexRunError(f"nah run codex: {feature} is disabled for guarded headless exec")


def _reject_headless_config(value: str) -> None:
    if "=" not in value:
        return
    raw_key, raw_value = value.split("=", 1)
    key = raw_key.strip().strip("'\"")
    if not _config_value_truthy(raw_value):
        return
    if _is_headless_disabled_feature_key(key) or _is_legacy_unified_exec_key(key):
        raise CodexRunError(f"nah run codex: {key}=true is disabled for guarded headless exec")


def _is_headless_disabled_feature_key(key: str) -> bool:
    parts = key.split(".")
    if len(parts) >= 2 and parts[-2] == "features":
        return parts[-1] in _HEADLESS_DISABLED_FEATURES
    return False


def _is_legacy_unified_exec_key(key: str) -> bool:
    return key == "experimental_use_unified_exec_tool" or key.endswith(
        ".experimental_use_unified_exec_tool",
    )


def _config_value_truthy(value: str) -> bool:
    normalized = value.strip().strip("'\"").lower()
    return normalized in {"true", "1", "yes", "on"}


def _is_owned_config_key(key: str) -> bool:
    for owned in _OWNED_CONFIG_KEYS:
        if key == owned or key.startswith(owned + "."):
            return True
    return False


def _reject_unsupported_subcommands(args: list[str]) -> None:
    sub = _first_subcommand(args)
    if sub in _UNSUPPORTED_SUBCOMMANDS:
        if sub in {"review", "apply", "a"}:
            raise CodexRunError(
                f"nah run codex: codex {sub} does not use interactive approvals safely yet",
            )
        raise CodexRunError("nah run codex: remote/cloud Codex runs are not supported yet")


def _reject_unsupported_headless_exec(args: list[str]) -> None:
    nested = _first_exec_argument(args)
    if nested in _HEADLESS_NESTED_UNSUPPORTED:
        raise CodexRunError(f"nah run codex: codex exec {nested} is not supported yet")


def _inject_headless_exec_args(args: list[str]) -> list[str]:
    sub_idx = _first_subcommand_index(args)
    if sub_idx < 0 or args[sub_idx] not in _HEADLESS_EXEC_SUBCOMMANDS:
        return args
    # Interactive `nah codex setup` installs exec-policy prompt rules so Codex
    # known-safe commands route through PermissionRequest. Headless exec cannot
    # ask, so the launcher ignores those rules and makes PreToolUse authoritative.
    # Hook trust is handled in preflight by recording the session-scoped nah
    # hook hashes in Codex config before the headless run starts.
    return args[: sub_idx + 1] + _HEADLESS_INTERNAL_EXEC_FLAGS + args[sub_idx + 1 :]


def _is_headless_exec(args: list[str]) -> bool:
    return _first_subcommand(args) in _HEADLESS_EXEC_SUBCOMMANDS


def _first_exec_argument(args: list[str]) -> str:
    sub_idx = _first_subcommand_index(args)
    if sub_idx < 0 or args[sub_idx] not in _HEADLESS_EXEC_SUBCOMMANDS:
        return ""
    i = sub_idx + 1
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


def _first_subcommand(args: list[str]) -> str:
    idx = _first_subcommand_index(args)
    return args[idx] if idx >= 0 else ""


def _first_subcommand_index(args: list[str]) -> int:
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            return -1
        if _is_codex_joined_value_flag(tok):
            i += 1
            continue
        if tok in _CODEX_VALUE_FLAGS:
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        return i
    return -1


def _is_codex_joined_value_flag(tok: str) -> bool:
    if not tok.startswith("--") or "=" not in tok:
        return False
    return tok.split("=", 1)[0] in _CODEX_LONG_VALUE_FLAGS
