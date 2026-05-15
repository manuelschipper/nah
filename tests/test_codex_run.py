"""Tests for the `nah run codex` launcher."""

import os

import pytest

from nah.codex_authority import AUTHORITY_RULES_FILE, authority_rules_path
from nah.codex_run import CodexRunError, build_codex_argv, build_codex_launch


def _argv(args):
    return build_codex_argv(args, codex_path="/usr/bin/codex", preflight=False)


def _launch(args, *, base_env=None):
    return build_codex_launch(
        args,
        codex_path="/usr/bin/codex",
        preflight=False,
        base_env={} if base_env is None else base_env,
    )


def test_injects_fixed_danger_full_access_preset_before_user_args():
    launch = _launch(["resume", "abc123"])
    argv = launch.argv

    assert argv[0] == "/usr/bin/codex"
    assert argv[-2:] == ["resume", "abc123"]
    assert launch.sandbox_mode == "danger-full-access"
    assert launch.approval_policy == "untrusted"
    assert launch.confirm_edits is False
    assert launch.network is False
    assert "NAH_CODEX_CONFIRM_EDITS" not in launch.env
    assert "features.apps=false" in argv
    assert "features.hooks=true" in argv
    assert "features.codex_hooks=true" not in argv
    assert "features.skill_mcp_dependency_install=false" in argv
    assert 'approval_policy="untrusted"' in argv
    assert 'sandbox_mode="danger-full-access"' in argv
    assert 'approvals_reviewer="user"' in argv
    pre_tool_override = next(arg for arg in argv if arg.startswith("hooks.PreToolUse="))
    assert "_codex-pre-tool-use" in pre_tool_override
    hook_override = next(arg for arg in argv if arg.startswith("hooks.PermissionRequest="))
    assert "_codex-permission-request" in hook_override
    post_tool_override = next(arg for arg in argv if arg.startswith("hooks.PostToolUse="))
    assert "_codex-post-tool-use" in post_tool_override


def test_passes_normal_codex_ui_flags_through():
    argv = _argv(["--no-alt-screen"])

    assert argv[-1] == "--no-alt-screen"


def test_confirm_edits_is_nah_launcher_flag():
    launch = _launch(["--confirm-edits", "resume", "abc123"])

    assert launch.confirm_edits is True
    assert launch.env["NAH_CODEX_CONFIRM_EDITS"] == "1"
    assert "--confirm-edits" not in launch.argv
    assert launch.argv[-2:] == ["resume", "abc123"]


def test_confirm_edits_env_is_owned_by_launcher():
    launch = _launch([], base_env={"NAH_CODEX_CONFIRM_EDITS": "1"})

    assert launch.confirm_edits is False
    assert "NAH_CODEX_CONFIRM_EDITS" not in launch.env


def test_confirm_edits_rejects_value_form():
    with pytest.raises(CodexRunError) as exc:
        _launch(["--confirm-edits=true"])

    assert "--confirm-edits does not take a value" in str(exc.value)


@pytest.mark.parametrize("flag", ["--flow", "--auto-edits", "--no-sandbox"])
def test_deleted_nah_mode_flags_have_no_launcher_behavior(flag):
    launch = _launch([flag, "--no-alt-screen"])

    assert launch.sandbox_mode == "danger-full-access"
    assert launch.approval_policy == "untrusted"
    assert flag in launch.argv
    assert launch.argv[-2:] == [flag, "--no-alt-screen"]
    assert "NAH_CODEX_AUTO_ALLOW_SAFE_APPLY_PATCH" not in launch.env
    assert "NAH_CODEX_ACCEPT_EDITS" not in launch.env
    assert "NAH_CODEX_CONFIRM_EDITS" not in launch.env


def test_inherited_deleted_edit_envs_do_not_change_launcher_preset():
    launch = _launch(
        [],
        base_env={
            "NAH_CODEX_AUTO_ALLOW_SAFE_APPLY_PATCH": "1",
            "NAH_CODEX_ACCEPT_EDITS": "1",
        },
    )

    assert launch.sandbox_mode == "danger-full-access"
    assert launch.approval_policy == "untrusted"
    assert launch.env["NAH_CODEX_AUTO_ALLOW_SAFE_APPLY_PATCH"] == "1"
    assert launch.env["NAH_CODEX_ACCEPT_EDITS"] == "1"


def test_rejects_bypass_aliases():
    for flag in ("--yolo", "--dangerously-bypass-approvals-and-sandbox"):
        with pytest.raises(CodexRunError) as exc:
            _argv([flag])
        message = str(exc.value)
        assert f"{flag} is not allowed" in message
        assert "disables Codex approvals and sandboxing" in message
        assert f"Run `nah run codex` without {flag}" in message
        assert f"run `codex {flag}` directly" in message


@pytest.mark.parametrize(
    "args",
    [
        ["exec", "echo hi"],
        ["e", "echo hi"],
        ["review", "--diff"],
        ["apply"],
        ["a"],
        ["cloud", "exec", "echo hi"],
    ],
)
def test_rejects_unsupported_codex_surfaces(args):
    with pytest.raises(CodexRunError):
        _argv(args)


@pytest.mark.parametrize(
    "args",
    [
        ["-a", "never"],
        ["--ask-for-approval", "on-request"],
        ["--ask-for-approval=on-request"],
        ["--remote", "server"],
        ["--remote-auth-token-env=CODEX_TOKEN"],
    ],
)
def test_rejects_approval_and_remote_flags(args):
    with pytest.raises(CodexRunError) as exc:
        _argv(args)

    assert "managed by nah" in str(exc.value)


@pytest.mark.parametrize(
    ("args", "sandbox"),
    [
        (["-s", "read-only"], "read-only"),
        (["--sandbox", "workspace-write"], "workspace-write"),
        (["--sandbox=danger-full-access"], "danger-full-access"),
        (["-s=danger-full-access"], "danger-full-access"),
    ],
)
def test_sandbox_is_nah_launcher_flag(args, sandbox):
    launch = _launch(args + ["resume", "abc123"])

    assert launch.sandbox_mode == sandbox
    assert f'sandbox_mode="{sandbox}"' in launch.argv
    assert launch.argv[-2:] == ["resume", "abc123"]
    assert "--sandbox" not in launch.argv
    assert "-s" not in launch.argv


@pytest.mark.parametrize(
    "args",
    [
        ["--sandbox"],
        ["--sandbox", "--network"],
        ["--sandbox=unknown"],
        ["-s", "unknown"],
    ],
)
def test_sandbox_rejects_missing_or_unknown_values(args):
    with pytest.raises(CodexRunError) as exc:
        _launch(args)

    assert "--sandbox" in str(exc.value)


def test_network_flag_enables_workspace_write_network_access():
    launch = _launch(["--sandbox", "workspace-write", "--network", "resume", "abc123"])

    assert launch.sandbox_mode == "workspace-write"
    assert launch.network is True
    assert "sandbox_workspace_write.network_access=true" in launch.argv
    assert "--network" not in launch.argv
    assert launch.argv[-2:] == ["resume", "abc123"]


def test_network_flag_is_redundant_for_default_danger_full_access():
    launch = _launch(["--network", "resume", "abc123"])

    assert launch.sandbox_mode == "danger-full-access"
    assert launch.network is True
    assert "sandbox_workspace_write.network_access=true" not in launch.argv
    assert "--network" not in launch.argv
    assert launch.argv[-2:] == ["resume", "abc123"]


def test_network_flag_rejects_value_form_and_read_only_sandbox():
    with pytest.raises(CodexRunError) as value_exc:
        _launch(["--network=true"])
    assert "--network does not take a value" in str(value_exc.value)

    with pytest.raises(CodexRunError) as readonly_exc:
        _launch(["--sandbox", "read-only", "--network"])
    assert "--network requires --sandbox workspace-write" in str(readonly_exc.value)


@pytest.mark.parametrize(
    "args",
    [
        ["-c", "approval_policy=\"never\""],
        ["--config", "sandbox_mode=\"danger-full-access\""],
        ["--config=features.hooks=false"],
        ["--config=features.codex_hooks=false"],
        ["--config=features.apps=true"],
        ["--config=features.skill_mcp_dependency_install=true"],
        ["-c", "hooks.PreToolUse=[]"],
        ["-c", "hooks.PermissionRequest=[]"],
        ["-c", "hooks.PostToolUse=[]"],
        ["-c", "rules.prefix_rules=[]"],
        ["--config=rules.prefix_rules=[]"],
        ["--disable", "hooks"],
        ["--disable", "codex_hooks"],
        ["--enable=hooks"],
        ["--enable=codex_hooks"],
        ["--enable", "apps"],
        ["--enable=skill_mcp_dependency_install"],
    ],
)
def test_rejects_user_owned_config(args):
    with pytest.raises(CodexRunError) as exc:
        _argv(args)

    assert "managed by nah" in str(exc.value)
    assert "--no-sandbox" not in str(exc.value)
    assert "--flow" not in str(exc.value)


def test_preflight_blocks_remembered_codex_allows(tmp_path, monkeypatch):
    codex_home = tmp_path / "codex"
    rules = codex_home / "rules"
    rules.mkdir(parents=True)
    (rules / "default.rules").write_text(
        'prefix_rule(pattern=["curl"], decision="allow")\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    with pytest.raises(CodexRunError) as exc:
        build_codex_argv(["--help"], codex_path="/usr/bin/codex")

    assert "approval state can bypass nah" in str(exc.value)
    assert "default.rules" in str(exc.value)
    assert "nah codex setup" in str(exc.value)
    assert (rules / AUTHORITY_RULES_FILE).exists()


def test_preflight_installs_authority_rules_before_scanning(tmp_path, monkeypatch):
    codex_home = tmp_path / "codex"
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    launch = build_codex_launch(["--help"], codex_path="/usr/bin/codex")

    path = authority_rules_path(codex_home)
    assert path.exists()
    assert launch.authority_rules_path == str(path)


def test_windows_hook_command_is_quoted(monkeypatch):
    import nah.codex_run as codex_run

    monkeypatch.setattr(codex_run.os, "name", "nt")
    argv = _argv([])
    hook_override = next(arg for arg in argv if arg.startswith("hooks.PermissionRequest="))
    assert os.path.basename(codex_run.sys.executable) in hook_override
    pre_tool_override = next(arg for arg in argv if arg.startswith("hooks.PreToolUse="))
    assert os.path.basename(codex_run.sys.executable) in pre_tool_override
    post_tool_override = next(arg for arg in argv if arg.startswith("hooks.PostToolUse="))
    assert os.path.basename(codex_run.sys.executable) in post_tool_override
