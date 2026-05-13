"""Tests for the `nah run codex` launcher."""

import os

import pytest

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


def test_injects_fixed_workspace_write_preset_before_user_args():
    launch = _launch(["resume", "abc123"])
    argv = launch.argv

    assert argv[0] == "/usr/bin/codex"
    assert argv[-2:] == ["resume", "abc123"]
    assert launch.sandbox_mode == "workspace-write"
    assert launch.approval_policy == "on-request"
    assert "features.apps=false" in argv
    assert "features.hooks=true" in argv
    assert "features.codex_hooks=true" not in argv
    assert "features.skill_mcp_dependency_install=false" in argv
    assert 'approval_policy="on-request"' in argv
    assert 'sandbox_mode="workspace-write"' in argv
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


@pytest.mark.parametrize("flag", ["--flow", "--auto-edits", "--no-sandbox"])
def test_deleted_nah_mode_flags_have_no_launcher_behavior(flag):
    launch = _launch([flag, "--no-alt-screen"])

    assert launch.sandbox_mode == "workspace-write"
    assert launch.approval_policy == "on-request"
    assert flag in launch.argv
    assert launch.argv[-2:] == [flag, "--no-alt-screen"]
    assert "NAH_CODEX_AUTO_ALLOW_SAFE_APPLY_PATCH" not in launch.env
    assert "NAH_CODEX_ACCEPT_EDITS" not in launch.env


def test_inherited_deleted_edit_envs_do_not_change_launcher_preset():
    launch = _launch(
        [],
        base_env={
            "NAH_CODEX_AUTO_ALLOW_SAFE_APPLY_PATCH": "1",
            "NAH_CODEX_ACCEPT_EDITS": "1",
        },
    )

    assert launch.sandbox_mode == "workspace-write"
    assert launch.approval_policy == "on-request"
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
        ["-s", "read-only"],
        ["--sandbox", "workspace-write"],
        ["--sandbox=danger-full-access"],
        ["-a", "never"],
        ["--ask-for-approval", "on-request"],
        ["--ask-for-approval=on-request"],
        ["--remote", "server"],
        ["--remote-auth-token-env=CODEX_TOKEN"],
    ],
)
def test_rejects_permission_sandbox_and_remote_flags(args):
    with pytest.raises(CodexRunError) as exc:
        _argv(args)

    assert "managed by nah" in str(exc.value)


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
