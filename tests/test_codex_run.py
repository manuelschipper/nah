"""Tests for the `nah run codex` launcher."""

import os

import pytest

from nah.codex_run import CodexRunError, build_codex_argv, build_codex_launch


def _argv(args):
    return build_codex_argv(args, codex_path="/usr/bin/codex", preflight=False)


def _launch(args):
    return build_codex_launch(
        args,
        codex_path="/usr/bin/codex",
        preflight=False,
        base_env={},
    )


def test_injects_root_overrides_before_user_args():
    argv = _argv(["resume", "abc123"])

    assert argv[0] == "/usr/bin/codex"
    assert argv[-2:] == ["resume", "abc123"]
    assert "-c" in argv
    assert "features.apps=false" in argv
    assert "features.codex_hooks=true" in argv
    assert "features.skill_mcp_dependency_install=false" in argv
    assert 'approval_policy="on-request"' in argv
    assert 'sandbox_mode="workspace-write"' in argv
    assert 'approvals_reviewer="user"' in argv
    hook_override = next(arg for arg in argv if arg.startswith("hooks.PermissionRequest="))
    assert "_codex-permission-request" in hook_override


def test_default_launch_clears_inherited_auto_edit_envs():
    launch = build_codex_launch(
        [],
        codex_path="/usr/bin/codex",
        preflight=False,
        base_env={
            "NAH_CODEX_AUTO_ALLOW_SAFE_APPLY_PATCH": "1",
            "NAH_CODEX_ACCEPT_EDITS": "1",
        },
    )

    assert launch.accept_edits is False
    assert launch.sandbox_mode == "workspace-write"
    assert launch.approval_policy == "on-request"
    assert "NAH_CODEX_AUTO_ALLOW_SAFE_APPLY_PATCH" not in launch.env
    assert "NAH_CODEX_ACCEPT_EDITS" not in launch.env


@pytest.mark.parametrize(
    "flag",
    ["-ae", "--ae", "--auto-edits", "--accept-edits-on", "--trust-edits"],
)
def test_accept_edits_flags_are_consumed_and_set_hook_env(flag):
    launch = _launch([flag, "--no-alt-screen"])

    assert launch.accept_edits is True
    assert launch.sandbox_mode == "workspace-write"
    assert launch.approval_policy == "on-request"
    assert launch.env["NAH_CODEX_AUTO_ALLOW_SAFE_APPLY_PATCH"] == "1"
    assert "NAH_CODEX_ACCEPT_EDITS" not in launch.env
    assert flag not in launch.argv
    assert launch.argv[-1] == "--no-alt-screen"


@pytest.mark.parametrize(
    ("args", "mode", "remaining"),
    [
        (["--sandbox", "read-only", "resume", "abc123"], "read-only", ["resume", "abc123"]),
        (["--sandbox=workspace-write"], "workspace-write", []),
        (["-s", "danger-full-access", "--help"], "danger-full-access", ["--help"]),
        (["--no-sandbox"], "danger-full-access", []),
        (["--ns", "resume"], "danger-full-access", ["resume"]),
        (["-ns", "resume"], "danger-full-access", ["resume"]),
    ],
)
def test_accepts_nah_owned_sandbox_flags(args, mode, remaining):
    argv = _argv(args)

    assert f'sandbox_mode="{mode}"' in argv
    assert "--sandbox" not in argv
    assert "--no-sandbox" not in argv
    assert "--ns" not in argv
    if remaining:
        assert argv[-len(remaining):] == remaining
    else:
        assert argv[-1] != mode


@pytest.mark.parametrize("args", [["--no-sandbox"], ["--ns"], ["-ns"], ["--sandbox", "danger-full-access"]])
def test_no_sandbox_keeps_nah_approval_path_without_auto_edits(args):
    launch = _launch(args)

    assert launch.sandbox_mode == "danger-full-access"
    assert launch.approval_policy == "untrusted"
    assert 'sandbox_mode="danger-full-access"' in launch.argv
    assert 'approval_policy="untrusted"' in launch.argv
    assert launch.accept_edits is False
    assert "NAH_CODEX_AUTO_ALLOW_SAFE_APPLY_PATCH" not in launch.env


@pytest.mark.parametrize("flag", ["--flow", "--guarded-yolo"])
def test_flow_presets_are_no_sandbox_with_safe_auto_edits(flag):
    launch = _launch([flag, "--no-alt-screen"])

    assert launch.sandbox_mode == "danger-full-access"
    assert launch.approval_policy == "untrusted"
    assert launch.accept_edits is True
    assert launch.env["NAH_CODEX_AUTO_ALLOW_SAFE_APPLY_PATCH"] == "1"
    assert flag not in launch.argv
    assert launch.argv[-1] == "--no-alt-screen"


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
        ["--ask-for-approval=on-request"],
        ["--remote", "server"],
        ["--remote-auth-token-env=CODEX_TOKEN"],
    ],
)
def test_rejects_permission_and_remote_flags(args):
    with pytest.raises(CodexRunError):
        _argv(args)


def test_accept_edits_does_not_relax_rejected_approval_flags():
    with pytest.raises(CodexRunError):
        _argv(["--ae", "-a", "never"])


@pytest.mark.parametrize(
    "args",
    [
        ["-c", "approval_policy=\"never\""],
        ["--config", "sandbox_mode=\"danger-full-access\""],
        ["--config=features.codex_hooks=false"],
        ["--config=features.apps=true"],
        ["--config=features.skill_mcp_dependency_install=true"],
        ["-c", "hooks.PermissionRequest=[]"],
        ["--disable", "codex_hooks"],
        ["--enable=codex_hooks"],
        ["--enable", "apps"],
        ["--enable=skill_mcp_dependency_install"],
    ],
)
def test_rejects_user_owned_config(args):
    with pytest.raises(CodexRunError):
        _argv(args)


@pytest.mark.parametrize(
    "args",
    [
        ["--sandbox"],
        ["-s"],
        ["--sandbox=full"],
        ["--sandbox", "full"],
        ["--no-sandbox", "--sandbox", "workspace-write"],
        ["--ns", "--no-sandbox"],
        ["-ns", "--sandbox", "workspace-write"],
        ["--flow", "--sandbox", "workspace-write"],
        ["--guarded-yolo", "-ns"],
    ],
)
def test_rejects_invalid_sandbox_flags(args):
    with pytest.raises(CodexRunError) as exc:
        _argv(args)

    assert "sandbox" in str(exc.value)


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
