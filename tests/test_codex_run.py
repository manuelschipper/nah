"""Tests for the `nah run codex` launcher."""

import os

import pytest

from nah.codex_run import CodexRunError, build_codex_argv


def _argv(args):
    return build_codex_argv(args, codex_path="/usr/bin/codex", preflight=False)


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


def test_rejects_bypass_aliases():
    for flag in ("--yolo", "--dangerously-bypass-approvals-and-sandbox"):
        with pytest.raises(CodexRunError):
            _argv([flag])


@pytest.mark.parametrize(
    "args",
    [
        ["exec", "echo hi"],
        ["e", "echo hi"],
        ["review", "--diff"],
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
        ["-s", "workspace-write"],
        ["--sandbox=danger-full-access"],
        ["--remote", "server"],
        ["--remote-auth-token-env=CODEX_TOKEN"],
    ],
)
def test_rejects_permission_and_remote_flags(args):
    with pytest.raises(CodexRunError):
        _argv(args)


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
