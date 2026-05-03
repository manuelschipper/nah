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


@pytest.mark.parametrize(
    ("args", "mode", "remaining"),
    [
        (["--sandbox", "read-only", "resume", "abc123"], "read-only", ["resume", "abc123"]),
        (["--sandbox=workspace-write"], "workspace-write", []),
        (["-s", "danger-full-access", "--help"], "danger-full-access", ["--help"]),
        (["--no-sandbox"], "danger-full-access", []),
        (["--ns", "resume"], "danger-full-access", ["resume"]),
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
