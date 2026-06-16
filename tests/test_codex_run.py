"""Tests for the `nah run codex` launcher."""

from unittest.mock import patch

import pytest

from nah.codex_authority import AUTHORITY_RULES_FILE, authority_rules_path
from nah.codex_run import CodexRunError, build_codex_argv, build_codex_launch


@pytest.fixture(autouse=True)
def _patch_nah_executable(monkeypatch):
    monkeypatch.setattr("nah.hook_command.resolve_nah_executable", lambda: "/usr/local/bin/nah")


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
    assert "/usr/local/bin/nah" in pre_tool_override
    assert "-m nah.cli" not in pre_tool_override
    assert "timeout = 10" in pre_tool_override
    hook_override = next(arg for arg in argv if arg.startswith("hooks.PermissionRequest="))
    assert "_codex-permission-request" in hook_override
    assert "/usr/local/bin/nah" in hook_override
    assert "-m nah.cli" not in hook_override
    assert "timeout = 14" in hook_override
    post_tool_override = next(arg for arg in argv if arg.startswith("hooks.PostToolUse="))
    assert "_codex-post-tool-use" in post_tool_override
    assert "/usr/local/bin/nah" in post_tool_override
    assert "-m nah.cli" not in post_tool_override
    assert "timeout = 10" in post_tool_override


def test_headless_exec_is_guarded_by_pre_tool_use():
    launch = _launch(["exec", "run git status"])
    argv = launch.argv

    assert argv[-3:] == ["exec", "--ignore-rules", "run git status"]
    assert launch.headless is True
    assert launch.headless_ask_fallback == "block"
    assert launch.sandbox_mode == "danger-full-access"
    assert launch.env["NAH_CODEX_HEADLESS"] == "1"
    assert launch.env["NAH_CODEX_HEADLESS_ASK_FALLBACK"] == "block"
    assert launch.env["NAH_CODEX_SANDBOX"] == "danger-full-access"
    assert launch.env["NAH_CODEX_NETWORK"] == "0"
    assert "features.unified_exec=false" in argv
    assert "features.code_mode=false" in argv
    assert "features.code_mode_only=false" in argv
    pre_tool_override = next(arg for arg in argv if arg.startswith("hooks.PreToolUse="))
    assert "nah enforcing" in pre_tool_override
    assert "timeout = 30" in pre_tool_override
    hook_override = next(arg for arg in argv if arg.startswith("hooks.PermissionRequest="))
    assert "timeout = 14" in hook_override
    post_tool_override = next(arg for arg in argv if arg.startswith("hooks.PostToolUse="))
    assert "timeout = 10" in post_tool_override


def test_headless_exec_alias_is_guarded():
    launch = _launch(["e", "run git status"])

    assert launch.headless is True
    assert launch.argv[-3:] == ["e", "--ignore-rules", "run git status"]


def test_interactive_launch_scrubs_inherited_headless_env():
    launch = _launch(
        ["resume"],
        base_env={
            "NAH_CODEX_HEADLESS": "1",
            "NAH_CODEX_HEADLESS_ASK_FALLBACK": "allow",
            "NAH_CODEX_SANDBOX": "read-only",
            "NAH_CODEX_NETWORK": "1",
        },
    )

    assert launch.headless is False
    assert "NAH_CODEX_HEADLESS" not in launch.env
    assert "NAH_CODEX_HEADLESS_ASK_FALLBACK" not in launch.env
    assert "NAH_CODEX_SANDBOX" not in launch.env
    assert "NAH_CODEX_NETWORK" not in launch.env


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


def test_probe_flag_arms_without_fixed_delay():
    launch = _launch(["--probe", "resume", "abc123"])

    assert launch.env["NAH_HOOK_PROBE"] == "1"
    assert "NAH_HOOK_PROBE_DELAY" not in launch.env
    assert "--probe" not in launch.argv
    assert launch.argv[-2:] == ["resume", "abc123"]


def test_probe_flag_with_delay_sets_env():
    launch = _launch(["--probe=8", "resume"])

    assert launch.env["NAH_HOOK_PROBE"] == "1"
    assert launch.env["NAH_HOOK_PROBE_DELAY"] == "8"
    assert "--probe=8" not in launch.argv


def test_probe_env_is_owned_by_launcher():
    launch = _launch(
        [],
        base_env={"NAH_HOOK_PROBE": "1", "NAH_HOOK_PROBE_DELAY": "9"},
    )

    assert "NAH_HOOK_PROBE" not in launch.env
    assert "NAH_HOOK_PROBE_DELAY" not in launch.env


@pytest.mark.parametrize("flag", ["--probe=", "--probe=abc", "--probe=-3"])
def test_probe_rejects_bad_delay(flag):
    with pytest.raises(CodexRunError):
        _launch([flag])


# --- measure-hook-timeout (relocated from `nah codex measure-hook-timeout`) ---


def test_parse_measure_request_absent_returns_none():
    from nah.codex_run import _parse_measure_request

    assert _parse_measure_request(["resume", "abc"]) is None
    # A measure flag after a bare subcommand token is a Codex arg, not measure mode.
    assert _parse_measure_request(["resume", "--measure-hook-timeout"]) is None


def test_parse_measure_request_parses_flags():
    from nah.codex_run import MeasureRequest, _parse_measure_request

    req = _parse_measure_request(
        ["--measure-hook-timeout", "--event", "PreToolUse", "--probe-high", "5", "--sweep"]
    )
    assert req == MeasureRequest(event="PreToolUse", probe_high=5.0, sweep=True)
    # Joined `=` forms parse identically.
    assert _parse_measure_request(
        ["--measure-hook-timeout", "--event=PermissionRequest", "--probe-high=3"]
    ) == MeasureRequest(event="PermissionRequest", probe_high=3.0, sweep=False)


def test_parse_measure_request_defaults():
    from nah.codex_run import MeasureRequest, _parse_measure_request

    assert _parse_measure_request(["--measure-hook-timeout"]) == MeasureRequest()


@pytest.mark.parametrize(
    "args",
    [
        ["--measure-hook-timeout", "--event", "Bogus"],
        ["--measure-hook-timeout", "--probe-high", "abc"],
        ["--measure-hook-timeout", "--probe-high", "0"],
        ["--measure-hook-timeout", "--unknown"],
        ["--measure-hook-timeout", "resume"],
        ["--measure-hook-timeout", "--"],
        ["--measure-hook-timeout", "--event"],
    ],
)
def test_parse_measure_request_rejects_bad_input(args):
    from nah.codex_run import _parse_measure_request

    with pytest.raises(CodexRunError):
        _parse_measure_request(args)


def test_run_codex_measure_mode_dispatches_without_launch(monkeypatch):
    import nah.codex_run as codex_run

    seen = {}

    def fake_measure(request):
        seen["request"] = request
        return 0

    monkeypatch.setattr(codex_run, "_run_measure_hook_timeout", fake_measure)

    def boom(*args, **kwargs):
        raise AssertionError("must not launch Codex in measure mode")

    monkeypatch.setattr(codex_run, "build_codex_launch", boom)

    rc = codex_run.run_codex(["--measure-hook-timeout", "--event", "PostToolUse"])

    assert rc == 0
    assert seen["request"].event == "PostToolUse"


def test_run_codex_measure_bad_input_returns_1(monkeypatch, capsys):
    import nah.codex_run as codex_run

    def boom(*args, **kwargs):
        raise AssertionError("must not launch Codex on a measure parse error")

    monkeypatch.setattr(codex_run, "build_codex_launch", boom)

    rc = codex_run.run_codex(["--measure-hook-timeout", "--event", "bogus"])

    assert rc == 1
    assert "must be one of" in capsys.readouterr().err


def test_provenance_run_id_is_created_and_preserves_inherited_value():
    launch = _launch([])
    assert launch.env["NAH_PROVENANCE_RUN_ID"].startswith("run-")

    inherited = _launch([], base_env={"NAH_PROVENANCE_RUN_ID": "parent-run"})
    assert inherited.env["NAH_PROVENANCE_RUN_ID"] == "parent-run"


def test_confirm_edits_rejects_value_form():
    with pytest.raises(CodexRunError) as exc:
        _launch(["--confirm-edits=true"])

    assert "--confirm-edits does not take a value" in str(exc.value)


def test_preset_is_nah_launcher_flag(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("presets:\n  strict: {}\n", encoding="utf-8")

    with patch("nah.config._GLOBAL_CONFIG", str(config_path)):
        launch = _launch(["--preset", "strict", "resume"])

    assert launch.selected_preset == "strict"
    assert launch.env["NAH_PRESET"] == "strict"
    assert "--preset" not in launch.argv
    assert "strict" not in launch.argv
    assert launch.argv[-1] == "resume"


def test_preset_rejects_value_errors():
    with pytest.raises(CodexRunError) as exc:
        _launch(["--preset"])

    assert "--preset requires a value" in str(exc.value)


def test_preset_rejects_unknown_name(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("presets:\n  strict: {}\n", encoding="utf-8")

    with patch("nah.config._GLOBAL_CONFIG", str(config_path)):
        with pytest.raises(CodexRunError) as exc:
            _launch(["--preset", "missing"])

    assert "unknown preset 'missing'" in str(exc.value)


def test_cli_preset_overrides_inherited_env(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("presets:\n  env: {}\n  cli: {}\n", encoding="utf-8")

    with patch("nah.config._GLOBAL_CONFIG", str(config_path)):
        launch = _launch(["--preset=cli"], base_env={"NAH_PRESET": "env"})

    assert launch.selected_preset == "cli"
    assert launch.env["NAH_PRESET"] == "cli"


def test_inherited_preset_is_preserved_and_validated(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("presets:\n  env: {}\n", encoding="utf-8")

    with patch("nah.config._GLOBAL_CONFIG", str(config_path)):
        launch = _launch([], base_env={"NAH_PRESET": "env"})

    assert launch.selected_preset == "env"
    assert launch.env["NAH_PRESET"] == "env"


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


def test_headless_network_metadata_is_set_for_default_danger_full_access():
    launch = _launch(["--network", "exec", "run curl -I https://example.com"])

    assert launch.headless is True
    assert launch.network is True
    assert launch.env["NAH_CODEX_NETWORK"] == "1"
    assert "sandbox_workspace_write.network_access=true" not in launch.argv
    assert launch.argv[-3:] == ["exec", "--ignore-rules", "run curl -I https://example.com"]


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


def test_headless_uses_trusted_target_ask_fallback(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "targets:\n  codex:\n    ask_fallback: allow\n",
        encoding="utf-8",
    )

    with patch("nah.config._GLOBAL_CONFIG", str(config_path)):
        launch = _launch(["exec", "run curl -I https://example.com"])

    assert launch.headless is True
    assert launch.headless_ask_fallback == "allow"
    assert launch.env["NAH_CODEX_HEADLESS_ASK_FALLBACK"] == "allow"


@pytest.mark.parametrize(
    "args",
    [
        ["exec", "--dangerously-bypass-hook-trust", "run git status"],
        ["exec", "--ignore-user-config", "run git status"],
        ["exec", "--ignore-rules", "run git status"],
    ],
)
def test_headless_rejects_flags_that_can_bypass_hooks_or_config(args):
    with pytest.raises(CodexRunError) as exc:
        _launch(args)

    assert "guarded headless exec" in str(exc.value)


@pytest.mark.parametrize(
    "args",
    [
        ["--enable", "unified_exec", "exec", "run git status"],
        ["--enable=code_mode", "exec", "run git status"],
        ["-c", "features.unified_exec=true", "exec", "run git status"],
        ["-c", "features.code_mode=true", "exec", "run git status"],
        ["-c", "profiles.auto.features.code_mode_only=true", "exec", "run git status"],
        ["-c", "experimental_use_unified_exec_tool=true", "exec", "run git status"],
        ["-c", "profiles.auto.experimental_use_unified_exec_tool=true", "exec", "run git status"],
    ],
)
def test_headless_rejects_reenabling_disabled_tool_surfaces(args):
    with pytest.raises(CodexRunError) as exc:
        _launch(args)

    assert "disabled for guarded headless exec" in str(exc.value)


@pytest.mark.parametrize(
    "args",
    [
        ["exec", "review"],
        ["exec", "resume"],
        ["exec", "apply"],
        ["exec", "a"],
        ["exec", "cloud"],
    ],
)
def test_headless_rejects_nested_unsupported_surfaces(args):
    with pytest.raises(CodexRunError) as exc:
        _launch(args)

    assert "codex exec" in str(exc.value)


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
    assert "nah setup codex" in str(exc.value)
    assert (rules / AUTHORITY_RULES_FILE).exists()


def test_preflight_installs_authority_rules_before_scanning(tmp_path, monkeypatch):
    codex_home = tmp_path / "codex"
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    launch = build_codex_launch(["--help"], codex_path="/usr/bin/codex")

    path = authority_rules_path(codex_home)
    assert path.exists()
    assert launch.authority_rules_path == str(path)


def test_headless_preflight_trusts_session_scoped_nah_hooks(tmp_path, monkeypatch):
    codex_home = tmp_path / "codex"
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    launch = build_codex_launch(
        ["exec", "run git status"],
        codex_path="/usr/bin/codex",
    )

    config = (codex_home / "config.toml").read_text(encoding="utf-8")
    assert launch.headless is True
    assert '[hooks.state."/<session-flags>/config.toml:pre_tool_use:0:0"]' in config
    assert '[hooks.state."/<session-flags>/config.toml:permission_request:0:0"]' in config
    assert '[hooks.state."/<session-flags>/config.toml:post_tool_use:0:0"]' in config
    assert "trusted_hash = \"sha256:" in config


def test_windows_hook_command_is_quoted(monkeypatch):
    import nah.codex_run as codex_run

    monkeypatch.setattr(
        "nah.hook_command.resolve_nah_executable",
        lambda: r"C:\Program Files\nah\nah.exe",
    )
    monkeypatch.setattr(codex_run.os, "name", "nt")
    argv = _argv([])
    hook_override = next(arg for arg in argv if arg.startswith("hooks.PermissionRequest="))
    assert r"C:\\Program Files\\nah\\nah.exe" in hook_override
    pre_tool_override = next(arg for arg in argv if arg.startswith("hooks.PreToolUse="))
    assert r"C:\\Program Files\\nah\\nah.exe" in pre_tool_override
    post_tool_override = next(arg for arg in argv if arg.startswith("hooks.PostToolUse="))
    assert r"C:\\Program Files\\nah\\nah.exe" in post_tool_override
