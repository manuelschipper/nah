"""Tests for the local Claude Code plugin artifact."""

import json
import os
import subprocess
import sys
from pathlib import Path

from nah import __version__, agents

ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "scripts" / "build_claude_plugin.py"
RUNNER_SOURCE = ROOT / "plugins" / "claude-code" / "nah" / "runtime" / "nah_plugin_runner.py"
FORBIDDEN_HOOK_COMMAND_PARTS = (
    "pip",
    "uvx",
    "curl",
    "~/.claude/hooks/nah_guard.py",
    str(ROOT),
)
EXPECTED_PLUGIN_KEYWORDS = [
    "claude-code",
    "hooks",
    "permissions",
    "safety",
    "security",
]


def _run_build(out: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(BUILD_SCRIPT), "--out", str(out), *extra],
        capture_output=True,
        text=True,
    )


def _run_marketplace_build(out: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(BUILD_SCRIPT), "--marketplace-out", str(out), *extra],
        capture_output=True,
        text=True,
    )


def _build(out: Path) -> None:
    result = _run_build(out)
    assert result.returncode == 0, result.stderr


def _build_marketplace(out: Path) -> None:
    result = _run_marketplace_build(out)
    assert result.returncode == 0, result.stderr


def _collect_hook_commands(value) -> list[str]:
    if isinstance(value, dict):
        commands = []
        if value.get("type") == "command" and isinstance(value.get("command"), str):
            commands.append(value["command"])
        for child in value.values():
            commands.extend(_collect_hook_commands(child))
        return commands
    if isinstance(value, list):
        commands = []
        for item in value:
            commands.extend(_collect_hook_commands(item))
        return commands
    return []


def _assert_no_bootstrap_commands(hooks: dict) -> None:
    commands = _collect_hook_commands(hooks)
    assert commands
    for command in commands:
        for forbidden in FORBIDDEN_HOOK_COMMAND_PARTS:
            assert forbidden not in command


def _assert_submission_ready_metadata(plugin: dict) -> None:
    assert plugin["name"] == "nah"
    assert plugin["version"] == __version__
    assert plugin["description"] == "Context-aware safety guard for Claude Code."
    assert plugin["homepage"] == "https://github.com/manuelschipper/nah"
    assert plugin["repository"] == "https://github.com/manuelschipper/nah"
    assert plugin["license"] == "MIT"
    assert plugin["keywords"] == EXPECTED_PLUGIN_KEYWORDS
    assert plugin["author"]["name"] == "Manuel Schipper"
    assert plugin["author"]["url"] == "https://github.com/manuelschipper"


def _assert_marketplace_entry_metadata(entry: dict) -> None:
    _assert_submission_ready_metadata(entry)
    assert entry["source"] == "./plugins/nah"
    assert entry["category"] == "security"
    assert entry["tags"] == EXPECTED_PLUGIN_KEYWORDS


def _run_plugin_hook(root: Path, payload: dict | str, home: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["CLAUDE_PLUGIN_ROOT"] = str(root)
    env["HOME"] = str(home)
    input_data = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run(
        [sys.executable, str(root / "runtime" / "nah_plugin_runner.py")],
        input=input_data,
        capture_output=True,
        text=True,
        env=env,
    )


def _fake_plugin_root(tmp_path: Path, hook_source: str | None) -> Path:
    root = tmp_path / "fake-plugin"
    nah_dir = root / "lib" / "nah"
    nah_dir.mkdir(parents=True)
    (nah_dir / "__init__.py").write_text("", encoding="utf-8")
    if hook_source is not None:
        (nah_dir / "hook.py").write_text(hook_source, encoding="utf-8")
    runtime_dir = root / "runtime"
    runtime_dir.mkdir()
    (runtime_dir / "nah_plugin_runner.py").write_text(
        RUNNER_SOURCE.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return root


def test_build_generates_complete_artifact(tmp_path):
    out = tmp_path / "nah"
    _build(out)

    plugin = json.loads((out / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    _assert_submission_ready_metadata(plugin)
    assert "marketplace" not in plugin
    assert "publisher" not in plugin

    readme = (out / "README.md").read_text(encoding="utf-8")
    assert "not a marketplace release" not in readme
    assert "official Anthropic marketplace listing is pending review" in readme
    assert "does not run `pip`" in readme
    assert (out / "SUBMISSION.md").exists()

    hooks = json.loads((out / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    pre_tool_use = hooks["hooks"]["PreToolUse"]
    assert [entry["matcher"] for entry in pre_tool_use] == agents.AGENT_TOOL_MATCHERS[agents.CLAUDE]

    for entry in pre_tool_use:
        hook = entry["hooks"][0]
        command = hook["command"]
        assert "${CLAUDE_PLUGIN_ROOT}/bin/nah-plugin-hook" in command
        assert hook["type"] == "command"

    session_hook = hooks["hooks"]["SessionStart"][0]["hooks"][0]
    assert "${CLAUDE_PLUGIN_ROOT}/bin/nah-plugin-session-start" in session_hook["command"]
    assert (out / "lib" / "nah" / "hook.py").exists()
    _assert_no_bootstrap_commands(hooks)


def test_marketplace_build_generates_catalog_and_self_contained_plugin(tmp_path):
    out = tmp_path / "marketplace"
    _build_marketplace(out)

    marketplace = json.loads((out / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    assert marketplace["name"] == "nah"
    assert "$schema" not in marketplace
    assert "description" not in marketplace
    assert marketplace["metadata"]["description"]
    assert marketplace["metadata"]["version"] == __version__
    assert len(marketplace["plugins"]) == 1

    entry = marketplace["plugins"][0]
    _assert_marketplace_entry_metadata(entry)
    assert "security" in entry["tags"]
    assert "plugins/claude-code" not in json.dumps(entry)

    plugin_root = out / "plugins" / "nah"
    plugin = json.loads((plugin_root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    hooks = json.loads((plugin_root / "hooks" / "hooks.json").read_text(encoding="utf-8"))

    _assert_submission_ready_metadata(plugin)
    assert (plugin_root / "README.md").exists()
    assert (plugin_root / "SUBMISSION.md").exists()
    assert (plugin_root / "bin" / "nah-plugin-hook").exists()
    assert (plugin_root / "bin" / "nah-plugin-session-start").exists()
    assert (plugin_root / "runtime" / "nah_plugin_runner.py").exists()
    assert (plugin_root / "lib" / "nah" / "hook.py").exists()
    _assert_no_bootstrap_commands(hooks)


def test_build_check_detects_stale_artifact(tmp_path):
    out = tmp_path / "nah"
    _build(out)

    clean = _run_build(out, "--check")
    assert clean.returncode == 0, clean.stderr

    plugin_path = out / ".claude-plugin" / "plugin.json"
    plugin = json.loads(plugin_path.read_text(encoding="utf-8"))
    plugin["description"] = "stale"
    plugin_path.write_text(json.dumps(plugin), encoding="utf-8")

    stale = _run_build(out, "--check")
    assert stale.returncode == 1
    assert "stale" in stale.stderr


def test_marketplace_check_detects_stale_catalog(tmp_path):
    out = tmp_path / "marketplace"
    _build_marketplace(out)

    clean = _run_marketplace_build(out, "--check")
    assert clean.returncode == 0, clean.stderr

    marketplace_path = out / ".claude-plugin" / "marketplace.json"
    marketplace = json.loads(marketplace_path.read_text(encoding="utf-8"))
    marketplace["plugins"][0]["version"] = "0.0.0"
    marketplace_path.write_text(json.dumps(marketplace), encoding="utf-8")

    stale = _run_marketplace_build(out, "--check")
    assert stale.returncode == 1
    assert "stale" in stale.stderr


def test_sdist_excludes_unpublished_plugin_sources_and_build_script():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert '"plugins/"' in pyproject
    assert '"scripts/"' in pyproject
    assert '"site/"' in pyproject


def test_plugin_runtime_llm_import_does_not_require_keyring(tmp_path):
    out = tmp_path / "nah"
    trap_dir = tmp_path / "trap"
    trap_dir.mkdir()
    (trap_dir / "keyring.py").write_text(
        "raise RuntimeError('keyring imported at module import time')\n",
        encoding="utf-8",
    )
    _build(out)

    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(trap_dir), str(out / "lib")])
    result = subprocess.run(
        [sys.executable, "-c", "import nah.llm; print('ok')"],
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_plugin_runner_allow_ask_and_block(tmp_path):
    out = tmp_path / "nah"
    home = tmp_path / "home"
    home.mkdir()
    _build(out)

    allow = _run_plugin_hook(out, {"tool_name": "Bash", "tool_input": {"command": "git status"}}, home)
    assert allow.returncode == 0
    assert json.loads(allow.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow"

    ask = _run_plugin_hook(out, {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}, home)
    assert ask.returncode == 0
    assert json.loads(ask.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"

    block = _run_plugin_hook(
        out,
        {"tool_name": "Write", "tool_input": {"file_path": "~/.claude/hooks/evil.py", "content": "x"}},
        home,
    )
    assert block.returncode == 0
    assert json.loads(block.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_plugin_runner_does_not_write_bytecode_into_artifact(tmp_path):
    out = tmp_path / "nah"
    home = tmp_path / "home"
    home.mkdir()
    _build(out)

    result = _run_plugin_hook(out, {"tool_name": "Bash", "tool_input": {"command": "git status"}}, home)

    assert result.returncode == 0
    assert not list((out / "lib" / "nah").rglob("*.pyc"))
    assert not list((out / "lib" / "nah").rglob("__pycache__"))
    clean = _run_build(out, "--check")
    assert clean.returncode == 0, clean.stderr


def test_plugin_runner_empty_output_falls_through(tmp_path):
    root = _fake_plugin_root(tmp_path, "def main():\n    pass\n")
    result = _run_plugin_hook(root, {"tool_name": "Bash", "tool_input": {"command": "git status"}}, tmp_path / "home")
    assert result.returncode == 0
    assert result.stdout == ""


def test_plugin_runner_invalid_json_fails_closed(tmp_path):
    root = _fake_plugin_root(tmp_path, "def main():\n    print('{\"broken\":')\n")
    result = _run_plugin_hook(root, {"tool_name": "Bash", "tool_input": {"command": "git status"}}, tmp_path / "home")
    assert result.returncode == 0
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_plugin_runner_import_failure_fails_closed(tmp_path):
    root = _fake_plugin_root(tmp_path, None)
    result = _run_plugin_hook(root, {"tool_name": "Bash", "tool_input": {"command": "git status"}}, tmp_path / "home")
    assert result.returncode == 0
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_shell_wrapper_no_python_fails_closed(tmp_path):
    out = tmp_path / "nah"
    _build(out)
    env = os.environ.copy()
    env["CLAUDE_PLUGIN_ROOT"] = str(out)
    env["PATH"] = str(tmp_path / "empty-path")
    result = subprocess.run(
        ["/bin/sh", str(out / "bin" / "nah-plugin-hook")],
        input='{"tool_name":"Bash","tool_input":{"command":"git status"}}',
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_session_start_warns_about_legacy_hooks_without_mutating(tmp_path):
    out = tmp_path / "nah"
    home = tmp_path / "home"
    settings_file = home / ".claude" / "settings.json"
    settings_file.parent.mkdir(parents=True)
    settings = {
        "hooks": {
            "PreToolUse": [{
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "python3 ~/.claude/hooks/nah_guard.py"}],
            }]
        }
    }
    settings_file.write_text(json.dumps(settings), encoding="utf-8")
    original = settings_file.read_text(encoding="utf-8")
    _build(out)

    env = os.environ.copy()
    env["CLAUDE_PLUGIN_ROOT"] = str(out)
    env["HOME"] = str(home)
    env["CLAUDE_PROJECT_DIR"] = str(tmp_path / "project")
    result = subprocess.run(
        ["/bin/sh", str(out / "bin" / "nah-plugin-session-start")],
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode == 0
    data = json.loads(result.stdout)
    context = data["hookSpecificOutput"]["additionalContext"]
    assert "legacy direct nah hooks" in context
    assert "nah uninstall" in context
    assert settings_file.read_text(encoding="utf-8") == original
