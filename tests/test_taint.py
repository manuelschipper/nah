"""Tests for runtime-neutral session taint tracking."""

import json

import pytest

from nah import config, paths, taint, taxonomy
from nah.config import NahConfig


def _cfg(mode="audit", **taint_overrides):
    data = {
        "mode": mode,
        "inherit_sensitive_paths": True,
        "sources": [{"paths": [".env", "secrets/*.json"], "labels": ["secret"]}],
        "propagation": {
            "filesystem_write": True,
            "git_write": True,
            "browser_file": True,
        },
        "policies": {
            "default": {"activation": "audit", "boundary": "ask", "unknown": "ask"},
            "secret": {"activation": "audit", "boundary": "ask", "unknown": "ask"},
        },
    }
    data.update(taint_overrides)
    config._cached_config = NahConfig(taint=data)
    config._cached_target = None


def _read_state(runtime="claude", session="sess"):
    with open(taint.state_path(runtime, session), encoding="utf-8") as f:
        return json.load(f)


def _activate_secret_source(session="sess"):
    source = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        source,
        runtime="claude",
        runtime_meta={"session_id": session},
        execution={"state": "requested"},
    )


def test_mode_off_does_not_create_state(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    config._cached_config = NahConfig()
    taint.reset_state()

    decision = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        decision,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "toolu_read"},
        execution={"state": "requested"},
    )

    assert "_meta" in decision
    assert "taint" not in decision["_meta"]
    assert not tmp_path.joinpath(".config", "nah", "taint").exists()


def test_allowed_source_read_waits_for_post_tool_confirmation(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg()
    taint.reset_state()

    decision = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        decision,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "toolu_read"},
        execution={"state": "requested"},
    )
    state = _read_state()
    assert "toolu_read" in state["pending_sources"]
    assert state["active_labels"] == {}
    assert decision["_meta"]["taint"]["updates"]["source"]["status"] == "pending"

    post = {"decision": taxonomy.ALLOW, "_meta": {}}
    taint.apply_post_tool(
        "Read",
        {"file_path": ".env"},
        post,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "toolu_read"},
        execution={"state": "executed", "ask_outcome": "approved_executed"},
    )
    state = _read_state()
    assert "toolu_read" not in state["pending_sources"]
    assert "secret" in state["active_labels"]
    assert post["_meta"]["taint"]["updates"]["source_finalized"] == "active"


def test_repeated_source_read_after_taint_is_not_unknown_sink(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(mode="enforce")
    taint.reset_state()

    first = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        first,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )
    assert first["_meta"]["taint"]["updates"]["source"]["status"] == "active"

    reread = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        reread,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    assert reread["decision"] == taxonomy.ALLOW
    meta = reread["_meta"]["taint"]
    assert meta["event"]["action_type"] == taxonomy.FILESYSTEM_READ
    assert meta.get("category", "") != "unknown"


def test_blocked_source_read_does_not_taint(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg()
    taint.reset_state()

    decision = {"decision": taxonomy.BLOCK, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        decision,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "toolu_read"},
        execution={"state": "not_run"},
    )

    assert not tmp_path.joinpath(".config", "nah", "taint").exists()


def test_malformed_state_fails_open_with_warning(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg()
    taint.reset_state()
    state_path = tmp_path / ".config" / "nah" / "taint" / "sessions" / "claude" / "sess.json"
    state_path.parent.mkdir(parents=True)
    state_path.write_text("{not json", encoding="utf-8")

    decision = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        decision,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    assert "ignoring unreadable session state" in capsys.readouterr().err
    assert decision["_meta"]["taint"]["updates"]["source"]["status"] == "active"


def test_desensitized_inherited_sensitive_path_is_not_taint_source(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    config._cached_config = NahConfig(
        sensitive_basenames={".env": "allow"},
        taint={"mode": "audit", "inherit_sensitive_paths": True},
    )
    config._cached_target = None
    paths.reset_sensitive_paths()
    taint.reset_state()

    decision = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        decision,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    assert "taint" not in decision["_meta"]
    assert not tmp_path.joinpath(".config", "nah", "taint").exists()


def test_audit_boundary_logs_would_decision_without_escalating(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(mode="audit")
    taint.reset_state()

    source = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        source,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    boundary = {
        "decision": taxonomy.ALLOW,
        "_meta": {"stages": [{"action_type": taxonomy.NETWORK_OUTBOUND, "decision": "allow"}]},
    }
    taint.apply_pre_tool(
        "Bash",
        {"command": "curl -I https://example.com"},
        boundary,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    assert boundary["decision"] == taxonomy.ALLOW
    meta = boundary["_meta"]["taint"]
    assert meta["policy_decision"] == taxonomy.ASK
    assert meta["would_decision"] == taxonomy.ASK
    assert meta["enforced"] is False


def test_enforce_boundary_escalates_allow_to_ask(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(mode="enforce")
    taint.reset_state()

    source = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        source,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    boundary = {
        "decision": taxonomy.ALLOW,
        "_meta": {"stages": [{"action_type": taxonomy.NETWORK_OUTBOUND, "decision": "allow"}]},
    }
    taint.apply_pre_tool(
        "Bash",
        {"command": "curl -I https://example.com"},
        boundary,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    assert boundary["decision"] == taxonomy.ASK
    assert "trust boundary" in boundary["reason"]
    assert boundary["_meta"]["taint"]["enforced"] is True


def test_enforce_service_read_after_source_is_boundary(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(mode="enforce")
    taint.reset_state()

    source = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        source,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    service_read = {
        "decision": taxonomy.ALLOW,
        "_meta": {"stages": [{"action_type": taxonomy.SERVICE_READ, "decision": "allow"}]},
    }
    taint.apply_pre_tool(
        "Bash",
        {"command": "curl https://example.com"},
        service_read,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    assert service_read["decision"] == taxonomy.ASK
    assert service_read["_meta"]["taint"]["category"] == "boundary"


@pytest.mark.parametrize(
    "action_type",
    [
        taxonomy.NETWORK_DIAGNOSTIC,
        taxonomy.GIT_HISTORY_REWRITE,
        taxonomy.DB_READ,
        taxonomy.CONTAINER_READ,
        taxonomy.CONTAINER_WRITE,
        taxonomy.CONTAINER_EXEC,
        taxonomy.CONTAINER_DESTRUCTIVE,
        taxonomy.BROWSER_INTERACT,
        taxonomy.BROWSER_NAVIGATE,
        taxonomy.BROWSER_EXEC,
    ],
)
def test_strict_default_boundary_sinks(action_type, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(mode="enforce")
    taint.reset_state()
    _activate_secret_source()

    sink = {
        "decision": taxonomy.ALLOW,
        "_meta": {"stages": [{"action_type": action_type, "decision": "allow"}]},
    }
    taint.apply_pre_tool(
        "Bash",
        {"command": f"{action_type} fixture"},
        sink,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    assert sink["decision"] == taxonomy.ASK
    assert sink["_meta"]["taint"]["category"] == "boundary"


@pytest.mark.parametrize("action_type", [taxonomy.CONTAINER_EXEC, taxonomy.BROWSER_EXEC])
def test_execution_shaped_boundaries_do_not_fall_back_to_activation_when_removed(
    action_type,
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(
        mode="enforce",
        categories={"boundary": {"remove": [action_type]}},
        policies={
            "default": {"activation": "ask", "boundary": "ask", "unknown": "ask"},
            "secret": {"activation": "ask", "boundary": "ask", "unknown": "ask"},
        },
    )
    taint.reset_state()
    _activate_secret_source()

    sink = {
        "decision": taxonomy.ALLOW,
        "_meta": {"stages": [{"action_type": action_type, "decision": "allow"}]},
    }
    taint.apply_pre_tool(
        "Bash",
        {"command": f"{action_type} fixture"},
        sink,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    assert sink["decision"] == taxonomy.ALLOW
    assert "taint" not in sink["_meta"]


def test_agent_exec_remote_is_boundary_not_activation(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(mode="enforce")
    taint.reset_state()

    source = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        source,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    remote = {
        "decision": taxonomy.ALLOW,
        "_meta": {"stages": [{"action_type": taxonomy.AGENT_EXEC_REMOTE, "decision": "allow"}]},
    }
    taint.apply_pre_tool(
        "Bash",
        {"command": "remote-agent run task"},
        remote,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    assert remote["decision"] == taxonomy.ASK
    assert remote["_meta"]["taint"]["category"] == "boundary"


def test_agent_exec_remote_removed_from_boundary_does_not_fall_into_activation(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(
        mode="enforce",
        categories={"boundary": {"remove": [taxonomy.AGENT_EXEC_REMOTE]}},
        policies={
            "default": {"activation": "ask", "boundary": "ask", "unknown": "ask"},
            "secret": {"activation": "ask", "boundary": "ask", "unknown": "ask"},
        },
    )
    taint.reset_state()

    source = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        source,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    remote = {
        "decision": taxonomy.ALLOW,
        "_meta": {"stages": [{"action_type": taxonomy.AGENT_EXEC_REMOTE, "decision": "allow"}]},
    }
    taint.apply_pre_tool(
        "Bash",
        {"command": "remote-agent run task"},
        remote,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    assert remote["decision"] == taxonomy.ALLOW
    assert "taint" not in remote["_meta"]


def test_agent_server_is_boundary_not_activation(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(mode="enforce")
    taint.reset_state()

    source = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        source,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    server = {
        "decision": taxonomy.ALLOW,
        "_meta": {"stages": [{"action_type": taxonomy.AGENT_SERVER, "decision": "allow"}]},
    }
    taint.apply_pre_tool(
        "Bash",
        {"command": "codex mcp-server"},
        server,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    assert server["decision"] == taxonomy.ASK
    assert server["_meta"]["taint"]["category"] == "boundary"


def test_agent_server_removed_from_boundary_does_not_fall_into_activation(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(
        mode="enforce",
        categories={"boundary": {"remove": [taxonomy.AGENT_SERVER]}},
        policies={
            "default": {"activation": "ask", "boundary": "ask", "unknown": "ask"},
            "secret": {"activation": "ask", "boundary": "ask", "unknown": "ask"},
        },
    )
    taint.reset_state()

    source = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        source,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    server = {
        "decision": taxonomy.ALLOW,
        "_meta": {"stages": [{"action_type": taxonomy.AGENT_SERVER, "decision": "allow"}]},
    }
    taint.apply_pre_tool(
        "Bash",
        {"command": "codex mcp-server"},
        server,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    assert server["decision"] == taxonomy.ALLOW
    assert "taint" not in server["_meta"]


def test_filesystem_write_propagates_state_without_prompt(monkeypatch, tmp_path, project_root):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(mode="enforce")
    taint.reset_state()
    target = f"{project_root}/debug.py"

    source = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        source,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    write = {
        "decision": taxonomy.ALLOW,
        "_meta": {"stages": [{"action_type": taxonomy.FILESYSTEM_WRITE, "decision": "allow"}]},
    }
    taint.apply_pre_tool(
        "Write",
        {"file_path": target, "content": "print('ok')"},
        write,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    assert write["decision"] == taxonomy.ALLOW
    state = _read_state()
    assert f"path:{paths.resolve_path(target)}" in state["tainted_targets"]


def test_explicit_write_propagation_waits_for_post_tool_execution(monkeypatch, tmp_path, project_root):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(mode="enforce")
    taint.reset_state()
    target = f"{project_root}/derived.py"

    source = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        source,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    write = {
        "decision": taxonomy.ASK,
        "_meta": {"stages": [{"action_type": taxonomy.FILESYSTEM_WRITE, "decision": "ask"}]},
    }
    taint.apply_pre_tool(
        "Write",
        {"file_path": target, "content": "print('ok')"},
        write,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "toolu_write"},
        execution={"state": "requested"},
    )

    state = _read_state()
    target_id = f"path:{paths.resolve_path(target)}"
    assert target_id not in state["tainted_targets"]
    assert "toolu_write" in state["pending_propagations"]

    post = {"decision": taxonomy.ALLOW, "_meta": {}}
    taint.apply_post_tool(
        "Write",
        {"file_path": target, "content": "print('ok')"},
        post,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "toolu_write"},
        execution={"state": "executed"},
    )

    state = _read_state()
    assert target_id in state["tainted_targets"]
    assert "toolu_write" not in state["pending_propagations"]
    assert post["_meta"]["taint"]["updates"]["propagation_finalized"] == "active"


def test_explicit_write_propagation_discarded_on_failed_post_tool(monkeypatch, tmp_path, project_root):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(mode="enforce")
    taint.reset_state()
    target = f"{project_root}/failed.py"

    source = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        source,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    write = {
        "decision": taxonomy.ALLOW,
        "_meta": {"stages": [{"action_type": taxonomy.FILESYSTEM_WRITE, "decision": "allow"}]},
    }
    taint.apply_pre_tool(
        "Write",
        {"file_path": target, "content": "print('ok')"},
        write,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "toolu_write"},
        execution={"state": "requested"},
    )

    post = {"decision": taxonomy.ALLOW, "_meta": {}}
    taint.apply_post_tool(
        "Write",
        {"file_path": target, "content": "print('ok')"},
        post,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "toolu_write"},
        execution={"state": "failed"},
    )

    state = _read_state()
    assert f"path:{paths.resolve_path(target)}" not in state["tainted_targets"]
    assert "toolu_write" not in state["pending_propagations"]
    assert post["_meta"]["taint"]["updates"]["propagation_finalized"] == "failed"


def test_bash_filesystem_write_propagates_destination_target(monkeypatch, tmp_path, project_root):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(mode="enforce")
    taint.reset_state()
    target = f"{project_root}/derived.py"

    source = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        source,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    write = {
        "decision": taxonomy.ALLOW,
        "_meta": {
            "stages": [{
                "tokens": ["cp", ".env", target],
                "action_type": taxonomy.FILESYSTEM_WRITE,
                "decision": "allow",
            }],
        },
    }
    taint.apply_pre_tool(
        "Bash",
        {"command": f"cp .env {target}"},
        write,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )

    state = _read_state()
    assert f"path:{paths.resolve_path(target)}" in state["tainted_targets"]
    assert "path:.env" not in state["tainted_targets"]


def test_git_write_taints_repo_and_git_remote_write_asks(monkeypatch, tmp_path, project_root):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(mode="enforce")
    taint.reset_state()

    source = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        source,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )
    git_write = {
        "decision": taxonomy.ALLOW,
        "_meta": {"stages": [{"action_type": taxonomy.GIT_WRITE, "decision": "allow"}]},
    }
    taint.apply_pre_tool(
        "Bash",
        {"command": "git add debug.py"},
        git_write,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )
    assert _read_state()["tainted_targets"][f"repo:{paths.resolve_path(project_root)}"]["labels"] == ["secret"]

    push = {
        "decision": taxonomy.ALLOW,
        "_meta": {"stages": [{"action_type": taxonomy.GIT_REMOTE_WRITE, "decision": "allow"}]},
    }
    taint.apply_pre_tool(
        "Bash",
        {"command": "git push"},
        push,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )
    assert push["decision"] == taxonomy.ASK


def test_unknown_under_taint_asks_even_if_policy_is_loosened(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(mode="enforce", policies={"default": {"unknown": "allow"}, "secret": {"unknown": "allow"}})
    taint.reset_state()

    source = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    taint.apply_pre_tool(
        "Read",
        {"file_path": ".env"},
        source,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )
    unknown = {
        "decision": taxonomy.ALLOW,
        "_meta": {"stages": [{"action_type": taxonomy.UNKNOWN, "decision": "allow"}]},
    }
    taint.apply_pre_tool(
        "Mystery",
        {},
        unknown,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "requested"},
    )
    assert unknown["decision"] == taxonomy.ASK
    assert unknown["_meta"]["taint"]["category"] == "unknown"
