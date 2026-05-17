"""Unit tests for session provenance tracking."""

import json
import os

import pytest

from nah import config, provenance, taxonomy
from nah.config import NahConfig


def _cfg(**provenance_overrides):
    base = {
        "mode": "enforce",
        "policies": {
            "activation": "ask",
            "boundary": "ask",
        },
    }
    base.update(provenance_overrides)
    config._cached_config = NahConfig(provenance=base)


def _state(run_id="run-test"):
    with open(provenance.state_path(run_id), encoding="utf-8") as f:
        return json.load(f)


def _write_pre(path, *, run_id="run-test", session="sess", event_id="tool-1"):
    decision = {"decision": taxonomy.ALLOW, "_meta": {"stages": []}}
    provenance.apply_pre_tool(
        "Write",
        {"file_path": str(path), "content": "print('ok')\n"},
        decision,
        runtime="claude",
        runtime_meta={"session_id": session, "tool_use_id": event_id},
        execution={"state": "requested"},
    )
    return decision


def _write_post(path, *, run_id="run-test", session="sess", event_id="tool-1", state="executed"):
    decision = {"decision": taxonomy.ALLOW, "_meta": {}}
    provenance.apply_post_tool(
        "Write",
        {"file_path": str(path), "content": "print('ok')\n"},
        decision,
        runtime="claude",
        runtime_meta={"session_id": session, "tool_use_id": event_id},
        execution={"state": state},
    )
    return decision


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("NAH_PROVENANCE_RUN_ID", "run-test")
    provenance.reset_state()
    yield
    provenance.reset_state()


def test_post_tool_success_finalizes_written_path(monkeypatch, project_root):
    monkeypatch.chdir(project_root)
    _cfg()
    target = os.path.join(project_root, "scripts", "foo.py")
    os.makedirs(os.path.dirname(target), exist_ok=True)

    pre = _write_pre(target)
    assert pre["_meta"]["provenance"]["updates"]["write"]["status"] == "pending"

    with open(target, "w", encoding="utf-8") as f:
        f.write("print('ok')\n")
    post = _write_post(target)

    path_id = f"path:{target}"
    state = _state()
    assert path_id in state["artifacts"]
    assert path_id in state["repos"][f"repo:{project_root}"]["paths"]
    assert post["_meta"]["provenance"]["updates"]["write_finalized"] == "active"


def test_failed_or_denied_write_does_not_create_active_artifact(monkeypatch, project_root):
    monkeypatch.chdir(project_root)
    _cfg()
    target = os.path.join(project_root, "scripts", "foo.py")
    os.makedirs(os.path.dirname(target), exist_ok=True)

    _write_pre(target)
    _write_post(target, state="failed")

    state = _state()
    assert state["artifacts"] == {}
    assert state["pending_writes"] == {}


def test_lang_exec_of_session_written_file_triggers_activation(monkeypatch, project_root):
    monkeypatch.chdir(project_root)
    _cfg()
    target = os.path.join(project_root, "derived.py")
    _write_pre(target)
    with open(target, "w", encoding="utf-8") as f:
        f.write("print('ok')\n")
    _write_post(target)

    sink = {
        "decision": taxonomy.ALLOW,
        "reason": "lang_exec allowed",
        "_meta": {
            "stages": [{
                "tokens": ["python3", "derived.py"],
                "action_type": taxonomy.LANG_EXEC,
                "decision": taxonomy.ALLOW,
                "policy": taxonomy.CONTEXT,
            }],
        },
    }
    provenance.apply_pre_tool(
        "Bash",
        {"command": "python3 derived.py"},
        sink,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-2"},
        execution={"state": "requested"},
    )

    assert sink["decision"] == taxonomy.ASK
    assert sink["_meta"]["provenance"]["category"] == "activation"
    assert sink["_meta"]["provenance"]["match"]["scope"] == "path"


def test_preexisting_file_without_session_write_does_not_trigger(monkeypatch, project_root):
    monkeypatch.chdir(project_root)
    _cfg()
    target = os.path.join(project_root, "existing.py")
    with open(target, "w", encoding="utf-8") as f:
        f.write("print('ok')\n")

    sink = {
        "decision": taxonomy.ALLOW,
        "_meta": {
            "stages": [{
                "tokens": ["python3", "existing.py"],
                "action_type": taxonomy.LANG_EXEC,
                "decision": taxonomy.ALLOW,
                "policy": taxonomy.CONTEXT,
            }],
        },
    }
    provenance.apply_pre_tool(
        "Bash",
        {"command": "python3 existing.py"},
        sink,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-2"},
        execution={"state": "requested"},
    )

    assert sink["decision"] == taxonomy.ALLOW
    assert "provenance" not in sink["_meta"]


def test_package_run_in_repo_with_session_written_state_triggers_activation(monkeypatch, project_root):
    monkeypatch.chdir(project_root)
    _cfg()
    target = os.path.join(project_root, "package.json")
    _write_pre(target)
    with open(target, "w", encoding="utf-8") as f:
        f.write('{"scripts":{"test":"node test.js"}}\n')
    _write_post(target)

    sink = {
        "decision": taxonomy.ALLOW,
        "_meta": {
            "stages": [{
                "tokens": ["npm", "test"],
                "action_type": taxonomy.PACKAGE_RUN,
                "decision": taxonomy.ALLOW,
                "policy": taxonomy.ALLOW,
            }],
        },
    }
    provenance.apply_pre_tool(
        "Bash",
        {"command": "npm test"},
        sink,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-2"},
        execution={"state": "requested"},
    )

    assert sink["decision"] == taxonomy.ASK
    assert sink["_meta"]["provenance"]["category"] == "activation"
    assert sink["_meta"]["provenance"]["match"]["scope"] == "repo"


def test_boundary_wins_for_container_exec(monkeypatch, project_root):
    monkeypatch.chdir(project_root)
    _cfg()
    target = os.path.join(project_root, "derived.py")
    _write_pre(target)
    with open(target, "w", encoding="utf-8") as f:
        f.write("print('ok')\n")
    _write_post(target)

    sink = {
        "decision": taxonomy.ALLOW,
        "_meta": {
            "stages": [{
                "tokens": ["docker", "exec", "app", "python3", "derived.py"],
                "action_type": taxonomy.CONTAINER_EXEC,
                "decision": taxonomy.ALLOW,
                "policy": taxonomy.ASK,
            }],
        },
    }
    provenance.apply_pre_tool(
        "Bash",
        {"command": "docker exec app python3 derived.py"},
        sink,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-2"},
        execution={"state": "requested"},
    )

    assert sink["decision"] == taxonomy.ASK
    assert sink["_meta"]["provenance"]["category"] == "boundary"


def test_context_policy_without_provider_stays_ask(monkeypatch, project_root):
    monkeypatch.chdir(project_root)
    _cfg(policies={"activation": "context", "boundary": "ask"})
    target = os.path.join(project_root, "derived.py")
    _write_pre(target)
    with open(target, "w", encoding="utf-8") as f:
        f.write("print('ok')\n")
    _write_post(target)

    sink = {
        "decision": taxonomy.ALLOW,
        "_meta": {
            "stages": [{
                "tokens": ["python3", "derived.py"],
                "action_type": taxonomy.LANG_EXEC,
                "decision": taxonomy.ALLOW,
                "policy": taxonomy.CONTEXT,
            }],
        },
    }
    provenance.apply_pre_tool(
        "Bash",
        {"command": "python3 derived.py"},
        sink,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-2"},
        execution={"state": "requested"},
    )

    assert sink["decision"] == taxonomy.ASK
    review = sink["_meta"]["provenance"]["review"]
    assert review["status"] == "no_provider"


def test_incomplete_review_packet_cannot_auto_allow(monkeypatch, project_root):
    monkeypatch.chdir(project_root)
    _cfg(
        policies={"activation": "context", "boundary": "ask"},
        review={"max_files": 50, "max_bytes_per_file": 4, "max_bytes_total": 100},
    )
    target = os.path.join(project_root, "derived.py")
    _write_pre(target)
    with open(target, "w", encoding="utf-8") as f:
        f.write("print('too big for fixture')\n")
    _write_post(target)

    sink = {
        "decision": taxonomy.ALLOW,
        "_meta": {
            "stages": [{
                "tokens": ["python3", "derived.py"],
                "action_type": taxonomy.LANG_EXEC,
                "decision": taxonomy.ALLOW,
                "policy": taxonomy.CONTEXT,
            }],
        },
    }
    provenance.apply_pre_tool(
        "Bash",
        {"command": "python3 derived.py"},
        sink,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-2"},
        execution={"state": "requested"},
    )

    assert sink["decision"] == taxonomy.ASK
    review = sink["_meta"]["provenance"]["review"]
    assert review["packet_complete"] is False
