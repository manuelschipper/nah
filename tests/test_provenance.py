"""Unit tests for session provenance tracking."""

import hashlib
import json
import os

import pytest

from nah import config, provenance, taxonomy
from nah.config import NahConfig
from nah.llm import LLMCallResult, ProviderAttempt


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


def test_bash_write_candidate_does_not_mark_later_lang_exec_path_as_written(
    monkeypatch,
    project_root,
):
    monkeypatch.chdir(project_root)
    _cfg()
    decision = {
        "decision": taxonomy.ALLOW,
        "_meta": {
            "stages": [
                {
                    "tokens": ["cat"],
                    "action_type": taxonomy.FILESYSTEM_WRITE,
                    "decision": taxonomy.ALLOW,
                    "policy": taxonomy.CONTEXT,
                    "redirect_target": "out.txt",
                },
                {
                    "tokens": ["python3", "existing.py"],
                    "action_type": taxonomy.LANG_EXEC,
                    "decision": taxonomy.ALLOW,
                    "policy": taxonomy.CONTEXT,
                },
            ],
        },
    }

    provenance.apply_pre_tool(
        "Bash",
        {"command": "cat > out.txt && python3 existing.py"},
        decision,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-write-exec"},
        execution={"state": "requested"},
    )

    pending = _state()["pending_writes"]["tool-write-exec"]["descriptors"]
    assert [item["raw"] for item in pending] == ["out.txt"]


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


def test_outside_project_write_records_artifact_without_repo_pollution(
    monkeypatch,
    project_root,
    tmp_path,
):
    monkeypatch.chdir(project_root)
    _cfg()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside = outside_dir / "run.py"

    _write_pre(outside)
    outside.write_text("print('outside')\n", encoding="utf-8")
    _write_post(outside)

    identity = f"path:{os.path.realpath(outside)}"
    state = _state()
    assert identity in state["artifacts"]
    assert state["artifacts"][identity]["repo"] == ""
    assert state["repos"] == {}


def test_project_activation_ignores_only_outside_project_write(
    monkeypatch,
    project_root,
    tmp_path,
):
    monkeypatch.chdir(project_root)
    _cfg()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside = outside_dir / "run.py"

    _write_pre(outside)
    outside.write_text("print('outside')\n", encoding="utf-8")
    _write_post(outside)

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
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-run"},
        execution={"state": "requested"},
    )

    assert sink["decision"] == taxonomy.ALLOW
    assert "provenance" not in sink["_meta"]


def test_exact_outside_project_activation_cannot_weaken_base_ask(
    monkeypatch,
    project_root,
    tmp_path,
):
    monkeypatch.chdir(project_root)
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside = outside_dir / "run.py"
    config._cached_config = NahConfig(
        provenance={
            "mode": "enforce",
            "policies": {"activation": "context", "boundary": "ask"},
        },
        llm_mode="on",
        llm={"providers": ["fake"], "fake": {}},
    )

    def fake_review(packet, llm_config):
        return LLMCallResult(
            decision={"decision": taxonomy.ALLOW, "reason": "safe outside file"},
            provider="fake",
            model="test",
            latency_ms=1,
            reasoning="safe outside file",
            cascade=[ProviderAttempt("fake", "success", 1, "test")],
        )

    monkeypatch.setattr("nah.llm.try_llm_provenance_review", fake_review)
    _write_pre(outside)
    outside.write_text("print('outside')\n", encoding="utf-8")
    _write_post(outside)

    sink = {
        "decision": taxonomy.ASK,
        "reason": f"script outside project: {outside}",
        "_meta": {
            "stages": [{
                "tokens": ["python3", str(outside)],
                "action_type": taxonomy.LANG_EXEC,
                "decision": taxonomy.ASK,
                "policy": taxonomy.ASK,
            }],
        },
    }
    provenance.apply_pre_tool(
        "Bash",
        {"command": f"python3 {outside}"},
        sink,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-run"},
        execution={"state": "requested"},
    )

    assert sink["decision"] == taxonomy.ASK
    meta = sink["_meta"]["provenance"]
    assert meta["match"]["scope"] == "path"
    assert meta["review"]["decision"] == taxonomy.ALLOW
    assert meta["enforced"] is False


def test_trusted_outside_project_path_stays_direct_path_only(
    monkeypatch,
    project_root,
    tmp_path,
):
    monkeypatch.chdir(project_root)
    outside_dir = tmp_path / "trusted"
    outside_dir.mkdir()
    outside = outside_dir / "run.py"
    packets = []
    config._cached_config = NahConfig(
        trusted_paths=[str(outside_dir)],
        provenance={
            "mode": "enforce",
            "policies": {"activation": "context", "boundary": "ask"},
        },
        llm_mode="on",
        llm={"providers": ["fake"], "fake": {}},
    )

    def fake_review(packet, llm_config):
        packets.append(packet)
        return LLMCallResult(
            decision={"decision": taxonomy.ALLOW, "reason": "trusted scratch file"},
            provider="fake",
            model="test",
            latency_ms=1,
            reasoning="trusted scratch file",
            cascade=[ProviderAttempt("fake", "success", 1, "test")],
        )

    monkeypatch.setattr("nah.llm.try_llm_provenance_review", fake_review)
    _write_pre(outside)
    outside.write_text("print('trusted scratch')\n", encoding="utf-8")
    _write_post(outside)

    sink = {
        "decision": taxonomy.ALLOW,
        "_meta": {
            "stages": [{
                "tokens": ["python3", str(outside)],
                "action_type": taxonomy.LANG_EXEC,
                "decision": taxonomy.ALLOW,
                "policy": taxonomy.CONTEXT,
            }],
        },
    }
    provenance.apply_pre_tool(
        "Bash",
        {"command": f"python3 {outside}"},
        sink,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-run"},
        execution={"state": "requested"},
    )

    identity = f"path:{os.path.realpath(outside)}"
    state = _state()
    assert state["artifacts"][identity]["repo"] == ""
    assert state["repos"] == {}
    assert sink["decision"] == taxonomy.ALLOW
    assert sink["_meta"]["provenance"]["match"]["scope"] == "path"
    assert [item["identity"] for item in packets[0]["files"]] == [identity]


def test_base_block_does_not_run_provenance_context_review(
    monkeypatch,
    project_root,
):
    monkeypatch.chdir(project_root)
    config._cached_config = NahConfig(
        provenance={
            "mode": "enforce",
            "policies": {"activation": "context", "boundary": "ask"},
        },
        llm_mode="on",
        llm={"providers": ["fake"], "fake": {}},
    )
    target = os.path.join(project_root, "derived.py")

    def fail_review(packet, llm_config):
        raise AssertionError("blocked base decisions must not call provenance review")

    monkeypatch.setattr("nah.llm.try_llm_provenance_review", fail_review)
    _write_pre(target)
    with open(target, "w", encoding="utf-8") as f:
        f.write("print('ok')\n")
    _write_post(target)

    sink = {
        "decision": taxonomy.BLOCK,
        "reason": "deterministic block",
        "_meta": {
            "stages": [{
                "tokens": ["python3", "derived.py"],
                "action_type": taxonomy.LANG_EXEC,
                "decision": taxonomy.BLOCK,
                "policy": taxonomy.BLOCK,
            }],
        },
    }
    provenance.apply_pre_tool(
        "Bash",
        {"command": "python3 derived.py"},
        sink,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-run"},
        execution={"state": "requested"},
    )

    assert sink["decision"] == taxonomy.BLOCK
    assert "review" not in sink["_meta"]["provenance"]


def test_context_review_error_not_truncated(monkeypatch, project_root):
    monkeypatch.chdir(project_root)
    config._cached_config = NahConfig(
        provenance={
            "mode": "enforce",
            "policies": {"activation": "context", "boundary": "ask"},
        },
        llm_mode="on",
        llm={"providers": ["fake"], "fake": {}},
    )
    target = os.path.join(project_root, "derived.py")
    long_error = "review failed " + ("x" * 400)

    def fail_review(packet, llm_config):
        raise RuntimeError(long_error)

    monkeypatch.setattr("nah.llm.try_llm_provenance_review", fail_review)
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
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-run"},
        execution={"state": "requested"},
    )

    assert sink["decision"] == taxonomy.ASK
    assert sink["_meta"]["provenance"]["review"]["error"] == long_error


def test_direct_lang_exec_context_packet_includes_session_repo_delta(
    monkeypatch,
    project_root,
    tmp_path,
):
    from nah import paths

    monkeypatch.chdir(project_root)
    config._cached_config = NahConfig(
        provenance={
            "mode": "enforce",
            "policies": {"activation": "context", "boundary": "ask"},
        },
        llm_mode="on",
        llm={"providers": ["fake"], "fake": {}},
    )
    packets = []

    def fake_review(packet, llm_config):
        packets.append((packet, llm_config))
        return LLMCallResult(
            decision={"decision": taxonomy.ALLOW, "reason": "safe delta"},
            provider="fake",
            model="test",
            latency_ms=1,
            reasoning="safe delta",
            cascade=[ProviderAttempt("fake", "success", 1, "test")],
        )

    monkeypatch.setattr("nah.llm.try_llm_provenance_review", fake_review)

    other_root = str(tmp_path / "other")
    os.makedirs(other_root, exist_ok=True)
    other_file = os.path.join(other_root, "other.py")
    paths.set_project_root(other_root)
    monkeypatch.chdir(other_root)
    _write_pre(other_file, event_id="tool-other")
    with open(other_file, "w", encoding="utf-8") as f:
        f.write("print('other')\n")
    _write_post(other_file, event_id="tool-other")

    paths.set_project_root(project_root)
    monkeypatch.chdir(project_root)
    helper = os.path.join(project_root, "helper.py")
    main = os.path.join(project_root, "main.py")
    baseline = os.path.join(project_root, "baseline.py")
    with open(baseline, "w", encoding="utf-8") as f:
        f.write("print('baseline')\n")
    _write_pre(helper, event_id="tool-helper")
    with open(helper, "w", encoding="utf-8") as f:
        f.write("def value():\n    return 42\n")
    _write_post(helper, event_id="tool-helper")
    _write_pre(main, event_id="tool-main")
    with open(main, "w", encoding="utf-8") as f:
        f.write("from helper import value\nprint(value())\n")
    _write_post(main, event_id="tool-main")

    sink = {
        "decision": taxonomy.ALLOW,
        "_meta": {
            "stages": [{
                "tokens": ["python3", "main.py"],
                "action_type": taxonomy.LANG_EXEC,
                "decision": taxonomy.ALLOW,
                "policy": taxonomy.CONTEXT,
            }],
        },
    }
    provenance.apply_pre_tool(
        "Bash",
        {"command": "python3 main.py"},
        sink,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-run"},
        execution={"state": "requested"},
    )

    assert sink["decision"] == taxonomy.ALLOW
    assert sink["_meta"]["provenance"]["match"]["scope"] == "path"
    assert packets
    packet = packets[0][0]
    paths_in_packet = [item["path"] for item in packet["files"]]
    assert paths_in_packet[0] == main
    assert helper in paths_in_packet
    assert baseline not in paths_in_packet
    assert other_file not in paths_in_packet


def test_package_run_context_packet_includes_session_repo_delta(
    monkeypatch,
    project_root,
    tmp_path,
):
    from nah import paths

    monkeypatch.chdir(project_root)
    config._cached_config = NahConfig(
        provenance={
            "mode": "enforce",
            "policies": {"activation": "context", "boundary": "ask"},
        },
        llm_mode="on",
        llm={"providers": ["fake"], "fake": {}},
    )
    packets = []

    def fake_review(packet, llm_config):
        packets.append((packet, llm_config))
        return LLMCallResult(
            decision={"decision": taxonomy.ALLOW, "reason": "safe test run"},
            provider="fake",
            model="test",
            latency_ms=1,
            reasoning="safe test run",
            cascade=[ProviderAttempt("fake", "success", 1, "test")],
        )

    monkeypatch.setattr("nah.llm.try_llm_provenance_review", fake_review)

    other_root = str(tmp_path / "other")
    os.makedirs(other_root, exist_ok=True)
    other_file = os.path.join(other_root, "package.json")
    paths.set_project_root(other_root)
    monkeypatch.chdir(other_root)
    _write_pre(other_file, event_id="tool-other")
    with open(other_file, "w", encoding="utf-8") as f:
        f.write('{"scripts":{"test":"node other.test.js"}}\n')
    _write_post(other_file, event_id="tool-other")

    paths.set_project_root(project_root)
    monkeypatch.chdir(project_root)
    manifest = os.path.join(project_root, "package.json")
    test_file = os.path.join(project_root, "client.test.js")
    baseline = os.path.join(project_root, "baseline.js")
    with open(baseline, "w", encoding="utf-8") as f:
        f.write("console.log('baseline')\n")
    _write_pre(manifest, event_id="tool-package")
    with open(manifest, "w", encoding="utf-8") as f:
        f.write('{"scripts":{"test":"node client.test.js"}}\n')
    _write_post(manifest, event_id="tool-package")
    _write_pre(test_file, event_id="tool-test")
    with open(test_file, "w", encoding="utf-8") as f:
        f.write("console.log('test')\n")
    _write_post(test_file, event_id="tool-test")

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
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-run"},
        execution={"state": "requested"},
    )

    assert sink["decision"] == taxonomy.ALLOW
    assert sink["_meta"]["provenance"]["match"]["scope"] == "repo"
    assert packets
    packet = packets[0][0]
    assert packet["action"]["category"] == "activation"
    paths_in_packet = [item["path"] for item in packet["files"]]
    assert manifest in paths_in_packet
    assert test_file in paths_in_packet
    assert baseline not in paths_in_packet
    assert other_file not in paths_in_packet


def test_boundary_context_packet_includes_session_repo_delta(
    monkeypatch,
    project_root,
    tmp_path,
):
    from nah import paths

    monkeypatch.chdir(project_root)
    config._cached_config = NahConfig(
        provenance={
            "mode": "enforce",
            "policies": {"activation": "ask", "boundary": "context"},
        },
        llm_mode="on",
        llm={"providers": ["fake"], "fake": {}},
    )
    packets = []

    def fake_review(packet, llm_config):
        packets.append((packet, llm_config))
        return LLMCallResult(
            decision={"decision": taxonomy.ALLOW, "reason": "safe boundary"},
            provider="fake",
            model="test",
            latency_ms=1,
            reasoning="safe boundary",
            cascade=[ProviderAttempt("fake", "success", 1, "test")],
        )

    monkeypatch.setattr("nah.llm.try_llm_provenance_review", fake_review)

    other_root = str(tmp_path / "other")
    os.makedirs(other_root, exist_ok=True)
    other_file = os.path.join(other_root, "other.py")
    paths.set_project_root(other_root)
    monkeypatch.chdir(other_root)
    _write_pre(other_file, event_id="tool-other")
    with open(other_file, "w", encoding="utf-8") as f:
        f.write("print('other')\n")
    _write_post(other_file, event_id="tool-other")

    paths.set_project_root(project_root)
    monkeypatch.chdir(project_root)
    app = os.path.join(project_root, "app.py")
    baseline = os.path.join(project_root, "baseline.py")
    with open(baseline, "w", encoding="utf-8") as f:
        f.write("print('baseline')\n")
    _write_pre(app, event_id="tool-app")
    with open(app, "w", encoding="utf-8") as f:
        f.write("print('app')\n")
    _write_post(app, event_id="tool-app")

    sink = {
        "decision": taxonomy.ALLOW,
        "_meta": {
            "stages": [{
                "tokens": ["curl", "-I", "https://api.example.test"],
                "action_type": taxonomy.NETWORK_OUTBOUND,
                "decision": taxonomy.ALLOW,
                "policy": taxonomy.CONTEXT,
            }],
        },
    }
    provenance.apply_pre_tool(
        "Bash",
        {"command": "curl -I https://api.example.test"},
        sink,
        runtime="claude",
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-boundary"},
        execution={"state": "requested"},
    )

    assert sink["decision"] == taxonomy.ALLOW
    assert sink["_meta"]["provenance"]["match"]["scope"] == "repo"
    assert packets
    packet = packets[0][0]
    assert packet["action"]["category"] == "boundary"
    paths_in_packet = [item["path"] for item in packet["files"]]
    assert app in paths_in_packet
    assert baseline not in paths_in_packet
    assert other_file not in paths_in_packet


@pytest.mark.parametrize("log_prompt", [False, True])
def test_context_review_records_prompt_hash_and_optional_exact_prompt(
    monkeypatch,
    project_root,
    log_prompt,
):
    monkeypatch.chdir(project_root)
    exact_prompt = "exact provenance review prompt\nwith session delta"
    config._cached_config = NahConfig(
        provenance={
            "mode": "enforce",
            "policies": {"activation": "context", "boundary": "ask"},
        },
        llm_mode="on",
        llm={"providers": ["fake"], "fake": {}},
        log={"llm_prompt": log_prompt},
    )

    def fake_review(packet, llm_config):
        return LLMCallResult(
            decision={"decision": taxonomy.ALLOW, "reason": "safe delta"},
            provider="fake",
            model="test",
            latency_ms=1,
            reasoning="safe delta",
            prompt=exact_prompt,
            cascade=[ProviderAttempt("fake", "success", 1, "test")],
        )

    monkeypatch.setattr("nah.llm.try_llm_provenance_review", fake_review)
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
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-run"},
        execution={"state": "requested"},
    )

    review = sink["_meta"]["provenance"]["review"]
    expected_hash = "sha256:" + hashlib.sha256(
        exact_prompt.encode("utf-8", "replace"),
    ).hexdigest()
    assert review["prompt_hash"] == expected_hash
    if log_prompt:
        assert review["prompt"] == exact_prompt
    else:
        assert "prompt" not in review


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


def test_dirty_git_state_without_file_delta_makes_context_packet_incomplete(
    monkeypatch,
    project_root,
):
    monkeypatch.chdir(project_root)
    _cfg(policies={"activation": "context", "boundary": "ask"})
    write = {
        "decision": taxonomy.ALLOW,
        "_meta": {
            "stages": [{
                "tokens": ["git", "commit", "-m", "change"],
                "action_type": taxonomy.GIT_WRITE,
                "decision": taxonomy.ALLOW,
                "policy": taxonomy.ALLOW,
            }],
        },
    }
    provenance.apply_pre_tool(
        "Bash",
        {"command": "git commit -m change"},
        write,
        runtime="claude",
        runtime_meta={"session_id": "sess"},
        execution={"state": "approved_to_run"},
    )

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
        runtime_meta={"session_id": "sess", "tool_use_id": "tool-run"},
        execution={"state": "requested"},
    )

    assert sink["decision"] == taxonomy.ASK
    assert sink["_meta"]["provenance"]["review"]["packet_complete"] is False
