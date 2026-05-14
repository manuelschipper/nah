"""Tests for Codex apply_patch parsing and acquisition."""

import json

import pytest

from nah import apply_patch
from nah.apply_patch import PatchParseError, acquire_patch_text, parse_patch


def _patch(path, added='print("ok")'):
    return f"""*** Begin Patch
*** Update File: {path}
@@
+{added}
*** End Patch
"""


def test_parse_add_and_update_extracts_paths_and_added_content():
    parsed = parse_patch("""*** Begin Patch
*** Add File: src/new.py
+print("new")
*** Update File: src/existing.py
@@
-old()
+new()
 context()
*** End Patch
""")

    assert [op.kind for op in parsed.operations] == ["add", "update"]
    assert parsed.paths == ("src/new.py", "src/existing.py")
    assert 'print("new")' in parsed.added_content
    assert "new()" in parsed.added_content
    assert "old()" not in parsed.added_content


def test_parse_delete_and_move_operations():
    parsed = parse_patch("""*** Begin Patch
*** Delete File: old.txt
*** Update File: src/name.py
*** Move to: src/renamed.py
@@
+name = "new"
*** End Patch
""")

    assert [op.kind for op in parsed.operations] == ["delete", "move"]
    assert parsed.paths == ("old.txt", "src/name.py", "src/renamed.py")
    assert parsed.has_destructive_operation is True


@pytest.mark.parametrize(
    "patch",
    [
        "",
        "*** Begin Patch\n*** Update File: a.txt\n",
        "*** Begin Patch\n*** Bogus: a.txt\n*** End Patch\n",
        "*** Begin Patch\norphan\n*** End Patch\n",
        "*** Begin Patch\n*** Update File: \n*** End Patch\n",
    ],
)
def test_parse_malformed_patches_raise(patch):
    with pytest.raises(PatchParseError):
        parse_patch(patch)


def test_acquire_direct_patch_text():
    patch = "*** Begin Patch\n*** Update File: a.txt\n@@\n+x\n*** End Patch\n"

    result = acquire_patch_text({"input": patch})

    assert result is not None
    assert result.text == patch
    assert result.source == "tool_input"


def test_acquire_direct_patch_text_allows_matching_transcript(tmp_path):
    patch = "*** Begin Patch\n*** Update File: a.txt\n@@\n+x\n*** End Patch\n"
    transcript = tmp_path / "session.jsonl"
    transcript.write_text(
        json.dumps({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call",
                "call_id": "call_1",
                "name": "apply_patch",
                "input": patch,
            },
        }) + "\n",
        encoding="utf-8",
    )

    result = acquire_patch_text({"input": patch}, str(transcript))

    assert result is not None
    assert result.text == patch
    assert result.source == "tool_input"


def test_acquire_direct_patch_text_wins_over_transcript_disagreement(tmp_path):
    direct = "*** Begin Patch\n*** Update File: a.txt\n@@\n+x\n*** End Patch\n"
    transcript_patch = "*** Begin Patch\n*** Update File: b.txt\n@@\n+y\n*** End Patch\n"
    transcript = tmp_path / "session.jsonl"
    transcript.write_text(
        json.dumps({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call",
                "call_id": "call_1",
                "name": "apply_patch",
                "input": transcript_patch,
            },
        }) + "\n",
        encoding="utf-8",
    )

    result = acquire_patch_text({"input": direct}, str(transcript))

    assert result is not None
    assert result.text == direct
    assert result.source == "tool_input"


def test_acquire_transcript_unmatched_apply_patch(tmp_path):
    patch = "*** Begin Patch\n*** Update File: a.txt\n@@\n+x\n*** End Patch\n"
    transcript = tmp_path / "session.jsonl"
    transcript.write_text(
        json.dumps({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call",
                "call_id": "call_1",
                "name": "apply_patch",
                "input": patch,
            },
        }) + "\n",
        encoding="utf-8",
    )

    result = acquire_patch_text({}, str(transcript))

    assert result is not None
    assert result.text == patch
    assert result.source == "transcript"


def test_acquire_transcript_retries_append_race(monkeypatch):
    patch = "*** Begin Patch\n*** Update File: a.txt\n@@\n+x\n*** End Patch\n"
    calls = []

    def fake_lookup(transcript_path):
        calls.append(transcript_path)
        if len(calls) == 1:
            return apply_patch.TranscriptPatchLookup(None, "missing")
        return apply_patch.TranscriptPatchLookup(
            apply_patch.PatchText(patch, "transcript"),
            "single",
        )

    monkeypatch.setattr(apply_patch, "_lookup_patch_text_from_transcript", fake_lookup)
    monkeypatch.setattr(apply_patch.time, "sleep", lambda _seconds: None)

    result = acquire_patch_text({}, "session.jsonl")

    assert result is not None
    assert result.text == patch
    assert result.source == "transcript"
    assert calls == ["session.jsonl", "session.jsonl"]


def test_acquire_transcript_ambiguous_pending_patches_asks(tmp_path):
    patch = "*** Begin Patch\n*** Update File: a.txt\n@@\n+x\n*** End Patch\n"
    transcript = tmp_path / "session.jsonl"
    transcript.write_text(
        "\n".join(
            json.dumps({
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "call_id": call_id,
                    "name": "apply_patch",
                    "input": patch,
                },
            })
            for call_id in ("call_1", "call_2")
        )
        + "\n",
        encoding="utf-8",
    )

    assert acquire_patch_text({}, str(transcript)) is None


def test_acquire_transcript_completed_call_is_not_current(tmp_path):
    patch = "*** Begin Patch\n*** Update File: a.txt\n@@\n+x\n*** End Patch\n"
    transcript = tmp_path / "session.jsonl"
    transcript.write_text(
        json.dumps({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call",
                "call_id": "call_1",
                "name": "apply_patch",
                "input": patch,
            },
        })
        + "\n"
        + json.dumps({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "call_1",
                "output": "{}",
            },
        })
        + "\n",
        encoding="utf-8",
    )

    assert acquire_patch_text({}, str(transcript)) is None


def test_classify_safe_patch_asks_even_with_deleted_edit_envs(project_root, monkeypatch):
    monkeypatch.setenv("NAH_CODEX_AUTO_ALLOW_SAFE_APPLY_PATCH", "1")
    monkeypatch.setenv("NAH_CODEX_ACCEPT_EDITS", "1")

    decision, log_input = apply_patch.classify_codex_apply_patch(
        {"input": _patch("app.py")},
        {"cwd": project_root, "transcript_path": ""},
    )

    assert decision["decision"] == "ask"
    assert decision["reason"] == "apply_patch: safe project edit handled by nah"
    assert "app.py" in log_input["_nah_patch_paths"][0]
