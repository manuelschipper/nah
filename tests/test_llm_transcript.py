"""Transcript-specific regression tests for LLM context formatting."""

import json

import pytest

from nah.llm import _read_transcript_tail


def _jsonl(*entries):
    return "\n".join(json.dumps(entry) for entry in entries) + "\n"


def _user_string(text):
    return {"type": "user", "message": {"role": "user", "content": text}}


def _assistant_string(text):
    return {"type": "assistant", "message": {"role": "assistant", "content": text}}


def _assistant_list(text, tool_uses=None):
    content = [{"type": "text", "text": text}]
    for tool_use in tool_uses or []:
        content.append({"type": "tool_use", **tool_use})
    return {
        "type": "assistant",
        "message": {"role": "assistant", "content": content},
    }


def _skill_meta(skill_name, body):
    return {
        "type": "user",
        "isMeta": True,
        "message": {
            "role": "user",
            "content": [{
                "type": "text",
                "text": (
                    f"Base directory for this skill: /tmp/skills/{skill_name}\n\n"
                    f"{body}"
                ),
            }],
        },
    }


@pytest.fixture
def write_transcript(tmp_path):
    def _write(*entries):
        path = tmp_path / "transcript.jsonl"
        path.write_text(_jsonl(*entries))
        return path

    return _write


class TestTranscriptSkillFormatting:
    def test_string_command_tags_are_reformatted(self, write_transcript):
        transcript = write_transcript(_user_string(
            "<command-message>design-mold</command-message>\n"
            "<command-name>/design-mold</command-name>\n"
            "<command-args>another pass</command-args>",
        ))

        result = _read_transcript_tail(str(transcript), 4000)

        assert "User invoked skill: /design-mold [args: another pass]" in result
        assert "<command-name>" not in result

    def test_plain_string_content_is_kept(self, write_transcript):
        transcript = write_transcript(_user_string("plain transcript text"))

        result = _read_transcript_tail(str(transcript), 4000)

        assert result == "User: plain transcript text"

    def test_skill_meta_is_labeled_and_header_is_stripped(self, write_transcript):
        transcript = write_transcript(_skill_meta("build-mold", "# Build Mold\n\nUse the spec"))

        result = _read_transcript_tail(str(transcript), 4000)

        assert "Skill expansion: build-mold" in result
        assert "# Build Mold" in result
        assert "Base directory for this skill" not in result
        assert "User: Base directory for this skill" not in result

    def test_malformed_skill_meta_falls_back_to_plain_user_text(self, write_transcript):
        transcript = write_transcript({
            "type": "user",
            "isMeta": True,
            "message": {
                "role": "user",
                "content": [{
                    "type": "text",
                    "text": "Base directory for this skill: \n\n# Missing path",
                }],
            },
        })

        result = _read_transcript_tail(str(transcript), 4000)

        assert "Skill expansion:" not in result
        assert "User: Base directory for this skill:" in result

    def test_duplicate_skill_meta_keeps_only_latest_full_body(self, write_transcript):
        transcript = write_transcript(
            _skill_meta("build-mold", "first body"),
            _skill_meta("build-mold", "second body"),
        )

        result = _read_transcript_tail(str(transcript), 4000)

        assert "Skill expansion: build-mold (see below)" in result
        assert "second body" in result
        assert "first body" not in result

    def test_different_skill_meta_bodies_are_kept(self, write_transcript):
        transcript = write_transcript(
            _skill_meta("build-mold", "first body"),
            _skill_meta("laptop-access", "second body"),
        )

        result = _read_transcript_tail(str(transcript), 4000)

        assert "Skill expansion: build-mold" in result
        assert "Skill expansion: laptop-access" in result
        assert "first body" in result
        assert "second body" in result

    def test_skill_meta_body_is_capped(self, write_transcript):
        body = "x" * 2500
        transcript = write_transcript(_skill_meta("build-mold", body))

        result = _read_transcript_tail(str(transcript), 10000)

        assert "x" * 2048 in result
        assert "x" * 2050 not in result
        assert "[truncated to 2048 of 2500 chars]" in result


class TestTranscriptRoles:
    def test_roles_filter_keeps_user_string_messages(self, write_transcript):
        transcript = write_transcript(
            _user_string("remove the dist directory"),
            _assistant_string("assistant string reply"),
        )

        result = _read_transcript_tail(str(transcript), 4000, roles=("user",))

        assert "User: remove the dist directory" in result
        assert "assistant string reply" not in result

    def test_roles_filter_still_keeps_assistant_tool_summaries(self, write_transcript):
        transcript = write_transcript(
            _user_string("remove the dist directory"),
            _assistant_list(
                "I will do it",
                [{"name": "Bash", "input": {"command": "rm -rf dist/"}}],
            ),
        )

        result = _read_transcript_tail(str(transcript), 4000, roles=("user",))

        assert "User: remove the dist directory" in result
        assert "I will do it" not in result
        assert "[Bash: rm -rf dist/]" in result
