"""Decision output should not include auto-allow remediation hints."""

import os

import pytest

from nah import paths, taxonomy
from nah.config import reset_config


REMEDIATION_TEXT = (
    "To always allow",
    "To trust this host",
    "To classify",
    "nah trust",
    "nah allow ",
    "nah allow-path",
    "nah classify",
    "cannot be remembered",
)


@pytest.fixture(autouse=True)
def _reset(tmp_path):
    paths.set_project_root(str(tmp_path))
    paths.reset_sensitive_paths()
    reset_config()
    yield
    paths.reset_project_root()
    paths.reset_sensitive_paths()
    reset_config()


def _assert_no_hint(decision: dict) -> None:
    assert "_hint" not in decision
    assert "hint" not in decision.get("_meta", {})
    rendered = "\n".join(
        str(value)
        for key, value in decision.items()
        if key not in {"_meta"}
    )
    for text in REMEDIATION_TEXT:
        assert text not in rendered


def _assert_no_remediation_text(text: str) -> None:
    for needle in REMEDIATION_TEXT:
        assert needle not in text


class TestNoDecisionHints:
    def test_bash_policy_ask_has_no_remediation_hint(self):
        from nah.hook import handle_bash, _to_hook_output

        decision = handle_bash({"command": "git push --force origin main"})
        assert decision["decision"] == taxonomy.ASK
        _assert_no_hint(decision)

        output = _to_hook_output(decision, "claude")
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        assert reason.startswith("nah paused: this can rewrite Git history.")
        _assert_no_remediation_text(reason)

    def test_bash_unknown_ask_has_no_classify_hint(self):
        from nah.hook import handle_bash, _to_hook_output

        decision = handle_bash({"command": "zzz_unknown_tool_xyz --flag"})
        assert decision["decision"] == taxonomy.ASK
        _assert_no_hint(decision)

        output = _to_hook_output(decision, "claude")
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "unrecognized command" in reason
        _assert_no_remediation_text(reason)

    def test_bash_network_ask_has_no_trust_hint(self):
        from nah.hook import handle_bash, _to_hook_output

        decision = handle_bash({"command": "curl https://api.example.com/data"})
        assert decision["decision"] == taxonomy.ASK
        _assert_no_hint(decision)

        output = _to_hook_output(decision, "claude")
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "api.example.com" in reason
        _assert_no_remediation_text(reason)

    def test_path_ask_has_no_allow_path_hint(self):
        result = paths.check_path("Read", "~/.aws/config")
        assert result is not None
        assert result["decision"] == taxonomy.ASK
        _assert_no_hint(result)

    def test_write_content_ask_has_no_content_varies_hint(self, project_root):
        from nah.hook import handle_write

        target = os.path.join(project_root, "test.py")
        decision = handle_write({
            "file_path": target,
            "content": "AKIAIOSFODNN7EXAMPLE",
        })
        if decision["decision"] == taxonomy.ASK:
            _assert_no_hint(decision)
            assert "content_match" in decision.get("_meta", {})

    def test_grep_credential_search_has_no_content_varies_hint(self):
        from nah.hook import handle_grep

        decision = handle_grep({
            "pattern": "AKIA[A-Z0-9]{16}",
            "path": "/etc",
        })
        if decision["decision"] == taxonomy.ASK:
            _assert_no_hint(decision)

    def test_hook_output_ignores_stale_hint_field(self):
        from nah.hook import _to_hook_output

        decision = {
            "decision": taxonomy.ASK,
            "reason": "Bash: git_history_rewrite -> ask",
            "_hint": "To always allow: nah allow git_history_rewrite",
        }
        output = _to_hook_output(decision, "claude")
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        assert reason.startswith("nah paused:")
        _assert_no_remediation_text(reason)
