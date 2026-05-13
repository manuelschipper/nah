"""Tests for nah-managed Codex authority rules."""

from pathlib import Path

import pytest

from nah.codex_authority import (
    AUTHORITY_RULE_PREFIXES,
    AUTHORITY_RULES_HASH_PREFIX,
    AUTHORITY_RULES_MARKER,
    AUTHORITY_RULES_FILE,
    CodexAuthorityError,
    authority_rules_path,
    authority_rules_status,
    ensure_authority_rules,
    remove_authority_rules,
    render_authority_rules,
)


def test_render_authority_rules_is_deterministic_prompt_only():
    first = render_authority_rules()
    second = render_authority_rules()

    assert first == second
    assert AUTHORITY_RULES_MARKER in first.splitlines()[:4]
    assert AUTHORITY_RULES_HASH_PREFIX in first
    assert 'decision = "prompt"' in first
    assert 'decision = "allow"' not in first
    assert 'decision = "forbidden"' not in first
    for prefix in AUTHORITY_RULE_PREFIXES:
        assert f'pattern = ["{prefix}"]' in first


def test_ensure_authority_rules_creates_and_is_idempotent(tmp_path):
    home = tmp_path / "codex"
    path = authority_rules_path(home)

    first = ensure_authority_rules(home=home)
    second = ensure_authority_rules(home=home)

    assert first.path == path
    assert first.current
    assert second.current
    assert path.read_text(encoding="utf-8") == render_authority_rules()


def test_ensure_authority_rules_refreshes_stale_managed_file(tmp_path):
    home = tmp_path / "codex"
    path = authority_rules_path(home)
    path.parent.mkdir(parents=True)
    path.write_text(f"{AUTHORITY_RULES_MARKER}\nold\n", encoding="utf-8")

    status = authority_rules_status(home)
    assert status.state == "stale"

    repaired = ensure_authority_rules(home=home)

    assert repaired.current
    assert path.read_text(encoding="utf-8") == render_authority_rules()


def test_ensure_authority_rules_refuses_unmanaged_file(tmp_path):
    home = tmp_path / "codex"
    path = authority_rules_path(home)
    path.parent.mkdir(parents=True)
    path.write_text('prefix_rule(pattern=["cat"], decision="prompt")\n', encoding="utf-8")

    with pytest.raises(CodexAuthorityError):
        ensure_authority_rules(home=home)


def test_remove_authority_rules_removes_only_managed_file(tmp_path):
    home = tmp_path / "codex"
    path = authority_rules_path(home)
    ensure_authority_rules(home=home)

    removed = remove_authority_rules(home=home)

    assert removed == path
    assert not path.exists()
    assert remove_authority_rules(home=home) is None


def test_remove_authority_rules_refuses_unmanaged_file(tmp_path):
    home = tmp_path / "codex"
    path = Path(home) / "rules" / AUTHORITY_RULES_FILE
    path.parent.mkdir(parents=True)
    path.write_text("user content\n", encoding="utf-8")

    with pytest.raises(CodexAuthorityError):
        remove_authority_rules(home=home)
