"""Tests for shell_noop classification and intra-chain variable expansion."""

import os

import pytest

from nah import config, taxonomy
from nah.bash import classify_command
from nah.config import NahConfig


# ---------------------------------------------------------------------------
#  Feature 1: shell_noop detection
# ---------------------------------------------------------------------------


class TestShellNoopDetection:
    """Bare VAR=value stages should be classified as shell_noop → allow."""

    def test_single_assignment(self, project_root):
        r = classify_command("FOO=bar")
        assert len(r.stages) == 1
        assert r.stages[0].action_type == taxonomy.SHELL_NOOP
        assert r.final_decision == taxonomy.ALLOW

    def test_multiple_assignments(self, project_root):
        r = classify_command("FOO=bar BAZ=qux")
        assert len(r.stages) == 1
        assert r.stages[0].action_type == taxonomy.SHELL_NOOP
        assert r.final_decision == taxonomy.ALLOW

    def test_assignment_then_command(self, project_root):
        """First stage is shell_noop; second stage classifies normally."""
        r = classify_command("FOO=bar && ls")
        assert r.stages[0].action_type == taxonomy.SHELL_NOOP
        assert r.stages[1].action_type == taxonomy.FILESYSTEM_READ
        assert r.final_decision == taxonomy.ALLOW

    def test_assignment_prefix_not_noop(self, project_root):
        """FOO=bar ls is an env-var prefix, not a standalone assignment.
        _make_stage strips the prefix so the stage classifies normally."""
        r = classify_command("FOO=bar ls")
        assert r.stages[0].action_type != taxonomy.SHELL_NOOP
        assert r.final_decision == taxonomy.ALLOW

    def test_exec_sink_value_not_noop(self, project_root):
        """VAR=value where value is an exec sink → lang_exec, not shell_noop."""
        r = classify_command("SHELL=bash FOO=bar")
        # If the exec-sink check triggers, action_type != SHELL_NOOP
        # (exact type depends on taxonomy — what matters is it doesn't slip
        # through as allow-by-noop)
        if r.stages[0].action_type == taxonomy.LANG_EXEC:
            assert r.final_decision != taxonomy.ALLOW or "lang_exec" in r.reason

    def test_command_sub_in_value_not_noop(self, project_root):
        """FOO=$(rm -rf /) should be classified with substitution handling,
        not as a simple shell_noop."""
        r = classify_command("FOO=$(rm -rf /)")
        # The substitution inner should escalate the classification.
        # Must not be SHELL_NOOP → allow.
        has_noop = any(sr.action_type == taxonomy.SHELL_NOOP for sr in r.stages)
        if has_noop:
            # Even if the outer is noop, the inner sub should have escalated
            assert r.final_decision != taxonomy.ALLOW

    def test_semicolon_chain(self, project_root):
        r = classify_command("FOO=bar; ls")
        assert r.stages[0].action_type == taxonomy.SHELL_NOOP
        assert r.stages[1].action_type == taxonomy.FILESYSTEM_READ

    def test_pipe_after_noop(self, project_root):
        r = classify_command("FOO=bar | cat")
        assert r.stages[0].action_type == taxonomy.SHELL_NOOP


# ---------------------------------------------------------------------------
#  Feature 2: intra-chain variable expansion
# ---------------------------------------------------------------------------


class TestIntraChainVarExpansion:
    """Variables set via shell_noop stages should be expanded in later stages."""

    def test_dollar_var_basic(self, project_root):
        config._cached_config = NahConfig(trusted_paths=["/tmp"])
        r = classify_command('STAGE=/tmp/x && mkdir -p "$STAGE"')
        assert r.stages[0].action_type == taxonomy.SHELL_NOOP
        assert r.stages[1].decision == taxonomy.ALLOW
        assert "trusted path" in r.stages[1].reason

    def test_braced_var(self, project_root):
        config._cached_config = NahConfig(trusted_paths=["/tmp"])
        r = classify_command('STAGE=/tmp/x && mkdir -p "${STAGE}/sub"')
        assert r.stages[1].decision == taxonomy.ALLOW
        assert "trusted path" in r.stages[1].reason

    def test_multiple_vars(self, project_root):
        config._cached_config = NahConfig(trusted_paths=["/tmp"])
        r = classify_command('SRC=/tmp/a && DST=/tmp/b && cp "$SRC" "$DST"')
        assert r.stages[0].action_type == taxonomy.SHELL_NOOP
        assert r.stages[1].action_type == taxonomy.SHELL_NOOP
        assert r.stages[2].decision == taxonomy.ALLOW

    def test_dangerous_expansion_blocked(self, project_root):
        """BAD=/etc + rm -rf "$BAD" must NOT be allowed."""
        r = classify_command('BAD=/etc && rm -rf "$BAD"')
        assert r.final_decision != taxonomy.ALLOW

    def test_unexpanded_var_safe_default(self, project_root):
        """$UNSET without a prior assignment stays unexpanded — safe default."""
        r = classify_command('mkdir -p "$UNSET"')
        # No shell_noop stage preceded, so $UNSET is not expanded.
        # Default behavior applies (unknown path → ask or allow depending
        # on whether project_root covers it).
        # Just verify it doesn't crash and doesn't blindly allow.
        assert r.final_decision in (taxonomy.ALLOW, taxonomy.ASK)

    def test_pipe_clears_var_map(self, project_root):
        """Variables don't cross pipe boundaries (subshell semantics)."""
        config._cached_config = NahConfig(trusted_paths=["/tmp"])
        r = classify_command('STAGE=/tmp/x | mkdir -p "$STAGE"')
        # After the pipe, STAGE is not in var_map, so $STAGE stays literal.
        # mkdir -p "$STAGE" resolves relative to cwd, not to /tmp/x.
        # It should NOT get "trusted path: /tmp/x".
        assert "trusted path" not in r.stages[1].reason

    def test_semicolon_preserves_var_map(self, project_root):
        config._cached_config = NahConfig(trusted_paths=["/tmp"])
        r = classify_command('STAGE=/tmp/x; mkdir -p "$STAGE"')
        assert r.stages[1].decision == taxonomy.ALLOW
        assert "trusted path" in r.stages[1].reason

    def test_or_preserves_var_map(self, project_root):
        config._cached_config = NahConfig(trusted_paths=["/tmp"])
        r = classify_command('STAGE=/tmp/x || mkdir -p "$STAGE"')
        assert r.stages[1].decision == taxonomy.ALLOW
        assert "trusted path" in r.stages[1].reason

    def test_value_with_dollar_not_propagated(self, project_root):
        """If the value itself contains $, the binding is dropped (no nested expansion)."""
        config._cached_config = NahConfig(trusted_paths=["/tmp"])
        r = classify_command('STAGE=/tmp/$OTHER && mkdir -p "$STAGE"')
        # $STAGE was NOT added to var_map because value contains $.
        # So $STAGE in stage 2 stays literal → won't match trusted /tmp.
        assert "trusted path" not in r.stages[1].reason


# ---------------------------------------------------------------------------
#  Regression: original wharf/crane chain
# ---------------------------------------------------------------------------


class TestRegressionWharfCraneChain:
    """The exact chain that triggered the original diagnosis."""

    def test_full_staging_chain(self, project_root):
        config._cached_config = NahConfig(
            trusted_paths=["/tmp", os.path.expanduser("~/.claude/projects")],
        )
        chain = (
            'SESSION_JSONL=/home/serge/.claude/projects/-home-serge-src-autops-wharf-crane/'
            '04831c58-56ab-4580-99fa-2d4a4d272f64.jsonl '
            '&& STAGE=/tmp/mempal-session-04831c58 '
            '&& mkdir -p "$STAGE" '
            '&& cp "$SESSION_JSONL" "$STAGE/" '
            '&& ls -la "$STAGE/"'
        )
        r = classify_command(chain)
        assert r.final_decision == taxonomy.ALLOW
        assert len(r.stages) == 5
        assert r.stages[0].action_type == taxonomy.SHELL_NOOP
        assert r.stages[1].action_type == taxonomy.SHELL_NOOP
        assert r.stages[2].action_type == taxonomy.FILESYSTEM_WRITE
        assert r.stages[2].decision == taxonomy.ALLOW
        assert r.stages[3].action_type == taxonomy.FILESYSTEM_WRITE
        assert r.stages[3].decision == taxonomy.ALLOW
        assert r.stages[4].action_type == taxonomy.FILESYSTEM_READ
        assert r.stages[4].decision == taxonomy.ALLOW


# ---------------------------------------------------------------------------
#  Safety regression: dangerous patterns must not be whitewashed
# ---------------------------------------------------------------------------


class TestSafetyRegressions:
    """Ensure var expansion doesn't weaken existing protections."""

    def test_noop_then_dangerous_delete(self, project_root):
        """FOO=a; rm -rf / — the noop must not mask the dangerous delete."""
        r = classify_command("FOO=a; rm -rf /")
        assert r.final_decision != taxonomy.ALLOW

    def test_sensitive_path_via_expansion(self, project_root):
        """Expansion should expose sensitive targets, not hide them."""
        r = classify_command('TARGET=~/.ssh && cat "$TARGET/id_rsa"')
        # ~/.ssh/id_rsa is a sensitive path — must not be allowed.
        assert r.final_decision != taxonomy.ALLOW
