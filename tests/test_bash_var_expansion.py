"""Tests for intra-chain variable expansion in sensitive-path checks.

Covers the bypass closure documented in mold ``nah-874``:
``BAD=/etc/shadow && cat "$BAD"`` must classify the same as the direct
``cat /etc/shadow`` invocation. Exercises both bare env-only stages
and ``export NAME=value`` stages, along with scope boundaries (pipe,
unsafe RHS), shadowing, and the stage-display surface.
"""

import pytest

from nah.bash import classify_command


# ---------------------------------------------------------------------------
# Group 1: bypass closure — bare env assignment
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    'BAD=/etc/shadow && cat "$BAD"',
    'DIR=/etc && ls "$DIR/shadow"',
    'DIR=/etc && cat "${DIR}/shadow"',
    'A=/tmp/ok B=/etc/shadow && cat "$B"',
])
def test_bare_assignment_blocks_sensitive_path(cmd):
    result = classify_command(cmd)
    assert result.final_decision == "block"
    assert "/etc/shadow" in result.reason


def test_bare_assignment_matches_direct_cat(tmp_path):
    direct = classify_command("cat /etc/shadow")
    via_var = classify_command('BAD=/etc/shadow && cat "$BAD"')
    assert direct.final_decision == via_var.final_decision == "block"
    assert direct.reason == via_var.reason


def test_home_ssh_via_var_matches_direct():
    # The mold pins behavior to "same as `cat ~/.ssh/id_rsa`" — whatever
    # that is, expansion must not introduce a divergence.
    direct = classify_command("cat ~/.ssh/id_rsa")
    via_var = classify_command('KEY=~/.ssh/id_rsa && cat "$KEY"')
    assert direct.final_decision == via_var.final_decision
    assert direct.reason == via_var.reason


# ---------------------------------------------------------------------------
# Group 2: bypass closure — export assignment
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    'export NAME=/etc/shadow && cat "$NAME"',
    'export A=/etc B=/tmp && cat "$A/shadow"',
])
def test_export_assignment_blocks_sensitive_path(cmd):
    result = classify_command(cmd)
    assert result.final_decision == "block"
    assert "/etc/shadow" in result.reason


# ---------------------------------------------------------------------------
# Group 3: LANG_EXEC benefits from expansion
# ---------------------------------------------------------------------------

def test_lang_exec_script_var_resolved():
    # Before expansion this produced a garbled reason like
    # "script not found: <cwd>/$SCRIPT". With expansion the consumer
    # stage sees /etc/shadow directly and blocks on sensitive path.
    result = classify_command('SCRIPT=/etc/shadow && bash "$SCRIPT"')
    assert result.final_decision in {"block", "ask"}
    assert "$SCRIPT" not in result.reason


# ---------------------------------------------------------------------------
# Group 4: friction non-regressions (must stay ALLOW)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    # /tmp is a default trusted path — the whole chain is safe.
    'SESSION=/tmp/session.jsonl && STAGE=/tmp/staging && '
    'mkdir -p "$STAGE" && cp "$SESSION" "$STAGE/"',
    # In-project relative paths remain fine.
    'OUT=./build && mkdir -p "$OUT"',
    # Pure env + echo is unchanged.
    'FOO=bar && echo hi',
    # Command substitution RHS is rejected; no path concern.
    'BAD=$(whoami) && echo "$BAD"',
])
def test_friction_non_regressions(cmd):
    assert classify_command(cmd).final_decision == "allow"


# ---------------------------------------------------------------------------
# Group 5: scope boundaries
# ---------------------------------------------------------------------------

def test_pipe_clears_var_map():
    # Pipe is a subshell boundary — the RHS cat does not see BAD.
    result = classify_command('BAD=/etc/shadow | cat "$BAD"')
    assert result.final_decision == "allow"


@pytest.mark.parametrize("cmd", [
    'BAD=$(whoami) && cat "$BAD"',
    'BAD=`whoami` && cat "$BAD"',
])
def test_unsafe_rhs_not_propagated(cmd):
    # Command-substitution results are placeholders — never propagate.
    result = classify_command(cmd)
    assert result.final_decision == "allow"


def test_chained_indirection_not_propagated():
    # A=/etc then BAD=$A/shadow — RHS of BAD contains $, rejected.
    result = classify_command('A=/etc && BAD=$A/shadow && cat "$BAD"')
    assert result.final_decision == "allow"


def test_unbound_variable_left_literal():
    # $UNSET is not bound — the path scanner should see no real path.
    result = classify_command('cat "$UNSET"')
    assert result.final_decision == "allow"


@pytest.mark.parametrize("cmd", [
    'BAD=/etc/shadow || cat "$BAD"',
    'BAD=/etc/shadow; cat "$BAD"',
])
def test_or_and_semicolon_preserve_var_map(cmd):
    # Real bash semantics: || and ; are not subshells.
    result = classify_command(cmd)
    assert result.final_decision == "block"
    assert "/etc/shadow" in result.reason


# ---------------------------------------------------------------------------
# Group 6: shadowing
# ---------------------------------------------------------------------------

def test_latest_binding_wins():
    result = classify_command(
        'BAD=/tmp/ok && BAD=/etc/shadow && cat "$BAD"'
    )
    assert result.final_decision == "block"
    assert "/etc/shadow" in result.reason


def test_unsafe_rhs_shadows_earlier_safe_binding():
    # BAD first bound to /etc/shadow, then rebound to $(whoami).
    # The unsafe rebinding drops the entry — consumer sees literal $BAD.
    result = classify_command(
        'BAD=/etc/shadow && BAD=$(whoami) && cat "$BAD"'
    )
    assert result.final_decision == "allow"


# ---------------------------------------------------------------------------
# Group 7: stage display (debug surface)
# ---------------------------------------------------------------------------

def test_consumer_stage_tokens_are_expanded():
    result = classify_command('BAD=/etc/shadow && cat "$BAD"')
    assert result.stages[1].tokens == ["cat", "/etc/shadow"]


def test_partial_substitution_stage_tokens():
    result = classify_command('DIR=/etc && cat "${DIR}/shadow"')
    assert result.stages[1].tokens == ["cat", "/etc/shadow"]


# ---------------------------------------------------------------------------
# Group 8: executed command untouched
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    'BAD=/etc/shadow && cat "$BAD"',
    'export NAME=/etc/shadow && cat "$NAME"',
    'DIR=/etc && cat "${DIR}/shadow"',
])
def test_command_string_preserved(cmd):
    result = classify_command(cmd)
    assert result.command == cmd


# ---------------------------------------------------------------------------
# Group 9: inline leading env assignment (out of scope — locked behavior)
# ---------------------------------------------------------------------------

@pytest.mark.xfail(
    reason=(
        "Single-stage inline env assignment (FOO=/etc/shadow cat $FOO) "
        "is a separate bypass tracked as a follow-up mold. _make_stage "
        "strips the prefix before any classifier sees it, so intra-chain "
        "expansion cannot reach it."
    ),
    strict=True,
)
def test_inline_leading_env_assignment_known_limitation():
    result = classify_command('FOO=/etc/shadow cat "$FOO"')
    assert result.final_decision == "block"
