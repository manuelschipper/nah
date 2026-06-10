"""Tests for the hook-timeout probe harness (nah.codex_probe).

These cover the pure pieces — output classification, binary search, the
measure orchestration, and the report formatter — with a fake trial runner, so
no real Codex process is spawned.
"""

import pytest

from nah import codex_probe as cp
from nah.codex_probe import (
    MeasureResult,
    TrialResult,
    binary_search_threshold,
    classify_trial,
    format_measure_result,
    measure_hook_timeout,
)


# --- classify_trial ---------------------------------------------------------


def test_classify_reads_reported_timeout_seconds():
    status, secs = classify_trial(
        "", "PreToolUse hook (failed) error: hook timed out after 5s", hit_outer_timeout=False
    )
    assert status == cp.STATUS_TIMEOUT
    assert secs == 5.0


def test_classify_completed_when_probe_armed_and_no_timeout():
    status, secs = classify_trial(
        "nah-probe-ok", "nah: PROBE armed — delaying PreToolUse hook 3.000s before decision",
        hit_outer_timeout=False,
    )
    assert status == cp.STATUS_COMPLETED
    assert secs is None


def test_classify_headless_completed_status():
    status, secs = classify_trial("hook: PostToolUse Completed", "", hit_outer_timeout=False)
    assert status == cp.STATUS_COMPLETED
    assert secs is None


def test_classify_headless_failed_status_is_timeout():
    # Headless exec reports a killed hook as "Failed" with no number.
    status, secs = classify_trial("hook: PostToolUse Failed", "", hit_outer_timeout=False)
    assert status == cp.STATUS_TIMEOUT
    assert secs is None


def test_classify_inconclusive_when_probe_never_armed():
    status, secs = classify_trial("nothing", "", hit_outer_timeout=False)
    assert status == cp.STATUS_INCONCLUSIVE
    assert secs is None


def test_classify_inconclusive_on_outer_timeout():
    status, _ = classify_trial("", "nah: PROBE armed", hit_outer_timeout=True)
    assert status == cp.STATUS_INCONCLUSIVE


# --- binary_search_threshold ------------------------------------------------


def _runner_with_enforced(threshold):
    """Fake runner: completes when delay <= threshold, else times out."""

    def run(delay):
        if delay <= threshold:
            return TrialResult(delay=delay, status=cp.STATUS_COMPLETED)
        return TrialResult(delay=delay, status=cp.STATUS_TIMEOUT, enforced_seconds=threshold)

    return run


def test_binary_search_brackets_the_threshold():
    est, trials = binary_search_threshold(_runner_with_enforced(5.0), lo=0.0, hi=30.0, tol=0.5)
    assert est is not None
    assert abs(est - 5.0) <= 1.0
    assert trials  # it actually probed


def test_binary_search_returns_none_when_never_times_out():
    run = lambda d: TrialResult(delay=d, status=cp.STATUS_COMPLETED)
    est, _ = binary_search_threshold(run, lo=0.0, hi=8.0, tol=0.5)
    assert est is None


# --- measure_hook_timeout ---------------------------------------------------


def test_measure_fast_path_reads_reported_number():
    def runner(delay):
        return TrialResult(
            delay=delay, status=cp.STATUS_TIMEOUT, enforced_seconds=5.0
        )

    result = measure_hook_timeout("PreToolUse", runner=runner, probe_high=12.0)
    assert result.method == "reported"
    assert result.enforced_seconds == 5.0
    assert len(result.trials) == 1  # no search needed


def test_measure_reports_exceeds_when_hook_completes():
    runner = lambda d: TrialResult(delay=d, status=cp.STATUS_COMPLETED)
    result = measure_hook_timeout("PreToolUse", runner=runner, probe_high=12.0)
    assert result.method == "exceeds"
    assert result.enforced_seconds is None


def test_measure_sweep_falls_back_to_search():
    result = measure_hook_timeout(
        "PreToolUse", runner=_runner_with_enforced(5.0), probe_high=12.0, sweep=True
    )
    assert result.method == "search"
    assert result.enforced_seconds is not None
    assert abs(result.enforced_seconds - 5.0) <= 1.0


# --- format_measure_result --------------------------------------------------


def test_format_flags_mismatch():
    result = MeasureResult(
        event="PreToolUse",
        enforced_seconds=5.0,
        method="reported",
        trials=[TrialResult(delay=12.0, status=cp.STATUS_TIMEOUT, enforced_seconds=5.0)],
    )
    text = format_measure_result(result, configured=30.0)
    assert "MISMATCH" in text
    assert "PreToolUse" in text


def test_format_reports_ok_when_matching():
    result = MeasureResult(event="PreToolUse", enforced_seconds=29.0, method="search")
    text = format_measure_result(result, configured=30.0)
    assert "OK" in text
    assert "MISMATCH" not in text
