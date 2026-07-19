"""Empirically measure the hook timeout Codex actually enforces.

nah configures a per-hook timeout (see ``codex_run.injected_overrides``), but a
Codex release can silently change the unit (seconds → milliseconds) or cap the
value. When that happens the guard is killed early and falls back, with no
visible signal beyond a terse "hook timed out after Ns" line.

This module drives Codex with the debug probe knob (see
``codex_hooks._maybe_probe_delay``): it asks Codex to run a trivial command,
makes nah's hook stall for a known number of seconds, and observes whether
Codex lets the hook finish or kills it. The wall-time at which Codex starts
killing the hook *is* the enforced timeout — independent of what nah believes
it configured.

The pure pieces (``classify_trial``, ``binary_search_threshold``,
``measure_hook_timeout``) take an injectable trial runner so they are unit
testable without spawning Codex. ``live_trial`` is the real runner.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field

# Interactive Codex prints "hook timed out after 5s" when it kills a hook; the
# number is the enforced timeout, so when present we read it straight off.
_TIMEOUT_RE = re.compile(r"timed out after\s+(\d+(?:\.\d+)?)\s*s", re.IGNORECASE)
# Headless `codex exec` does not print a timeout message — it surfaces a hook
# status line instead: "hook: PostToolUse Completed" when the hook finished in
# time, "hook: PostToolUse Failed" when Codex killed it.
_HOOK_FAILED_RE = re.compile(r"hook:\s*\w+\s+failed", re.IGNORECASE)
_HOOK_COMPLETED_RE = re.compile(r"hook:\s*\w+\s+completed", re.IGNORECASE)
# nah's probe writes this to stderr immediately before it sleeps; Codex usually
# swallows hook stderr, but when present it confirms the hook fired.
_PROBE_MARK_RE = re.compile(r"nah: PROBE armed")

SUPPORTED_EVENTS = ("PreToolUse", "PermissionRequest", "PostToolUse")
# Of the three events, only PostToolUse can be measured non-interactively:
#   - PreToolUse is disabled in this setup (enabled=false in hook trust state),
#   - PermissionRequest never fires under headless `codex exec` (approval=never),
#   - PostToolUse is synchronous (async=false) and Codex enforces its timeout.
# PostToolUse therefore acts as the headless witness for how Codex treats the
# injected `timeout` field. PermissionRequest must be probed interactively with
# `nah run codex --probe`.
RELIABLE_EVENT = "PostToolUse"

STATUS_TIMEOUT = "timeout"
STATUS_COMPLETED = "completed"
STATUS_INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class TrialResult:
    """Outcome of a single probe trial at a given delay."""

    delay: float
    status: str  # STATUS_TIMEOUT | STATUS_COMPLETED | STATUS_INCONCLUSIVE
    enforced_seconds: float | None = None  # parsed from Codex's message, if any
    detail: str = ""


@dataclass(frozen=True)
class MeasureResult:
    """Result of measuring one event's enforced hook timeout."""

    event: str
    enforced_seconds: float | None
    method: str  # "reported" | "search" | "exceeds" | "inconclusive"
    note: str = ""
    trials: list[TrialResult] = field(default_factory=list)


def classify_trial(
    stdout: str,
    stderr: str,
    *,
    hit_outer_timeout: bool,
) -> tuple[str, float | None]:
    """Classify a trial's captured output into (status, enforced_seconds)."""
    blob = f"{stdout}\n{stderr}"
    match = _TIMEOUT_RE.search(blob)
    if match:
        try:
            return STATUS_TIMEOUT, float(match.group(1))
        except ValueError:
            return STATUS_TIMEOUT, None
    # Headless: a failed hook status means Codex killed it (no number surfaced).
    if _HOOK_FAILED_RE.search(blob):
        return STATUS_TIMEOUT, None
    if hit_outer_timeout:
        # Our own subprocess guard fired before Codex reported anything; we
        # cannot tell what happened from this trial.
        return STATUS_INCONCLUSIVE, None
    if _HOOK_COMPLETED_RE.search(blob) or _PROBE_MARK_RE.search(blob):
        # The hook ran to completion within Codex's timeout.
        return STATUS_COMPLETED, None
    # Nothing recognizable — the event under test was not triggered.
    return STATUS_INCONCLUSIVE, None


def binary_search_threshold(
    trial_fn,
    *,
    lo: float = 0.0,
    hi: float = 30.0,
    tol: float = 0.5,
    max_iters: int = 8,
) -> tuple[float | None, list[TrialResult]]:
    """Find the largest delay Codex lets a hook complete (≈ enforced timeout).

    ``trial_fn(delay) -> TrialResult``. Invariant assumed: completes for small
    delays, times out for large ones. Returns (threshold_estimate, trials);
    threshold is None if no clean crossing was observed.
    """
    trials: list[TrialResult] = []
    best_completed: float | None = None
    least_timeout: float | None = None
    iters = 0
    while iters < max_iters and (hi - lo) > tol:
        mid = round((lo + hi) / 2.0, 3)
        result = trial_fn(mid)
        trials.append(result)
        if result.status == STATUS_COMPLETED:
            best_completed = mid
            lo = mid
        elif result.status == STATUS_TIMEOUT:
            least_timeout = mid
            hi = mid
        else:
            # Inconclusive: nudge slightly higher and keep going rather than
            # trusting a noisy point.
            lo = mid
        iters += 1
    if best_completed is not None and least_timeout is not None:
        return round((best_completed + least_timeout) / 2.0, 2), trials
    if least_timeout is not None:
        return least_timeout, trials
    return None, trials


def measure_hook_timeout(
    event: str,
    *,
    runner,
    probe_high: float = 12.0,
    sweep: bool = False,
    search_hi: float = 30.0,
) -> MeasureResult:
    """Measure the timeout Codex enforces for ``event``.

    Fast path: one over-long trial. If Codex kills it and prints the number, we
    report it directly. If the hook completes, the enforced timeout is at least
    ``probe_high``. ``sweep=True`` (or an unreported timeout) falls back to a
    binary search via ``runner``.
    """
    trials: list[TrialResult] = []
    high = runner(probe_high)
    trials.append(high)

    if not sweep:
        if high.status == STATUS_TIMEOUT and high.enforced_seconds is not None:
            return MeasureResult(
                event=event,
                enforced_seconds=high.enforced_seconds,
                method="reported",
                note=f"Codex reported the timeout directly at a {probe_high}s probe",
                trials=trials,
            )
        if high.status == STATUS_COMPLETED:
            return MeasureResult(
                event=event,
                enforced_seconds=None,
                method="exceeds",
                note=f"hook ran the full {probe_high}s without being killed",
                trials=trials,
            )

    threshold, search_trials = binary_search_threshold(
        runner, lo=0.0, hi=search_hi,
    )
    trials.extend(search_trials)
    if threshold is None:
        return MeasureResult(
            event=event,
            enforced_seconds=None,
            method="inconclusive",
            note="could not observe a clean completed/timeout crossing",
            trials=trials,
        )
    return MeasureResult(
        event=event,
        enforced_seconds=threshold,
        method="search",
        note="estimated by binary search on completed/timeout crossing",
        trials=trials,
    )


def configured_timeout_seconds(event: str) -> float | None:
    """Return the timeout nah intends for ``event`` in a headless exec probe.

    live_trial drives Codex via ``exec`` (headless), so the relevant constants
    are the headless ones. These are authored as seconds; if the wire unit ever
    changes (e.g. to milliseconds) update this mapping to keep reporting intent
    in seconds.
    """
    from nah import codex_run as cr

    return {
        "PreToolUse": float(cr._HEADLESS_PRE_TOOL_TIMEOUT),
        "PermissionRequest": float(cr._HEADLESS_PERMISSION_TIMEOUT),
        "PostToolUse": float(cr._HEADLESS_POST_TOOL_TIMEOUT),
    }.get(event)


def _trigger_argv(event: str, *, sandbox: str = "read-only") -> list[str]:
    """Codex args that make Codex invoke the shell tool once (fires the hooks).

    Headless `codex exec` exercises PostToolUse; PreToolUse/PermissionRequest do
    not fire here (see RELIABLE_EVENT) but the call shape is identical.
    """
    prompt = "Use your shell tool to run exactly this command once and then stop: echo hi"
    return ["exec", "--sandbox", sandbox, prompt]


def live_trial(
    delay: float,
    event: str,
    *,
    codex_path: str | None = None,
    timeout_pad: float = 25.0,
) -> TrialResult:
    """Run one real Codex probe trial at ``delay`` seconds for ``event``."""
    from nah.codex_run import build_codex_launch

    launch = build_codex_launch(_trigger_argv(event), codex_path=codex_path)
    env = dict(launch.env)
    env["NAH_HOOK_PROBE"] = "1"
    env["NAH_HOOK_PROBE_DELAY"] = str(delay)
    env["NAH_HOOK_PROBE_EVENT"] = event

    hit_outer = False
    try:
        proc = subprocess.run(
            launch.argv,
            env=env,
            capture_output=True,
            text=True,
            timeout=delay + timeout_pad,
        )
        out, err = proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        hit_outer = True
        out = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        err = (exc.stderr or "") if isinstance(exc.stderr, str) else ""

    status, enforced = classify_trial(out, err, hit_outer_timeout=hit_outer)
    tail = "\n".join((err or out).strip().splitlines()[-3:])
    return TrialResult(delay=delay, status=status, enforced_seconds=enforced, detail=tail)


def format_measure_result(result: MeasureResult, *, configured: float | None = None) -> str:
    """Render a human-readable report for a measurement."""
    lines = [f"event:      {result.event}"]
    if configured is not None:
        lines.append(f"configured: {configured:g}s  (nah-injected)")
    if result.enforced_seconds is not None:
        lines.append(f"enforced:  ~{result.enforced_seconds:g}s  ({result.method})")
    else:
        lines.append(f"enforced:   {result.note or 'unknown'}  ({result.method})")
    if result.note and result.enforced_seconds is not None:
        lines.append(f"note:       {result.note}")
    if (
        configured is not None
        and result.enforced_seconds is not None
        and abs(result.enforced_seconds - configured) > max(1.0, 0.25 * configured)
    ):
        lines.append(
            "VERDICT:    MISMATCH — Codex enforces a shorter timeout than "
            "configured (likely a per-event cap; verify the field name/unit)."
        )
    elif configured is not None and result.enforced_seconds is not None:
        lines.append("VERDICT:    OK — enforced timeout matches the configured value.")
    trail = ", ".join(
        f"{t.delay:g}s:{t.status}" for t in result.trials
    )
    if trail:
        lines.append(f"trials:     {trail}")
    return "\n".join(lines)
